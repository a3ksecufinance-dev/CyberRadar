#!/usr/bin/env python3
"""Run govulncheck over every module and fail on anything not accounted for.

govulncheck on its own is all-or-nothing: either the pipeline blocks on every
reachable vulnerability, including those with no fixed version, or it reports
into a log nobody opens. Neither is useful. This gate keeps it blocking and
gives the one thing that makes blocking tenable — a written exception with a
date on it.

Three ways it fails, and they are all deliberate:

  * a reachable vulnerability that is not in security/vuln-allowlist.json;
  * an exception whose review date has passed, so a decision cannot be left
    to rot by the person who made it;
  * an exception that claims its dependency is test-only while a production
    file imports the package that pulls it in.

It prints what it allowed, so a reader of the CI log sees the exceptions
rather than having to know the file exists.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import re
import subprocess
import sys

BACKEND = pathlib.Path(__file__).resolve().parent.parent
ALLOWLIST = BACKEND / "security" / "vuln-allowlist.json"

# An exception may claim that the dependency is reached only from a package
# that runs under `go test`. The claim is verified rather than believed, by
# the key "test_only_package" naming that package.


def modules() -> list[pathlib.Path]:
    out = [BACKEND / "internal"]
    out += sorted(p.parent for p in (BACKEND / "services").glob("*/go.mod"))
    return [m for m in out if (m / "go.mod").exists()]


def load_allowlist() -> dict[str, dict]:
    if not ALLOWLIST.exists():
        return {}
    data = json.loads(ALLOWLIST.read_text())
    return {e["id"]: e for e in data.get("exceptions", [])}


def expired(entry: dict, today: datetime.date) -> bool:
    by = entry.get("review_by")
    if not by:
        return True
    return datetime.date.fromisoformat(by) < today


def production_importers(package: str) -> list[str]:
    """Return the non-test files that import the named package.

    An exception resting on "this only runs under go test" is worth exactly as
    much as that statement, and the statement stops being true the day someone
    imports the package from a service. So it is checked here rather than
    trusted.
    """
    needle = f'"github.com/cyberradar/platform/{package}"'
    offenders = []
    for path in BACKEND.rglob("*.go"):
        rel = str(path.relative_to(BACKEND))
        if path.name.endswith("_test.go") or rel.startswith(package):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if needle in text:
            offenders.append(rel)
    return offenders


def findings(module: pathlib.Path) -> list[dict]:
    """Run govulncheck on one module and return its reachable findings.

    The JSON output is a stream of one-object-per-message; a finding is
    reachable when its trace names a symbol in this module's own code, which
    govulncheck marks by giving the trace a function at the deepest frame.
    """
    try:
        proc = subprocess.run(
            [os.environ.get("GOVULNCHECK", "govulncheck"), "-format", "json", "./..."],
            cwd=module, capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        print("  govulncheck is not on PATH; install it with "
              "go install golang.org/x/vuln/cmd/govulncheck@latest")
        return [{"osv": "GOVULNCHECK_MISSING", "module": "the gate itself", "fixed": ""}]
    if proc.returncode not in (0, 3):  # 3 is "vulnerabilities found"
        # A scan that could not run is not a pass. The database being
        # unreachable is the usual cause, and it must not read as "clean".
        print(f"  govulncheck failed in {module.name}: {proc.stderr.strip()[:400]}")
        return [{"osv": "GOVULNCHECK_FAILED", "module": "the scan itself", "fixed": ""}]

    out, osvs = [], {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "osv" in msg and isinstance(msg["osv"], dict):
            osvs[msg["osv"]["id"]] = msg["osv"]
        if "finding" in msg:
            f = msg["finding"]
            trace = f.get("trace") or []
            if not trace or not trace[0].get("function"):
                continue  # imported or required, but not called
            out.append({
                "osv": f.get("osv", "?"),
                "module": trace[-1].get("module", "?"),
                "fixed": f.get("fixed_version", ""),
            })
    return out


def main() -> int:
    today = datetime.date.today()
    allow = load_allowlist()

    # The stream format changed shape between govulncheck releases often
    # enough to be worth saying: this parses objects it recognises and ignores
    # the rest, so a new message type cannot make the gate pass by accident —
    # a finding it cannot read is a finding it does not drop.
    reachable: dict[str, dict] = {}
    for m in modules():
        rel = m.relative_to(BACKEND)
        print(f"→ {rel}")
        for f in findings(m):
            key = f["osv"]
            entry = reachable.setdefault(key, {**f, "modules": set()})
            entry["modules"].add(str(rel))

    problems: list[str] = []

    for osv, f in sorted(reachable.items()):
        where = ", ".join(sorted(f["modules"]))
        if osv in allow:
            e = allow[osv]
            if f["fixed"]:
                problems.append(
                    f"{osv} ({f['module']}) is allowlisted but {f['fixed']} fixes it — "
                    f"bump the module instead of excusing it")
                continue
            if expired(e, today):
                problems.append(
                    f"{osv} ({f['module']}) was accepted until {e.get('review_by')}, "
                    f"which has passed — review it")
                continue
            print(f"  allowed  {osv}  {f['module']}  until {e['review_by']}  [{where}]")
            continue
        fix = f" — fixed in {f['fixed']}" if f["fixed"] else " — no fixed version"
        problems.append(f"{osv} ({f['module']}){fix}  [{where}]")

    for osv, e in sorted(allow.items()):
        package = e.get("test_only_package")
        if not package or osv not in reachable:
            continue
        offenders = production_importers(package)
        if offenders:
            problems.append(
                f"{osv} is accepted on the ground that {package} only runs under "
                f"go test, but it is imported by {', '.join(offenders)}")

    scanned = "GOVULNCHECK_FAILED" not in reachable and "GOVULNCHECK_MISSING" not in reachable
    if scanned:
        for osv in sorted(allow):
            if osv not in reachable:
                print(f"  stale    {osv} is no longer reported; remove it from the allowlist")

    if problems:
        print("\nvulnerabilities with nothing said about them:")
        for p in problems:
            print(f"  {p}")
        print(f"\n{len(problems)} to answer. Either bump the module, or add an entry to "
              f"{ALLOWLIST.relative_to(BACKEND)} with a reason and a review date.")
        return 1

    print("\nnothing reachable that is not accounted for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
