#!/usr/bin/env python3
"""Run npm audit and fail on anything not accounted for.

The backend has had a blocking gate over govulncheck for a while. The frontend
had `npm audit --audit-level=high` with `continue-on-error: true`, which is the
arrangement that reads well and does nothing: between two readings of that log
the count went from ten advisories to fourteen, and the comment in the workflow
explaining them became wrong without anybody noticing. A report nobody is
obliged to read is not a control.

This is the same bargain the Go gate makes. Blocking on every advisory is not
possible here — the critical one needs Next 16, four more need Tailwind 4, and
`braces` has no fixed version at all, its latest published release being the
one the advisory names. Blocking on all of them would mean a pipeline that can
never be green, which teaches everyone to ignore it. So the gate holds the
exceptions, each with a reason and a review date, and fails on everything else.

Five ways it fails, all deliberate:

  * an advisory that is not in security/npm-audit-allowlist.json;
  * an exception whose review date has passed;
  * an exception that has since gained a fix needing no breaking change, which
    makes it work rather than an exception;
  * an exception that claims to be build-time-only while the package is a
    runtime dependency;
  * a scan that could not run — npm audit exits non-zero both when it finds
    something and when it fails, so the two have to be told apart.

It prints what it allowed, so a reader of the CI log sees the exceptions
rather than having to know the file exists.

    python3 scripts/npm-audit-gate.py
"""

from __future__ import annotations

import datetime
import json
import pathlib
import subprocess
import sys

FRONTEND = pathlib.Path(__file__).resolve().parent.parent
ALLOWLIST = FRONTEND / "security" / "npm-audit-allowlist.json"

# Below this, an advisory is noted but does not have to be answered for. The
# workflow used --audit-level=high; moderate ones are held too, because the
# open redirect in next-intl is a moderate and is worth a written decision.
MINIMUM = "moderate"
RANK = {"info": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}


def load_allowlist() -> dict[str, dict]:
    if not ALLOWLIST.exists():
        return {}
    data = json.loads(ALLOWLIST.read_text())
    return {e["package"]: e for e in data.get("exceptions", [])}


def expired(entry: dict, today: datetime.date) -> bool:
    by = entry.get("review_by")
    if not by:
        return True
    return datetime.date.fromisoformat(by) < today


def runtime_dependencies() -> set[str]:
    """The packages that ship, as opposed to those that only build."""
    pkg = json.loads((FRONTEND / "package.json").read_text())
    return set(pkg.get("dependencies", {}))


def audit() -> dict | None:
    """npm audit's report, or None when the scan itself did not run.

    npm audit exits 1 when it finds something at or above the audit level, so
    a non-zero exit is not by itself a failure to scan. What distinguishes the
    two is whether a report came back at all.
    """
    proc = subprocess.run(
        ["npm", "audit", "--json"],
        cwd=FRONTEND, capture_output=True, text=True, check=False,
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("npm audit produced no report:", file=sys.stderr)
        print((proc.stderr or proc.stdout)[:2000], file=sys.stderr)
        return None
    if "vulnerabilities" not in report:
        print("npm audit's report has no vulnerabilities section — "
              "the format changed, or the scan did not complete", file=sys.stderr)
        return None
    return report


def own_advisories(entry: dict) -> list[dict]:
    """The advisories filed against this package itself.

    npm's `via` mixes two things: advisory objects, which are this package's
    own, and bare package names, which mean "flagged because something it
    depends on is". A package with none of the former carries no advisory of
    its own — it inherits one, and it is cleared when its parent is.
    """
    return [v for v in entry.get("via", []) if isinstance(v, dict)]


def inherited_parents(entry: dict) -> list[str]:
    return [v for v in entry.get("via", []) if isinstance(v, str)]


def fix_without_breaking(entry: dict) -> bool:
    """True when npm says this one can be fixed without a major bump.

    `fixAvailable: true` means a patched version exists in range; an object
    means the fix is a different package at a version npm calls a breaking
    change. Only the first makes an exception indefensible.

    An inherited advisory is excluded, and the exclusion is not a loosening:
    npm reports `fixAvailable: true` for a package that is only flagged
    through a dependency, because a newer release of it exists — but
    installing that newer release changes nothing, since the advisory is its
    parent's. `npm audit fix` agrees: run against this tree it moves neither.
    Blocking on them would make the gate demand a fix that does not exist.
    """
    return entry.get("fixAvailable") is True and bool(own_advisories(entry))


def main() -> int:
    today = datetime.date.today()
    allow = load_allowlist()
    runtime = runtime_dependencies()

    report = audit()
    if report is None:
        print("\nthe scan did not run — that is a failure, not a pass.")
        return 1

    found = {
        name: v for name, v in report["vulnerabilities"].items()
        if RANK.get(v.get("severity", "info"), 0) >= RANK[MINIMUM]
    }

    problems: list[str] = []

    for name, v in sorted(found.items()):
        severity = v.get("severity", "?")
        if name in allow:
            e = allow[name]
            if fix_without_breaking(v):
                problems.append(
                    f"{name} ({severity}) is allowlisted, but npm reports a fix that "
                    f"needs no breaking change — take it instead of excusing it")
                continue
            if expired(e, today):
                problems.append(
                    f"{name} ({severity}) was accepted until {e.get('review_by')}, "
                    f"which has passed — review it")
                continue
            if e.get("build_time_only") and name in runtime:
                problems.append(
                    f"{name} is accepted on the ground that it only runs at build time, "
                    f"but package.json lists it under dependencies")
                continue
            # An entry that rests on "its parent carries this" has to name the
            # parent, the parent has to be what npm actually reports, and the
            # parent has to be answered for too — otherwise the child outlives
            # the reasoning the moment the parent is cleared or renamed.
            parents = inherited_parents(v)
            if not own_advisories(v):
                claimed = e.get("inherited_from")
                if not claimed:
                    problems.append(
                        f"{name} ({severity}) has no advisory of its own — it is flagged "
                        f"through {', '.join(parents) or 'something npm did not name'}. "
                        f"Say so with \"inherited_from\"")
                    continue
                named = [claimed] if isinstance(claimed, str) else list(claimed)
                wrong = [c for c in named if c not in parents]
                if wrong:
                    problems.append(
                        f"{name} ({severity}) is accepted as inherited from "
                        f"{', '.join(wrong)}, but npm reports it through "
                        f"{', '.join(parents) or 'nothing'}")
                    continue
                # Naming one parent explains it; every parent has to be
                # answered for, or clearing the named one would leave the
                # child excused by a reason that no longer holds.
                orphans = [c for c in parents if c in found and c not in allow]
                if orphans:
                    problems.append(
                        f"{name} ({severity}) is accepted as inherited, but "
                        f"{', '.join(orphans)} — which npm also reports it through — "
                        f"is not itself accounted for")
                    continue
            print(f"  allowed  {severity:8} {name:26} until {e['review_by']}  ({e['needs']})")
            continue
        fix = v.get("fixAvailable")
        if fix is True:
            how = " — a fix is available with no breaking change"
        elif isinstance(fix, dict):
            how = f" — fixed by {fix.get('name')}@{fix.get('version')}, a breaking change"
        else:
            how = " — no fixed version"
        problems.append(f"{name} ({severity}){how}")

    for name in sorted(allow):
        if name not in found:
            print(f"  stale    {name} is no longer reported; remove it from the allowlist")

    if problems:
        print("\nadvisories with nothing said about them:")
        for p in problems:
            print(f"  {p}")
        print(f"\n{len(problems)} to answer. Either take the fix, or add an entry to "
              f"{ALLOWLIST.relative_to(FRONTEND)} with a reason and a review date.")
        return 1

    counts = report.get("metadata", {}).get("vulnerabilities", {})
    print(f"\nnothing unaccounted for ({counts.get('critical', 0)} critical, "
          f"{counts.get('high', 0)} high, {counts.get('moderate', 0)} moderate, "
          f"all answered for).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
