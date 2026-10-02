#!/usr/bin/env python3
"""Derive docs/07-reference-api.md from the services' own route registrations.

Written rather than maintained by hand for the reason every other check in this
repository exists: a reference list nobody regenerates is a list that is wrong,
and it is wrong silently — the reader finds out when a call 404s. `make docs-api`
regenerates it and CI fails if the committed file differs from what the code
says, so a route added without documenting it is a failing build rather than a
support ticket.

What it reads, per service:
  · cmd/server/main.go   the /api/v1 subtree, r.Mount prefixes, and the
                         authorisation middleware applied to the whole subtree;
  · internal/handler/*.go  RegisterRoutes(r chi.Router) and Routes() bodies,
                         following r.Route/r.Group nesting and r.Use(...) scope.

It is a parser, not a compiler: it understands the shapes this codebase uses and
refuses to guess at anything else. A service whose routes it cannot find is
reported as such rather than omitted, because a silently empty section is the
failure mode this file exists to prevent.
"""

import json
import os
import re
import sys
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
REPO = os.path.dirname(BACKEND)
OUT = os.path.join(REPO, "docs", "07-reference-api.md")

METHODS = ("Get", "Post", "Put", "Patch", "Delete", "Head", "Options")
# Parentheses nested two deep: enough for authmw.RequirePermission("x:y").
BAL = r'(?:[^()]|\((?:[^()]|\([^()]*\))*\))*'

call_re = re.compile(
    r'\br\.(?:With\((?P<with>' + BAL + r')\)\.)?(?P<m>' + "|".join(METHODS) + r')\(\s*"(?P<p>[^"]*)"')
route_re = re.compile(r'\br\.(?:Route|Group)\(\s*(?:"(?P<p>[^"]*)")?\s*,?\s*func\s*\(')
use_re = re.compile(r'\br\.Use\(\s*authmw\.RequirePermission(?P<by>ByMethod)?\(\s*"(?P<v>[^"]+)"')
perm_re = re.compile(r'RequirePermission\(\s*"([^"]+)"')
permby_re = re.compile(r'RequirePermissionByMethod\(\s*"([^"]+)"')
mount_re = re.compile(r'r\.Mount\(\s*"(?P<p>[^"]*)"\s*,\s*\w+\.(?P<fn>\w+)\(')

BY_METHOD = object()   # marker: permission depends on the HTTP verb


def resolve(perm, method):
    """A RequirePermissionByMethod resource becomes :read for GET/HEAD, :write otherwise."""
    if perm is None:
        return "—"
    if isinstance(perm, tuple) and perm[0] is BY_METHOD:
        return perm[1] + (":read" if method in ("GET", "HEAD") else ":write")
    return perm


def walk(src, start, prefix, perm, out):
    """Collect routes from the { ... } block whose opening brace is at `start`."""
    depth, i, n = 0, start, len(src)
    while i < n:
        m = use_re.match(src, i)
        if m:
            # r.Use(...) governs every route declared later in this block.
            perm = (BY_METHOD, m.group('v')) if m.group('by') else m.group('v')
            i = m.end()
            continue
        c = src[i]
        if c == '{':
            depth += 1
            i += 1
            continue
        if c == '}':
            depth -= 1
            if depth == 0:
                return i
            i += 1
            continue
        m = route_re.match(src, i)
        if m:
            brace = src.find('{', m.end() - 1)
            if brace != -1:
                i = walk(src, brace, prefix + (m.group('p') or ""), perm, out) + 1
                continue
        m = call_re.match(src, i)
        if m:
            path = re.sub(r'/+', '/', prefix + m.group('p'))
            if path != "/" and path.endswith("/"):
                path = path[:-1]
            own = perm_re.search(m.group('with') or "")
            out.append((m.group('m').upper(), path or "/", own.group(1) if own else perm))
            i = m.end()
            continue
        i += 1
    return i


def service_routes(svc):
    main = os.path.join(BACKEND, "services", svc, "cmd", "server", "main.go")
    if not os.path.exists(main):
        return None
    msrc = open(main).read()
    pb = permby_re.search(msrc)
    perm = (BY_METHOD, pb.group(1)) if pb else None
    mounts = {m.group('fn'): m.group('p') for m in mount_re.finditer(msrc)}

    out = []
    for m in re.finditer(r'r\.Route\(\s*"(/api/v1[^"]*)"\s*,\s*func', msrc):
        walk(msrc, msrc.find('{', m.end() - 1), "", perm, out)
    for f in sorted(glob.glob(os.path.join(BACKEND, "services", svc, "internal", "handler", "*.go"))):
        if f.endswith("_test.go"):
            continue
        src = open(f).read()
        for m in re.finditer(r'func \([^)]*\) RegisterRoutes\([^)]*\)\s*\{', src):
            walk(src, m.end() - 1, "", perm, out)
        for m in re.finditer(r'func \([^)]*\) (\w+)\(\)\s*(?:chi\.Router|http\.Handler)\s*\{', src):
            if m.group(1) in mounts:
                walk(src, m.end() - 1, mounts[m.group(1)], perm, out)

    seen, uniq = set(), []
    for r_ in out:
        key = (r_[0], r_[1])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r_)
    return sorted(uniq, key=lambda t: (t[1], t[0]))


def ports():
    """The service→port table dev-local.sh and docker-compose agree on."""
    src = open(os.path.join(BACKEND, "scripts", "dev-local.sh")).read()
    return {m.group(2): m.group(1)
            for m in re.finditer(r'"[a-z]+-service:(\d{4}):([a-z]+)"', src)}


def main():
    svcs = sorted(os.listdir(os.path.join(BACKEND, "services")))
    table, empty, total = {}, [], 0
    for svc in svcs:
        rs = service_routes(svc)
        if rs is None:
            continue
        if not rs:
            empty.append(svc)
        table[svc] = rs
        total += len(rs)

    port = ports()
    lines = []
    w = lines.append

    w("<!-- GÉNÉRÉ — ne pas modifier à la main.")
    w("     Régénérer : cd backend && make docs-api")
    w("     Source : les enregistrements de routes des services eux-mêmes. -->")
    w("")
    w("# Référence API")
    w("")
    w(f"> {total} routes sur {len([s for s in table if table[s]])} services.")
    w("> Dérivé du code, pas tenu à la main — voir `backend/scripts/gen-api-reference.py`.")
    w("> Conventions, enveloppe de réponse et codes d'erreur : [`06-api.md`](06-api.md).")
    w("")
    w("Toutes les routes ci-dessous sont préfixées par `/api/v1` et exigent un JWT.")
    w("La colonne **Permission** donne ce que le RBAC vérifie ; `—` signifie qu'aucune")
    w("permission n'est exigée au-delà d'un jeton valide.")
    w("")
    w("Chaque service expose en plus `GET /health`, sans authentification.")
    w("")
    w("## Index")
    w("")
    w("| Service | Port | Routes |")
    w("|---|---|---|")
    for svc in sorted(table):
        if not table[svc]:
            continue
        anchor = svc.replace("_", "-")
        w(f"| [`{svc}`](#{anchor}) | {port.get(svc, '—')} | {len(table[svc])} |")
    w("")
    if empty:
        w("Sans API HTTP : " + ", ".join(f"`{s}`" for s in empty) +
          " — voir [`09-ingestion.md`](09-ingestion.md).")
        w("")
    w("---")
    w("")

    for svc in sorted(table):
        rs = table[svc]
        if not rs:
            continue
        w(f"## {svc}")
        w("")
        w(f"`:{port.get(svc, '—')}` · {len(rs)} routes")
        w("")
        w("| Méthode | Chemin | Permission |")
        w("|---|---|---|")
        for method, path, perm in rs:
            w(f"| `{method}` | `/api/v1{path}` | `{resolve(perm, method)}` |")
        w("")

    body = "\n".join(lines) + "\n"
    if "--check" in sys.argv:
        current = open(OUT).read() if os.path.exists(OUT) else ""
        if current != body:
            print(f"{OUT} is out of date with the services' routes — run: make docs-api",
                  file=sys.stderr)
            return 1
        print(f"{OUT} matches the code ({total} routes)")
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "w").write(body)
    print(f"{OUT}: {total} routes across {len([s for s in table if table[s]])} services")
    return 0


if __name__ == "__main__":
    sys.exit(main())
