"""Command-line interface.

    overstep run -r <requests> -i <identities.json> -s <scope.txt> [options]
    overstep identities template
    overstep requests list -r <requests>

``run`` exits 0 when nothing was bypassed, 3 when at least one BYPASSED finding was
observed (so a pipeline can gate on it), and 2 on a usage/IO error.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, report
from .banner import banner
from .capture import load_requests
from .identities import IdentityError, IdentitySet, template
from .replay import SAFE_METHODS, WRITE_METHODS, run as replay_run
from .scope import Scope


def _stderr_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stderr, "isatty") and sys.stderr.isatty()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="overstep", description=__doc__)
    p.add_argument("--version", action="version", version=f"overstep {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="replay requests across identities and diff responses")
    r.add_argument("-r", "--requests", required=True, help="HAR file, raw request file, or a directory of them")
    r.add_argument("-i", "--identities", required=True, help="identities JSON file")
    r.add_argument("-s", "--scope", required=True, help="scope file (authorized hosts)")
    r.add_argument("-o", "--json-out", help="write JSON findings to this path")
    r.add_argument("--md", help="write a Markdown report draft to this path")
    r.add_argument("--delay", type=float, default=0.5, help="seconds between requests (default 0.5)")
    r.add_argument("--methods", help="comma list of methods to test (default: GET,HEAD,OPTIONS)")
    r.add_argument("--include-writes", action="store_true", help="also replay POST/PUT/PATCH/DELETE (can MUTATE other users' data — use with care)")
    r.add_argument("--verify", action="store_true", help="verify TLS certs (default: off, for staging targets)")
    r.add_argument("--timeout", type=float, default=15.0, help="per-request timeout seconds (default 15)")
    r.add_argument("--scheme", default="https", choices=("https", "http"), help="scheme for raw requests without one (default https)")
    r.add_argument("--all", action="store_true", help="show ENFORCED/ERROR rows too, not just hits")

    i = sub.add_parser("identities", help="identity helpers")
    i.add_argument("action", choices=("template", "list"))
    i.add_argument("-i", "--identities", help="identities file (for 'list')")

    q = sub.add_parser("requests", help="inspect captured requests")
    q.add_argument("action", choices=("list",))
    q.add_argument("-r", "--requests", required=True)
    q.add_argument("--scheme", default="https", choices=("https", "http"))

    return p


def _cmd_run(args) -> int:
    try:
        scope = Scope.from_file(args.scope)
    except FileNotFoundError:
        print(f"error: scope file not found: {args.scope}", file=sys.stderr)
        return 2
    if not scope.includes:
        print("error: scope file has no in-scope rules — refusing to run", file=sys.stderr)
        return 2

    try:
        idset = IdentitySet.from_file(args.identities)
    except FileNotFoundError:
        print(f"error: identities file not found: {args.identities}", file=sys.stderr)
        return 2
    except (IdentityError, ValueError) as exc:
        print(f"error: bad identities file: {exc}", file=sys.stderr)
        return 2

    try:
        requests = load_requests(args.requests, scheme=args.scheme)
    except FileNotFoundError:
        print(f"error: requests path not found: {args.requests}", file=sys.stderr)
        return 2
    if not requests:
        print("error: no requests loaded from the given path", file=sys.stderr)
        return 2

    if args.methods:
        allowed = tuple(m.strip().upper() for m in args.methods.split(",") if m.strip())
    else:
        allowed = SAFE_METHODS + (WRITE_METHODS if args.include_writes else ())

    sys.stderr.write(banner(color=_stderr_color()) + "\n")
    if any(m in WRITE_METHODS for m in allowed):
        sys.stderr.write(
            "!! write methods are enabled — replays may modify other users' data. "
            "Only proceed if that is authorized and intended.\n\n"
        )

    run_obj = replay_run(
        requests, idset, scope,
        allowed_methods=allowed, delay=args.delay,
        verify=args.verify, timeout=args.timeout, version=__version__,
    )

    report.render_console(run_obj, show_all=args.all)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(report.to_json(run_obj))
        print(f"\nJSON findings → {args.json_out}", file=sys.stderr)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(report.to_markdown(run_obj))
        print(f"Markdown draft → {args.md}", file=sys.stderr)

    return 3 if run_obj.hits() else 0


def _cmd_identities(args) -> int:
    if args.action == "template":
        print(template())
        return 0
    if not args.identities:
        print("error: 'list' needs -i/--identities", file=sys.stderr)
        return 2
    try:
        idset = IdentitySet.from_file(args.identities)
    except (FileNotFoundError, IdentityError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for i in idset.identities:
        print(f"{i.name:<16} {i.role:<9} headers={list(i.headers)}")
    print(f"\nauth headers stripped from owner on replay: {idset.auth_headers}")
    return 0


def _cmd_requests(args) -> int:
    try:
        reqs = load_requests(args.requests, scheme=args.scheme)
    except FileNotFoundError:
        print(f"error: requests path not found: {args.requests}", file=sys.stderr)
        return 2
    for r in reqs:
        print(f"{r.label():<60} {r.url}")
    print(f"\n{len(reqs)} request(s) loaded")
    return 0


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "identities":
        return _cmd_identities(args)
    if args.command == "requests":
        return _cmd_requests(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
