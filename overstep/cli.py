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

    g = sub.add_parser("gui", help="launch the local web GUI")
    g.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1; keep it local)")
    g.add_argument("--port", type=int, default=8000, help="bind port (default 8000; 0 picks a free one)")
    g.add_argument("--no-browser", action="store_true", help="don't auto-open a browser")

    e = sub.add_parser("enum", help="enumerate an object ID across a range as one identity (scale a BOLA)")
    e.add_argument("--url", help="URL template with the ID marker, e.g. https://api.t.com/orders/§ID§")
    e.add_argument("-r", "--requests", help="a captured request file containing the marker (instead of --url)")
    e.add_argument("--method", default="GET", help="HTTP method for --url (default GET)")
    e.add_argument("-i", "--identities", required=True, help="identities JSON file")
    e.add_argument("-s", "--scope", required=True, help="scope file")
    e.add_argument("--as", dest="as_identity", help="identity name to enumerate as (default: first non-owner)")
    e.add_argument("--range", dest="range_spec", help="numeric range A-B or A-B:step")
    e.add_argument("--ids", help="comma-separated list of IDs")
    e.add_argument("--ids-file", help="file with one ID per line")
    e.add_argument("--marker", default="§ID§", help="the placeholder standing in for the ID (default §ID§)")
    e.add_argument("--max", dest="max_ids", type=int, default=200, help="safety cap on ID count (default 200)")
    e.add_argument("--delay", type=float, default=0.5, help="seconds between requests (default 0.5)")
    e.add_argument("--verify", action="store_true", help="verify TLS certs")
    e.add_argument("--scheme", default="https", choices=("https", "http"))
    e.add_argument("-o", "--json-out", help="write JSON results to this path")
    e.add_argument("--all", action="store_true", help="list every ID result, not just the summary")

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


def _cmd_enum(args) -> int:
    from .capture import CapturedRequest, load_requests
    from .enumerate import EnumError, enumerate_ids, expand_ids

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

    if args.as_identity:
        matches = [i for i in idset.identities if i.name == args.as_identity]
        if not matches:
            print(f"error: no identity named {args.as_identity!r}", file=sys.stderr)
            return 2
        identity = matches[0]
    else:
        cands = idset.candidates()
        if not cands:
            print("error: no non-owner identity to enumerate as", file=sys.stderr)
            return 2
        identity = cands[0]
    if identity.role == "owner":
        sys.stderr.write("!! enumerating as the owner proves nothing — pick a peer/lowpriv/unauth identity.\n")

    if args.requests:
        reqs = load_requests(args.requests, scheme=args.scheme)
        with_marker = [
            r for r in reqs
            if args.marker in (r.url + "".join(r.headers.values()) + (r.body or b"").decode("utf-8", "replace"))
        ]
        if not with_marker:
            print(f"error: none of the requests contain the marker {args.marker!r}", file=sys.stderr)
            return 2
        base = with_marker[0]
    elif args.url:
        base = CapturedRequest(args.method.upper(), args.url, {}, None, "cli")
    else:
        print("error: enum needs --url or -r/--requests", file=sys.stderr)
        return 2

    try:
        ids = expand_ids(args.range_spec, args.ids, args.ids_file, cap=args.max_ids)
    except EnumError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    sys.stderr.write(banner(color=_stderr_color()) + "\n")
    try:
        result = enumerate_ids(
            base, identity, idset.auth_headers, scope, ids,
            marker=args.marker, delay=args.delay, verify=args.verify,
        )
    except EnumError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report.render_enum(result, show_all=args.all)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(report.enum_to_json(result))
        print(f"\nJSON results → {args.json_out}", file=sys.stderr)
    return 3 if result.n_hit else 0


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        return _cmd_run(args)
    if args.command == "identities":
        return _cmd_identities(args)
    if args.command == "requests":
        return _cmd_requests(args)
    if args.command == "gui":
        from .gui import serve

        return serve(args.host, args.port, open_browser=not args.no_browser)
    if args.command == "enum":
        return _cmd_enum(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
