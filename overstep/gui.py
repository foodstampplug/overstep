"""A local, zero-dependency web GUI for overstep.

Served by the stdlib :mod:`http.server` and bound to localhost by default, so the whole
thing stays on your box — the same local-only posture as the CLI. The page lets you paste a
capture, your identities, and your scope, run the differential, and read the matrix; the
engine that runs is exactly the one the CLI uses.

Safety:

* Binds to 127.0.0.1 unless you deliberately pass another host (then it warns).
* ``/api/run`` requires a per-session token embedded in the page, and rejects non-local
  Host headers — so a random site open in your browser cannot drive the tool (a drive-by
  can't read the localhost page cross-origin, so it can't learn the token).
* The scope gate still governs every outbound request, exactly as in the CLI.
"""

from __future__ import annotations

import json
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, report
from .capture import CapturedRequest, parse_text
from .enumerate import EnumError, enumerate_ids, expand_ids
from .identities import IdentityError, IdentitySet
from .replay import SAFE_METHODS, WRITE_METHODS, run as replay_run
from .scope import Scope

_WEB = Path(__file__).parent / "web"


class _RunError(Exception):
    """A user-correctable problem with the submitted run (bad scope/identities/etc.)."""


def _page(token: str) -> str:
    html = (_WEB / "index.html").read_text(encoding="utf-8")
    return html.replace("__OVERSTEP_TOKEN__", token).replace("__OVERSTEP_VERSION__", __version__)


def _do_run(req: dict) -> dict:
    scope_text = (req.get("scope") or "").strip()
    if not scope_text:
        raise _RunError("Scope is required — add at least one authorized host.")
    scope = Scope.from_lines(scope_text.splitlines())
    if not scope.includes:
        raise _RunError("Scope has no in-scope rules.")

    try:
        idset = IdentitySet.from_dict(json.loads(req.get("identities") or "{}"))
    except (IdentityError, ValueError) as exc:
        raise _RunError(f"Identities: {exc}")

    scheme = req.get("scheme") or "https"
    reqs = parse_text(req.get("requests") or "", scheme=scheme)
    if not reqs:
        raise _RunError("No requests parsed — paste a HAR export or raw HTTP request(s).")

    methods = SAFE_METHODS + (WRITE_METHODS if req.get("include_writes") else ())
    if req.get("methods"):
        methods = tuple(m.strip().upper() for m in req["methods"].split(",") if m.strip())

    try:
        delay = float(req.get("delay", 0.3) or 0)
    except (TypeError, ValueError):
        delay = 0.3

    run_obj = replay_run(
        reqs, idset, scope,
        allowed_methods=methods, delay=delay,
        verify=bool(req.get("verify")), version=__version__,
    )
    return {
        "version": __version__,
        "counts": run_obj.counts(),
        "findings": [f.as_dict() for f in run_obj.findings],
        "skipped": [
            {"request": s.request_label, "url": s.url, "reason": s.reason}
            for s in run_obj.skipped
        ],
        "markdown": report.to_markdown(run_obj),
        "json": report.to_json(run_obj),
    }


def _do_enum(req: dict) -> dict:
    scope_text = (req.get("scope") or "").strip()
    if not scope_text:
        raise _RunError("Scope is required.")
    scope = Scope.from_lines(scope_text.splitlines())
    if not scope.includes:
        raise _RunError("Scope has no in-scope rules.")
    try:
        idset = IdentitySet.from_dict(json.loads(req.get("identities") or "{}"))
    except (IdentityError, ValueError) as exc:
        raise _RunError(f"Identities: {exc}")

    name = req.get("as")
    if name:
        matches = [i for i in idset.identities if i.name == name]
        if not matches:
            raise _RunError(f"No identity named {name!r}.")
        identity = matches[0]
    else:
        cands = idset.candidates()
        if not cands:
            raise _RunError("No non-owner identity to enumerate as.")
        identity = cands[0]

    url = (req.get("url") or "").strip()
    if not url:
        raise _RunError("A URL template with the ID marker is required.")
    marker = req.get("marker") or "§ID§"
    base = CapturedRequest(req.get("method", "GET").upper(), url, {}, None, "gui")
    try:
        ids = expand_ids(req.get("range") or None, req.get("ids") or None, None,
                         cap=int(req.get("max", 200) or 200))
        result = enumerate_ids(base, identity, idset.auth_headers, scope, ids,
                               marker=marker, delay=float(req.get("delay", 0.3) or 0),
                               verify=bool(req.get("verify")))
    except EnumError as exc:
        raise _RunError(str(exc))

    return {
        "identity": result.identity_name, "role": result.identity_role,
        "url_template": result.url_template, "total": result.total,
        "hit": result.n_hit, "miss": result.n_miss, "error": result.n_error,
        "distinct": result.distinct, "mass_bola": result.mass_bola,
        "hit_ids": result.hit_ids(),
        "results": [{"id": h.id, "verdict": h.verdict, "status": h.status, "length": h.length}
                    for h in result.hits],
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = f"overstep/{__version__}"
    token = ""  # set on the class before serving

    def log_message(self, *args):  # keep the console quiet
        pass

    # -- helpers --
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _is_local(self) -> bool:
        host = self.headers.get("Host", "")
        return host.startswith("127.0.0.1") or host.startswith("localhost")

    # -- routes --
    def do_GET(self):
        if self.path.split("?", 1)[0] != "/":
            return self._json(404, {"error": "not found"})
        self._send(200, _page(self.token).encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        if route not in ("/api/run", "/api/enum"):
            return self._json(404, {"error": "not found"})
        if not self._is_local():
            return self._json(403, {"error": "non-local Host header refused"})
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return self._json(400, {"error": "invalid JSON body"})
        if not secrets.compare_digest(str(req.get("token", "")), self.token):
            return self._json(403, {"error": "bad or missing session token"})
        try:
            handler = _do_run if route == "/api/run" else _do_enum
            return self._json(200, handler(req))
        except _RunError as exc:
            return self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - report, don't crash the server
            return self._json(500, {"error": f"{type(exc).__name__}: {exc}"})


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> int:
    token = secrets.token_hex(16)
    _Handler.token = token

    if host not in ("127.0.0.1", "localhost"):
        sys.stderr.write(
            f"!! binding to {host} exposes a tool that makes outbound requests to your "
            "network. Use 127.0.0.1 unless you really mean to.\n"
        )

    httpd = ThreadingHTTPServer((host, port), _Handler)
    actual = httpd.server_address[1]
    url = f"http://{host}:{actual}/"
    print(f"overstep {__version__} GUI  →  {url}")
    print("local-only · scope-gated · reads-only unless you enable writes · Ctrl-C to stop")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
