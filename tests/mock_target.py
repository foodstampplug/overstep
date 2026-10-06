"""An in-process HTTP target with hand-built authorization behaviors, so the full
replay→diff→classify path can be exercised with no network and no real server.

Sessions are keyed off the ``Cookie: session=<USER>`` header:
    ALICE = owner/admin, BOB = peer user, LOW = low-privilege user, (none) = unauth.

Routes model the exact scenarios overstep exists to catch:
    GET /orders/1001  — returns the SAME order to any logged-in user (BOLA); 403 to unauth
    GET /admin/report — admin function reachable by ALICE and (wrongly) LOW (BFLA);
                        403 to BOB; 302 /login to unauth
    GET /my/settings  — properly per-user data (diverges a lot); 403 to unauth  (ENFORCED)
    GET /public/status— public 200 to everyone including unauth
    GET /login        — a login page (redirect target)
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _user(handler) -> str | None:
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("session="):
            return part[len("session="):] or None
    return None


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence test noise
        pass

    def _send(self, code: int, body: str = "", location: str | None = None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        user = _user(self)
        path = self.path

        if path.startswith("/orders/"):
            if user is None:
                return self._send(403, "forbidden")
            # same order object returned to ANY authenticated user — the BOLA
            return self._send(200, "ORDER 1001 total $500.00 customer Alice ship 123 Main St")

        if path.startswith("/api/record/"):
            # distinct per-ID records 1..50, readable by ANY logged-in user (mass BOLA);
            # 404 outside that range; 403 if unauthenticated.
            if user is None:
                return self._send(403, "forbidden")
            rid = path.rsplit("/", 1)[1]
            try:
                n = int(rid)
            except ValueError:
                return self._send(404, "not found")
            if 1 <= n <= 50:
                return self._send(
                    200, f"record {n}: owner user{n} email user{n}@corp.example balance {n * 137}"
                )
            return self._send(404, "not found")

        if path == "/admin/report":
            if user in ("ALICE", "LOW"):
                return self._send(200, "ADMIN REPORT q3 revenue 1.2M users 48213 churn 2.1pct")
            if user == "BOB":
                return self._send(403, "forbidden")
            return self._send(302, "", location="/login")

        if path == "/my/settings":
            if user is None:
                return self._send(403, "forbidden")
            # genuinely per-user payload — bodies diverge, must NOT be flagged
            blob = (user + "-") * 150
            return self._send(200, f"settings for {user}: {blob}")

        if path == "/public/status":
            return self._send(200, "OK service healthy build 7 region us-east")

        if path == "/login":
            return self._send(200, "login page please sign in to continue")

        return self._send(404, "not found")

    def do_POST(self):
        # Writes should normally be skipped by overstep; respond if one slips through.
        self._send(200, "created")


@contextlib.contextmanager
def mock_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
