#!/usr/bin/env python3
"""overstep practice target — an INTENTIONALLY VULNERABLE local app, for learning overstep.

Localhost only. No real data. The authorization is deliberately broken so you can watch
overstep find it. This is a teaching sandbox (like DVWA / Juice Shop, but tiny) — never
deploy it anywhere.

Run it:
    python3 examples/practice_target.py        # serves http://127.0.0.1:8799

Users — send one as a cookie, e.g.  Cookie: session=ALICE
    ALICE  the account you "captured" as   (owner)
    BOB    another normal user             (peer)
    CAROL  a low-privilege user            (lowpriv)
    (none) unauthenticated

Endpoints:
    GET /api/orders/<id>    BOLA: any logged-in user gets any order (bug). 401 unauth.
    GET /admin/export       BFLA: any logged-in user reaches admin export (bug). 401 unauth.
    GET /api/me             OK: returns the CALLER's own data (differs per user). 401 unauth.
    GET /api/public/stats   MISSING AUTH: 200 to everyone, even logged-out (bug).
    GET /api/records/<id>   BOLA at scale: records 1..100 exist for any logged-in user.
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {"ALICE", "BOB", "CAROL"}


def who(handler):
    for part in handler.headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith("session="):
            val = part[len("session="):]
            return val if val in USERS else None
    return None


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        user = who(self)
        path = self.path.split("?", 1)[0]

        if path.startswith("/api/orders/"):
            if not user:
                return self.send(401, '{"error":"login required"}')
            oid = path.rsplit("/", 1)[1]
            # BUG: returns the SAME order (alice's) to any logged-in user
            return self.send(200, f'{{"order":"{oid}","owner":"alice","total":"$482.10","card":"**** 4242","address":"123 Main St"}}')

        if path == "/admin/export":
            if not user:
                return self.send(401, '{"error":"login required"}')
            # BUG: no admin check — any logged-in user reaches it
            return self.send(200, '{"export":"all_users","rows":5000,"secret":"ADMIN_ONLY_DATA"}')

        if path == "/api/me":
            if not user:
                return self.send(401, '{"error":"login required"}')
            # OK: the caller's OWN data — distinct per user, so overstep leaves it alone
            blob = user * 60
            return self.send(200, f'{{"user":"{user.lower()}","email":"{user.lower()}@corp.example","role":"user","token":"{blob}"}}')

        if path == "/api/public/stats":
            # BUG: should require login, but is open to everyone incl. unauthenticated
            return self.send(200, '{"status":"ok","uptime":"99.98%","build":"prod-7","internal_host":"10.0.3.14"}')

        if path.startswith("/api/records/"):
            if not user:
                return self.send(401, '{"error":"login required"}')
            rid = path.rsplit("/", 1)[1]
            try:
                n = int(rid)
            except ValueError:
                return self.send(404, '{"error":"not found"}')
            if 1 <= n <= 100:
                # BUG: any logged-in user can read every record
                return self.send(200, f'{{"record":{n},"owner":"user{n}","email":"user{n}@corp.example","ssn_last4":"{1000 + n}"}}')
            return self.send(404, '{"error":"not found"}')

        return self.send(404, '{"error":"not found"}')


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    srv = ThreadingHTTPServer(("127.0.0.1", port), _H)
    print(f"practice target → http://127.0.0.1:{port}   (users: ALICE, BOB, CAROL · Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
