"""Minimal HTTP client built on :mod:`http.client` (stdlib only).

Design choices that matter for authorization testing:

* **Redirects are never followed.** A 302 to ``/login`` is itself the strongest signal
  that authorization is enforced — following it would hide that and could chase a
  redirect out of scope. We capture the 3xx + ``Location`` and let the classifier read it.
* **Scope is checked before every send.** Nothing leaves the process un-authorized.
* **TLS verification is off by default** (pentest/staging targets are routinely
  self-signed); pass ``verify=True`` to turn it on.
* **Accept-Encoding is stripped** so bodies come back as plaintext we can diff without
  gzip handling.
"""

from __future__ import annotations

import http.client
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .scope import Scope

# Response bodies are capped so a giant download can't blow up memory or the differ.
MAX_BODY = 2_000_000


@dataclass
class Response:
    status: int = 0
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status != 0

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


def _context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def send(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    scope: Scope,
    *,
    timeout: float = 15.0,
    verify: bool = False,
) -> Response:
    """Send one request. Always scope-checked. Never raises for HTTP status or
    transport errors — a failure is recorded on ``Response.error`` so a single dead
    host never aborts a run."""
    scope.authorize(url)

    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    # Normalize headers: drop hop-by-hop / encoding / length bits we must control.
    send_headers = {
        k: v
        for k, v in headers.items()
        if k.lower() not in ("accept-encoding", "content-length", "connection", "host")
    }

    started = time.monotonic()
    conn = None
    try:
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                host, port or 443, timeout=timeout, context=_context(verify)
            )
        else:
            conn = http.client.HTTPConnection(host, port or 80, timeout=timeout)
        conn.request(method, path, body=body, headers=send_headers)
        raw = conn.getresponse()
        data = raw.read(MAX_BODY)
        resp_headers = {k.lower(): v for k, v in raw.getheaders()}
        return Response(
            status=raw.status,
            reason=raw.reason,
            headers=resp_headers,
            body=data,
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception as exc:  # noqa: BLE001 - report, don't crash the run
        return Response(
            error=f"{type(exc).__name__}: {exc}",
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    finally:
        if conn is not None:
            conn.close()
