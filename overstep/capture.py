"""Load captured requests from HAR exports or raw HTTP request files.

Two formats, because that is what people actually have on hand:

* **HAR** (``.har``) — what a browser DevTools "Save all as HAR" or Burp/mitmproxy export
  produces. Full URLs with scheme are in the file.
* **Raw HTTP** — a Burp "Copy to file" / "Save item" style request:
  ``GET /path HTTP/1.1`` + headers + blank line + optional body. The URL is rebuilt from
  the ``Host`` header; scheme defaults to https (override with ``--scheme http``). Several
  raw requests may live in one file separated by a line of ``>>>>``.

A directory path loads every file inside it.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class CapturedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    source: str = ""

    def label(self) -> str:
        from urllib.parse import urlsplit

        p = urlsplit(self.url)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return f"{self.method} {path}"


# ---- HAR -------------------------------------------------------------------
def parse_har(text: str, source: str = "har") -> list[CapturedRequest]:
    doc = json.loads(text)
    out: list[CapturedRequest] = []
    entries = doc.get("log", {}).get("entries", [])
    for i, entry in enumerate(entries):
        req = entry.get("request", {})
        method = req.get("method", "GET").upper()
        url = req.get("url", "")
        if not url:
            continue
        headers = {}
        for h in req.get("headers", []):
            name = h.get("name", "")
            if name.startswith(":"):  # HTTP/2 pseudo-headers aren't real headers
                continue
            headers[name] = h.get("value", "")
        body = None
        post = req.get("postData")
        if post and post.get("text"):
            body = post["text"].encode("utf-8", "replace")
        out.append(
            CapturedRequest(method, url, headers, body, f"{source}#{i}")
        )
    return out


# ---- raw HTTP --------------------------------------------------------------
def parse_raw(text: str, scheme: str = "https", source: str = "raw") -> list[CapturedRequest]:
    out: list[CapturedRequest] = []
    chunks = [c for c in text.split("\n>>>>") if c.strip()]
    for j, chunk in enumerate(chunks):
        req = _parse_one_raw(chunk, scheme, f"{source}#{j}")
        if req:
            out.append(req)
    return out


def _parse_one_raw(text: str, scheme: str, source: str) -> CapturedRequest | None:
    # Normalize line endings; split headers from body on the first blank line.
    norm = text.replace("\r\n", "\n").lstrip("\n")
    if "\n\n" in norm:
        head, body_text = norm.split("\n\n", 1)
    else:
        head, body_text = norm, ""
    lines = [ln for ln in head.split("\n") if ln.strip() != ""]
    if not lines:
        return None
    parts = lines[0].split()
    if len(parts) < 2:
        return None
    method, path = parts[0].upper(), parts[1]

    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        name, value = ln.split(":", 1)
        headers[name.strip()] = value.strip()

    host = ""
    for k, v in headers.items():
        if k.lower() == "host":
            host = v.strip()
            break

    if path.lower().startswith("http://") or path.lower().startswith("https://"):
        url = path
    else:
        if not host:
            return None
        url = f"{scheme}://{host}{path}"

    body = body_text.encode("utf-8", "replace") if body_text.strip() else None
    return CapturedRequest(method, url, headers, body, source)


# ---- dispatch --------------------------------------------------------------
def load_requests(path: str, scheme: str = "https") -> list[CapturedRequest]:
    if os.path.isdir(path):
        out: list[CapturedRequest] = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full):
                out.extend(_load_file(full, scheme))
        return out
    return _load_file(path, scheme)


def _load_file(path: str, scheme: str) -> list[CapturedRequest]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if path.lower().endswith(".har"):
        return parse_har(text, source=os.path.basename(path))
    stripped = text.lstrip()
    if stripped.startswith("{") and '"log"' in stripped[:200]:
        return parse_har(text, source=os.path.basename(path))
    return parse_raw(text, scheme=scheme, source=os.path.basename(path))
