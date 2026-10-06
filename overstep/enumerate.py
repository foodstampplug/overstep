"""Sequential-ID enumeration — scale a single BOLA into proof of mass access.

Finding that a *peer* can read one object you don't own is a bug. Showing that the same
identity can walk an ID range and pull *hundreds* of other users' objects is what makes it
Critical. This module takes a request with an ID **marker**, substitutes each ID in a range
(or list) as one chosen identity, and reports how many came back as real, distinct objects.

Safety: scope-gated like everything else; a default cap on the number of IDs so you can't
accidentally hammer a target; reads-only intent; and it does **not** dump every body to disk
— it counts and samples, because a PoC needs evidence of scale, not a copy of the data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import http
from .capture import CapturedRequest
from .diff import is_login_redirect, normalize
from .identities import Identity
from .replay import apply_identity
from .scope import OutOfScope, Scope

HIT = "HIT"
MISS = "MISS"
ERROR = "ERROR"

_BODY_FLOOR = 40  # a "success" body must be at least this many bytes to count as an object


class EnumError(Exception):
    pass


@dataclass
class EnumHit:
    id: str
    verdict: str
    status: int
    length: int
    body_hash: str = ""


@dataclass
class EnumResult:
    identity_name: str
    identity_role: str
    marker: str
    method: str
    url_template: str
    hits: list[EnumHit] = field(default_factory=list)

    @property
    def n_hit(self) -> int:
        return sum(1 for h in self.hits if h.verdict == HIT)

    @property
    def n_miss(self) -> int:
        return sum(1 for h in self.hits if h.verdict == MISS)

    @property
    def n_error(self) -> int:
        return sum(1 for h in self.hits if h.verdict == ERROR)

    @property
    def total(self) -> int:
        return len(self.hits)

    @property
    def distinct(self) -> int:
        return len({h.body_hash for h in self.hits if h.verdict == HIT and h.body_hash})

    @property
    def mass_bola(self) -> bool:
        # Many successful AND mostly-distinct bodies = pulling per-object data at scale,
        # not one generic page served with 200.
        return self.n_hit > 1 and self.distinct >= max(2, self.n_hit // 2)

    def hit_ids(self) -> list[str]:
        return [h.id for h in self.hits if h.verdict == HIT]


def expand_ids(
    range_spec: str | None = None,
    ids_csv: str | None = None,
    ids_file: str | None = None,
    cap: int = 200,
) -> list[str]:
    out: list[str] = []
    if range_spec:
        body, _, step_s = range_spec.partition(":")
        lo_s, _, hi_s = body.partition("-")
        try:
            lo, hi = int(lo_s), int(hi_s)
            step = int(step_s) if step_s else 1
        except ValueError:
            raise EnumError(f"bad --range {range_spec!r}; use A-B or A-B:step")
        if step <= 0 or hi < lo:
            raise EnumError(f"bad --range {range_spec!r}")
        out.extend(str(n) for n in range(lo, hi + 1, step))
    if ids_csv:
        out.extend(x.strip() for x in ids_csv.split(",") if x.strip())
    if ids_file:
        with open(ids_file, "r", encoding="utf-8") as fh:
            out.extend(ln.strip() for ln in fh if ln.strip())
    # de-dupe, preserve order
    seen: set[str] = set()
    uniq = [x for x in out if not (x in seen or seen.add(x))]
    if not uniq:
        raise EnumError("no IDs to enumerate — pass --range, --ids, or --ids-file")
    if len(uniq) > cap:
        raise EnumError(
            f"{len(uniq)} IDs exceeds the safety cap of {cap}. Raise it deliberately with "
            f"--max {len(uniq)} if the program's rate rules allow it."
        )
    return uniq


def _classify(resp: http.Response) -> str:
    if resp.error or resp.status == 0:
        return ERROR
    if resp.status in (401, 403, 404, 407) or is_login_redirect(resp):
        return MISS
    if 200 <= resp.status < 300 and len(resp.body) >= _BODY_FLOOR:
        return HIT
    return MISS


def _sub(text: str, marker: str, value: str) -> str:
    return text.replace(marker, value)


def enumerate_ids(
    base: CapturedRequest,
    identity: Identity,
    auth_headers: list[str],
    scope: Scope,
    ids: list[str],
    *,
    marker: str = "§ID§",
    delay: float = 0.5,
    verify: bool = False,
    timeout: float = 15.0,
) -> EnumResult:
    import time

    if marker not in (base.url + "".join(base.headers.values()) + (base.body or b"").decode("utf-8", "replace")):
        raise EnumError(f"marker {marker!r} not found in the request — put it where the ID goes")

    headers0 = apply_identity(base, identity, auth_headers)
    result = EnumResult(
        identity_name=identity.name,
        identity_role=identity.role,
        marker=marker,
        method=base.method,
        url_template=base.url,
    )
    for i in ids:
        url = _sub(base.url, marker, i)
        headers = {k: _sub(v, marker, i) for k, v in headers0.items()}
        body = base.body.replace(marker.encode(), i.encode()) if base.body else None
        try:
            resp = http.send(base.method, url, headers, body, scope, timeout=timeout, verify=verify)
        except OutOfScope as exc:
            raise EnumError(str(exc))
        verdict = _classify(resp)
        bh = ""
        if verdict == HIT:
            bh = hashlib.sha1(normalize(resp.body).encode("utf-8", "replace")).hexdigest()[:12]
        result.hits.append(EnumHit(i, verdict, resp.status, len(resp.body), bh))
        time.sleep(delay)
    return result
