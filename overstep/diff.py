"""Deterministic response comparison and verdict classification.

The core question for every (request, identity) pair: did this identity get *the owner's
result*? We answer it from three signals — status code, body length, and body similarity —
with fixed thresholds, so the same inputs always produce the same verdict (no ML, no luck).

Verdicts:

* ``BYPASSED``    — identity got a success whose body closely matches the owner's. For a
                    peer/low-priv/unauth identity this is the finding.
* ``ENFORCED``    — identity was blocked (401/403, a login redirect) or got clearly
                    different/!success content. Authorization is working.
* ``UNCLEAR``     — a success, but only partially similar: could be the identity's *own*
                    data (fine) or a partial leak (bug). Needs a human eye.
* ``OWNER_FAILED``— the owner baseline itself wasn't a success, so nothing can be judged
                    (usually stale capture / expired owner session — refresh and re-run).
* ``ERROR``       — a transport error hitting the candidate.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass

from .http import Response

BYPASSED = "BYPASSED"
ENFORCED = "ENFORCED"
UNCLEAR = "UNCLEAR"
OWNER_FAILED = "OWNER_FAILED"
ERROR = "ERROR"

# difflib is quadratic; cap the compared text so a large body can't stall a run.
_CMP_CAP = 20_000

_LOGIN_HINTS = ("login", "signin", "sign-in", "sso", "auth", "session", "account/login")


def normalize(body: bytes) -> str:
    return body.decode("utf-8", "replace")[:_CMP_CAP]


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def length_ratio(a_len: int, b_len: int) -> float:
    hi = max(a_len, b_len)
    if hi == 0:
        return 1.0
    return min(a_len, b_len) / hi


def is_login_redirect(resp: Response) -> bool:
    if not (300 <= resp.status < 400):
        return False
    loc = resp.header("location").lower()
    return any(h in loc for h in _LOGIN_HINTS)


@dataclass
class Comparison:
    verdict: str
    similarity: float
    length_ratio: float
    owner_status: int
    cand_status: int


def classify(
    owner: Response,
    cand: Response,
    *,
    sim_hi: float = 0.95,
    sim_lo: float = 0.60,
    len_lo: float = 0.85,
) -> Comparison:
    o_status = owner.status
    c_status = cand.status

    if owner.error or owner.status == 0 or owner.status >= 400:
        return Comparison(OWNER_FAILED, 0.0, 0.0, o_status, c_status)
    if cand.error or cand.status == 0:
        return Comparison(ERROR, 0.0, 0.0, o_status, c_status)

    if c_status in (401, 403, 407):
        return Comparison(ENFORCED, 0.0, 0.0, o_status, c_status)
    if is_login_redirect(cand):
        return Comparison(ENFORCED, 0.0, 0.0, o_status, c_status)

    if 200 <= c_status < 300:
        sim = similarity(normalize(owner.body), normalize(cand.body))
        lr = length_ratio(len(owner.body), len(cand.body))
        if sim >= sim_hi and lr >= len_lo:
            return Comparison(BYPASSED, sim, lr, o_status, c_status)
        if sim >= sim_lo:
            return Comparison(UNCLEAR, sim, lr, o_status, c_status)
        return Comparison(ENFORCED, sim, lr, o_status, c_status)

    # Any other status (404, 5xx, non-login 3xx): not evidence of a bypass.
    return Comparison(ENFORCED, 0.0, 0.0, o_status, c_status)
