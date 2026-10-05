"""The engine: replay each captured request as the owner (baseline) then as every other
identity, classify each comparison, and collect findings.

Safety is the default:

* Only idempotent read methods (GET/HEAD/OPTIONS) are replayed unless writes are
  explicitly enabled — replaying a POST/PUT/DELETE as another user can *mutate their
  data*, which you must never do without intent.
* A fixed delay between requests keeps the traffic gentle and respects program rate rules.
* Out-of-scope requests inside a capture (third-party hosts in a HAR) are skipped loudly,
  never sent.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from . import http
from .capture import CapturedRequest
from .diff import BYPASSED, UNCLEAR, classify
from .findings import Finding, Run, Skipped
from .identities import ROLE_FINDING, Identity, IdentitySet
from .scope import OutOfScope, Scope

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def apply_identity(
    req: CapturedRequest, identity: Identity, auth_headers: list[str]
) -> dict[str, str]:
    """Build the headers to send for this identity: start from the captured headers, strip
    the owner's credentials, then layer on the identity's own headers."""
    auth_lower = {a.lower() for a in auth_headers}
    headers = {k: v for k, v in req.headers.items() if k.lower() not in auth_lower}
    # The identity's headers override anything with the same (case-insensitive) name.
    ident_lower = {k.lower() for k in identity.headers}
    headers = {k: v for k, v in headers.items() if k.lower() not in ident_lower}
    headers.update(identity.headers)
    return headers


def run(
    requests: list[CapturedRequest],
    idset: IdentitySet,
    scope: Scope,
    *,
    allowed_methods: tuple[str, ...] = SAFE_METHODS,
    delay: float = 0.5,
    verify: bool = False,
    timeout: float = 15.0,
    version: str = "0.0.0",
) -> Run:
    owner = idset.owner()
    candidates = idset.candidates()
    allowed = tuple(m.upper() for m in allowed_methods)

    run_obj = Run(
        version=version,
        identities=[{"name": i.name, "role": i.role} for i in idset.identities],
        methods=list(allowed),
        n_requests=len(requests),
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    for req in requests:
        if req.method.upper() not in allowed:
            run_obj.skipped.append(
                Skipped(req.label(), req.url, f"method {req.method} not enabled")
            )
            continue

        # Owner baseline (also the self-check that the request is still replayable).
        try:
            owner_headers = apply_identity(req, owner, idset.auth_headers)
            owner_resp = http.send(
                req.method, req.url, owner_headers, req.body, scope,
                timeout=timeout, verify=verify,
            )
        except OutOfScope as exc:
            run_obj.skipped.append(Skipped(req.label(), req.url, str(exc)))
            continue
        time.sleep(delay)

        for cand in candidates:
            try:
                cand_headers = apply_identity(req, cand, idset.auth_headers)
                cand_resp = http.send(
                    req.method, req.url, cand_headers, req.body, scope,
                    timeout=timeout, verify=verify,
                )
            except OutOfScope as exc:
                run_obj.skipped.append(Skipped(req.label(), req.url, str(exc)))
                continue
            time.sleep(delay)

            cmp = classify(owner_resp, cand_resp)
            label = ROLE_FINDING.get(cand.role, "") if cmp.verdict in (BYPASSED, UNCLEAR) else ""
            note = ""
            if cmp.verdict == "OWNER_FAILED":
                note = (
                    f"owner baseline not a success (status {owner_resp.status}"
                    f"{', ' + owner_resp.error if owner_resp.error else ''}) — "
                    "refresh the owner session / capture and re-run"
                )
            run_obj.findings.append(
                Finding(
                    method=req.method,
                    url=req.url,
                    request_label=req.label(),
                    identity_name=cand.name,
                    identity_role=cand.role,
                    verdict=cmp.verdict,
                    label=label,
                    similarity=cmp.similarity,
                    length_ratio=cmp.length_ratio,
                    owner_status=cmp.owner_status,
                    cand_status=cmp.cand_status,
                    note=note,
                )
            )

    return run_obj
