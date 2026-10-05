"""Identities — the personas a captured request is replayed as.

An identities file is JSON::

    {
      "auth_headers": ["cookie", "authorization", "x-api-key"],
      "identities": [
        {"name": "alice", "role": "owner",   "headers": {"Cookie": "session=ALICE"}},
        {"name": "bob",   "role": "peer",    "headers": {"Cookie": "session=BOB"}},
        {"name": "anon",  "role": "unauth",  "headers": {}}
      ]
    }

* **owner** — the identity the traffic was captured as. Exactly one is required; it is the
  baseline every other identity is compared against (and a self-check that the request is
  still replayable).
* **peer** — a different user at the same privilege level. A peer seeing the owner's data
  is **BOLA / IDOR**.
* **lowpriv** — a lower-privilege user. Reaching an owner-only function is **privilege
  escalation / BFLA**.
* **unauth** — no credentials at all. Success here is **missing authentication**.

On replay, the owner's credentials are stripped from the captured request (so they never
leak into another identity's request) and the identity's own ``headers`` are applied. The
set of header names treated as credentials is ``auth_headers`` (sensible default below).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

ROLES = ("owner", "peer", "lowpriv", "unauth")

DEFAULT_AUTH_HEADERS = [
    "cookie",
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
]

ROLE_FINDING = {
    "peer": "BOLA / IDOR (cross-user object access)",
    "lowpriv": "Privilege escalation / BFLA (function-level authorization)",
    "unauth": "Missing authentication (unauthenticated access)",
}


class IdentityError(Exception):
    pass


@dataclass
class Identity:
    name: str
    role: str
    headers: dict[str, str] = field(default_factory=dict)
    note: str = ""


@dataclass
class IdentitySet:
    identities: list[Identity] = field(default_factory=list)
    auth_headers: list[str] = field(default_factory=lambda: list(DEFAULT_AUTH_HEADERS))

    @classmethod
    def from_dict(cls, doc: dict) -> "IdentitySet":
        auth = [h.lower() for h in doc.get("auth_headers", DEFAULT_AUTH_HEADERS)]
        idents: list[Identity] = []
        for raw in doc.get("identities", []):
            name = raw.get("name")
            role = raw.get("role")
            if not name or role not in ROLES:
                raise IdentityError(
                    f"identity {raw!r} needs a name and a role in {ROLES}"
                )
            idents.append(
                Identity(name, role, dict(raw.get("headers", {})), raw.get("note", ""))
            )
        obj = cls(idents, auth)
        obj.validate()
        return obj

    @classmethod
    def from_file(cls, path: str) -> "IdentitySet":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def validate(self) -> None:
        names = [i.name for i in self.identities]
        if len(names) != len(set(names)):
            raise IdentityError("identity names must be unique")
        owners = [i for i in self.identities if i.role == "owner"]
        if len(owners) != 1:
            raise IdentityError(
                f"exactly one identity must have role 'owner' (found {len(owners)})"
            )

    def owner(self) -> Identity:
        return next(i for i in self.identities if i.role == "owner")

    def candidates(self) -> list[Identity]:
        return [i for i in self.identities if i.role != "owner"]


def template() -> str:
    return json.dumps(
        {
            "auth_headers": DEFAULT_AUTH_HEADERS,
            "identities": [
                {"name": "alice", "role": "owner", "headers": {"Cookie": "session=PASTE_ALICE"}},
                {"name": "bob", "role": "peer", "headers": {"Cookie": "session=PASTE_BOB"}},
                {"name": "lowpriv_user", "role": "lowpriv", "headers": {"Authorization": "Bearer PASTE_LOW"}},
                {"name": "anon", "role": "unauth", "headers": {}},
            ],
        },
        indent=2,
    )
