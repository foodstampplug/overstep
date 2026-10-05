"""Result model: one :class:`Finding` per (request, identity) pair, collected in a
:class:`Run`."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    method: str
    url: str
    request_label: str
    identity_name: str
    identity_role: str
    verdict: str
    label: str = ""  # bug class, set when verdict is a hit/unclear
    similarity: float = 0.0
    length_ratio: float = 0.0
    owner_status: int = 0
    cand_status: int = 0
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "request": self.request_label,
            "identity": self.identity_name,
            "role": self.identity_role,
            "verdict": self.verdict,
            "label": self.label,
            "similarity": round(self.similarity, 4),
            "length_ratio": round(self.length_ratio, 4),
            "owner_status": self.owner_status,
            "candidate_status": self.cand_status,
            "note": self.note,
        }


@dataclass
class Skipped:
    request_label: str
    url: str
    reason: str


@dataclass
class Run:
    version: str
    identities: list[dict] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    n_requests: int = 0
    findings: list[Finding] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    started_at: str = ""

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f.verdict] = c.get(f.verdict, 0) + 1
        return c

    def hits(self) -> list[Finding]:
        from .diff import BYPASSED

        return [f for f in self.findings if f.verdict == BYPASSED]

    def review(self) -> list[Finding]:
        from .diff import UNCLEAR

        return [f for f in self.findings if f.verdict == UNCLEAR]
