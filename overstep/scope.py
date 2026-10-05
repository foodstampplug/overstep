"""Scope gate — authorized-targets-only enforcement.

A scope file is newline-delimited. Each non-blank, non-``#`` line is a rule:

* a bare host            -> exact host match (case-insensitive), e.g. ``api.target.com``
* ``*.domain``           -> the domain itself and any subdomain, e.g. ``*.target.com``
* a CIDR (contains ``/``)-> matched only against literal-IP hosts, e.g. ``10.0.0.0/8``
* ``!``-prefixed         -> an exclusion; an excluded host is never in scope, even if an
                            include rule would otherwise match (exclusion always wins)

There is deliberately **no override flag**. Every outbound request is authorized against
the scope before it is sent; an out-of-scope URL raises :class:`OutOfScope`. This mirrors
the proven gate in promptprobe/deadfall — testing anything you are not authorized to test
is how researchers get banned, so the gate fails closed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class OutOfScope(Exception):
    """Raised when a URL is not authorized by the active scope."""


@dataclass
class Scope:
    includes: list[str] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)

    # ---- construction ------------------------------------------------------
    @classmethod
    def from_lines(cls, lines) -> "Scope":
        inc: list[str] = []
        exc: list[str] = []
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("!"):
                rule = line[1:].strip()
                if rule:
                    exc.append(rule.lower())
            else:
                inc.append(line.lower())
        return cls(includes=inc, excludes=exc)

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_lines(fh.readlines())

    # ---- matching ----------------------------------------------------------
    @staticmethod
    def _host_of(target: str) -> str:
        # Strip any path/userinfo/port a rule or URL might carry so a parser
        # differential (evil.com/.target.com) cannot slip past a *.target.com rule.
        t = target.strip().lower()
        if "://" not in t:
            t = "//" + t
        host = urlsplit(t).hostname or ""
        return host

    @classmethod
    def _rule_matches(cls, rule: str, host: str) -> bool:
        if "/" in rule:  # CIDR — only meaningful against a literal IP host
            try:
                net = ipaddress.ip_network(rule, strict=False)
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        if rule.startswith("*."):
            base = rule[2:]
            return host == base or host.endswith("." + base)
        return host == rule

    def contains(self, url: str) -> bool:
        host = self._host_of(url)
        if not host:
            return False
        if any(self._rule_matches(r, host) for r in self.excludes):
            return False  # exclusion always wins
        return any(self._rule_matches(r, host) for r in self.includes)

    def authorize(self, url: str) -> None:
        if not self.contains(url):
            raise OutOfScope(
                f"{self._host_of(url) or url!r} is not in scope — refusing to send. "
                f"Add it to the scope file only if the program authorizes it."
            )
