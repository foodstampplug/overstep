"""overstep — authorization / BOLA differential tester.

Replay captured HTTP requests under multiple identities (owner / peer / low-priv /
unauthenticated), diff the responses against the owner's baseline, and flag where an
identity reached something it should not: BOLA/IDOR, missing authentication, or
privilege escalation (BFLA).

Zero third-party dependencies. Scope-gated. Safe methods only unless writes are
explicitly enabled. Built for authorized bug-bounty / pentest work only.
"""

__version__ = "0.1.0"
