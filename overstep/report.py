"""Render a :class:`~overstep.findings.Run` to the console, to JSON, and to a Markdown
draft that drops into Trapline's report generator."""

from __future__ import annotations

import json
import os
import sys

from .diff import BYPASSED, ENFORCED, ERROR, OWNER_FAILED, UNCLEAR
from .findings import Run

_COLORS = {
    BYPASSED: "\033[91m",   # red — a hit
    UNCLEAR: "\033[93m",    # yellow — review
    ENFORCED: "\033[92m",   # green — working as intended
    OWNER_FAILED: "\033[95m",
    ERROR: "\033[90m",
}
_RESET = "\033[0m"


def _use_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render_console(run: Run, *, show_all: bool = False, stream=sys.stdout) -> None:
    color = _use_color(stream)

    def paint(verdict: str, text: str) -> str:
        if not color:
            return text
        return f"{_COLORS.get(verdict, '')}{text}{_RESET}"

    # Group findings by request so the matrix reads like Autorize's table.
    by_request: dict[str, list] = {}
    order: list[str] = []
    for f in run.findings:
        if f.request_label not in by_request:
            by_request[f.request_label] = []
            order.append(f.request_label)
        by_request[f.request_label].append(f)

    print(f"overstep {run.version} — authorization differential\n", file=stream)
    for label in order:
        rows = by_request[label]
        interesting = [r for r in rows if r.verdict in (BYPASSED, UNCLEAR, OWNER_FAILED)]
        if not interesting and not show_all:
            continue
        print(label, file=stream)
        for r in rows:
            if r.verdict in (ENFORCED, ERROR) and not show_all:
                continue
            tag = paint(r.verdict, f"{r.verdict:<13}")
            extra = ""
            if r.verdict in (BYPASSED, UNCLEAR):
                extra = f" sim={r.similarity:.2f} len={r.length_ratio:.2f}  → {r.label}"
            elif r.note:
                extra = f"  ({r.note})"
            print(
                f"    {r.identity_name:<14}{r.identity_role:<9} {tag}"
                f" owner={r.owner_status} cand={r.cand_status}{extra}",
                file=stream,
            )
        print(file=stream)

    c = run.counts()
    print(
        "summary: "
        + f"{c.get(BYPASSED, 0)} BYPASSED, "
        + f"{c.get(UNCLEAR, 0)} UNCLEAR, "
        + f"{c.get(ENFORCED, 0)} ENFORCED, "
        + f"{c.get(OWNER_FAILED, 0)} OWNER_FAILED, "
        + f"{c.get(ERROR, 0)} ERROR"
        + (f"; {len(run.skipped)} skipped" if run.skipped else ""),
        file=stream,
    )
    if run.hits():
        print(
            paint(BYPASSED, f"\n⚠  {len(run.hits())} likely authorization bug(s) — review and verify before reporting."),
            file=stream,
        )


def to_json(run: Run) -> str:
    doc = {
        "tool": "overstep",
        "version": run.version,
        "started_at": run.started_at,
        "identities": run.identities,
        "methods": run.methods,
        "requests_loaded": run.n_requests,
        "counts": run.counts(),
        "findings": [f.as_dict() for f in run.findings if f.verdict in (BYPASSED, UNCLEAR)],
        "skipped": [{"request": s.request_label, "url": s.url, "reason": s.reason} for s in run.skipped],
    }
    return json.dumps(doc, indent=2)


def to_markdown(run: Run) -> str:
    out: list[str] = ["# overstep — authorization findings\n"]
    hits = run.hits()
    review = run.review()
    if not hits and not review:
        out.append("No authorization bypasses or ambiguous responses were observed.\n")
        return "\n".join(out)

    for f in hits:
        out.append(f"## {f.label} — `{f.request_label}`\n")
        out.append(f"**Severity:** _fill in_  |  **Endpoint:** `{f.url}`\n")
        out.append(
            f"**Summary:** Identity `{f.identity_name}` (role `{f.identity_role}`) received "
            f"the owner's successful response for this request — authorization is not "
            f"enforced at the object/function level.\n"
        )
        out.append("**Evidence:**\n")
        out.append(
            f"- Owner response: HTTP {f.owner_status}. "
            f"`{f.identity_name}` response: HTTP {f.cand_status}.\n"
            f"- Body similarity to owner: {f.similarity:.0%}; length ratio {f.length_ratio:.0%}.\n"
        )
        out.append(
            "**Steps to reproduce:**\n"
            f"1. Authenticate as `{f.identity_name}` (or no auth, for an unauth identity).\n"
            f"2. Send: `{f.request_label}` with that identity's credentials.\n"
            "3. Observe the owner's data/action is returned despite the identity not owning it.\n"
        )
        out.append(
            "**Impact:** _fill in — what this identity can read or do that it must not "
            "(scale it: enumerate IDs, cross-tenant, etc.)._\n"
        )
        out.append("---\n")

    if review:
        out.append("## Needs manual review (UNCLEAR)\n")
        for f in review:
            out.append(
                f"- `{f.request_label}` as `{f.identity_name}` ({f.identity_role}): "
                f"HTTP {f.cand_status}, {f.similarity:.0%} similar to owner — "
                "confirm whether this is the identity's own data or a partial leak.\n"
            )
    return "\n".join(out)
