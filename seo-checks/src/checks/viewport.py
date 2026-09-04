"""viewport — the one-line mobile-readiness fact (schema 4).

A page without ``<meta name=viewport>`` renders at desktop width and
gets scaled down on every phone: Google reads that as not
mobile-friendly, and the fix is one line of HTML. ``meta_viewport`` has
been in the snapshot since schema 4; a missing value on such a snapshot
means the tag genuinely isn't there.

Reading a schema-3 snapshot, the check says so plainly — an absent
field must not read as "every page is fine".
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 4:
        return [Finding(
            "viewport", "info", "site",
            "cannot check viewport meta tags — this snapshot predates "
            "their capture (schema 3)",
            "Re-crawl with a Site Crawler that records the viewport "
            "(schema 4+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page) or page.meta_viewport:
            continue
        findings.append(Finding(
            "viewport", "warn", page.url,
            "no <meta name=viewport> — the page renders at desktop width "
            "on phones",
            "Add <meta name=viewport content=\"width=device-width, "
            "initial-scale=1\"> — one line, and the difference it makes "
            "on mobile is the whole page",
        ))

    return findings
