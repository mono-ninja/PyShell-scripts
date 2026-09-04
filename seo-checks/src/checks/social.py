"""Social sharing meta — the full Open Graph / Twitter sets (schema 5).

What a page looks like when *shared* is decided by these tags: a link
without ``og:title`` shows a bare URL in chat apps, without ``og:image``
no preview image renders anywhere. Schema 5 captured every ``og:*`` and
``twitter:*`` property; before that only og:title/og:description
existed (schema 2), which made "missing og:image" uncheckable.

Findings, per content page and grouped where the noise would drown the
signal:

* missing ``og:title`` or ``og:image`` → ``warn``, the two properties
  every shared URL needs;
* pages without ``twitter:card`` → one ``info`` summary — X/Twitter
  falls back to Open Graph, so this is polish, not breakage.

Reading a schema-4 snapshot, the check says so plainly instead of
judging og:image on data it never had.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, join_urls, judgable

_REQUIRED_OG = ("og:title", "og:image")


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 5:
        return [Finding(
            "social", "info", "site",
            "cannot check social sharing meta — the full Open Graph set "
            "needs a schema-5 snapshot (this one records only "
            "og:title/og:description)",
            "Re-crawl with a Site Crawler that records every og:* and "
            "twitter:* property (schema 5+)",
        )]

    findings: list[Finding] = []
    no_card: list[str] = []

    for page in snapshot.pages:
        if not judgable(page):
            continue
        missing = [prop for prop in _REQUIRED_OG
                   if not page.open_graph.get(prop)]
        if missing:
            findings.append(Finding(
                "social", "warn", page.url,
                "missing " + " and ".join(missing),
                "Without og:title a shared link shows a bare URL; without "
                "og:image no preview renders anywhere — set both in "
                "<head>",
            ))
        if not page.twitter.get("twitter:card"):
            no_card.append(page.url)

    if no_card:
        findings.append(Finding(
            "social", "info", join_urls(no_card),
            f"{len(no_card)} page(s) have no twitter:card",
            "X/Twitter falls back to Open Graph, so this is polish — add "
            "twitter:card (usually summary_large_image) where previews "
            "matter",
            pages=no_card,
        ))

    return findings
