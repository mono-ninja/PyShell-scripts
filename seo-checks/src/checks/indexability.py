"""A6. Indexability — linked pages that search engines are told to ignore.

Two independent signals, both meaning "reachable by users, invisible to
search engines," which is very often unintentional:

* ``noindex`` on a page with incoming internal links — from
  ``<meta name=robots>`` **or** from the ``X-Robots-Tag`` response header,
  which is the one nobody sees because it never appears in the markup
  (schema 2 captures it; a schema-1 snapshot falls back to the meta tag);
* robots.txt-blocked — the crawler never fetched it, but its presence in
  the snapshot as a link target is exactly what makes this checkable
  without a re-crawl.

Pages nothing links to are skipped: obscurity is its own state, and the
orphan check is where that gets reported.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import (
    Finding,
    Snapshot,
    has_noindex,
    join_urls,
    page_noindex,
)


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    findings: list[Finding] = []

    for page in snapshot.pages:
        referrers = snapshot.incoming(page.url)
        if not referrers:
            continue  # nothing links to it: orphans' territory

        if page_noindex(page):
            source = ("meta robots" if has_noindex(page.meta_robots)
                      else "the X-Robots-Tag header")
            findings.append(Finding(
                "indexability", "warn", page.url,
                f"{source} says noindex, but {len(referrers)} page(s) "
                f"link to it internally",
                "Deliberate (a thank-you page, an internal search result)? "
                "If not, drop the noindex — linked from: "
                + join_urls(referrers),
                referrers=referrers,
            ))
        if page.blocked_by_robots:
            findings.append(Finding(
                "indexability", "warn", page.url,
                f"robots.txt disallows crawling, but {len(referrers)} page(s) "
                f"link to it",
                "Users can reach it, search engines are told to stay away — "
                "allow it in robots.txt if it should rank",
                referrers=referrers,
            ))

    return findings
