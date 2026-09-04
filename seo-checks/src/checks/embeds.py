"""Third-party embeds — ``iframes`` (schema 5), grouped, informational.

Every iframe is another origin's code running on the page: a privacy
note (what loads without the visitor asking), a performance note (each
embed is its own payload of JS), and occasionally a compliance note.
None of that is the crawler's call to make — the check surfaces the
facts, one ``info`` for the whole site, and lets the reader decide.

Only embeds whose host is not one of the crawled site's own count: a
same-host iframe is the site's own page in a frame, not a third party.
"""
from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from src.options import Options
from src.snapshot import Finding, Snapshot


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 5:
        return [Finding(
            "embeds", "info", "site",
            "cannot check third-party embeds — this snapshot predates "
            "iframe capture (schema 4)",
            "Re-crawl with a Site Crawler that records iframes "
            "(schema 5+)",
        )]

    by_host: dict[str, int] = defaultdict(int)
    pages_with: set[str] = set()
    for page in snapshot.pages:
        for src in page.iframes:
            host = (urlsplit(src).hostname or "").lower()
            if host and host not in snapshot.hosts:
                by_host[host] += 1
                pages_with.add(page.url)

    if not by_host:
        return []

    ordered = sorted(pages_with)
    hosts = ", ".join(f"{host} ({count})"
                      for host, count in sorted(by_host.items()))
    return [Finding(
        "embeds", "info", "site",
        f"{len(ordered)} page(s) embed third-party content from "
        f"{len(by_host)} host(s): {hosts}",
        "Each embed is another origin running on the page — privacy and "
        "performance both care. Nothing to fix unless one of these hosts "
        "isn't meant to be there",
        pages=ordered,
    )]
