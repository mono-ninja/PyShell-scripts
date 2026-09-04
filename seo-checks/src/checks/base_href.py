"""Off-site <base href> — the fact that explains "missing" internal links.

A ``<base href>`` pointing at another host silently rewrites what every
relative link on the page resolves to: the site's own ``/about`` becomes
someone else's page, internal link equity stops flowing, and the
url_variants and broken_links checks see a *symptom* — links that look
internal in the markup but external in the graph. ``base_href``
(schema 5) is the explanation; this check surfaces it.

Only a base whose host is not one of the crawled site's own is flagged:
a same-host base is unusual but harmless.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 5:
        return [Finding(
            "base_href", "info", "site",
            "cannot check <base href> — this snapshot predates its "
            "capture (schema 4)",
            "Re-crawl with a Site Crawler that records the effective base "
            "(schema 5+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page) or not page.base_href:
            continue
        host = (urlsplit(page.base_href).hostname or "").lower()
        if not host or host in snapshot.hosts:
            continue
        findings.append(Finding(
            "base_href", "warn", page.url,
            f"links resolve against an off-site base: {page.base_href}",
            "Every relative link on this page points at another host — "
            "internal linking and equity stop at this page. Point <base> "
            "at the site's own origin, or drop it and use absolute paths",
        ))

    return findings
