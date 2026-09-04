"""Sitemap freshness — ``sitemap_lastmod`` (schema 5) vs the page's own
``Last-Modified``.

A ``<lastmod>`` in a sitemap is a promise: "this URL changed on this
date." Search engines use it to schedule re-crawls, and a lastmod that
the page's own ``Last-Modified`` header contradicts is a promise the
site doesn't keep — Google has said plainly that it stops trusting
lastmod dates it catches being wrong.

Only the misleading direction is flagged: the sitemap claiming a change
newer than the page's actual modification. A lastmod *older* than the
real change is sloppy but harmless to trust.

Dates the check cannot parse (lastmod is W3C, Last-Modified is RFC
7231, and both get hand-written wrong) are skipped rather than guessed
at. Comparing on date granularity, not timestamps: a same-day
difference is timezone noise, not a contradiction.
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from src.options import Options
from src.snapshot import Finding, Snapshot, header_value, judgable


def _as_utc(value: str, kind: str) -> datetime | None:
    try:
        if kind == "sitemap":
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            parsed = parsedate_to_datetime(value)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 5:
        return [Finding(
            "sitemap_freshness", "info", "site",
            "cannot check sitemap freshness — sitemap <lastmod> needs a "
            "schema-5 snapshot from a --use-sitemap crawl",
            "Re-crawl with Site Crawler's sitemap seeding on (schema 5+)",
        )]

    findings: list[Finding] = []
    checked = 0
    for page in snapshot.pages:
        if not judgable(page) or not page.sitemap_lastmod:
            continue
        header = header_value(page, "last-modified")
        if not header:
            continue
        sitemap_date = _as_utc(page.sitemap_lastmod, "sitemap")
        server_date = _as_utc(header, "header")
        if not sitemap_date or not server_date:
            continue                      # unparsable: skipped, not guessed
        checked += 1
        if sitemap_date.date() > server_date.date():
            findings.append(Finding(
                "sitemap_freshness", "warn", page.url,
                f"sitemap claims a change on {page.sitemap_lastmod} but "
                f"the page's Last-Modified says {header}",
                "Search engines stop trusting lastmod dates they catch "
                "being wrong — emit it from the CMS's real update time, "
                "not the sitemap generation time",
            ))

    if not checked:
        findings.append(Finding(
            "sitemap_freshness", "info", "site",
            "no page carries both a sitemap <lastmod> and a "
            "Last-Modified header to compare",
            "Nothing to compare — either the sitemap declares no lastmod, "
            "the server sends no Last-Modified, or sitemap seeding was "
            "off during the crawl",
        ))

    return findings
