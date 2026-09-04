"""A2. Broken links — 4xx/5xx pages and pages that never responded.

One finding per broken URL, listing every referring page: the fix lives on
the pages that link to it, not on the dead URL. ``fail`` severity — a dead
internal link is never intentional.

Two kinds of page are somebody else's territory and are skipped here:
robots-blocked ones (``indexability``) and redirect loops (``redirects``),
so the same URL never shows up twice under two different explanations.
A refused redirect hop — site-crawler records a 3xx response *and* an
error when ``robots.txt``/the crawl scope forbids the next hop — is
skipped the same way: the URL answers, it just can't be followed to the
end, and ``redirects`` reports it for what it is.

A response that arrived but couldn't be used (a parse failure, recorded
as status 2xx + error) is still a finding — worded as what it is, not
"no response".

When the dead URL is reached *through* a redirect, the finding names both
ends: the crawler records the requested URL with the **final** response's
status, so ``/old`` carrying a 404 usually means ``/new`` is the dead one
and reporting only ``/old`` sends people to fix the wrong file.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, is_redirect_loop, join_urls


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    findings: list[Finding] = []

    for page in snapshot.pages:
        if page.blocked_by_robots:
            continue  # never fetched — indexability's territory, not ours
        if is_redirect_loop(page.error):
            continue  # a redirect defect — redirects' territory
        if page.error is not None and page.status is not None \
                and 300 <= page.status < 400:
            continue  # refused redirect hop — redirects' territory
        if page.error is None and (page.status is None or page.status < 400):
            continue

        if page.error is not None:
            reason = (f"unusable response ({page.error})"
                      if page.status is not None
                      else f"no response ({page.error})")
        else:
            reason = f"HTTP {page.status}"

        referrers = snapshot.incoming(page.url)
        if page.redirect_chain:
            final = page.redirect_chain[-1]
            detail = (f"{page.url} redirects to {final}, which is dead — "
                      f"{reason} · linked from {len(referrers)} page(s)")
        else:
            detail = (f"{page.url} is dead — {reason} · linked from "
                      f"{len(referrers)} page(s)")

        if referrers:
            recommendation = ("Fix or remove the link(s) on: "
                              + join_urls(referrers))
        else:
            recommendation = ("No internal page links to it — check the "
                              "sitemap and external sources")
        findings.append(Finding("broken_links", "fail", page.url,
                                detail, recommendation, referrers=referrers))

    return findings
