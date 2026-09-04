"""C6. Sitemap cross-check — what the site *claims* vs what it links.

The sitemap is the site's own list of pages worth indexing; the crawl is
what the internal link graph actually reaches. Where the two disagree is
where pages get lost, and neither list on its own can tell you.

The URLs come from the snapshot (schema 2's ``sitemap_urls``, recorded by
``site-crawler`` from ``robots.txt``'s ``Sitemap:`` directives), so this
check stays as network-free as every other one here. Reading a schema-1
snapshot, it says so plainly instead of silently finding nothing.

Findings, all grouped — a sitemap listing 4000 URLs must not produce 4000
rows:

* listed but broken / redirecting / ``noindex`` / robots-blocked →
  ``fail``, except redirects (``warn``): a sitemap is a set of promises
  about final, indexable URLs;
* listed but never reached by the crawl → ``warn``, and skipped entirely
  on a capped or partial run, where "not reached" mostly means "we
  stopped early";
* crawled, indexable, and *not* listed → ``info``.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import (
    Finding,
    Snapshot,
    join_urls,
    judgable,
    page_noindex,
)


def _finding(severity: str, urls: list[str], detail: str,
             recommendation: str) -> Finding:
    return Finding("sitemap", severity, join_urls(urls),
                   f"{len(urls)} sitemap URL(s) {detail}",
                   recommendation, pages=urls)


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if not snapshot.sitemap_urls:
        # site-crawler reads sitemaps only when run with --use-sitemap —
        # an empty list on a modern snapshot usually means the flag was
        # off, not that the site has no sitemap.
        reason = ("this snapshot predates sitemap capture (schema 1)"
                  if snapshot.schema < 2
                  else "the crawl recorded no sitemap URLs — Site Crawler "
                       "only reads them when run with --use-sitemap")
        return [Finding(
            "sitemap", "info", "site",
            f"no sitemap data to cross-check — {reason}",
            "Re-crawl with Site Crawler's --use-sitemap on (it also makes "
            "orphan pages visible), or add a Sitemap: line to robots.txt "
            "if the site has none",
        )]

    listed = [u for u in snapshot.sitemap_urls if snapshot.selected(u)]
    listed_keys = set(snapshot.sitemap_urls)

    broken, redirecting, noindexed, blocked, missing, offsite = [], [], [], [], [], []
    for url in listed:
        if not snapshot.in_scope(url):
            offsite.append(url)
            continue
        page = snapshot.resolve(url)
        if page is None:
            missing.append(url)
        elif page.status is not None and page.status >= 400:
            broken.append(url)
        elif snapshot.redirect_final(url):
            redirecting.append(url)
        elif page.blocked_by_robots:
            blocked.append(url)
        elif page_noindex(page):
            noindexed.append(url)

    findings: list[Finding] = []
    if broken:
        findings.append(_finding(
            "fail", broken, "are dead (4xx/5xx)",
            "Remove them from the sitemap or fix the pages — a sitemap full "
            "of 404s costs crawl budget and trust"))
    if noindexed:
        findings.append(_finding(
            "fail", noindexed, "are noindex",
            "Contradictory: the sitemap asks for indexing, the page refuses "
            "it. Drop one of the two signals"))
    if blocked:
        findings.append(_finding(
            "fail", blocked, "are disallowed by robots.txt",
            "Search engines cannot fetch what the sitemap advertises — allow "
            "them in robots.txt or remove them from the sitemap"))
    if redirecting:
        findings.append(_finding(
            "warn", redirecting, "redirect elsewhere",
            "List the final URLs instead — a sitemap should name the "
            "destination, not the detour"))
    if offsite:
        findings.append(_finding(
            "warn", offsite, "point at another host",
            "A sitemap may only list URLs on the site it belongs to"))

    if missing and not (snapshot.capped or snapshot.partial):
        findings.append(_finding(
            "warn", missing, "were never reached by the crawl",
            "Nothing on the site links to them — add internal links, or "
            "remove them from the sitemap if they are not meant to rank"))

    unlisted = [p.url for p in snapshot.pages
                if judgable(p) and not page_noindex(p)
                and p.key not in listed_keys and not p.in_sitemap]
    if unlisted:
        findings.append(Finding(
            "sitemap", "info", join_urls(unlisted),
            f"{len(unlisted)} crawled, indexable page(s) are not in the "
            f"sitemap",
            "Add them so search engines learn about them without depending "
            "on the link graph",
            pages=unlisted,
        ))

    return findings
