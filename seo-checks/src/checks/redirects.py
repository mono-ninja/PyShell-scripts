"""A1. Redirects — chains, loops, and internal links that rely on them.

Three questions, in ascending order of value:

* "the site has multi-hop chains" — worth a warn, a chain should usually
  collapse to one hop;
* "a URL redirects forever" — the crawler gave up after 10 hops and
  recorded a loop; that is a redirect defect, so it is reported here
  rather than as a nondescript "no response" broken link;
* "the site *relies* on redirects internally" — pages linking straight to
  a URL that redirects. This is the fixable one, and it only shows up
  because the crawler kept the redirect chain and the link graph in the
  same snapshot.

Single redirects themselves are normal and often intentional — no finding
for a redirect's own sake. And the internal-link finding is **one per
redirecting URL** with the referring pages listed, not one per referrer:
a nav link on 500 pages is one problem with 500 places to edit, not 500
problems.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, is_redirect_loop, join_urls


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    findings: list[Finding] = []

    for page in snapshot.pages:
        if is_redirect_loop(page.error):
            chain = " → ".join([page.url, *page.redirect_chain])
            findings.append(Finding(
                "redirects", "fail", page.url,
                f"redirect loop — still redirecting after "
                f"{len(page.redirect_chain)} hops: {chain}",
                "Break the loop: the chain never reaches a final response, "
                "so neither users nor search engines can load this URL",
            ))
            continue
        if page.error is not None and page.status is not None \
                and 300 <= page.status < 400:
            # site-crawler refused the next hop — the target would leave
            # the crawl scope or robots.txt disallows it. The URL answers
            # with a redirect; where it lands is a fact this snapshot
            # cannot carry, and the error names the refused target. Not a
            # broken link, so broken_links steps aside.
            findings.append(Finding(
                "redirects", "info", page.url,
                f"redirects somewhere this crawl could not follow "
                f"({page.error})",
                "The target is outside the crawl's scope or disallowed by "
                "robots.txt — widen the scope and re-crawl to see where "
                "it lands",
            ))
            continue
        if len(page.redirect_chain) > 1:
            chain = " → ".join([page.url, *page.redirect_chain])
            findings.append(Finding(
                "redirects", "warn", page.url,
                f"{len(page.redirect_chain)} hops: {chain}",
                "Collapse the chain to a single redirect — every hop is "
                "extra latency for users and crawl budget for search engines",
            ))

    # Internal links pointing at a URL that redirects elsewhere, grouped by
    # the redirecting URL (same shape as broken_links). The map covers the
    # whole site (links resolve site-wide even under --include-path), so the
    # *source* is filtered here — same rule every other check follows: a
    # scoped run reports findings inside the scope only.
    for source in sorted(snapshot.redirect_targets):
        if not snapshot.selected(source):
            continue
        referrers = snapshot.incoming(source)
        if not referrers:
            continue
        final = snapshot.redirect_targets[source]
        findings.append(Finding(
            "redirects", "warn", source,
            f"{len(referrers)} page(s) link to {source}, which redirects "
            f"to {final}",
            f"Point those links straight at {final}: {join_urls(referrers)}",
            referrers=referrers,
        ))

    return findings
