"""C2. rel attributes on links — the fact the crawler collected and
nothing read.

``link_rels`` (and, in schema 2, the derived ``nofollow_links``) has been
in the snapshot from the start. Two things worth saying about it:

* an **internal** link with ``rel=nofollow`` → ``warn``. Almost always a
  CMS or plugin default nobody chose; it tells search engines not to pass
  authority between two pages of the same site, which is rarely what
  anyone wants. Grouped by target, because a nofollowed nav link is one
  decision repeated, not N problems;
* ``sponsored``/``ugc`` on **external** links → one ``info`` summary.
  These are correct and required disclosures — the finding exists so the
  report can confirm they are present, not to ask for a change.

A target counts as nofollowed only when *every* internal link pointing at
it is nofollowed: one plain link elsewhere makes it followed. Schema 2's
``nofollow_links`` already applies that rule per page; for schema 1 it is
recomputed here from ``link_rels``.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, has_rel, join_urls


def _nofollowed_targets(page) -> set[str]:
    """Internal targets this page links to only with rel=nofollow."""
    if page.nofollow_links:
        return set(page.nofollow_links)
    if not page.link_rels:
        return set()
    return {url for url in page.links_internal
            if has_rel(page.rel_for(url), "nofollow")}


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    findings: list[Finding] = []

    internal: dict[str, list[str]] = {}
    disclosed: dict[str, int] = {"sponsored": 0, "ugc": 0}
    disclosed_urls: list[str] = []

    for page in snapshot.pages:
        for target in sorted(_nofollowed_targets(page)):
            internal.setdefault(target, []).append(page.url)
        for link in page.links_external:
            rel = page.rel_for(link)
            for token in ("sponsored", "ugc"):
                if has_rel(rel, token):
                    disclosed[token] += 1
                    if link not in disclosed_urls:
                        disclosed_urls.append(link)

    for target in sorted(internal):
        sources = internal[target]
        findings.append(Finding(
            "nofollow", "warn", target,
            f"{len(sources)} internal link(s) to {target} carry rel=nofollow",
            f"Internal nofollow stops link equity flowing between your own "
            f"pages — remove it unless it is deliberate. On: "
            f"{join_urls(sources)}",
            referrers=sources,
        ))

    if disclosed["sponsored"] or disclosed["ugc"]:
        findings.append(Finding(
            "nofollow", "info", "site",
            f"{disclosed['sponsored']} sponsored and {disclosed['ugc']} ugc "
            f"external link(s) across {len(disclosed_urls)} URL(s)",
            "Nothing to fix — recorded so paid and user-generated links can "
            "be confirmed as disclosed",
            pages=disclosed_urls,
        ))

    return findings
