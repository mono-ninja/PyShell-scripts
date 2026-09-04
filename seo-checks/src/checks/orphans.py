"""C1. Orphans and click depth — pages the internal link graph forgot.

Both facts are already in the snapshot and were going unused: the
reverse-link index answers "how many pages link here", and ``depth``
answers "how many clicks from the seed". Together they describe how much
of the site's own authority a page can actually receive.

* no incoming internal links at all → ``warn``. The page exists and
  responds, but nothing on the site points at it; it is reachable only
  from a sitemap or an external link;
* exactly one incoming link → ``info``. Thin, but deliberate often enough
  (a leaf article linked from one index) that it isn't a warning;
* deeper than ``--max-depth-ok`` clicks from the seed → ``info``.

Two kinds of page are excluded from the orphan rule because they are
reachable by construction: the seed itself, and any URL that is the
*destination* of a redirect — links point at the old URL, which is
exactly how visitors arrive.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable, normalize_url


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    options = options or Options()
    findings: list[Finding] = []
    seed = normalize_url(snapshot.seed_url)

    for page in snapshot.pages:
        if not judgable(page):
            continue

        referrers = snapshot.incoming(page.url)
        if not referrers and page.key != seed \
                and page.key not in snapshot.redirect_destinations:
            findings.append(Finding(
                "orphans", "warn", page.url,
                "no internal links point at this page",
                "Link to it from a relevant page — an orphan gets no internal "
                "link equity and is found only via the sitemap or externally",
            ))
        elif len(referrers) == 1 and page.key != seed:
            findings.append(Finding(
                "orphans", "info", page.url,
                f"only one internal link points here (from {referrers[0]})",
                "Fine for a leaf page; worth more links if it matters "
                "commercially",
            ))

        if page.depth > options.max_depth:
            findings.append(Finding(
                "orphans", "info", page.url,
                f"{page.depth} clicks from the seed URL "
                f"(over the {options.max_depth}-click guideline)",
                "Deeply buried pages are crawled less often — shorten the "
                "path from the home page if this should rank",
            ))

    return findings
