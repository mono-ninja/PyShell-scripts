"""Structured data — JSON-LD and microdata, the facts schemas 4–5 kept.

Structured data is how a page states what it *is* to machines that
don't render: a broken block is worse than none, because it can turn a
rich result into an error in Search Console. Two facts feed this check:

* ``json_ld_broken`` (schema 4) — ld+json blocks that don't parse as
  JSON at all → ``fail``: the site ships structured data and it is
  broken;
* ``json_ld`` + ``itemtypes`` (schema 5) — pages that ship *neither*
  JSON-LD nor microdata → one grouped ``info``: not an error, but the
  rich-result opportunity is unclaimed.

On a schema-4 snapshot only the broken check runs: microdata is
invisible there, so "no structured data" could not be said honestly.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, join_urls, judgable


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 4:
        return [Finding(
            "structured_data", "info", "site",
            "cannot check structured data — this snapshot predates "
            "JSON-LD capture (schema 3)",
            "Re-crawl with a Site Crawler that records JSON-LD and "
            "microdata (schema 5+)",
        )]

    findings: list[Finding] = []
    without_any: list[str] = []

    for page in snapshot.pages:
        if not judgable(page):
            continue
        if page.json_ld_broken:
            findings.append(Finding(
                "structured_data", "fail", page.url,
                f"{page.json_ld_broken} JSON-LD block(s) fail to parse",
                "A broken ld+json block is worse than none — it can turn "
                "a rich result into a Search Console error. Fix the "
                "syntax or remove the block",
            ))
            continue
        if not page.json_ld and not page.itemtypes:
            without_any.append(page.url)

    # "No structured data" can only be said honestly when microdata is
    # visible too — schema 5. On schema 4, absence of JSON-LD might just
    # mean the site uses microdata.
    if without_any and snapshot.schema >= 5:
        findings.append(Finding(
            "structured_data", "info", join_urls(without_any),
            f"{len(without_any)} content page(s) ship no structured data "
            f"(no JSON-LD, no microdata)",
            "Not an error — but the rich-result opportunity is "
            "unclaimed. Schema.org JSON-LD for the page's main type "
            "(Article, Product, …) is the cheapest win",
            pages=without_any,
        ))

    return findings
