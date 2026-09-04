"""Conflicting <title> tags — ``title_all``, the fact schema 5 kept.

The crawler's ``title`` is the first non-empty tag, which is the only
sane single value — but *how many* tags there were is itself a finding:
two ``<title>`` elements means a template and a plugin both wrote one,
and which one a browser shows is load order, not design. Same shape as
``canonical_all``: every value kept, conflicts visible.

A present-but-empty ``<title>`` is recorded here too — ``meta_quality``
already fails a page with no title at all; this adds the distinction
that the tag *exists* and says nothing.

Reading a schema-4 snapshot, the check says so plainly instead of
silently finding nothing.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 5:
        return [Finding(
            "titles", "info", "site",
            "cannot check for conflicting <title> tags — this snapshot "
            "predates title_all (schema 4)",
            "Re-crawl with a Site Crawler that records every <title> "
            "(schema 5+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page):
            continue
        if len(page.title_all) > 1:
            shown = " | ".join(repr(t) if t else "∅" for t in page.title_all)
            findings.append(Finding(
                "titles", "warn", page.url,
                f"{len(page.title_all)} conflicting <title> tags: {shown}",
                "Exactly one <title> per page — two means a template and a "
                "plugin both wrote one, and what a browser shows depends on "
                "load order, not design",
            ))
        elif page.title is None and "" in page.title_all:
            findings.append(Finding(
                "titles", "info", page.url,
                "the <title> tag is present but empty",
                "Usually a template placeholder that never got filled in — "
                "meta_quality flags the missing title; this adds that the "
                "tag itself exists",
            ))

    return findings
