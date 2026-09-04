"""Anchor text — what a link *says*, the fact schema 4 recorded and
nothing read.

The anchor is a ranking signal and a usability one: ``read more`` tells
neither users nor search engines what the destination is about, and a
page whose links all say it has outsourced its own navigation copy.
``anchor_text`` (schema 4) keeps the unique visible texts per target, so
this is checkable without a re-crawl.

The rule is deliberately conservative: a target counts as generically
linked from a page only when **every** anchor that page uses for it is
generic — one descriptive anchor anywhere makes the link fine. Findings
are grouped by the generic text itself: ``read more`` on a blog index
and in the nav is one problem with many places to edit, not one finding
per page or per target.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, join_urls, judgable

# Short, content-free anchors. Kept conservative on purpose: a longer
# list would start flagging functional labels that carry meaning in
# context ("download", "contact us").
GENERIC_ANCHORS = {
    "click here", "click", "here", "this", "this page", "this link",
    "link", "read more", "more", "more info", "learn more", "see more",
    "view more", "view", "details", "info", "continue", "read on",
    "go", "next", "previous", "prev", "back", "start",
}


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 4:
        return [Finding(
            "anchors", "info", "site",
            "cannot check anchor text — this snapshot predates its "
            "capture (schema 3)",
            "Re-crawl with a Site Crawler that records the visible text "
            "per link target (schema 4+)",
        )]

    by_text: dict[str, tuple[list[str], list[str]]] = {}  # text -> (pages, targets)
    for page in snapshot.pages:
        if not judgable(page):
            continue
        for target in page.links_internal:
            texts = page.anchor_text.get(target, [])
            if not texts or not all(t.strip().lower() in GENERIC_ANCHORS
                                    for t in texts):
                continue
            text = texts[0].strip().lower()
            pages, targets = by_text.setdefault(text, ([], []))
            if page.url not in pages:
                pages.append(page.url)
            if target not in targets:
                targets.append(target)

    findings: list[Finding] = []
    for text, (pages, targets) in sorted(by_text.items()):
        findings.append(Finding(
            "anchors", "info", join_urls(targets),
            f"'{text}' is the only anchor text for {len(targets)} internal "
            f"link(s) across {len(pages)} page(s)",
            "Describe the destination in the anchor — generic text tells "
            "neither users nor search engines what the link leads to. On: "
            + join_urls(pages),
            pages=targets,
            referrers=pages,
        ))
    return findings
