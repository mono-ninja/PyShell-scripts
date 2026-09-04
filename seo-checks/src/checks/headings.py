"""Heading structure — the outline schema 4 recorded and nothing read.

The heading hierarchy is how both search engines and screen readers
navigate a page: a skipped level is a missing rung on the only ladder
they have. ``headings`` keeps the outline in document order, empty
headings included, so the structure can be judged without a re-crawl.

Findings, per content page:

* no headings at all → ``warn`` — a page without a single h1–h6 has no
  outline to navigate;
* the first heading is not an h1 → ``warn`` — every outline has to start
  somewhere, and a page that starts at h2 reads as a subsection;
* a level jump (h1 straight to h3) → ``info`` — skipped levels, listed
  with the jumps actually made;
* more than one h1 → ``info`` — no longer wrong per HTML5's outline
  algorithm, but worth seeing on a classic document page;
* an empty heading → ``warn`` — a rung with no label helps nobody.

Reading a schema-3 snapshot, the check says so plainly instead of
reporting every page as "no headings".
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 4:
        return [Finding(
            "headings", "info", "site",
            "no heading outline to check — this snapshot predates it "
            "(schema 3)",
            "Re-crawl with a Site Crawler that records the heading "
            "outline (schema 4+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page):
            continue
        headings = page.headings
        if not headings:
            findings.append(Finding(
                "headings", "warn", page.url,
                "no headings at all (h1–h6)",
                "Every page needs at least an h1 — it is the top rung of "
                "the outline humans, search engines and screen readers "
                "all navigate by",
            ))
            continue

        first = headings[0]
        if first["level"] != 1:
            findings.append(Finding(
                "headings", "warn", page.url,
                f"the first heading is an h{first['level']}, not an h1",
                "Start the outline at h1 and nest downwards — a page that "
                "begins mid-hierarchy reads as someone else's subsection",
            ))

        jumps = []
        previous = 0
        for heading in headings:
            level = heading["level"]
            if previous and level > previous + 1:
                jumps.append(f"h{previous} → h{level}")
            previous = level if level else previous
        if jumps:
            findings.append(Finding(
                "headings", "info", page.url,
                "skipped heading level(s): " + ", ".join(jumps),
                "Use the next level down (h2 → h3) instead of jumping — "
                "a skipped level is a missing rung in the outline",
            ))

        h1_count = sum(1 for h in headings if h["level"] == 1)
        if h1_count > 1:
            findings.append(Finding(
                "headings", "info", page.url,
                f"{h1_count} h1 headings on one page",
                "Fine under the HTML5 outline algorithm, but on a classic "
                "document page one h1 says what the page is — keep the "
                "rest as h2",
            ))

        empty = [h for h in headings if not h["text"].strip()]
        if empty:
            findings.append(Finding(
                "headings", "warn", page.url,
                f"{len(empty)} empty heading(s) (e.g. h{empty[0]['level']})",
                "An empty heading is a rung with no label — fill it in or "
                "remove the element",
            ))

    return findings
