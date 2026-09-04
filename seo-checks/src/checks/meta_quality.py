"""A5. Meta quality — missing or badly sized title / meta description.

Per page, only for pages that actually carry content (``judgable`` —
which, importantly, excludes redirect sources: the crawler attributes a
301's title to its *target*, so judging the redirect's own record used to
report "no <title>" for every legacy redirect on the site).

A missing title is the only ``fail`` — it's the single strongest on-page
signal. A missing description is ``warn``.

Lengths are ``info`` framed as a guideline ("may be truncated"), and the
"too short" bound sits far below the familiar ~50-60 advice on purpose: a
45-character title is fine, and flagging it turns every page into an
info-level finding that buries the real ones. So only genuinely stubby
(<30) or overflowing (>60) titles are worth a line. All four bounds are
CLI-tunable — they are rules of thumb, and a CJK site or a long brand
name legitimately needs different ones.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    options = options or Options()
    findings: list[Finding] = []

    for page in snapshot.pages:
        if not judgable(page):
            continue

        if not page.title:
            findings.append(Finding(
                "meta_quality", "fail", page.url,
                "no <title>",
                "Add a unique, descriptive title — the strongest on-page "
                "signal a page has",
            ))
        else:
            length = len(page.title)
            if length > options.title_max:
                findings.append(Finding(
                    "meta_quality", "info", page.url,
                    f"title is {length} characters (over ~{options.title_max})",
                    "Longer titles may be truncated in search results — put "
                    "the distinctive words first",
                ))
            elif length < options.title_min:
                findings.append(Finding(
                    "meta_quality", "info", page.url,
                    f"title is {length} characters (under ~{options.title_min})",
                    "A very short title wastes the most valuable space a "
                    "result has",
                ))

        if not page.meta_description:
            findings.append(Finding(
                "meta_quality", "warn", page.url,
                "no meta description",
                "Add one — search engines fall back to a random snippet "
                "from the page without it",
            ))
        else:
            length = len(page.meta_description)
            if length > options.desc_max:
                findings.append(Finding(
                    "meta_quality", "info", page.url,
                    f"meta description is {length} characters "
                    f"(over ~{options.desc_max})",
                    "Longer descriptions may be truncated in search results",
                ))
            elif length < options.desc_min:
                findings.append(Finding(
                    "meta_quality", "info", page.url,
                    f"meta description is {length} characters "
                    f"(under ~{options.desc_min})",
                    "A short description under-uses the snippet space",
                ))

    return findings
