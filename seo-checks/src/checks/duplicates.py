"""A4. Duplicates — pages sharing a title, meta description, or body.

Three keys. Two modes for the meta ones. ``exact`` (default) catches
the most common real-world case, a forgotten default title/description
on a CMS template. ``normalized`` folds case, whitespace and a trailing
brand suffix (``… | Example Shop``) before grouping, which catches
templated titles that differ only by the site name — still a
deterministic rule, not a similarity threshold that would need tuning
to avoid nonsense.

The third key is ``text_hash`` (schema 5): a whitespace-insensitive
hash of the page's whole visible copy. Title/description grouping
catches forgotten templates; the hash catches the real thing — two URLs
serving byte-identical content, printer-friendly twins, staging copies
that leaked into production. Near-duplicates are deliberately *not*
attempted: a similarity threshold would need tuning per site, and the
deterministic facts stay checkable.

Only content-bearing pages are grouped (``judgable``): a 404 and a
redirect source have no title of their own, and pages the site already
marked ``noindex`` are not competing in search results, so a shared title
there is not a duplicate-content problem.

A group whose members all canonicalize to the same URL is already fixed —
that is precisely what a canonical is for — so it drops to ``info``.

Also exposes :func:`duplicate_groups` — the grouping ``canonical`` needs
for its "duplicate content without a canonical" cross-check.
"""
from __future__ import annotations

import re

from src.options import Options
from src.snapshot import (
    Finding,
    PageRecord,
    Snapshot,
    join_urls,
    judgable,
    page_noindex,
)

Group = tuple[str, str, list[str]]  # (field label, shared value, page urls)

# " | Brand", " — Brand", " - Brand", " :: Brand" at the very end.
_BRAND_SUFFIX = re.compile(r"\s*[|–—\-·:]{1,2}\s*[^|–—\-:]{1,40}$")


def normalize_value(value: str) -> str:
    """Case-, whitespace- and brand-insensitive form of a title/description."""
    folded = re.sub(r"\s+", " ", value).strip().lower()
    stripped = _BRAND_SUFFIX.sub("", folded).strip()
    # Never let the rule eat the whole string ("Home | Shop" -> "home").
    return stripped or folded


def duplicate_groups(pages: list[PageRecord], mode: str = "exact") -> list[Group]:
    """Group content-bearing pages by title, then by meta description.
    Only groups with more than one page are returned."""
    groups: list[Group] = []
    candidates = [p for p in pages if judgable(p) and not page_noindex(p)]

    for label, value_of in (("title", lambda p: p.title),
                            ("meta description", lambda p: p.meta_description)):
        by_value: dict[str, tuple[str, list[str]]] = {}
        for page in candidates:
            value = (value_of(page) or "").strip()
            if not value:
                continue
            key = normalize_value(value) if mode == "normalized" else value
            _, urls = by_value.setdefault(key, (value, []))
            urls.append(page.url)
        groups.extend(
            (label, shown, urls)
            for shown, urls in by_value.values()
            if len(urls) > 1
        )
    return groups


def _all_share_one_canonical(snapshot: Snapshot, urls: list[str]) -> str | None:
    """The URL every page in the group canonicalizes to, or None."""
    targets = set()
    for url in urls:
        page = snapshot.resolve(url)
        if page is None or not page.canonical:
            return None
        targets.add(page.canonical)
    return targets.pop() if len(targets) == 1 else None


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    options = options or Options()
    findings: list[Finding] = []

    for label, value, urls in duplicate_groups(snapshot.pages,
                                               options.duplicates_mode):
        shared = _all_share_one_canonical(snapshot, urls)
        if shared:
            findings.append(Finding(
                "duplicates", "info", join_urls(urls),
                f"{len(urls)} pages share the same {label} ({value!r}) but "
                f"all canonicalize to {shared}",
                "Already resolved by the canonical — no action needed unless "
                "these are meant to be distinct pages",
                pages=urls,
            ))
            continue
        findings.append(Finding(
            "duplicates", "warn", join_urls(urls),
            f"{len(urls)} pages share the same {label}: {value!r}",
            f"Give each page a unique {label}, or point the duplicates at "
            f"one canonical version",
            pages=urls,
        ))

    # --- identical body text (schema 5) --------------------------------
    # The hash of the whole visible copy catches what titles cannot:
    # two URLs serving the same content with different titles.
    hashed = [p for p in snapshot.pages
              if judgable(p) and not page_noindex(p) and p.text_hash]
    if snapshot.schema < 5:
        findings.append(Finding(
            "duplicates", "info", "site",
            "exact-content duplicate detection needs a schema-5 snapshot "
            "(this one predates text_hash)",
            "Re-crawl with a Site Crawler that records the text hash "
            "(schema 5+) to catch pages with identical body text",
        ))
    else:
        by_hash: dict[str, list[str]] = {}
        for page in hashed:
            by_hash.setdefault(page.text_hash, []).append(page.url)
        for urls in by_hash.values():
            if len(urls) < 2:
                continue
            shared = _all_share_one_canonical(snapshot, urls)
            severity = "info" if shared else "warn"
            note = (f" but all canonicalize to {shared}" if shared else "")
            findings.append(Finding(
                "duplicates", severity, join_urls(urls),
                f"{len(urls)} pages carry byte-identical visible text{note}",
                "Identical content under several URLs splits ranking "
                "signals — 301 the copies to one canonical URL, or give "
                "each its own content",
                pages=urls,
            ))

    return findings
