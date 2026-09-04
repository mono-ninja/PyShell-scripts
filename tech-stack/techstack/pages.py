"""Page selection: main + up to 9 internal pages.

The stack of the homepage ≠ the stack of checkout: payment, chat and half the
analytics live on inner pages. But a full crawl is a different tool's job, not ours.
Compromise: the main page plus a handful picked by a heuristic from its internal
links — longest path, or a path mentioning `/product`, `/blog`, `/checkout`… —
plus operator-supplied ``extra_urls`` when the human knows better.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .evidence import Evidence
from .util import hostname_of, resolve_url

_ANCHOR_RE = re.compile(r"<a\b[^>]*\shref=[\"']([^\"']+)[\"']", re.I)

# Path keywords that signal a page worth sampling (checkout, blog post, product…).
PATH_HINTS = (
    "product", "blog", "post", "contact", "checkout", "login", "signin",
    "shop", "cart", "account", "about", "pricing", "docs", "news", "article",
    "category", "search",
)


def _internal_links(main_url: str, evidence: Evidence) -> list[str]:
    host = hostname_of(main_url)
    out: list[str] = []
    if not evidence.html:
        return out
    seen: set[str] = set()
    for m in _ANCHOR_RE.finditer(evidence.html):
        href = m.group(1).strip()
        if not href or href.startswith("#") or href.startswith("javascript:") \
                or href.startswith("mailto:") or href.startswith("tel:"):
            continue
        absu = resolve_url(href, main_url)
        parts = urlsplit(absu)
        if parts.hostname != host:
            continue
        # Same host, drop fragment, keep path+query.
        clean = f"{parts.path or '/'}{('?' + parts.query) if parts.query else ''}"
        if clean in seen or clean == "/" or clean == "":
            continue
        seen.add(clean)
        out.append(absu)
    return out


def _score(url: str) -> int:
    path = (urlsplit(url).path or "").lower()
    score = 0
    for hint in PATH_HINTS:
        if hint in path:
            score += 10
    # A long path usually means a real page, not a nav stub.
    score += min(len(path.strip("/").split("/")), 6)
    return score


def select_pages(
    main_url: str,
    main_evidence: Evidence,
    count: int,
    extra_urls: list[str],
) -> list[str]:
    """Return the additional page URLs to sample (main page is already fetched).

    ``count`` is the total number of pages (main + extras), clamped to 1–10.
    """
    want = max(1, min(count, 10)) - 1  # internal slots beyond the main page
    picks: list[str] = []
    picked_set: set[str] = set()

    links = _internal_links(main_url, main_evidence)
    ranked = []
    for u in links:
        if u == main_url:
            continue
        ranked.append((_score(u), len(ranked), u))
    ranked.sort(key=lambda x: (-x[0], x[1]))
    for _, _, u in ranked:
        if len(picks) >= want:
            break
        picks.append(u)
        picked_set.add(u)

    # Operator-supplied URLs are additive on top — the human knows better than
    # the heuristic.
    for u in (extra_urls or []):
        u = u.strip()
        if u and u not in picked_set and u != main_url:
            picks.append(u)
            picked_set.add(u)

    # Cap total pages at 10 (form max) → at most 9 beyond the main page.
    return picks[:9]
