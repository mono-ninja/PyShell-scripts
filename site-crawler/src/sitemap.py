"""Sitemap discovery — the only way to see orphan pages (plan 6.1).

A link-following crawl can only ever find pages something links to, so
*orphans* — present in the sitemap, linked from nowhere — are invisible
to it by construction. That is one of the more valuable SEO findings, and
the crawler is the only place it can be obtained: seeding the frontier
from the sitemap and recording ``in_sitemap`` per page gives
``seo-checks`` orphan detection, 404s-in-sitemap and
noindex-in-sitemap for free.

Sitemap locations come from robots.txt's ``Sitemap:`` lines first (the
authoritative declaration) and ``/sitemap.xml`` as the conventional
fallback. Sitemap *index* files are followed one level deep.

Parsing is namespace-agnostic — real sitemaps vary in (and sometimes
omit) the sitemaps.org namespace, so matching on the local tag name is
more robust than a fully-qualified match. ``.gz`` sitemaps are
decompressed; anything unparseable is skipped rather than fatal, since a
broken sitemap must not end a crawl that would otherwise work.
"""
from __future__ import annotations

import gzip
from collections.abc import Callable

from lxml import etree

MAX_INDEX_DEPTH = 1          # sitemap index -> child sitemaps, no deeper
MAX_SITEMAPS = 50            # a pathological index must not become a crawl
MAX_URLS = 100_000

# fetch(url) -> (status, bytes) — bytes is None when there was no body.
SitemapFetch = Callable[[str], "tuple[int | None, bytes | None]"]


def _localname(tag) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rpartition("}")[2].lower()


def _maybe_gunzip(raw: bytes) -> bytes:
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except OSError:
            return raw
    return raw


def parse_sitemap(raw: bytes) -> tuple[list[tuple[str, str | None]], list[str]]:
    """Return ``(page_entries, child_sitemap_urls)`` from one sitemap body.

    Each page entry is ``(loc, lastmod)`` — ``lastmod`` is the raw
    ``<lastmod>`` text or ``None``; parsing it into a date is the
    reader's job, not this module's.
    """
    try:
        root = etree.fromstring(_maybe_gunzip(raw),
                                etree.XMLParser(recover=True, resolve_entities=False,
                                                no_network=True, huge_tree=False))
    except (etree.XMLSyntaxError, ValueError):
        return [], []
    if root is None:
        return [], []

    pages: list[tuple[str, str | None]] = []
    children: list[str] = []
    for element in root.iter():
        name = _localname(element.tag)
        if name != "loc":
            continue
        text = (element.text or "").strip()
        if not text:
            continue
        parent = element.getparent()
        parent_name = _localname(parent.tag) if parent is not None else ""
        if parent_name == "sitemap":
            children.append(text)
        else:
            pages.append((text, _lastmod_of(parent)))
    return pages, children


def _lastmod_of(url_element) -> str | None:
    """The ``<lastmod>`` child of a ``<url>`` element, when it has one."""
    for child in url_element:
        if _localname(child.tag) == "lastmod":
            return (child.text or "").strip() or None
    return None


def discover(seed_url: str, fetch: SitemapFetch, *,
             robots_sitemaps: list[str] | None = None
             ) -> list[tuple[str, str | None]]:
    """Every page URL the site's sitemaps advertise, deduped, in order.

    Returns ``(url, lastmod)`` pairs — the first occurrence of a URL
    wins, lastmod included. Never raises: a missing, broken or hostile
    sitemap yields fewer URLs, never an error — the link crawl is the
    primary source and stands on its own.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(seed_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    queue = list(robots_sitemaps or [])
    if not queue:
        queue = [f"{origin}/sitemap.xml"]
    else:
        queue.append(f"{origin}/sitemap.xml")

    seen_sitemaps: set[str] = set()
    urls: list[tuple[str, str | None]] = []
    seen_urls: set[str] = set()
    depth = {url: 0 for url in queue}

    while queue and len(seen_sitemaps) < MAX_SITEMAPS and len(urls) < MAX_URLS:
        sitemap_url = queue.pop(0)
        if sitemap_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap_url)
        try:
            status, raw = fetch(sitemap_url)
        except Exception:
            continue
        if status is None or not (200 <= status < 300) or not raw:
            continue

        pages, children = parse_sitemap(raw)
        for page, lastmod in pages:
            if page not in seen_urls:
                seen_urls.add(page)
                urls.append((page, lastmod))
                if len(urls) >= MAX_URLS:
                    break
        if depth.get(sitemap_url, 0) < MAX_INDEX_DEPTH:
            for child in children:
                if child not in seen_sitemaps:
                    depth[child] = depth.get(sitemap_url, 0) + 1
                    queue.append(child)
    return urls
