"""Snapshot loading — the read side of ``site_snapshot.json``.

``site-crawler/`` writes the snapshot; this module loads it once, checks
the ``schema`` version, and builds the small amount of derived state the
generator needs (the by-URL index and the host set). It is a deliberately
slimmed-down sibling of ``seo-checks/src/snapshot.py`` — same tolerant
read discipline (unknown fields ignored, missing fields defaulted, wrong
types coerced), but only the fields a sitemap decision actually reads:
status, redirects, canonical, robots signals, lastmod sources, hreflang.

**Normalization lives on the read side**, exactly as in seo-checks: the
crawler writes ``canonical`` and ``redirect_chain`` verbatim as evidence,
so every comparison here runs against :func:`normalize_url` output while
the raw string is kept for display.
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

# schema 1: the original contract; schema 2 adds response headers (the
# X-Robots-Tag half of noindex) and hreflang; schema 5 adds the sitemap's
# <lastmod> per page. All six load — a field absent in an older snapshot
# is reported as a capability gap by the report, never silently ignored.
SUPPORTED_SCHEMAS = {1, 2, 3, 4, 5, 6}

HTML_TYPES = {"text/html", "application/xhtml+xml"}


class SnapshotError(Exception):
    """The snapshot can't be used: unparsable or an unknown schema version."""


# ---------------------------------------------------------------------------
# URL handling — mirrors seo-checks/src/snapshot.py
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """The comparison form for every URL this script matches on.

    Lowercase scheme/host, no default port, no fragment, ``/`` for an
    empty path. Anything that isn't an absolute http(s) URL comes back
    stripped but otherwise untouched — a snapshot is data, and unparsable
    data must not raise on load.
    """
    if not isinstance(url, str):
        return ""
    raw = url.strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:          # malformed port, bad IPv6 literal, …
        return raw
    if scheme not in ("http", "https") or not host:
        return raw
    netloc = f"[{host}]" if ":" in host else host   # hostname drops IPv6 brackets
    if port is not None and (scheme, port) not in (("http", 80), ("https", 443)):
        netloc += f":{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def url_origin(url: str) -> str:
    """``scheme://host[:port]`` — the unit a sitemap belongs to.

    A sitemap may only list URLs on the host it is served from, so
    eligibility compares origins, not hosts: ``http://example.com`` and
    ``https://example.com`` are different sitemap territories, and so are
    ``example.com`` and ``www.example.com``.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme or not parts.hostname:
        return ""
    host = parts.hostname.lower()
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and (parts.scheme, parts.port) not in (("http", 80), ("https", 443)):
        netloc += f":{parts.port}"
    return f"{parts.scheme.lower()}://{netloc}"


# ---------------------------------------------------------------------------
# Shared predicates
# ---------------------------------------------------------------------------

def has_noindex(meta_robots: str | None) -> bool:
    if not meta_robots:
        return False
    return "noindex" in re.split(r"[,\s]+", meta_robots.lower())


def header_value(page: "PageRecord", name: str) -> str | None:
    """A response header by name, matched case-insensitively.

    site-crawler writes header names lowercase; a foreign or hand-edited
    snapshot may not, and a fact must not disappear over letter case.
    """
    wanted = name.lower()
    for key, value in page.headers.items():
        if key.lower() == wanted:
            return value
    return None


def page_noindex(page: "PageRecord") -> bool:
    """Whether the page is excluded from indexing by *either* signal.

    ``<meta name=robots>`` is the one everybody looks at; ``X-Robots-Tag``
    does the same job from the response headers and is invisible in the
    markup (schema 2+). A schema-1 snapshot has no headers, so this falls
    back to the meta tag alone — and the report says so.
    """
    if has_noindex(page.meta_robots):
        return True
    header = header_value(page, "x-robots-tag")
    # "googlebot: noindex" — the directive can be prefixed with an agent.
    return has_noindex(header.split(":")[-1] if header else None)


def is_html(page: "PageRecord") -> bool:
    """HTML check tolerant of parameters and of a missing content type.

    Servers answer ``text/html; charset=utf-8``; a sitemap lists pages, so
    PDF/image/JSON leaves are out — but a record with no content type at
    all (foreign snapshot) is not punished for the gap.
    """
    if page.content_type is None:
        return True
    return page.content_type.split(";")[0].strip().lower() in HTML_TYPES


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass
class PageRecord:
    """Read-side view of one snapshot page — the sitemap-relevant subset.

    ``key`` is the normalized form of ``url``; ``canonical`` is normalized
    the same way while ``canonical_raw`` keeps what the markup said, so
    the exclusion CSV can quote the real value.
    """
    url: str
    status: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    content_type: str | None = None
    canonical: str | None = None
    meta_robots: str | None = None
    blocked_by_robots: bool = False
    fetched_at: str = ""
    error: str | None = None
    # --- schema 2+ ----------------------------------------------------
    headers: dict[str, str] = field(default_factory=dict)
    hreflang: dict[str, str] = field(default_factory=dict)
    # --- schema 5+ ----------------------------------------------------
    sitemap_lastmod: str | None = None
    meta_refresh: str | None = None

    key: str = ""
    canonical_raw: str | None = None

    def __post_init__(self) -> None:
        if not self.key:
            self.key = normalize_url(self.url) or self.url
        if self.canonical and self.canonical_raw is None:
            self.canonical_raw = self.canonical
            self.canonical = normalize_url(self.canonical) or self.canonical


@dataclass
class Snapshot:
    seed_url: str
    crawled_at: datetime | None
    pages: list[PageRecord]
    pages_discovered: int
    pages_crawled: int
    capped: bool
    partial: bool = False
    stopped_reason: str | None = None
    schema: int = 1
    site_origin: str = ""

    # Derived state, built once in load_snapshot(). Unlike seo-checks,
    # path filters do NOT narrow ``pages`` here: an out-of-scope URL is
    # reported by eligibility as a ``filtered`` exclusion instead of
    # silently vanishing — the sitemap's scope boundary stays visible
    # in the report and the CSV.
    all_pages: list[PageRecord] = field(default_factory=list)
    by_url: dict[str, PageRecord] = field(default_factory=dict)

    include_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()

    def resolve(self, url: str) -> PageRecord | None:
        """The record for ``url``, matched on the normalized form."""
        return self.by_url.get(normalize_url(url) or url)

    def selected(self, url: str) -> bool:
        """Whether --include-path/--exclude-path keep this URL in the run.

        Patterns are globs matched against the path *and* the full URL, so
        both ``/blog/*`` and ``https://example.com/blog/*`` work.
        """
        if not self.include_paths and not self.exclude_paths:
            return True
        path = urlsplit(url).path or "/"

        def matches(pattern: str) -> bool:
            return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(url, pattern)

        if self.include_paths and not any(map(matches, self.include_paths)):
            return False
        return not any(map(matches, self.exclude_paths))

    def snapshot_age(self, now: datetime | None = None) -> float | None:
        """Age of the crawl in days, or None when crawled_at is unusable."""
        if self.crawled_at is None:
            return None
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        if self.crawled_at.tzinfo is None:
            crawled = self.crawled_at.replace(tzinfo=timezone.utc)
        else:
            crawled = self.crawled_at
        return (now - crawled).total_seconds() / 86400


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _parse_crawled_at(raw) -> datetime | None:
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _as_int(value) -> int | None:
    """Tolerant int read: a snapshot that says ``"404"`` must not make a
    decision raise TypeError three modules later."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _as_str(value) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_url_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _as_rels(value) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items()
            if isinstance(k, str) and isinstance(v, str) and v}


def load_snapshot(path: str, *, include_paths=(), exclude_paths=()) -> Snapshot:
    """Load + validate a site_snapshot.json and build the derived indexes.

    Raises :class:`SnapshotError` when the file doesn't parse or its
    ``schema`` field is a version this script doesn't understand — the
    caller turns that into exit code 1.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"cannot read snapshot {path!r}: {exc}") from exc

    if not isinstance(data, dict):
        raise SnapshotError("snapshot is not a JSON object")
    schema = data.get("schema")
    if schema not in SUPPORTED_SCHEMAS:
        raise SnapshotError(
            f"unsupported snapshot schema {schema!r} — this script understands "
            f"{sorted(SUPPORTED_SCHEMAS)}; re-crawl the site with a matching "
            f"site-crawler version"
        )

    raw_pages = data.get("pages")
    if not isinstance(raw_pages, list):
        raise SnapshotError("snapshot has no 'pages' list")

    pages = []
    for i, raw in enumerate(raw_pages):
        if not isinstance(raw, dict) or not raw.get("url"):
            raise SnapshotError(f"pages[{i}] is malformed (missing url)")
        pages.append(PageRecord(
            url=raw["url"],
            status=_as_int(raw.get("status")),
            redirect_chain=_as_url_list(raw.get("redirect_chain")),
            content_type=_as_str(raw.get("content_type")),
            canonical=_as_str(raw.get("canonical")),
            meta_robots=_as_str(raw.get("meta_robots")),
            blocked_by_robots=bool(raw.get("blocked_by_robots")),
            fetched_at=raw.get("fetched_at") or "",
            error=_as_str(raw.get("error")),
            headers=_as_rels(raw.get("headers")),
            hreflang=_as_rels(raw.get("hreflang")),
            sitemap_lastmod=_as_str(raw.get("sitemap_lastmod")),
            meta_refresh=_as_str(raw.get("meta_refresh")),
        ))

    seed_url = data.get("seed_url") or ""
    site_origin = url_origin(normalize_url(seed_url) or seed_url)
    if not site_origin and pages:
        # A snapshot without a usable seed falls back to the first page's
        # origin — the sitemap still has to belong to some host.
        site_origin = url_origin(pages[0].key)

    snapshot = Snapshot(
        seed_url=seed_url,
        crawled_at=_parse_crawled_at(data.get("crawled_at")),
        pages=pages,
        pages_discovered=_as_int(data.get("pages_discovered")) or len(pages),
        pages_crawled=_as_int(data.get("pages_crawled")) or len(pages),
        capped=bool(data.get("capped")),
        partial=bool(data.get("partial")),
        stopped_reason=_as_str(data.get("stopped_reason")),
        schema=schema,
        site_origin=site_origin,
        include_paths=tuple(include_paths or ()),
        exclude_paths=tuple(exclude_paths or ()),
    )
    snapshot.all_pages = pages
    for page in pages:
        snapshot.by_url[page.key] = page

    return snapshot
