"""Snapshot loading, URL normalization, and the shared Finding contract.

``site_snapshot.json`` (written by ``site-crawler/``) is loaded once,
validated against the ``schema`` version, and turned into a
:class:`Snapshot` — the pages plus the derived state almost every check
needs: the **reverse-link index** (``target_url -> referring pages``), the
redirect map, and the host set, all built once here instead of each check
re-scanning ``pages[*].links_internal`` on its own.

**Normalization lives on the read side.** The crawler normalizes page keys
and ``links_internal`` but writes ``canonical`` and ``redirect_chain``
exactly as the markup and the ``Location`` headers gave them — those are
facts, and a crawler that rewrites them is editing evidence. So this module
applies the same canonical form (lowercase scheme/host, no default port, no
fragment, ``/`` for an empty path) to *everything it compares*, and keeps
the raw string for display. Tracking parameters are deliberately **not**
stripped here: ``?page=2`` and ``?utm_source=x`` are indistinguishable to a
generic rule, and a canonical is far more likely to carry the meaningful
kind.

Everything in this package is pure functions over already-collected facts:
no crawling, no judgment in the crawler, no network (the one exception —
optional external-link verification — lives in
``src/checks/external_links.py`` and is off by default).
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

# schema 1: the original contract. schema 2 adds response headers and
# page-structure facts; schema 3 adds resource URLs and image srcs;
# schema 4 adds parsed JSON-LD, the heading outline, anchor texts and
# the document's charset/viewport; schema 5 adds the full Open
# Graph/Twitter property sets, meta-refresh, every <title>, a text hash
# for exact-duplicate detection, base href, iframes, microdata
# itemtypes and the sitemap's <lastmod>; schema 6 adds retries_used and
# the document's dir (ltr/rtl). All six load — every field is optional
# on this side, and the checks that need a newer field say so plainly
# when it is absent.
SUPPORTED_SCHEMAS = {1, 2, 3, 4, 5, 6}

# How many URLs a finding spells out before it switches to "(+N more)".
# The full list always survives in Finding.pages / Finding.referrers, which
# is what findings.json carries.
MAX_LISTED = 5

HTML_TYPES = {"text/html", "application/xhtml+xml"}

# site-crawler writes "too many redirects (more than 10 hops)" as the error
# for a redirect loop. It is a redirect problem, not a broken link, so the
# redirects check claims it and broken_links steps aside.
REDIRECT_LOOP_MARKER = "too many redirects"

# Mirrors site-crawler's rule exactly: anything utm_* (the crawler strips
# every such param on a default crawl — this fires only when it was run
# with --keep-tracking-params) plus the two big click-id params.
_TRACKING_RE = re.compile(r"^(?:utm_\S*|gclid|fbclid)$", re.IGNORECASE)


class SnapshotError(Exception):
    """The snapshot can't be used: unparsable or an unknown schema version."""


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """The comparison form for every URL this script matches on.

    Mirrors ``site-crawler``'s ``normalize_url`` *minus* tracking-param
    stripping (see the module docstring). Anything that isn't an absolute
    http(s) URL comes back stripped but otherwise untouched — a snapshot
    is data, and unparsable data must not raise on load.
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


def has_tracking_params(url: str) -> bool:
    """True when the URL carries utm_*/gclid/fbclid."""
    query = urlsplit(url).query
    return any(_TRACKING_RE.match(pair.split("=", 1)[0])
               for pair in query.split("&") if pair)


def join_urls(urls, max_listed: int = MAX_LISTED) -> str:
    """Human-readable URL list, truncated. The whole point of the cap is
    that one nav link repeated on 500 pages must not produce a 40 KB
    markdown cell — the full list stays in ``Finding.pages``."""
    items = list(urls)
    if not items:
        return ""
    shown = ", ".join(items[:max_listed])
    if len(items) > max_listed:
        shown += f" (+{len(items) - max_listed} more)"
    return shown


# ---------------------------------------------------------------------------
# Shared predicates — facts about a page, not judgments about it
# ---------------------------------------------------------------------------

def has_noindex(meta_robots: str | None) -> bool:
    if not meta_robots:
        return False
    return "noindex" in re.split(r"[,\s]+", meta_robots.lower())


def page_noindex(page: PageRecord) -> bool:
    """Whether the page is excluded from indexing by *either* signal.

    ``<meta name=robots>`` is the one everybody looks at; ``X-Robots-Tag``
    does exactly the same job from the response headers and is invisible
    in the markup, which is what makes it worth capturing as a fact
    (schema 2). A schema-1 snapshot simply has no headers, so this falls
    back to the meta tag alone.
    """
    if has_noindex(page.meta_robots):
        return True
    header = header_value(page, "x-robots-tag")
    # "googlebot: noindex" — the directive can be prefixed with an agent.
    return has_noindex(header.split(":")[-1] if header else None)


def header_value(page: PageRecord, name: str) -> str | None:
    """A response header by name, matched case-insensitively.

    site-crawler writes header names lowercase; a foreign or hand-edited
    snapshot may not, and a fact must not disappear over letter case.
    """
    wanted = name.lower()
    for key, value in page.headers.items():
        if key.lower() == wanted:
            return value
    return None


def has_rel(rel: str | None, token: str) -> bool:
    if not rel:
        return False
    return token in re.split(r"[,\s]+", rel.lower())


def is_redirect_loop(error: str | None) -> bool:
    return bool(error) and REDIRECT_LOOP_MARKER in error.lower()


def judgable(page: PageRecord) -> bool:
    """True when this record actually carries page content worth judging.

    Excluded, each for its own reason:

    * robots-blocked — never fetched, ``indexability``'s territory;
    * errored — no response to judge, ``broken_links``' territory;
    * **a redirect source** — the crawler attributes title/canonical/links
      to the record of the *final* URL, so a 301's own record legitimately
      has no title. Judging it produced a "no <title>" fail for every
      legacy redirect on the site;
    * non-2xx — fixing meta on a dead URL is pointless until the link is;
    * non-HTML — a PDF leaf has no meta to miss. The media type is read
      without its parameters: servers routinely answer
      ``text/html; charset=utf-8``, and an exact-match test would silently
      drop such pages from every content check.

    A record with no status at all (tolerant read of a foreign snapshot)
    is still judged.
    """
    if page.blocked_by_robots or page.error is not None:
        return False
    if page.redirect_chain:
        return False
    if page.status is not None and not 200 <= page.status < 300:
        return False
    return page.content_type is None \
        or page.content_type.split(";")[0].strip().lower() in HTML_TYPES


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass
class PageRecord:
    """Read-side view of one snapshot page — every field optional-ish.

    Tolerant by design: unknown extra fields are ignored, missing fields
    default, wrong-typed fields are coerced or dropped, so a snapshot from
    a slightly different crawler version still loads as long as the schema
    version matches.

    ``key`` is the normalized form of ``url``, filled in by
    :func:`load_snapshot`; ``canonical`` is normalized the same way while
    ``canonical_raw`` keeps what the markup actually said, so findings can
    quote the real value.
    """
    url: str
    depth: int = 0
    status: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    content_type: str | None = None
    title: str | None = None
    meta_description: str | None = None
    canonical: str | None = None
    meta_robots: str | None = None
    links_internal: list[str] = field(default_factory=list)
    links_external: list[str] = field(default_factory=list)
    link_rels: dict[str, str] = field(default_factory=dict)
    blocked_by_robots: bool = False
    fetched_at: str = ""
    error: str | None = None
    # --- schema 2 (absent and harmless in a schema-1 snapshot) --------
    headers: dict[str, str] = field(default_factory=dict)
    nofollow_links: list[str] = field(default_factory=list)
    in_sitemap: bool = False
    canonical_all: list[str] = field(default_factory=list)  # raw, every tag
    hreflang: dict[str, str] = field(default_factory=dict)  # lang -> raw url
    lang: str | None = None
    images_total: int | None = None
    images_without_alt: int | None = None
    # --- schema 3 (absent and harmless in older snapshots) ------------
    resources: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    images_missing_alt: list[str] = field(default_factory=list)
    # --- schema 4 (absent and harmless in older snapshots) ------------
    json_ld: list = field(default_factory=list)
    json_ld_broken: int = 0
    headings: list[dict] = field(default_factory=list)
    anchor_text: dict[str, list[str]] = field(default_factory=dict)
    charset: str | None = None
    meta_viewport: str | None = None
    # --- schema 5 (absent and harmless in older snapshots) ------------
    open_graph: dict[str, str] = field(default_factory=dict)
    twitter: dict[str, str] = field(default_factory=dict)
    meta_refresh: str | None = None
    title_all: list[str] = field(default_factory=list)
    text_hash: str | None = None
    base_href: str | None = None
    iframes: list[str] = field(default_factory=list)
    itemtypes: list[str] = field(default_factory=list)
    sitemap_lastmod: str | None = None
    # --- schema 6 (absent and harmless in older snapshots) ------------
    retries_used: int = 0
    dir: str | None = None

    key: str = ""
    canonical_raw: str | None = None

    def __post_init__(self) -> None:
        if not self.key:
            self.key = normalize_url(self.url) or self.url
        if self.canonical and self.canonical_raw is None:
            self.canonical_raw = self.canonical
            self.canonical = normalize_url(self.canonical) or self.canonical

    def rel_for(self, link: str) -> str:
        return self.link_rels.get(link, "")


@dataclass
class Finding:
    """The one shape every check produces.

    ``page`` is the display string — a URL, a truncated list for cross-page
    issues, or ``"site"`` for whole-site observations. ``pages`` is that
    same thing structured, and ``referrers`` names the pages that have to
    be *edited* to fix it, which is often a different set entirely (for a
    broken link, ``page`` is the dead URL and ``referrers`` are the pages
    linking to it). Display truncates; the structured lists never do, so
    ``findings.json`` stays complete for CI.
    """
    check: str
    severity: Literal["info", "warn", "fail"]
    page: str
    detail: str
    recommendation: str
    pages: list[str] = field(default_factory=list)
    referrers: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.pages and self.page and self.page != "site":
            self.pages = [self.page]


@dataclass
class Snapshot:
    seed_url: str
    crawled_at: datetime | None
    pages: list[PageRecord]
    pages_discovered: int
    pages_crawled: int
    capped: bool
    include_subdomains: bool
    path_prefix: str | None
    schema: int = 1
    sitemap_urls: list[str] = field(default_factory=list)
    partial: bool = False
    stopped_reason: str | None = None

    # Derived state, built once in load_snapshot(). Every index is keyed by
    # the *normalized* URL and covers `all_pages`, so a --include-path run
    # still resolves link targets and redirects across the whole site.
    all_pages: list[PageRecord] = field(default_factory=list)
    by_url: dict[str, PageRecord] = field(default_factory=dict)
    reverse_links: dict[str, list[str]] = field(default_factory=dict)
    redirect_targets: dict[str, str] = field(default_factory=dict)
    redirect_destinations: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)

    include_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()

    def incoming(self, url: str) -> list[str]:
        """Pages that link to ``url`` internally (unique, in page order)."""
        return self.reverse_links.get(normalize_url(url) or url, [])

    def resolve(self, url: str) -> PageRecord | None:
        """The record for ``url``, matched on the normalized form."""
        return self.by_url.get(normalize_url(url) or url)

    def redirect_final(self, url: str) -> str | None:
        """Where ``url`` ends up, when it is a redirect source."""
        return self.redirect_targets.get(normalize_url(url) or url)

    def in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return bool(host) and host in self.hosts

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
    check raise TypeError three modules later."""
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


def _as_text_list(value) -> list[str]:
    """Like :func:`_as_url_list` but keeps empty strings — an empty
    ``<title>`` tag is a fact (schema 5 ``title_all``), not nothing."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _as_rels(value) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items()
            if isinstance(k, str) and isinstance(v, str) and v}


def _as_str_list_dict(value) -> dict[str, list[str]]:
    """Tolerant ``dict[str, list[str]]`` read (schema 4 ``anchor_text``)."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, list[str]] = {}
    for k, v in value.items():
        if isinstance(k, str) and k and isinstance(v, list):
            texts = [t for t in v if isinstance(t, str) and t.strip()]
            if texts:
                out[k] = texts
    return out


def load_snapshot(path: str, *, include_paths=(), exclude_paths=()) -> Snapshot:
    """Load + validate a site_snapshot.json and build the derived indexes.

    Raises :class:`SnapshotError` when the file doesn't parse or its
    ``schema`` field is a version this script doesn't understand — the
    caller turns that into exit code 1.

    ``include_paths``/``exclude_paths`` narrow ``snapshot.pages`` (what the
    checks iterate) while leaving every index built over the whole site, so
    scoping the report to ``/blog/*`` doesn't make the rest of the site's
    links look broken.
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
            depth=_as_int(raw.get("depth")) or 0,
            status=_as_int(raw.get("status")),
            redirect_chain=_as_url_list(raw.get("redirect_chain")),
            content_type=_as_str(raw.get("content_type")),
            title=_as_str(raw.get("title")),
            meta_description=_as_str(raw.get("meta_description")),
            canonical=_as_str(raw.get("canonical")),
            meta_robots=_as_str(raw.get("meta_robots")),
            links_internal=_as_url_list(raw.get("links_internal")),
            links_external=_as_url_list(raw.get("links_external")),
            link_rels=_as_rels(raw.get("link_rels")),
            headers=_as_rels(raw.get("headers")),
            nofollow_links=_as_url_list(raw.get("nofollow_links")),
            in_sitemap=bool(raw.get("in_sitemap")),
            canonical_all=_as_url_list(raw.get("canonical_all")),
            hreflang=_as_rels(raw.get("hreflang")),
            lang=_as_str(raw.get("lang")),
            images_total=_as_int(raw.get("images_total")),
            images_without_alt=_as_int(raw.get("images_without_alt")),
            resources=_as_url_list(raw.get("resources")),
            images=_as_url_list(raw.get("images")),
            images_missing_alt=_as_url_list(raw.get("images_missing_alt")),
            json_ld=raw.get("json_ld") if isinstance(raw.get("json_ld"), list) else [],
            json_ld_broken=_as_int(raw.get("json_ld_broken")) or 0,
            headings=[h for h in raw.get("headings", [])
                      if isinstance(h, dict)] if isinstance(raw.get("headings"), list) else [],
            anchor_text=_as_str_list_dict(raw.get("anchor_text")),
            charset=_as_str(raw.get("charset")),
            meta_viewport=_as_str(raw.get("meta_viewport")),
            open_graph=_as_rels(raw.get("open_graph")),
            twitter=_as_rels(raw.get("twitter")),
            meta_refresh=_as_str(raw.get("meta_refresh")),
            title_all=_as_text_list(raw.get("title_all")),
            text_hash=_as_str(raw.get("text_hash")),
            base_href=_as_str(raw.get("base_href")),
            iframes=_as_url_list(raw.get("iframes")),
            itemtypes=_as_url_list(raw.get("itemtypes")),
            sitemap_lastmod=_as_str(raw.get("sitemap_lastmod")),
            retries_used=_as_int(raw.get("retries_used")) or 0,
            dir=_as_str(raw.get("dir")),
            blocked_by_robots=bool(raw.get("blocked_by_robots")),
            fetched_at=raw.get("fetched_at") or "",
            error=_as_str(raw.get("error")),
        ))

    scope = data.get("scope") if isinstance(data.get("scope"), dict) else {}
    snapshot = Snapshot(
        seed_url=data.get("seed_url") or "",
        crawled_at=_parse_crawled_at(data.get("crawled_at")),
        pages=pages,
        pages_discovered=_as_int(data.get("pages_discovered")) or len(pages),
        pages_crawled=_as_int(data.get("pages_crawled")) or len(pages),
        capped=bool(data.get("capped")),
        include_subdomains=bool(scope.get("include_subdomains")),
        path_prefix=scope.get("path_prefix"),
        schema=schema,
        sitemap_urls=[normalize_url(u) or u
                      for u in _as_url_list(data.get("sitemap_urls"))],
        partial=bool(data.get("partial")),
        stopped_reason=_as_str(data.get("stopped_reason")),
        include_paths=tuple(include_paths or ()),
        exclude_paths=tuple(exclude_paths or ()),
    )
    snapshot.all_pages = pages

    for page in pages:
        snapshot.by_url[page.key] = page
        host = urlsplit(page.url).hostname
        if host:
            snapshot.hosts.add(host.lower())
        for target in page.links_internal:
            referrers = snapshot.reverse_links.setdefault(
                normalize_url(target) or target, [])
            if page.url not in referrers:
                referrers.append(page.url)
        # A page with a redirect chain maps its (requested) URL to the
        # final target — the site-crawler contract: the chain excludes the
        # requested URL and ends with the final one. Both ends are
        # normalized, because Location headers are not.
        if page.redirect_chain:
            final = normalize_url(page.redirect_chain[-1]) or page.redirect_chain[-1]
            if final != page.key:
                snapshot.redirect_targets[page.key] = final
                snapshot.redirect_destinations.add(final)

    if snapshot.include_paths or snapshot.exclude_paths:
        snapshot.pages = [p for p in pages if snapshot.selected(p.url)]

    return snapshot
