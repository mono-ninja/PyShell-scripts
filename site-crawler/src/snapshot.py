"""Snapshot assembly and the site_snapshot.json writer (plan A6).

The snapshot is the whole output of this script: **facts only** — the
"is this a problem" calls live in ``seo-checks``. The JSON contract
carries a top-level ``schema`` version; if it ever needs a breaking
change, bump it and have ``seo-checks`` refuse versions it doesn't
understand (same discipline as ``pyshell.yaml``'s own ``schema: 1``).

Schema 2 adds fields only — response headers (notably ``X-Robots-Tag``,
which a ``<meta name=robots>``-only reader cannot see), timing, and the
page-structure facts (``h1``, ``lang``, ``hreflang``, Open Graph, word
count, images missing ``alt``) that a checker cannot recover from a
schema-1 snapshot without re-crawling the whole site.

Schema 3 again adds fields only — the resource URLs a page references
(``resources``: img/script/stylesheet/etc.) and the image srcs
(``images``, plus ``images_missing_alt`` naming *which* srcs lack the
attribute). The counts stay: ``images_total``/``images_without_alt``
count ``<img>`` elements, the lists are deduped URLs, and the two can
legitimately disagree when one src is repeated.

Schema 4 stays additive too — the facts a deeper analysis needs without
re-crawling: parsed JSON-LD blocks (``json_ld``, with ``json_ld_broken``
counting the ones that won't parse), the full heading outline
(``headings``, empty headings included), the visible anchor text per
link target (``anchor_text``), and the document's own ``charset`` /
``meta_viewport``. Raw HTML bodies are deliberately *not* stored: any
fact worth checking is extracted here instead, keeping the snapshot
light and free of page content it has no business carrying around.

Schema 5, still additive — the remaining facts that die with the
response: the full Open Graph and Twitter card property sets
(``open_graph``/``twitter``; the schema-2 ``og_title``/``og_description``
stay and derive from the dict), HTML-level redirects the redirect chain
cannot see (``meta_refresh``), every ``<title>`` tag (``title_all``,
empty ones included — two conflicting titles is a finding, the same way
two canonicals are), a whitespace-collapsed ``text_hash`` of the visible
copy for exact-duplicate detection, the effective ``base_href``, iframe
embeds (``iframes``), microdata ``itemtypes``, and the sitemap's
``<lastmod>`` for the page (``sitemap_lastmod``).

Schema 6 mops up: ``retries_used`` (how many retries a page cost — a
fact about the page's stability that dies with the run), the document's
``dir`` (ltr/rtl, the i18n twin of ``lang``), and the *whole*
``Content-Type`` response header now lands in ``headers`` — the
normalized ``content_type`` field drops parameters, and the server's
half of a "server says utf-8, document says cp1251" charset conflict
lives exactly there.

Written to both ``--out-dir`` (a real project folder, so the snapshot
survives past this one Run for ``seo-checks`` to pick up) and, when
running under PyShell, to ``PYSHELL_OUTPUT_DIR`` so the artifact card
works — the same dual-write ``svg-sprite-build`` uses for ``--out``.
"""
from __future__ import annotations

import csv
import io
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SNAPSHOT_SCHEMA = 6


@dataclass
class PageRecord:
    """One page (or non-HTML leaf) in the snapshot — plan A6's contract.

    ``url`` is the *requested* (pre-redirect) normalized URL; when the
    fetch redirected, ``redirect_chain`` holds the hops after it, ending
    at the final URL. ``link_rels`` carries ``rel`` attributes (nofollow,
    sponsored, ugc) for the links that had them, while ``nofollow_links``
    is the derived list of internal targets that are *only* ever linked
    with ``rel=nofollow`` — one plain link elsewhere on the page makes a
    target followed, however many nofollowed links also point at it.
    """
    url: str
    depth: int
    status: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    content_type: str | None = None
    title: str | None = None
    meta_description: str | None = None
    canonical: str | None = None
    meta_robots: str | None = None
    links_internal: list[str] = field(default_factory=list)
    links_external: list[str] = field(default_factory=list)
    blocked_by_robots: bool = False
    fetched_at: str = ""
    error: str | None = None
    link_rels: dict[str, str] = field(default_factory=dict)
    # --- schema 2 ---------------------------------------------------
    headers: dict[str, str] = field(default_factory=dict)
    response_time_ms: int | None = None
    body_bytes: int | None = None
    truncated: bool = False
    in_sitemap: bool = False
    canonical_all: list[str] = field(default_factory=list)
    hreflang: dict[str, str] = field(default_factory=dict)
    pagination: dict[str, str] = field(default_factory=dict)
    nofollow_links: list[str] = field(default_factory=list)
    h1: list[str] = field(default_factory=list)
    lang: str | None = None
    og_title: str | None = None
    og_description: str | None = None
    word_count: int | None = None
    images_total: int | None = None
    images_without_alt: int | None = None
    # --- schema 3 ---------------------------------------------------
    resources: list[str] = field(default_factory=list)   # img/script/css/… srcs
    images: list[str] = field(default_factory=list)      # deduped <img> srcs
    images_missing_alt: list[str] = field(default_factory=list)
    # --- schema 4 ---------------------------------------------------
    json_ld: list = field(default_factory=list)          # parsed ld+json blocks
    json_ld_broken: int = 0
    headings: list[dict] = field(default_factory=list)   # outline {level, text}
    anchor_text: dict[str, list[str]] = field(default_factory=dict)
    charset: str | None = None
    meta_viewport: str | None = None
    # --- schema 5 ---------------------------------------------------
    open_graph: dict[str, str] = field(default_factory=dict)  # every og:*
    twitter: dict[str, str] = field(default_factory=dict)     # every twitter:*
    meta_refresh: str | None = None       # http-equiv=refresh content, raw
    title_all: list[str] = field(default_factory=list)  # every <title>, empties too
    text_hash: str | None = None          # sha256 of collapsed visible text
    base_href: str | None = None          # effective <base href>, if any
    iframes: list[str] = field(default_factory=list)      # embed srcs
    itemtypes: list[str] = field(default_factory=list)    # microdata tokens
    sitemap_lastmod: str | None = None    # <lastmod> from the sitemap
    # --- schema 6 ---------------------------------------------------
    retries_used: int = 0                # retries this page cost the run
    dir: str | None = None               # ltr / rtl, from <html dir>


@dataclass
class Snapshot:
    seed_url: str
    include_subdomains: bool
    path_prefix: str | None
    capped: bool
    pages_discovered: int
    pages_crawled: int          # fetched (robots-blocked pages are recorded but not crawled)
    pages: list[PageRecord]
    crawled_at: str = ""
    partial: bool = False       # run was interrupted or hit --max-duration
    stopped_reason: str | None = None
    exclude_patterns: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema": SNAPSHOT_SCHEMA,
            "crawled_at": self.crawled_at,
            "seed_url": self.seed_url,
            "scope": {
                "include_subdomains": self.include_subdomains,
                "path_prefix": self.path_prefix,
                "exclude_patterns": self.exclude_patterns,
            },
            "capped": self.capped,
            "partial": self.partial,
            "stopped_reason": self.stopped_reason,
            "sitemap_urls": self.sitemap_urls,
            "pages_discovered": self.pages_discovered,
            "pages_crawled": self.pages_crawled,
            "pages": [asdict(p) for p in self.pages],
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def output_dir() -> str | None:
    """PyShell's scratch directory for artifacts, or ``None`` from a terminal."""
    return os.environ.get("PYSHELL_OUTPUT_DIR")


def write_artifact(out_dir: str, name: str, data: str) -> str:
    """Write ``name`` to ``out_dir`` and mirror it to PYSHELL_OUTPUT_DIR when
    that is set and distinct. Returns the primary path written.

    ``newline=""`` because the CSV writer emits its own ``\\r\\n``; letting
    the platform translate those again produces ``\\r\\r\\n`` on Windows.
    """
    primary = os.path.join(out_dir, name)
    os.makedirs(out_dir, exist_ok=True)
    with open(primary, "w", encoding="utf-8", newline="") as fh:
        fh.write(data)

    psd = output_dir()
    if psd and os.path.abspath(psd) != os.path.abspath(out_dir):
        os.makedirs(psd, exist_ok=True)
        with open(os.path.join(psd, name), "w", encoding="utf-8", newline="") as fh:
            fh.write(data)
    return primary


def write_snapshot(snapshot: Snapshot, out_dir: str) -> str:
    if not snapshot.crawled_at:
        snapshot.crawled_at = now_iso()
    data = json.dumps(snapshot.to_dict(), indent=2, ensure_ascii=False)
    return write_artifact(out_dir, "site_snapshot.json", data + "\n")


def read_snapshot(path: str) -> list[PageRecord]:
    """Page records from an existing snapshot, for ``--resume``.

    Unknown keys are ignored and missing ones default, so a schema-1
    snapshot resumes into a schema-2 run without a conversion step.
    A record whose ``url`` isn't a string or whose ``depth`` isn't an
    integer is tolerated rather than trusted — a hand-edited or corrupted
    snapshot must not crash the final sort with a str-vs-int comparison.
    Returns an empty list when the file is absent or unreadable — a
    resume with nothing to resume from is just a fresh crawl.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get("pages"), list):
        return []
    known = {f for f in PageRecord.__dataclass_fields__}
    records = []
    for raw in data["pages"]:
        if not (isinstance(raw, dict) and isinstance(raw.get("url"), str)
                and raw["url"]):
            continue
        fields = {k: v for k, v in raw.items() if k in known}
        if not isinstance(fields.get("depth"), int):
            fields["depth"] = 0
        records.append(PageRecord(**fields))
    return records


SUMMARY_COLUMNS = ["url", "status", "depth", "redirects", "canonical",
                   "blocked", "title", "content_type", "words",
                   "response_ms", "in_sitemap", "error"]


def write_summary_csv(snapshot: Snapshot, out_dir: str) -> str:
    """One row per page — the flat columns, a quick spreadsheet view."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(SUMMARY_COLUMNS)
    for page in snapshot.pages:
        writer.writerow([
            page.url,
            page.status if page.status is not None else "",
            page.depth,
            len(page.redirect_chain),
            "yes" if page.canonical else "no",
            "yes" if page.blocked_by_robots else "no",
            page.title or "",
            page.content_type or "",
            page.word_count if page.word_count is not None else "",
            page.response_time_ms if page.response_time_ms is not None else "",
            "yes" if page.in_sitemap else "no",
            page.error or "",
        ])
    return write_artifact(out_dir, "crawl_summary.csv", buf.getvalue())
