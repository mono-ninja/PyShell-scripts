"""Eligibility — the per-URL decision: into the sitemap, or out with a reason.

A sitemap is a set of promises about final, indexable, canonical URLs
(the same bar ``seo-checks``' sitemap cross-check holds a live sitemap
to). This module walks the snapshot once and turns every page record
into exactly one :class:`Decision`:

* **included** — the URL to list (the redirect chain's final URL, not
  the requested one), its ``lastmod``, and its hreflang alternates;
* **excluded** — a stable reason code plus a detail string that names
  the target where one exists (the canonical that stole the page's
  place, the URL a redirect resolves to, the entry that won the dedup).

**Attribution discipline** (the load-bearing invariant): a record's
facts — status, content type, canonical, hreflang, noindex signals —
describe the *final* response the crawler got, i.e. the content at the
end of ``redirect_chain``. So a redirecting record may list that final
URL and apply its facts to it. A ``canonical`` pointing elsewhere is
*not* a substitution license, though: the canonical target has (or
should have) a record of its own carrying its own facts, so the page is
excluded as ``non_canonical`` instead of being rewritten. The one
consequence worth remembering: ``sitemap_lastmod`` was matched against
the *record's own* URL, so in preserve mode it is only trusted when the
listed URL is that same URL — see :func:`entry_lastmod`.

The walk is two passes — direct records first, redirecting records
second — so when ``/old`` (301 → ``/new``) and ``/new`` both have
records, the entry is built from ``/new``'s own record, whose
``sitemap_lastmod`` and hreflang are attributed to the right URL, and
``/old`` lands in the CSV as ``duplicate``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.snapshot import (
    PageRecord,
    Snapshot,
    is_html,
    normalize_url,
    page_noindex,
    url_origin,
)

#: lastmod source modes — mirror the ``--lastmod-mode`` choice exactly.
LASTMOD_MODES = ("preserve", "crawl", "none")

#: Exclusion reason codes, in report-display order. Codes are stable
#: identifiers (CSV, tests); labels live in src/report.py.
REASON_ORDER = (
    "filtered",
    "robots_blocked",
    "fetch_error",
    "not_crawled",
    "meta_refresh",
    "broken",
    "redirect_status",
    "non_html",
    "noindex",
    "non_canonical",
    "canonical_offsite",
    "off_host",
    "duplicate",
)

# Reason -> one-line explanation for the report. Keep in sync with
# docs/pyshell.md's Result section.
REASON_EXPLANATIONS = {
    "filtered": "outside the --include-path/--exclude-path filters",
    "robots_blocked": "disallowed in robots.txt — search engines cannot fetch it",
    "fetch_error": "the crawl recorded an error for it (timeout, loop, …)",
    "not_crawled": "discovered but never fetched — nothing vouches for it",
    "meta_refresh": "redirects via <meta refresh> — not a final destination",
    "broken": "answered 4xx/5xx",
    "redirect_status": "answered 3xx without a recorded redirect chain",
    "non_html": "not an HTML page (PDF, image, JSON, …)",
    "noindex": "asks not to be indexed (meta robots or X-Robots-Tag)",
    "non_canonical": "canonicalizes to another URL on this site — that URL's own record is the one listed",
    "canonical_offsite": "canonicalizes to another site — it does not claim this site's index",
    "off_host": "the final URL belongs to another host (subdomain, http/https twin, redirect off-site)",
    "duplicate": "already listed from another record — a sitemap must not repeat URLs",
}


@dataclass
class Entry:
    """One sitemap <url>: the listed URL plus what hangs off it."""
    url: str                      # normalized, the URL written into <loc>
    lastmod: str | None           # W3C datetime, or None to omit
    alternates: list[tuple[str, str]] = field(default_factory=list)  # (lang, href)
    source_url: str = ""          # the record that produced it (for the dedup CSV)


@dataclass
class Decision:
    """One page record's fate."""
    page: PageRecord
    included: bool
    reason: str | None = None     # exclusion code when not included
    detail: str = ""              # target URL / status / error text


@dataclass
class Outcome:
    """Everything the writers and the report need, decided up front."""
    included: list[Entry] = field(default_factory=list)
    excluded: list[Decision] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)   # reason -> count
    #: same-host canonical targets that no record covers — pages the
    #: sitemap is missing *because* the crawl never fetched them
    unfetched_canonicals: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.included) + len(self.excluded)

    def add(self, decision: Decision, entry: Entry | None = None) -> None:
        if decision.included:
            self.included.append(entry)  # type: ignore[arg-type]
        else:
            self.excluded.append(decision)
            self.counts[decision.reason] = self.counts.get(decision.reason, 0) + 1


# ---------------------------------------------------------------------------
# lastmod
# ---------------------------------------------------------------------------

def _w3c_datetime(raw: str | None) -> str | None:
    """Normalize a snapshot timestamp to a W3C datetime, or None.

    ``fetched_at`` is ISO from site-crawler; ``sitemap_lastmod`` is
    whatever the previous sitemap carried (usually ISO or YYYY-MM-DD,
    but it is foreign input and treated as untrusted). Naive timestamps
    are read as UTC — a lastmod an hour off is harmless, an unparseable
    one is dropped rather than emitted broken.
    """
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat(timespec="seconds")


def entry_lastmod(page: PageRecord, listed_url: str, mode: str) -> str | None:
    """The <lastmod> for an included entry.

    * ``none`` — no lastmod at all.
    * ``crawl`` — when the crawler fetched the page (``fetched_at``).
    * ``preserve`` — the previous sitemap's ``lastmod`` for this URL
      (schema 5+), falling back to the crawl time. The previous value is
      trusted **only when the listed URL is the record's own** — it was
      matched against that URL, and attributing it to a redirect's final
      URL would date the wrong page.
    """
    if mode == "none":
        return None
    if mode == "preserve" and listed_url == page.key:
        kept = _w3c_datetime(page.sitemap_lastmod)
        if kept:
            return kept
    if mode == "crawl" or mode == "preserve":
        return _w3c_datetime(page.fetched_at)
    return None


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def _final_url(page: PageRecord) -> str:
    """The URL a record's facts belong to: the redirect chain's last hop,
    or the record's own URL when there was no redirect."""
    if page.redirect_chain:
        return normalize_url(page.redirect_chain[-1]) or page.redirect_chain[-1]
    return page.key


def _decide_one(page: PageRecord, snapshot: Snapshot) -> tuple[bool, str | None, str, str]:
    """One record -> (included, reason, detail, listed_url).

    The order of checks is itself part of the contract — the most
    fundamental disqualifiers first (never fetched, dead, not a page),
    then indexing signals, then canonical/redirect resolution, then
    scope. See the CLAUDE.md decision table before reordering.
    """
    listed = page.key

    if not snapshot.selected(page.url):
        return False, "filtered", "", listed
    if page.blocked_by_robots:
        return False, "robots_blocked", "", listed
    if page.error is not None:
        return False, "fetch_error", page.error, listed
    if page.meta_refresh is not None:
        return False, "meta_refresh", "", listed
    if page.status is None:
        return False, "not_crawled", "", listed
    if 300 <= page.status < 400:
        return False, "redirect_status", f"HTTP {page.status}", listed
    if not 200 <= page.status < 300:
        return False, "broken", f"HTTP {page.status}", listed
    if not is_html(page):
        return False, "non_html", page.content_type or "", listed
    if page_noindex(page):
        return False, "noindex", "", listed

    listed = _final_url(page)

    if page.canonical and page.canonical != listed:
        detail = page.canonical_raw or page.canonical
        if url_origin(page.canonical) != snapshot.site_origin:
            return False, "canonical_offsite", detail, listed
        return False, "non_canonical", detail, listed

    if url_origin(listed) != snapshot.site_origin:
        return False, "off_host", listed, listed
    return True, None, "", listed


def decide(snapshot: Snapshot, *, lastmod_mode: str = "preserve",
           hreflang: bool = True,
           on_progress=None) -> Outcome:
    """Walk the snapshot and decide every record.

    Two passes: direct records (empty ``redirect_chain``) first, then
    redirecting ones — both in crawl order — so the dedup prefers the
    record that owns the URL outright over one that merely redirects to
    it, and ``sitemap_lastmod``/hreflang stay attributed to the record
    that actually carries them.

    ``on_progress(done)`` fires once per record (both passes combined)
    so the caller can drive a progress bar; it is rate-limited on the
    caller's side, not here.
    """
    if lastmod_mode not in LASTMOD_MODES:
        raise ValueError(f"unknown lastmod mode {lastmod_mode!r}")

    outcome = Outcome()
    seen: dict[str, str] = {}     # listed URL -> source record URL

    def consider(page: PageRecord) -> None:
        included, reason, detail, listed = _decide_one(page, snapshot)
        if not included:
            outcome.add(Decision(page, False, reason, detail))
            if reason == "non_canonical":
                target = page.canonical or ""
                if target and snapshot.resolve(target) is None \
                        and target not in outcome.unfetched_canonicals:
                    outcome.unfetched_canonicals.append(target)
            return
        if listed in seen:
            outcome.add(Decision(page, False, "duplicate", seen[listed]))
            return
        alternates = (sorted(page.hreflang.items()) if hreflang else [])
        outcome.add(Decision(page, True), Entry(
            url=listed,
            lastmod=entry_lastmod(page, listed, lastmod_mode),
            alternates=alternates,
            source_url=page.url,
        ))
        seen[listed] = page.url

    done = 0
    total = len(snapshot.pages)
    for page in snapshot.pages:
        if not page.redirect_chain:
            consider(page)
        done += 1
        if on_progress is not None and (done % 100 == 0 or done == total):
            on_progress(done)
    for page in snapshot.pages:
        if page.redirect_chain:
            consider(page)
        done += 1
        if on_progress is not None and (done % 100 == 0 or done == total):
            on_progress(done)
    if on_progress is not None and total == 0:
        on_progress(0)
    return outcome
