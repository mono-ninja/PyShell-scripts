#!/usr/bin/env python3
"""site-crawler/main.py — crawl a site and write one structured snapshot.

Crawls from a seed URL (BFS, thread pool, robots.txt-gated) and writes
``site_snapshot.json`` + ``crawl_summary.csv``. **Facts only, no judgment
calls** — the "is this actually a problem" interpretation lives in the
separate ``seo-checks`` script, which reads the snapshot without any
re-crawling. Crawl once, check as many times as you like.

This is the one script in this workspace that generates real, repeated
traffic against a third-party site, so politeness is the main design
constraint: robots.txt respected by default — on redirect targets as
well as on the URLs we chose ourselves — an honest identifying
User-Agent, bounded concurrency, a per-worker delay between requests,
optional ``Crawl-delay`` compliance, and bodies read only when they are
HTML.

Structured events are emitted on stderr so PyShell renders them natively;
from a terminal they degrade to plain JSON log lines. Exit codes:

* ``0`` — the crawl ran, whatever it found (capped run, a site full of
  404s — both are a successful crawl);
* ``1`` — the seed URL itself was unreachable (or robots-blocked), so
  there was nothing to crawl;
* ``2`` — bad arguments (including a seed its own scope excludes);
* ``130`` — interrupted with Ctrl+C; the partial snapshot is still
  written.
"""
import argparse
import json
import os
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import requests
from requests.adapters import HTTPAdapter
from src import sitemap as sitemap_mod
from src.fetch import MAX_BODY_BYTES, FetchResult, fetch_page
from src.frontier import Frontier, Scope, normalize_url
from src.parse import parse_page
from src.robots import RobotsGate
from src.snapshot import (
    PageRecord,
    Snapshot,
    now_iso,
    read_snapshot,
    write_snapshot,
    write_summary_csv,
)

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ

DEFAULT_UA = "site-crawler/1.0 (+PyShell)"


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    print(json.dumps({**event, "pyshell": True}), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


class CrawlProgress:
    """The discovering → progress transition (plan A7).

    Total page count is unknown up front, so while new URLs keep showing
    up the run reports *status* lines (indeterminate). Once the discovery
    rate hits zero — the frontier size has stabilized — crawled/planned
    becomes a meaningful percentage and the run switches to *progress*.

    The denominator is the number of URLs that hold a ticket, not the
    number discovered: past the page cap, discovery keeps counting URLs
    that are guaranteed never to be crawled, which on a capped run (the
    default, at 500 pages) pins the bar near zero for the whole run.
    """

    def __init__(self, on_status=None, on_progress=None):
        self._on_status = on_status
        self._on_progress = on_progress
        self._last_known = -1

    def tick(self, fetched: int, known: int, outstanding: int,
             planned: int | None = None) -> None:
        if outstanding <= 0:
            return
        if known > self._last_known:
            self._last_known = known
            if self._on_status:
                self._on_status(f"Discovering — {fetched} crawled · {known} URLs found")
            return
        if self._on_progress:
            total = planned if planned is not None else known
            pct = min(99, round(100 * fetched / max(total, 1)))
            self._on_progress(pct, f"{fetched}/{total} pages")


class Interrupted(Exception):
    """Ctrl+C or --max-duration: stop crawling, still write the snapshot."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

def build_session(user_agent: str, concurrency: int, *,
                  headers: dict[str, str] | None = None,
                  basic_auth: tuple[str, str] | None = None
                  ) -> requests.Session:
    """A session sized for the pool it will actually be used from.

    requests' default adapter keeps 10 pooled connections; with more
    workers than that it silently discards and re-opens connections on
    every request, which is both slower and ruder to the target.
    """
    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    session.headers.setdefault(
        "Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5")
    for name, value in (headers or {}).items():
        session.headers[name] = value
    if basic_auth is not None:
        session.auth = basic_auth
    adapter = HTTPAdapter(pool_connections=max(concurrency, 10),
                          pool_maxsize=max(concurrency, 10))
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ---------------------------------------------------------------------------
# The crawl itself — pure of PyShell; events go through callbacks
# ---------------------------------------------------------------------------

def crawl(seed_url: str, *, include_subdomains: bool = False,
          path_prefix: str | None = None, max_depth: int = 5,
          max_pages: int = 500, strip_tracking_params: bool = True,
          crawl_resources: bool = False, concurrency: int = 5,
          delay_ms: int = 200, respect_robots: bool = True,
          user_agent: str = DEFAULT_UA, timeout: int = 15,
          exclude_patterns: tuple[str, ...] = (),
          drop_params: tuple[str, ...] = (), drop_all_params: bool = False,
          use_sitemap: bool = False, respect_crawl_delay: bool = False,
          respect_nofollow: bool = False, retries: int = 1,
          max_body_bytes: int = MAX_BODY_BYTES,
          max_duration: float | None = None,
          resume_from: str | None = None,
          extra_headers: dict[str, str] | None = None,
          basic_auth: tuple[str, str] | None = None,
          on_status=None, on_progress=None) -> Snapshot:
    """Run the whole crawl and return the assembled Snapshot.

    Raises ``ValueError`` for a malformed seed URL, a bad exclude regex,
    or a seed its own scope excludes — all before any request is sent.
    Never raises for anything that happens *during* the crawl — a dead
    page, a parse failure, or a redirect loop is recorded as a fact, not
    an error. ``KeyboardInterrupt`` and ``--max-duration`` stop the crawl
    and return the snapshot built so far, marked ``partial``.
    """
    norm_kw = dict(strip_tracking_params=strip_tracking_params,
                   drop_params=drop_params, drop_all_params=drop_all_params)
    seed = normalize_url(seed_url, **norm_kw)
    scope = Scope(seed, include_subdomains=include_subdomains,
                  path_prefix=path_prefix, exclude_patterns=exclude_patterns)
    if not scope.in_scope(seed):
        raise ValueError(_seed_excluded_reason(seed, scope))

    frontier = Frontier(scope, max_depth=max_depth, max_pages=max_pages,
                        **norm_kw)
    session = build_session(user_agent, concurrency, headers=extra_headers,
                            basic_auth=basic_auth)

    robots: RobotsGate | None = None
    if respect_robots:
        def robots_fetch(url: str) -> tuple[int | None, str | None]:
            try:
                resp = session.get(url, timeout=timeout)
                return resp.status_code, resp.text
            except requests.RequestException:
                return None, None
        robots = RobotsGate(user_agent, robots_fetch)

    pages: dict[str, PageRecord] = {}
    leaves: set[str] = set()          # resource URLs: fetched, never expanded
    sitemap_entries: list[tuple[str, str | None]] = []   # (url, lastmod)
    fetched_count = 0
    started = time.monotonic()
    stopped_reason: str | None = None
    delay_seconds = delay_ms / 1000
    worker_state = threading.local()  # per-thread last-request time → per-worker delay

    if resume_from:
        for record in read_snapshot(resume_from):
            if not scope.in_scope(record.url):
                continue
            pages[record.url] = record
            if record.status is None:
                # Never produced a response: a timeout or connection
                # error is a fact about one attempt, not a verdict on
                # the page, so it gets retried rather than carried
                # forward as already-fetched. Robots-blocked pages (also
                # status-less) are re-gated the same way; until then the
                # restored record keeps the fact.
                continue
            # Restored responses count toward pages_crawled: the summary
            # table sits next to the full restored snapshot, and "Pages
            # crawled" counting only the new fetches would read as if the
            # resume started from nothing.
            if not record.blocked_by_robots:
                fetched_count += 1
            frontier.mark_fetched(record.url, record.depth)
            for link in record.links_internal:
                if respect_nofollow and link in record.nofollow_links:
                    continue
                frontier.add(link, record.depth + 1)

    def allow_hop(target: str) -> str | None:
        """Gate one redirect hop — the same rules as any other request.

        A redirect is a request the *site* chose for us; letting it
        through unchecked would mean a link to an allowed URL can pull
        the crawler into a robots.txt-disallowed area or onto a host the
        user never pointed it at.
        """
        try:
            norm = frontier.normalize(target)
        except ValueError:
            return f"redirect to a non-http(s) URL: {target}"
        if not scope.host_in_scope(norm):
            return f"redirect leaves the crawl scope: {norm}"
        excluded = scope.excluded(norm)
        if excluded is not None:
            return f"redirect matches --exclude-pattern {excluded!r}: {norm}"
        if not scope.in_scope(norm):
            return f"redirect leaves the crawl scope: {norm}"
        if robots is not None and not robots.allowed(norm):
            return f"redirect target disallowed by robots.txt: {norm}"
        return None

    def effective_delay(url: str) -> float:
        if respect_crawl_delay and robots is not None:
            declared = robots.crawl_delay(url)
            if declared is not None:
                return max(delay_seconds, declared)
        return delay_seconds

    def worker(url: str) -> FetchResult:
        # robots.txt is consulted here, not in the scheduling loop: the
        # first URL of a new host has to fetch that host's robots.txt,
        # and doing it inline would stall every other worker meanwhile.
        try:
            if robots is not None and not robots.allowed(url):
                return FetchResult(url, None, None, None, [], None,
                                   blocked_by_robots=True)
            delay = effective_delay(url)
            last = getattr(worker_state, "last", None)
            if last is not None and delay > 0:
                remaining = delay - (time.monotonic() - last)
                if remaining > 0:
                    time.sleep(remaining)
            return fetch_page(session, url, timeout=timeout,
                              max_body_bytes=max_body_bytes,
                              allow_hop=allow_hop, retries=retries)
        except Exception as exc:  # bug guard: one page never kills the crawl
            return FetchResult(url, None, None, None, [],
                               f"unexpected error: {type(exc).__name__}: {exc}")
        finally:
            worker_state.last = time.monotonic()

    def handle(url: str, depth: int, fr: FetchResult) -> None:
        nonlocal fetched_count
        if fr.blocked_by_robots:
            # Recorded, never fetched — seo-checks needs "this page exists
            # and is linked, but robots.txt excludes it" as a fact. Merged
            # into any existing record rather than replacing it: the page
            # may already carry content picked up as a redirect target.
            record = pages.setdefault(url, PageRecord(url=url, depth=depth,
                                                      fetched_at=now_iso()))
            record.blocked_by_robots = True
            return

        fetched_count += 1
        record = pages.get(url)
        if record is None:
            record = PageRecord(url=url, depth=depth)
            pages[url] = record
        record.depth = min(record.depth, depth) if record.fetched_at else depth
        record.status = fr.status
        record.redirect_chain = fr.redirect_chain
        record.content_type = fr.content_type
        record.fetched_at = now_iso()
        record.error = fr.error
        record.headers = fr.headers
        record.response_time_ms = fr.response_time_ms
        record.body_bytes = fr.body_bytes
        record.truncated = fr.truncated
        record.retries_used = fr.retries_used

        # Only successful HTML responses discovered as *links* get parsed.
        # Resource leaves are recorded status-only and never expanded, and
        # pages that failed to fetch or parse aren't about to yield links.
        final_url = fr.redirect_chain[-1] if fr.redirect_chain else url
        parseable = (
            fr.error is None
            and fr.status is not None and 200 <= fr.status < 300
            and fr.body is not None
            and url not in leaves
        )
        if not parseable:
            return

        try:
            parsed = parse_page(fr.body, final_url, scope, **norm_kw)
        except Exception as exc:
            record.error = f"parse error: {type(exc).__name__}"
            return

        # Attribute the parsed content to whichever URL it actually
        # belongs to. When a redirect resolved to real HTML, that is the
        # *final* URL, not the one requested — a 3xx response has no title
        # or canonical of its own. Merging the target's content onto the
        # redirect source's record would make a perfectly normal redirect
        # look like a phantom duplicate of its own target to seo-checks'
        # duplicate-content check, and make the target's own canonical
        # read as "points outside the crawl" even though it was fully
        # fetched and parsed right here.
        if final_url == url:
            target = record
        else:
            target = pages.setdefault(
                final_url, PageRecord(url=final_url, depth=depth,
                                      status=fr.status,
                                      content_type=fr.content_type,
                                      fetched_at=record.fetched_at,
                                      headers=fr.headers,
                                      response_time_ms=fr.response_time_ms,
                                      body_bytes=fr.body_bytes,
                                      truncated=fr.truncated))
            # Its response already arrived here; requesting it again just
            # because something also links to it doubles the load on every
            # site that redirects http→https or adds trailing slashes.
            frontier.mark_fetched(final_url, depth)
        target.title = parsed.title
        target.meta_description = parsed.meta_description
        target.canonical = parsed.canonical
        target.canonical_all = parsed.canonical_all
        target.meta_robots = parsed.meta_robots
        target.links_internal = parsed.links_internal
        target.links_external = parsed.links_external
        target.link_rels = parsed.link_rels
        target.nofollow_links = parsed.nofollow_links
        target.hreflang = parsed.hreflang
        target.pagination = parsed.pagination
        target.h1 = parsed.h1
        target.lang = parsed.lang
        target.dir = parsed.dir
        target.og_title = parsed.og_title
        target.og_description = parsed.og_description
        target.word_count = parsed.word_count
        target.images_total = parsed.images_total
        target.images_without_alt = parsed.images_without_alt
        target.resources = parsed.resources
        target.images = parsed.images
        target.images_missing_alt = parsed.images_missing_alt
        target.json_ld = parsed.json_ld
        target.json_ld_broken = parsed.json_ld_broken
        target.headings = parsed.headings
        target.anchor_text = parsed.anchor_text
        target.charset = parsed.charset
        target.meta_viewport = parsed.meta_viewport
        target.open_graph = parsed.open_graph
        target.twitter = parsed.twitter
        target.meta_refresh = parsed.meta_refresh
        target.title_all = parsed.title_all
        target.text_hash = parsed.text_hash
        target.base_href = parsed.base_href
        target.iframes = parsed.iframes
        target.itemtypes = parsed.itemtypes

        skip = set(parsed.nofollow_links) if respect_nofollow else set()
        for link in parsed.links_internal:
            if link not in skip:
                frontier.add(link, depth + 1)
        # rel=next/prev and hreflang alternates are pages, not assets:
        # queued as normal crawl targets so they get parsed and expanded.
        for related in (*parsed.pagination.values(), *parsed.hreflang.values()):
            frontier.add(related, depth + 1)
        if crawl_resources:
            for res in parsed.resources:
                enqueued = frontier.add(res, depth + 1)
                if enqueued is not None:
                    leaves.add(enqueued)

    progress = CrawlProgress(on_status, on_progress)
    frontier.add(seed, 0)

    if use_sitemap:
        if on_status:
            on_status("Reading sitemaps…")
        sitemap_entries = _load_sitemap_urls(session, seed, robots, timeout)
        for url, _lastmod in sitemap_entries:
            frontier.add(url, 0)
    sitemap_urls = [url for url, _lastmod in sitemap_entries]

    def check_deadline() -> None:
        if max_duration is not None and time.monotonic() - started >= max_duration:
            raise Interrupted(f"--max-duration ({max_duration:g}s) reached")

    try:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            inflight: dict = {}  # Future -> (url, depth)
            while True:
                while len(inflight) < concurrency:
                    item = frontier.pop()
                    if item is None:
                        break
                    url, depth = item
                    inflight[executor.submit(worker, url)] = (url, depth)
                if not inflight:
                    break
                done, _ = wait(set(inflight), return_when=FIRST_COMPLETED)
                for fut in done:
                    url, depth = inflight.pop(fut)
                    handle(url, depth, fut.result())
                    progress.tick(fetched_count, frontier.discovered,
                                  len(frontier) + len(inflight),
                                  planned=frontier.enqueued_total)
                check_deadline()
    except (KeyboardInterrupt, Interrupted) as exc:
        stopped_reason = (exc.reason if isinstance(exc, Interrupted)
                          else "interrupted (Ctrl+C)")
        if on_status:
            on_status(f"Stopping — {stopped_reason}; writing partial snapshot")

    in_sitemap: set[str] = set()
    sitemap_lastmod: dict[str, str] = {}
    for url, lastmod in sitemap_entries:
        try:
            norm = frontier.normalize(url)
        except ValueError:
            continue
        in_sitemap.add(norm)
        if lastmod is not None:
            sitemap_lastmod[norm] = lastmod
    for url, record in pages.items():
        record.in_sitemap = url in in_sitemap
        record.sitemap_lastmod = sitemap_lastmod.get(url)

    return Snapshot(
        seed_url=seed,
        include_subdomains=include_subdomains,
        path_prefix=path_prefix,
        capped=frontier.capped,
        pages_discovered=frontier.discovered,
        pages_crawled=fetched_count,
        pages=sorted(pages.values(), key=lambda p: (p.depth, p.url)),
        crawled_at=now_iso(),
        partial=stopped_reason is not None,
        stopped_reason=stopped_reason,
        exclude_patterns=list(exclude_patterns),
        sitemap_urls=sitemap_urls,
    )


def _seed_excluded_reason(seed: str, scope: Scope) -> str:
    """Why the seed fell outside its own scope — a silent empty crawl
    otherwise looks exactly like a clean site."""
    excluded = scope.excluded(seed)
    if excluded is not None:
        return (f"--exclude-pattern {excluded!r} matches the seed URL itself "
                f"({seed}) — the crawl would have nothing to start from")
    if scope.path_prefix:
        return (f"--path-prefix {scope.path_prefix!r} excludes the seed URL "
                f"itself ({seed}) — start from a URL under that prefix")
    return f"the seed URL is outside its own crawl scope: {seed}"


def _load_sitemap_urls(session: requests.Session, seed: str,
                       robots: RobotsGate | None, timeout: int
                       ) -> list[tuple[str, str | None]]:
    """Sitemap entries as ``(url, lastmod)`` pairs, lastmod raw."""
    def fetch(url: str) -> tuple[int | None, bytes | None]:
        try:
            resp = session.get(url, timeout=timeout)
            return resp.status_code, resp.content
        except requests.RequestException:
            return None, None

    declared = robots.sitemaps(seed) if robots is not None else []
    return sitemap_mod.discover(seed, fetch, robots_sitemaps=declared)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def status_breakdown(pages: list[PageRecord]) -> list[list]:
    """Final table (plan A7): status-code breakdown + discovered/crawled/capped."""
    fetched = [p for p in pages if not p.blocked_by_robots]

    def count_status(lo: int, hi: int) -> int:
        return sum(1 for p in fetched
                   if p.status is not None and lo <= p.status <= hi)

    return [
        ["2xx", count_status(200, 299)],
        ["3xx (final response)", count_status(300, 399)],
        ["4xx", count_status(400, 499)],
        ["5xx", count_status(500, 599)],
        ["no response (error)", sum(1 for p in fetched if p.status is None)],
        ["robots.txt-blocked", sum(1 for p in pages if p.blocked_by_robots)],
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_header(raw: str) -> tuple[str, str]:
    name, sep, value = raw.partition(":")
    if not sep or not name.strip():
        raise argparse.ArgumentTypeError(
            f"--header must be 'Name: value', got {raw!r}")
    return name.strip(), value.strip()


def parse_basic_auth(raw: str) -> tuple[str, str]:
    user, sep, password = raw.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError(
            "--basic-auth must be 'user:password'")
    return user, password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Site Crawler — crawl a site and save a structured "
                    "snapshot (pages, status codes, redirects, canonical, links)")
    parser.add_argument("--seed-url", required=True,
                        help="URL to start crawling from")
    parser.add_argument("--include-subdomains", action="store_true",
                        help="Also crawl subdomains (blog.example.com for example.com)")
    parser.add_argument("--path-prefix", default=None,
                        help="Only crawl URLs under this path (e.g. /blog/)")
    parser.add_argument("--exclude-pattern", action="append", default=[],
                        metavar="REGEX",
                        help="Skip URLs matching this regex; repeatable "
                             "(e.g. '/cart/' or '\\?filter=')")
    parser.add_argument("--max-depth", type=int, default=5,
                        help="Maximum link depth from the seed (default 5)")
    parser.add_argument("--max-pages", type=int, default=500,
                        help="Hard cap on pages crawled (default 500)")
    parser.add_argument("--keep-tracking-params", action="store_true",
                        help="Keep utm_*/gclid/fbclid params — URLs differing "
                             "only in tracking params count as distinct pages")
    parser.add_argument("--drop-query-param", action="append", default=[],
                        metavar="NAME",
                        help="Also drop this query param before dedup; "
                             "repeatable (for faceted navigation)")
    parser.add_argument("--ignore-all-query-params", action="store_true",
                        help="Drop every query string before dedup — the blunt "
                             "instrument against faceted-URL explosion")
    parser.add_argument("--use-sitemap", action="store_true",
                        help="Also seed the crawl from robots.txt Sitemap: "
                             "entries and /sitemap.xml, and record in_sitemap "
                             "(the only way orphan pages become visible)")
    parser.add_argument("--crawl-resources", action="store_true",
                        help="Also fetch non-HTML resources (img/css/js) as "
                             "status-only leaf records")
    parser.add_argument("--respect-nofollow", action="store_true",
                        help="Do not queue links that are only ever linked "
                             "with rel=nofollow")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Concurrent requests (default 5)")
    parser.add_argument("--delay-ms", type=int, default=200,
                        help="Delay between requests per worker in ms (default 200)")
    parser.add_argument("--respect-crawl-delay", action="store_true",
                        help="Honor robots.txt Crawl-delay when it asks for "
                             "more than --delay-ms")
    parser.add_argument("--ignore-robots-txt", action="store_true",
                        help="Crawl URLs that robots.txt disallows — only for "
                             "sites you own or are authorized to crawl")
    parser.add_argument("--user-agent", default=DEFAULT_UA,
                        help="User-Agent header (identifies the tool honestly)")
    parser.add_argument("--header", action="append", default=[],
                        type=parse_header, metavar="NAME:VALUE",
                        help="Extra request header; repeatable")
    parser.add_argument("--basic-auth", default=None, type=parse_basic_auth,
                        metavar="USER:PASSWORD",
                        help="HTTP basic auth, for password-gated staging "
                             "sites (also read from the BASIC_AUTH env var; "
                             "never put a password on argv under PyShell)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Per-request timeout in seconds (default 15)")
    parser.add_argument("--retries", type=int, default=1,
                        help="Retries per request on connection errors and "
                             "429/502/503/504, honoring Retry-After (default 1)")
    parser.add_argument("--max-body-bytes", type=int, default=MAX_BODY_BYTES,
                        help=f"Cap on HTML bytes read per page "
                             f"(default {MAX_BODY_BYTES})")
    parser.add_argument("--max-duration", type=float, default=None,
                        metavar="SECONDS",
                        help="Stop crawling after this long and still write "
                             "the snapshot, instead of being killed by a "
                             "runtime timeout with nothing to show")
    parser.add_argument("--resume", action="store_true",
                        help="Continue from the site_snapshot.json already in "
                             "--out-dir instead of re-crawling from scratch")
    parser.add_argument("--out-dir", required=True,
                        help="Folder to write site_snapshot.json and "
                             "crawl_summary.csv into")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no request sent", flush=True)
        return 0

    if (args.max_depth < 0 or args.max_pages < 1 or args.concurrency < 1
            or args.delay_ms < 0 or args.timeout < 1 or args.retries < 0
            or args.max_body_bytes < 1
            or (args.max_duration is not None and args.max_duration <= 0)):
        print("error: --max-depth >= 0, --max-pages >= 1, --concurrency >= 1, "
              "--delay-ms >= 0, --timeout >= 1, --retries >= 0, "
              "--max-body-bytes >= 1 and --max-duration > 0 are required",
              file=sys.stderr, flush=True)
        return 2

    strip_tracking = not args.keep_tracking_params
    drop_params = tuple(args.drop_query_param)

    # Basic auth: PyShell passes the secret via the BASIC_AUTH env var
    # (Keychain → env, never on argv — see _reference/authoring-guide.md, Secrets).
    # The CLI flag stays for terminal use and wins when both are given.
    basic_auth = args.basic_auth
    if basic_auth is None:
        env_auth = os.environ.get("BASIC_AUTH")
        if env_auth:
            try:
                basic_auth = parse_basic_auth(env_auth)
            except argparse.ArgumentTypeError as exc:
                print(f"error: BASIC_AUTH: {exc}", file=sys.stderr, flush=True)
                return 2

    try:
        seed = normalize_url(args.seed_url, strip_tracking_params=strip_tracking,
                             drop_params=drop_params,
                             drop_all_params=args.ignore_all_query_params)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr, flush=True)
        return 2

    if args.ignore_robots_txt and not UNDER_PYSHELL:
        print("⚠ robots.txt will be ignored — make sure you own this site or "
              "are authorized to crawl it", file=sys.stderr, flush=True)

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    resume_from = (os.path.join(out_dir, "site_snapshot.json")
                   if args.resume else None)

    print(f"Crawling {seed} (max {args.max_pages} pages, depth "
          f"{args.max_depth}, {args.concurrency} workers)", flush=True)
    status(f"Crawling {seed}…")

    try:
        snapshot = crawl(
            seed,
            include_subdomains=args.include_subdomains,
            path_prefix=args.path_prefix,
            max_depth=args.max_depth,
            max_pages=args.max_pages,
            strip_tracking_params=strip_tracking,
            crawl_resources=args.crawl_resources,
            concurrency=args.concurrency,
            delay_ms=args.delay_ms,
            respect_robots=not args.ignore_robots_txt,
            user_agent=args.user_agent,
            timeout=args.timeout,
            exclude_patterns=tuple(args.exclude_pattern),
            drop_params=drop_params,
            drop_all_params=args.ignore_all_query_params,
            use_sitemap=args.use_sitemap,
            respect_crawl_delay=args.respect_crawl_delay,
            respect_nofollow=args.respect_nofollow,
            retries=args.retries,
            max_body_bytes=args.max_body_bytes,
            max_duration=args.max_duration,
            resume_from=resume_from,
            extra_headers=dict(args.header),
            basic_auth=basic_auth,
            on_status=status,
            on_progress=lambda pct, msg: emit(
                {"type": "progress", "pct": pct, "message": msg}),
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr, flush=True)
        return 2

    snapshot_path = write_snapshot(snapshot, out_dir)
    csv_path = write_summary_csv(snapshot, out_dir)

    # A capped run reads as "capped", not "that's the whole site" (plan A2).
    not_crawled = snapshot.pages_discovered - snapshot.pages_crawled
    summary_rows = [
        ["Pages discovered", snapshot.pages_discovered],
        ["Pages crawled", snapshot.pages_crawled],
        ["Discovered, not crawled (depth/page cap)", not_crawled],
    ] + status_breakdown(snapshot.pages)
    if snapshot.sitemap_urls:
        summary_rows.append(["In sitemap",
                             sum(1 for p in snapshot.pages if p.in_sitemap)])
    emit({"type": "table", "columns": ["Metric", "Count"], "rows": summary_rows})

    capped_note = (f" · ⚠ capped: {not_crawled} URL(s) discovered but not crawled"
                   if snapshot.capped else "")
    status(f"Crawled {snapshot.pages_crawled} of {snapshot.pages_discovered} "
           f"pages{capped_note}")
    print(f"Snapshot: {snapshot_path}\nSummary:  {csv_path}", flush=True)
    emit({"type": "progress", "pct": 100, "message": "Done"})

    if snapshot.partial:
        print(f"⚠ partial crawl: {snapshot.stopped_reason} — the snapshot "
              f"holds what was crawled up to that point",
              file=sys.stderr, flush=True)
        if snapshot.stopped_reason == "interrupted (Ctrl+C)":
            return 130

    # Exit 1 only when there was nothing to crawl: the seed never produced
    # a response (unreachable) or was robots-blocked.
    seed_record = next((p for p in snapshot.pages if p.url == seed), None)
    if seed_record is not None and seed_record.blocked_by_robots:
        print("✗ the seed URL is disallowed by the site's robots.txt",
              file=sys.stderr, flush=True)
        return 1
    if (seed_record is not None and seed_record.status is None
            and seed_record.error):
        print(f"✗ seed URL unreachable: {seed_record.error}",
              file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
