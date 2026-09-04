"""Scope rules, URL normalization, and the BFS frontier (plan A1–A2).

Facts only, no judgment: this module decides *what counts as the same URL*
and *what is inside the crawl* — nothing about whether a page is good or
bad. ``normalize_url`` is the single canonicalization used both for dedup
and for the URL keys written into the snapshot, so ``seo-checks``' reverse
link index lines up with page records by construction.
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urlsplit, urlunsplit

# Tracking params stripped before dedup when the option is on (default).
# Anything utm_* plus the two big click-id params.
EXTRA_TRACKING_PARAMS = {"gclid", "fbclid"}


def _is_tracking_param(pair: str) -> bool:
    name = pair.split("=", 1)[0].lower()
    return name.startswith("utm_") or name in EXTRA_TRACKING_PARAMS


def normalize_url(url: str, *, strip_tracking_params: bool = True,
                  drop_params: tuple[str, ...] | frozenset[str] = (),
                  drop_all_params: bool = False) -> str:
    """Canonical form used for dedup and as a snapshot page key.

    Lowercases scheme and host, strips the default port (:80/:443) and the
    fragment, and adds the ``/`` path when empty (``https://x.com`` ==
    ``https://x.com/``). Query strings are kept byte-as-is (no re-encoding)
    except for the params dropped here: tracking params when
    ``strip_tracking_params`` — otherwise one page with ``?utm_source=...``
    multiplied by every campaign link becomes dozens of "different" URLs —
    plus any name in ``drop_params``, or the whole query when
    ``drop_all_params`` (the blunt instrument for faceted navigation,
    where ``?color=red&size=m`` explodes combinatorially).

    Raises ``ValueError`` for anything that isn't an absolute http(s) URL.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        raise ValueError(f"not an absolute http(s) URL: {url!r}")

    netloc = f"[{host}]" if ":" in host else host  # hostname strips IPv6 brackets
    port = parts.port
    if port is not None and (scheme, port) not in (("http", 80), ("https", 443)):
        netloc += f":{port}"

    query = parts.query
    if drop_all_params:
        query = ""
    elif query and (strip_tracking_params or drop_params):
        dropped = {name.lower() for name in drop_params}
        query = "&".join(
            pair for pair in query.split("&")
            if pair
            and not (strip_tracking_params and _is_tracking_param(pair))
            and pair.split("=", 1)[0].lower() not in dropped
        )

    return urlunsplit((scheme, netloc, parts.path or "/", query, ""))


class Scope:
    """Which URLs belong to this crawl (plan A1).

    Exact host match by default; ``include_subdomains`` widens it to a host
    *suffix* match (``blog.example.com`` matches ``example.com``).
    Deliberately not registrable-domain (eTLD+1) aware — that needs a
    public-suffix list dependency that isn't worth it for v1, so
    ``co.uk``-style domains need ``include_subdomains`` used carefully.
    ``path_prefix`` (e.g. ``/blog/``) narrows the crawl further, and
    ``exclude_patterns`` (regexes matched against the whole URL) carve
    holes out of it — the defence against crawler traps like an infinite
    calendar or faceted navigation eating the whole page budget.
    """

    def __init__(self, seed_url: str, *, include_subdomains: bool = False,
                 path_prefix: str | None = None,
                 exclude_patterns: list[str] | tuple[str, ...] = ()):
        seed_host = urlsplit(seed_url).hostname
        if not seed_host:
            raise ValueError(f"seed URL has no host: {seed_url!r}")
        self.host = seed_host.lower()
        self.include_subdomains = include_subdomains
        self.path_prefix = (path_prefix or "").strip() or None
        self.exclude_patterns: list[re.Pattern] = []
        for pattern in exclude_patterns:
            try:
                self.exclude_patterns.append(re.compile(pattern))
            except re.error as exc:
                raise ValueError(f"bad --exclude-pattern {pattern!r}: {exc}") from exc

    def _prefix(self) -> str | None:
        if self.path_prefix is None:
            return None
        # "/blog" must not match "/blogroll": normalize to a trailing slash.
        pfx = self.path_prefix
        return pfx if pfx.endswith("/") else pfx + "/"

    def host_in_scope(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            return False
        if self.include_subdomains:
            return host == self.host or host.endswith("." + self.host)
        return host == self.host

    def excluded(self, url: str) -> str | None:
        """The first ``--exclude-pattern`` this URL matches, if any."""
        for pattern in self.exclude_patterns:
            if pattern.search(url):
                return pattern.pattern
        return None

    def in_scope(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https"):
            return False
        if not self.host_in_scope(url):
            return False
        pfx = self._prefix()
        if pfx is not None:
            path = parts.path or "/"
            if not (path == pfx.rstrip("/") or path.startswith(pfx)):
                return False
        return self.excluded(url) is None


class Frontier:
    """BFS queue with dedupe, depth and page-cap tracking (plan A2).

    URLs are normalized on ``add()`` and deduped on the normalized form;
    each URL is enqueued at most once, at the shallowest depth it was
    first *enqueuable* at. ``max_pages`` is a hard cap on enqueued URLs —
    once hit, new URLs are still counted as discovered but never enqueued,
    so the snapshot can say "capped," not "that's the whole site."
    """

    def __init__(self, scope: Scope, *, max_depth: int, max_pages: int,
                 strip_tracking_params: bool = True,
                 drop_params: tuple[str, ...] = (),
                 drop_all_params: bool = False):
        self.scope = scope
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.strip_tracking_params = strip_tracking_params
        self._norm_kw = dict(strip_tracking_params=strip_tracking_params,
                             drop_params=drop_params,
                             drop_all_params=drop_all_params)
        self._queue: deque[tuple[str, int]] = deque()
        self._known_depth: dict[str, int] = {}   # normalized url -> best depth seen
        self._enqueued: set[str] = set()
        self._fetched: set[str] = set()          # already retrieved, never re-request
        self._depth_discarded: set[str] = set()  # counting is idempotent per URL
        self._cap_discarded: set[str] = set()
        self.out_of_scope = 0                    # diagnostics only, not "discovered"

    def normalize(self, url: str) -> str:
        """This frontier's canonicalization — the snapshot's page keys."""
        return normalize_url(url, **self._norm_kw)

    def add(self, url: str, depth: int) -> str | None:
        """Register a discovered URL; enqueue it if new and within the caps.

        Returns the normalized URL when it was enqueued, ``None``
        otherwise (out of scope, duplicate, over depth, or over the page
        cap). Out-of-scope URLs are not counted as discovered — they were
        never candidates for this crawl.
        """
        try:
            norm = self.normalize(url)
        except ValueError:
            self.out_of_scope += 1
            return None
        if not self.scope.in_scope(norm):
            self.out_of_scope += 1
            return None

        if norm not in self._known_depth:
            self._known_depth[norm] = depth
        elif depth < self._known_depth[norm]:
            # Rediscovered at a shallower depth. Only matters when it was
            # previously discarded as too deep — an enqueued URL keeps its
            # original (deeper) ticket; re-queueing would double-fetch it.
            if norm in self._enqueued:
                return None
            if self._known_depth[norm] <= self.max_depth:
                return None
            self._known_depth[norm] = depth
        else:
            return None

        if depth > self.max_depth:
            self._depth_discarded.add(norm)
            return None
        if len(self._enqueued) >= self.max_pages:
            self._cap_discarded.add(norm)
            return None

        self._enqueued.add(norm)
        self._depth_discarded.discard(norm)   # it got a ticket after all
        self._cap_discarded.discard(norm)
        self._queue.append((norm, depth))
        return norm

    def mark_fetched(self, url: str, depth: int = 0) -> str | None:
        """Record that ``url`` has already been retrieved — never request it.

        Used for redirect targets (the response for ``/b`` already arrived
        while fetching ``/a`` → 301 → ``/b``) and for pages restored by
        ``--resume``. Without this, every trailing-slash or http→https
        redirect on a site makes the crawler fetch its target twice.

        The URL counts as discovered and consumes page budget — it *was*
        a fetch — but it never gets a queue ticket, and a ticket it
        already holds is skipped on ``pop()``.
        """
        try:
            norm = self.normalize(url)
        except ValueError:
            return None
        if not self.scope.in_scope(norm):
            return None
        self._known_depth.setdefault(norm, depth)
        self._enqueued.add(norm)
        self._fetched.add(norm)
        self._depth_discarded.discard(norm)
        self._cap_discarded.discard(norm)
        return norm

    def pop(self) -> tuple[str, int] | None:
        """Next ``(url, depth)`` in BFS order, or ``None`` when empty."""
        while self._queue:
            url, depth = self._queue.popleft()
            if url in self._fetched:
                continue          # arrived as a redirect target in the meantime
            return url, depth
        return None

    def __len__(self) -> int:
        return len(self._queue)

    @property
    def discovered(self) -> int:
        """Unique in-scope URLs this crawl has ever seen."""
        return len(self._known_depth)

    @property
    def enqueued_total(self) -> int:
        """URLs that got (or consumed) a ticket — the honest progress total.

        Bounded by ``max_pages``, unlike :attr:`discovered`, which keeps
        counting URLs the caps guarantee will never be crawled.
        """
        return len(self._enqueued)

    @property
    def discarded_by_depth(self) -> int:
        return len(self._depth_discarded)

    @property
    def discarded_by_cap(self) -> int:
        return len(self._cap_discarded)

    @property
    def capped(self) -> bool:
        """True when in-scope URLs were discovered but never crawled."""
        return bool(self._depth_discarded) or bool(self._cap_discarded)
