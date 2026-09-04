"""Per-host robots.txt cache and gate (plan A3).

Fetched once per host, cached for the run. A blocked URL is never fetched
by the crawler — but the caller records it in the snapshot with
``blocked_by_robots: true`` so ``seo-checks`` can flag "linked but
robots-excluded" pages without a re-crawl.

Fetch outcomes map to the standard interpretation:

* 2xx — parse the rules and honor them;
* 4xx (typically 404) — no robots.txt, everything allowed;
* 5xx — treated as *disallow everything* for that host: the conservative
  reading (matches how Google treats a persistently erroring robots.txt).
  A crawl that quietly proceeds when the site just said "I can't show you
  my crawl rules" is exactly the failure mode the politeness defaults
  exist to prevent;
* unreachable (no response at all) — allowed, the same as a missing
  robots.txt. A transient DNS or connection failure on one request is not
  the site declining to publish rules, and treating it as a site-wide
  disallow would let one dropped packet silently empty a crawl.

The gate is consulted from worker threads, so the cache is lock-guarded
and each origin's robots.txt is fetched exactly once even under
concurrency.
"""
from __future__ import annotations

import re
import threading
from collections.abc import Callable
from urllib import robotparser
from urllib.parse import urlsplit

# fetch(url) -> (status, body): status is None when the request failed
# entirely, body is None when there is no body to read.
RobotsFetch = Callable[[str], "tuple[int | None, str | None]"]

# "Disallow: /" for every agent — used when robots.txt itself is broken.
_BLOCK_ALL = ["User-agent: *", "Disallow: /"]

# stdlib's parser drops fractional Crawl-delay values (it guards the
# int() conversion with str.isdigit(), so "Crawl-delay: 0.5" is silently
# ignored). Sites do write those, so re-read the directive ourselves.
_CRAWL_DELAY_RE = re.compile(r"^\s*crawl-delay\s*:\s*([0-9]*\.?[0-9]+)\s*$",
                             re.IGNORECASE)
_USER_AGENT_RE = re.compile(r"^\s*user-agent\s*:\s*(.*?)\s*$", re.IGNORECASE)


def _fractional_crawl_delay(body: str, user_agent: str) -> float | None:
    """Best Crawl-delay for ``user_agent``, floats included.

    Same precedence as the rule matching: a group naming our agent wins
    over the ``*`` group. Returns ``None`` when the file sets none.
    """
    agent_token = user_agent.split("/")[0].strip().lower()
    star_delay: float | None = None
    own_delay: float | None = None
    agents: list[str] = []
    previous_was_agent = False
    for line in body.splitlines():
        line = line.split("#", 1)[0]
        agent_match = _USER_AGENT_RE.match(line)
        if agent_match:
            if not previous_was_agent:
                agents = []
            agents.append(agent_match.group(1).lower())
            previous_was_agent = True
            continue
        previous_was_agent = False
        delay_match = _CRAWL_DELAY_RE.match(line)
        if not delay_match:
            continue
        value = float(delay_match.group(1))
        for agent in agents:
            if agent == "*" and star_delay is None:
                star_delay = value
            elif agent and agent != "*" and agent in agent_token and own_delay is None:
                own_delay = value
    return own_delay if own_delay is not None else star_delay


class RobotsGate:
    def __init__(self, user_agent: str, fetch: RobotsFetch):
        self.user_agent = user_agent
        self._fetch = fetch
        self._cache: dict[str, robotparser.RobotFileParser | None] = {}
        self._delays: dict[str, float | None] = {}
        self._sitemaps: dict[str, list[str]] = {}
        self._lock = threading.Lock()
        self._origin_locks: dict[str, threading.Lock] = {}

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        # netloc keeps the port — a port-bearing origin has its own
        # robots.txt, and dropping it would query the wrong server.
        netloc = parts.netloc.rpartition("@")[2].lower()
        return f"{parts.scheme.lower()}://{netloc}"

    def _parser_for(self, url: str) -> robotparser.RobotFileParser | None:
        origin = self._origin(url)
        with self._lock:
            if origin in self._cache:
                return self._cache[origin]
            origin_lock = self._origin_locks.setdefault(origin, threading.Lock())

        # One fetch per origin even with every worker hitting a new host at
        # once: the losers block here, then read the cache the winner filled.
        with origin_lock:
            with self._lock:
                if origin in self._cache:
                    return self._cache[origin]

            parser: robotparser.RobotFileParser | None = None
            delay: float | None = None
            sitemaps: list[str] = []
            try:
                status, body = self._fetch(f"{origin}/robots.txt")
            except Exception:  # a robots.txt failure must never crash the crawl
                status, body = None, None

            if status is not None and 200 <= status < 300 and body is not None:
                parser = robotparser.RobotFileParser()
                parser.parse(body.splitlines())
                delay = parser.crawl_delay(self.user_agent)
                if delay is None:
                    delay = _fractional_crawl_delay(body, self.user_agent)
                sitemaps = list(parser.site_maps() or [])
            elif status is not None and status >= 500:
                parser = robotparser.RobotFileParser()
                parser.parse(_BLOCK_ALL)
            # 4xx or unreachable (status None): no rules -> allow everything.

            with self._lock:
                self._cache[origin] = parser
                self._delays[origin] = float(delay) if delay is not None else None
                self._sitemaps[origin] = sitemaps
            return parser

    def allowed(self, url: str) -> bool:
        """True when robots.txt permits fetching ``url`` with our UA."""
        parser = self._parser_for(url)
        if parser is None:
            return True
        return parser.can_fetch(self.user_agent, url)

    def crawl_delay(self, url: str) -> float | None:
        """The host's ``Crawl-delay`` for our UA, in seconds, if it sets one."""
        self._parser_for(url)
        with self._lock:
            return self._delays.get(self._origin(url))

    def sitemaps(self, url: str) -> list[str]:
        """``Sitemap:`` URLs the host's robots.txt advertises."""
        self._parser_for(url)
        with self._lock:
            return list(self._sitemaps.get(self._origin(url), ()))
