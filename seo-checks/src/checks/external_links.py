"""A7. External links — the one network-touching check (opt-in).

Only runs when ``check_external_links`` is on, because it sends requests
to third-party hosts the crawler never visited (it only crawled in-scope
pages). Dedup first — a footer link repeated on 500 pages must trigger one
request, not 500 — then ``HEAD`` each unique URL with a ``GET`` fallback
when HEAD isn't allowed, on this check's own concurrency and timeout
knobs, deliberately separate from anything in ``site-crawler``.

Three things keep this from being the check that ruins a run:

* **a cap** (``--external-max-urls``). A site with thousands of unique
  external links at 5 concurrent requests and a 10s timeout can outlast
  any sane script timeout, and a run killed at 100% loses every finding
  the no-network checks already computed;
* **per-host spacing.** 200 links to one domain are spread out rather
  than fired at once — the URLs come from someone else's server and this
  script has no business hammering it;
* **no exception escapes.** ``requests`` raises things that aren't
  ``RequestException`` (an over-long domain label surfaces as
  ``UnicodeError``), and one of those propagating out of ``future.result()``
  used to replace the entire report with a traceback.

Being blocked is not the same as being broken: ``401``/``403``/``429``
are what bot-protected hosts (LinkedIn, Cloudflare challenges) answer to
anything without a browser, so they are reported as ``warn`` — a human
should click them — while genuine 4xx/5xx and dead hosts stay ``fail``.

``requests`` is imported lazily so the default no-network run never needs
it, and the probe itself is injectable so tests never touch the network.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

from src.snapshot import Finding, Snapshot, has_rel, join_urls

DEFAULT_UA = "PyShell-SEOChecks/1.0 (+external link check)"

# Hosts that answer HEAD with a refusal but serve GET fine.
HEAD_NOT_ALLOWED = {400, 403, 405, 501}

# Codes that mean "you are not a browser", not "this link is dead".
BLOCKED_STATUSES = {401, 403, 429}

DEFAULT_MAX_URLS = 500
HOST_DELAY = 0.2          # seconds between request *starts* to one host


class _Missing(Exception):
    """requests isn't installed — reported, never raised at the user."""


def _default_probe(user_agent: str):
    try:
        import requests
    except ImportError as exc:      # pragma: no cover - environment-specific
        raise _Missing from exc

    session = requests.Session()
    session.headers["User-Agent"] = user_agent

    def probe(url: str, timeout: int) -> tuple[int | None, str | None]:
        try:
            resp = session.head(url, timeout=timeout, allow_redirects=True)
            if resp.status_code in HEAD_NOT_ALLOWED:
                resp = session.get(url, timeout=timeout,
                                   allow_redirects=True, stream=True)
                resp.close()
            return resp.status_code, None
        except requests.RequestException as exc:
            return None, type(exc).__name__

    return probe


def _collect(snapshot: Snapshot, skip_nofollow: bool,
             ignore_hosts: frozenset[str]) -> dict[str, list[str]]:
    """Unique external URL -> unique referring pages."""
    targets: dict[str, list[str]] = {}
    for page in snapshot.pages:
        for link in page.links_external:
            if skip_nofollow and has_rel(page.rel_for(link), "nofollow"):
                continue
            host = (urlsplit(link).hostname or "").lower()
            if host in ignore_hosts or any(host.endswith("." + h)
                                           for h in ignore_hosts):
                continue
            referrers = targets.setdefault(link, [])
            if page.url not in referrers:
                referrers.append(page.url)
    return targets


def run(snapshot: Snapshot, *, concurrency: int = 5, timeout: int = 10,
        user_agent: str = DEFAULT_UA, probe=None, on_progress=None,
        max_urls: int = DEFAULT_MAX_URLS, skip_nofollow: bool = False,
        ignore_hosts=frozenset()) -> list[Finding]:
    """Verify every unique external link; non-2xx → one finding per URL,
    with all referring pages listed (same shape as broken_links)."""
    if probe is None:
        try:
            probe = _default_probe(user_agent)
        except _Missing:
            return [Finding(
                "external_links", "info", "site",
                "external-link check skipped — the 'requests' package is not "
                "installed",
                "Press Prepare Env in PyShell, or `pip install requests` for "
                "a terminal run. Every other check ran normally",
            )]

    targets = _collect(snapshot, skip_nofollow, frozenset(ignore_hosts))
    if not targets:
        return []

    urls = sorted(targets)
    truncated = len(urls) - max_urls if len(urls) > max_urls else 0
    urls = urls[:max_urls]

    statuses = _probe_all(urls, probe, timeout, concurrency, on_progress)

    findings: list[Finding] = []
    if truncated:
        findings.append(Finding(
            "external_links", "info", "site",
            f"checked {len(urls)} of {len(urls) + truncated} unique external "
            f"URLs",
            "Raise --external-max-urls to check the rest — the cap exists so "
            "one large site cannot run past the script timeout",
        ))

    for url in urls:
        status, error = statuses[url]
        if status is not None and 200 <= status < 300:
            continue
        referrers = targets[url]
        if status in BLOCKED_STATUSES:
            severity = "warn"
            reason = f"HTTP {status} — the host blocks automated checks"
            fix = ("Open it in a browser to confirm; bot protection answers "
                   "this way to anything without a session")
        else:
            severity = "fail"
            reason = (f"HTTP {status}" if status is not None
                      else f"no response ({error})")
            fix = "Fix or remove the link(s) on: " + join_urls(referrers)
        findings.append(Finding(
            "external_links", severity, url,
            f"{url} is unreachable — {reason} · linked from "
            f"{len(referrers)} page(s)",
            fix, referrers=referrers,
        ))
    return findings


def _probe_all(urls, probe, timeout, concurrency, on_progress):
    """Probe every URL, parallel across hosts and spaced within a host.

    The per-host lock is released before the request goes out, so it
    staggers *starts* rather than serializing a host completely — one slow
    domain must not hold the whole check hostage.
    """
    host_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
    host_last: dict[str, float] = {}
    progress_lock = threading.Lock()
    done = 0

    def polite(url: str):
        nonlocal done
        host = (urlsplit(url).hostname or "").lower()
        with host_locks[host]:
            last = host_last.get(host)
            if last is not None:
                wait = HOST_DELAY - (time.monotonic() - last)
                if wait > 0:
                    time.sleep(wait)
            host_last[host] = time.monotonic()
        try:
            result = probe(url, timeout)
        except Exception as exc:
            # Never let one malformed URL replace the report with a
            # traceback — requests raises beyond RequestException.
            result = (None, type(exc).__name__)
        with progress_lock:
            done += 1
            if on_progress:
                on_progress(done, len(urls))
        return result

    statuses: dict[str, tuple[int | None, str | None]] = {}
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        futures = {executor.submit(polite, url): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                statuses[url] = future.result()
            except Exception as exc:  # pragma: no cover - belt and braces
                statuses[url] = (None, type(exc).__name__)
    return statuses
