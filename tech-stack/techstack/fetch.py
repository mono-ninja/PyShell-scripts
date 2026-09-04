"""HTTP fetcher scoped to one target.

``SiteFetcher`` keeps an own session, L1 cache, UA rotation and a polite
delay, and adds what fingerprinting needs:

  * ``fetch_evidence`` — GET a page and parse it into ``Evidence``;
  * ``fetch_bundle_text`` — ``Range: bytes=0-262143`` on the same-origin main
    bundle, then grep its first ~256KB for `react-dom` / `Vue warn`.
    External (CDN) hosts are never fetched, only counted;
  * ``probe_path`` — opt-in probe of public files (``/composer.json``…) for a
    version source. Off by default: in a target's logs this looks like a scanner.

SSL verification is off: Tech Stack fingerprints what the server sends, it does
not grade TLS. Fingerprinting and grading are different jobs.
"""
from __future__ import annotations

import random
import time
from typing import Optional
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

from .evidence import Evidence, from_response
from .util import hostname_of

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 "
    "Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100100 "
    "Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
    "Mobile/15E148 Safari/604.1",
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9,uk;q=0.8",
    "en-GB,en;q=0.9",
    "uk-UA,uk;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.5",
]

MAX_HTML = 2_000_000          # cap parsed HTML so a 50MB page does not OOM us
MAX_BUNDLE_BYTES = 262_144    # 256KB
MAX_BUNDLE_TOTAL = 393_216    # up to ~3 bundles' heads, capped
BUNDLE_HINTS = ("main", "app", "bundle", "chunk", "build", "runtime", "vendor")


class SiteFetcher:
    def __init__(self, timeout: int = 15, delay: float = 0.5, user_agent: str = ""):
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.session = requests.Session()
        self._mem: dict[str, Optional[requests.Response]] = {}
        self._setup_session()

    def _setup_session(self) -> None:
        retry = Retry(
            total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504],
            allowed_methods=["GET"], raise_on_status=False,
        )
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,*/*;q=0.8",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        if self.user_agent:
            self.session.headers["User-Agent"] = self.user_agent

    def _rotate_ua(self) -> None:
        if not self.user_agent:
            self.session.headers["User-Agent"] = random.choice(USER_AGENTS)
            self.session.headers["Accept-Language"] = random.choice(ACCEPT_LANGS)

    def _wait(self) -> None:
        if self.delay > 0:
            jitter = self.delay * 0.3 * random.uniform(-1, 1)
            time.sleep(max(0.0, self.delay + jitter))

    def get(
        self,
        url: str,
        *,
        extra_headers: Optional[dict] = None,
        allow_redirects: bool = True,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        self._wait()
        self._rotate_ua()
        headers = dict(extra_headers) if extra_headers else None
        try:
            return self.session.get(
                url, timeout=timeout or self.timeout, verify=False,
                allow_redirects=allow_redirects, headers=headers,
            )
        except requests.RequestException:
            return None

    def get_cached(self, url: str) -> Optional[requests.Response]:
        if url in self._mem:
            return self._mem[url]
        resp = self.get(url)
        self._mem[url] = resp
        return resp

    def fetch_evidence(self, url: str) -> tuple[Optional[Evidence], list[str]]:
        """GET ``url`` and parse to ``Evidence``. Returns ``(evidence, warnings)``."""
        warnings: list[str] = []
        resp = self.get(url)
        if resp is None:
            return None, [f"unreachable: {url}"]
        if resp.status_code >= 400:
            warnings.append(f"HTTP {resp.status_code} for {url}")
        text = resp.text or ""
        if len(text) > MAX_HTML:
            text = text[:MAX_HTML]
            warnings.append(f"HTML truncated to {MAX_HTML} chars")
        headers = {k: v for k, v in resp.headers.items()}
        ev = from_response(
            url=url, final_url=resp.url, status=resp.status_code,
            headers=headers, html=text,
        )
        return ev, warnings

    def fetch_bundle_text(self, evidence: Evidence) -> str:
        """Range-fetch the heads of same-origin bundle scripts; concat to a blob.

        External hosts are never touched. Same-origin only, and only
        a handful: this is a fingerprinting hint, not a crawl.
        """
        page_host = hostname_of(evidence.final_url or evidence.url)
        if not page_host:
            return ""
        candidates = [s for s in evidence.scripts if hostname_of(s) == page_host]
        # Prefer scripts that look like bundles; keep order otherwise.
        candidates.sort(key=lambda s: -sum(h in s.lower() for h in BUNDLE_HINTS))
        blob_parts: list[str] = []
        total = 0
        for src in candidates[:3]:
            if total >= MAX_BUNDLE_TOTAL:
                break
            body = self._range_get_text(src, MAX_BUNDLE_BYTES)
            if body:
                blob_parts.append(body)
                total += len(body)
        return "\n".join(blob_parts)

    def _range_get_text(self, url: str, max_bytes: int) -> str:
        resp = self.get(
            url,
            extra_headers={"Range": f"bytes=0-{max_bytes - 1}"},
            allow_redirects=True,
        )
        if resp is None or resp.status_code >= 400:
            return ""
        # 206 Partial Content (ideal) or 200 (server ignored Range) both fine.
        body = resp.text or ""
        return body[:max_bytes]

    def probe_path(self, url: str) -> Optional[requests.Response]:
        """Single GET for opt-in known-path probing (``--probe-known-paths``)."""
        return self.get(url, allow_redirects=False)

    def close(self) -> None:
        self.session.close()
        self._mem.clear()
