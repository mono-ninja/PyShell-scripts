"""One page fetch, with the full redirect chain captured (plan A4).

``GET``, not ``HEAD`` — title/canonical/meta need the body. Redirects are
followed manually (requests would only expose the final response) so the
hop chain lands in the snapshot; ``seo-checks`` uses it later to decide
whether internal links point at stale pre-redirect URLs.

Following redirects by hand is also what makes them *governable*: every
hop is put through the caller's ``allow_hop`` gate before it is
requested, so a redirect can neither smuggle the crawler past robots.txt
nor walk it off the site it was pointed at. A refused hop is recorded as
a fact on the requesting URL, not followed.

Response bodies are streamed and read only when they are HTML, and only
up to ``max_body_bytes`` — recording the status code of a 2 GB video must
not mean downloading a 2 GB video.

``redirect_chain`` semantics (the contract ``seo-checks`` depends on):
the URLs followed *after* the requested one — the requested URL itself is
``FetchResult.url``/the page key, and the chain ends with the final URL.
Empty when no redirect happened. So a single redirect is a one-element
chain, and "is a redirect source" == "has a non-empty chain whose last
element differs from the page URL".
"""
from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests

MAX_HOPS = 10
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Bodies are only read for these; anything else is a status-only leaf.
HTML_TYPES = {"text/html", "application/xhtml+xml"}

# 5 MB of HTML is already an extreme outlier; past this the rest of the
# document is truncated rather than buffered.
MAX_BODY_BYTES = 5 * 1024 * 1024

# Response headers worth keeping as facts. X-Robots-Tag is the important
# one: a server-level `noindex` is invisible to any check that only looks
# at <meta name=robots>, and it cannot be recovered from the snapshot later.
# Content-Type is kept whole, parameters included: the normalized
# `content_type` field drops them, and the server's charset half of a
# "server says utf-8, document says cp1251" mojibake conflict lives here.
CAPTURED_HEADERS = ("x-robots-tag", "content-type", "content-length",
                    "last-modified", "etag", "cache-control",
                    "content-language", "server")

# Transient statuses worth one polite retry rather than a recorded failure.
RETRY_STATUSES = {429, 502, 503, 504}
MAX_RETRY_AFTER = 60.0        # never park a worker longer than this

_META_CHARSET_RE = re.compile(rb"""charset\s*=\s*["']?\s*([\w.:+-]+)""", re.I)

# allow_hop(url) -> None when the hop may be followed, else the reason it
# may not (used verbatim in the recorded error).
AllowHop = Callable[[str], "str | None"]


@dataclass
class FetchResult:
    url: str                      # the requested URL
    status: int | None            # final response status, None when no response
    content_type: str | None      # normalized ("text/html"), no parameters
    body: str | None              # HTML body, only for HTML responses
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None      # timeout / connection error / redirect loop
    blocked_by_robots: bool = False
    headers: dict[str, str] = field(default_factory=dict)   # CAPTURED_HEADERS
    response_time_ms: int | None = None
    body_bytes: int | None = None  # bytes read off the wire for the body
    truncated: bool = False        # body hit max_body_bytes
    retries_used: int = 0          # retries this page cost, all hops combined


def _content_type(resp: requests.Response) -> str | None:
    raw = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    return raw or None


def _captured(resp: requests.Response) -> dict[str, str]:
    return {name: resp.headers[name]
            for name in CAPTURED_HEADERS if name in resp.headers}


def _looks_like_html(head: bytes) -> bool:
    """Sniff a body whose response carried no Content-Type at all.

    Plenty of servers omit the header; without this, such a page is
    recorded as an unparseable leaf and the crawl dead-ends on it.
    """
    start = head[:1024].lstrip().lower()
    if start.startswith(b"\xef\xbb\xbf"):
        start = start[3:].lstrip()
    return (start.startswith(b"<!doctype html") or start.startswith(b"<html")
            or start.startswith(b"<head") or b"<html" in start[:512])


def _decode(raw: bytes, declared: str | None) -> str:
    """Decode an HTML body, preferring the server's charset, then the
    document's own ``<meta charset>``, then UTF-8.

    Never falls back to requests' ISO-8859-1 default for a charset-less
    ``text/*``, which mojibakes every UTF-8 page on the web.
    """
    for encoding in (declared, _meta_charset(raw), "utf-8"):
        if not encoding:
            continue
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _meta_charset(raw: bytes) -> str | None:
    match = _META_CHARSET_RE.search(raw[:4096])
    if not match:
        return None
    try:
        return match.group(1).decode("ascii")
    except UnicodeDecodeError:
        return None


def _read_body(resp: requests.Response, content_type: str | None,
               max_body_bytes: int) -> tuple[str | None, int | None, bool]:
    """Return ``(text, bytes_read, truncated)``; ``(None, None, False)``
    for anything that isn't HTML, without downloading it."""
    if content_type is not None and content_type not in HTML_TYPES:
        return None, None, False

    chunks: list[bytes] = []
    size = 0
    truncated = False
    for chunk in resp.iter_content(8192):
        chunks.append(chunk)
        size += len(chunk)
        if content_type is None and len(chunks) == 1 and not _looks_like_html(chunk):
            return None, None, False     # sniffed as non-HTML: stop reading
        if size >= max_body_bytes:
            truncated = True
            break
    raw = b"".join(chunks)
    if content_type is None and not _looks_like_html(raw):
        return None, None, False

    declared = None
    if "charset" in (resp.headers.get("Content-Type") or "").lower():
        declared = resp.encoding
    return _decode(raw, declared), size, truncated


def _retry_after(resp: requests.Response) -> float | None:
    """``Retry-After`` in seconds, when the server sends a usable one."""
    raw = (resp.headers.get("Retry-After") or "").strip()
    if not raw:
        return None
    try:
        return max(0.0, min(float(raw), MAX_RETRY_AFTER))
    except ValueError:
        return None   # HTTP-date form: fall back to the normal backoff


def fetch_page(session: requests.Session, url: str, *, timeout: int,
               max_body_bytes: int = MAX_BODY_BYTES,
               allow_hop: AllowHop | None = None,
               retries: int = 1, backoff: float = 1.0,
               sleep: Callable[[float], None] = time.sleep) -> FetchResult:
    """Fetch ``url``, following (and gating) redirects and recording every hop.

    Never raises for network problems — they come back as a FetchResult
    with ``error`` set, so one unreachable page can't take down the crawl.
    ``retries`` applies to connection failures and to the transient
    statuses in :data:`RETRY_STATUSES`, honoring ``Retry-After`` when the
    server sends one. ``response_time_ms`` measures time spent waiting
    on the *server* — the delays between retry attempts are the crawler
    being polite, not the site being slow, and are not billed to it.
    """
    chain: list[str] = []
    current = url
    started = time.monotonic()
    waited = 0.0
    used = [0]                     # retries consumed, read after every path out

    def counted_sleep(seconds: float) -> None:
        nonlocal waited
        waited += seconds
        sleep(seconds)

    def elapsed_ms() -> int:
        return int(max(0.0, (time.monotonic() - started - waited)) * 1000)

    try:
        resp: requests.Response | None = None
        for _ in range(MAX_HOPS):
            resp = _get_with_retries(session, current, timeout=timeout,
                                     retries=retries, backoff=backoff,
                                     sleep=counted_sleep, used=used)
            if resp.status_code not in REDIRECT_STATUSES:
                break
            location = resp.headers.get("Location")
            if not location:
                break
            target = urljoin(current, location)
            refusal = allow_hop(target) if allow_hop is not None else None
            if refusal is not None:
                # The hop is a fact worth recording, but not one worth
                # following: robots.txt and the crawl scope apply to
                # every request, not only to the ones we chose ourselves.
                resp.close()
                return FetchResult(url, resp.status_code, _content_type(resp),
                                   None, chain, refusal,
                                   headers=_captured(resp),
                                   response_time_ms=elapsed_ms(),
                                   retries_used=used[0])
            resp.close()
            current = target
            chain.append(current)
        else:
            # Still redirecting after MAX_HOPS — keep the last response as
            # evidence and mark the loop, same truncation rule
            # security-headers uses for its own chain capture.
            return FetchResult(
                url, resp.status_code if resp is not None else None,
                _content_type(resp) if resp is not None else None,
                None, chain, f"too many redirects (more than {MAX_HOPS} hops)",
                headers=_captured(resp) if resp is not None else {},
                response_time_ms=elapsed_ms(),
                retries_used=used[0],
            )

        assert resp is not None
        content_type = _content_type(resp)
        try:
            body, body_bytes, truncated = _read_body(resp, content_type,
                                                     max_body_bytes)
        finally:
            resp.close()
        return FetchResult(url, resp.status_code, content_type, body, chain,
                           None, headers=_captured(resp),
                           response_time_ms=elapsed_ms(),
                           body_bytes=body_bytes, truncated=truncated,
                           retries_used=used[0])
    except requests.RequestException as exc:
        return FetchResult(url, None, None, None, chain,
                           f"{type(exc).__name__}: {exc}",
                           response_time_ms=elapsed_ms(),
                           retries_used=used[0])


def _get_with_retries(session: requests.Session, url: str, *, timeout: int,
                      retries: int, backoff: float,
                      sleep: Callable[[float], None],
                      used: list) -> requests.Response:
    """One hop, retried on transient failures. Raises the last
    RequestException when every attempt failed.

    ``used`` is a one-element list the caller reads on every path out of
    :func:`fetch_page` — success, refusal or exception — to learn how many
    retries this hop cost; the fact dies with the run, so it is tallied
    here rather than reconstructed later.
    """
    attempt = 0
    while True:
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=False,
                               stream=True)
        except requests.RequestException:
            if attempt >= retries:
                raise
            used[0] += 1
            sleep(backoff * (2 ** attempt))
            attempt += 1
            continue

        if resp.status_code not in RETRY_STATUSES or attempt >= retries:
            return resp
        # 429/503 is the site asking for a slower crawl; obey Retry-After
        # when it names a delay, otherwise back off exponentially.
        used[0] += 1
        wait = _retry_after(resp)
        resp.close()
        sleep(wait if wait is not None else backoff * (2 ** attempt))
        attempt += 1
