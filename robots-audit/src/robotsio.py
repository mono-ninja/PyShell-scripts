"""Fetching and reading robots.txt — the only I/O in the script.

URL mode GETs ``{origin}/robots.txt`` with redirects followed and
classifies the outcome per RFC 9309 §2.3.1: 200 parses, 404 means an
**unrestricted** crawl (not an error — a finding), 401/403 and 5xx are
"unavailable" territories where crawler behavior diverges (some treat
them as disallow-all) — reported with that exact nuance. A redirect
that leaves the host is followed but flagged: robots.txt is only valid
at the origin it governs.

File mode reads a local draft — the Bot Hunter workflow: the draft
never touches the site until it has passed this audit.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

import requests

MAX_REDIRECTS = 5


class SourceError(Exception):
    """The robots.txt could not be obtained at all (exit 1)."""


@dataclass
class RobotsSource:
    """What the source produced, before any parsing."""
    text: str | None = None          # None when there is no file to parse
    status: int | None = None        # HTTP status (URL mode)
    final_url: str | None = None
    note: str = ""                   # the headline fact about how it went
    severity: str = "info"           # info | warn — how the report frames it
    origin: str = ""                 # scheme://host the file governs


def normalize_origin(site_url: str) -> str:
    """``scheme://host[:port]`` — robots.txt governs an origin, and the
    Sitemap: lines and test URLs are judged relative to it."""
    parts = urlsplit(site_url if "://" in site_url else f"https://{site_url}")
    if not parts.hostname:
        raise SourceError(f"{site_url!r} is not a usable site URL")
    netloc = parts.hostname.lower()
    if parts.port is not None:
        netloc += f":{parts.port}"
    return f"{parts.scheme.lower()}://{netloc}"


def fetch_robots(origin: str, timeout: float) -> RobotsSource:
    """GET ``{origin}/robots.txt`` and classify the response per RFC 9309."""
    url = f"{origin}/robots.txt"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "PyShell-robots-audit/1.0"})
    except requests.RequestException as exc:
        raise SourceError(f"cannot fetch {url}: {exc}") from exc

    source = RobotsSource(status=resp.status_code, final_url=resp.url,
                          origin=origin)

    if resp.status_code == 200:
        source.text = resp.text
        if urlsplit(resp.url).hostname != urlsplit(url).hostname:
            source.note = (f"redirected to {resp.url} — followed, but "
                           f"robots.txt is only authoritative at its own origin")
            source.severity = "warn"
        return source

    if resp.status_code == 404:
        source.note = ("no robots.txt (404) — per RFC 9309 the crawl is "
                       "unrestricted: everything is allowed")
        return source
    if resp.status_code in (401, 403):
        source.note = (f"HTTP {resp.status_code} — crawlers diverge: some "
                       f"treat this as disallow-all (conservative), some as "
                       f"unavailable. Access control is not robots.txt's job")
        source.severity = "warn"
        return source
    if 500 <= resp.status_code < 600:
        source.note = (f"HTTP {resp.status_code} — server error; crawlers "
                       f"treat the file as temporarily unavailable and may "
                       f"fall back to disallow-all")
        source.severity = "warn"
        return source
    source.note = (f"HTTP {resp.status_code} — unusual; crawlers most likely "
                   f"treat it as unavailable")
    source.severity = "warn"
    return source


def read_robots_file(path: str) -> RobotsSource:
    """Read a local robots.txt (or draft). Never touches the network."""
    if not os.path.isfile(path):
        raise SourceError(f"no such file: {path}")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        raise SourceError(f"cannot read {path}: {exc}") from exc
    return RobotsSource(text=text, note=f"local file: {path}", origin="")


def verify_sitemap(url: str, timeout: float) -> tuple[bool, str]:
    """(ok, detail) for one Sitemap: line — a 200 is what a crawler
    needs; anything else is a broken promise. A non-absolute URL can't
    be fetched at all — the audit's Sitemap finding already covers it,
    so this says so instead of inventing a schema error."""
    if not url.startswith(("http://", "https://")):
        return False, ("not an absolute URL — cannot verify "
                       "(see the Sitemap finding)")
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": "PyShell-robots-audit/1.0"})
    except requests.RequestException as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if resp.status_code == 200:
        return True, "200 OK"
    return False, f"HTTP {resp.status_code}"
