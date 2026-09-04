"""meta refresh — an HTML-level redirect the redirect chain can't see.

The crawler records ``http-equiv=refresh`` as a fact and pointedly does
not follow it: a meta refresh is the page saying "go elsewhere" in a
way search engines treat as a redirect — but a slow, non-standard one.
Google accepts it, reluctantly, for 0-second refreshes; anything slower
is shown to the user first and is the worst of both worlds.

Findings, per content page:

* a refresh with ``url=`` and delay 0 → ``warn`` — a pseudo-redirect:
  the intent is a redirect, the mechanism is the wrong one;
* any other refresh (delayed, or plain periodic reload) → ``info``.

Reading a schema-4 snapshot, the check says so plainly instead of
silently finding nothing.
"""
from __future__ import annotations

import re

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable

_DELAY_URL = re.compile(r"^\s*([0-9.]+)\s*[;,]?\s*url\s*=\s*(.+)$", re.I)


def _parse(content: str) -> tuple[float | None, str | None]:
    """(delay, url) as the attribute states them, best effort."""
    match = _DELAY_URL.match(content)
    if not match:
        try:
            return float(content.strip().rstrip(";,")), None
        except ValueError:
            return None, None
    try:
        delay = float(match.group(1))
    except ValueError:
        delay = None
    return delay, match.group(2).strip().strip("'\"")


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 5:
        return [Finding(
            "meta_refresh", "info", "site",
            "cannot check for meta-refresh redirects — this snapshot "
            "predates their capture (schema 4)",
            "Re-crawl with a Site Crawler that records meta refresh "
            "(schema 5+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page) or not page.meta_refresh:
            continue
        delay, url = _parse(page.meta_refresh)
        if url and delay == 0:
            findings.append(Finding(
                "meta_refresh", "warn", page.url,
                f"immediate meta refresh to {url} ({page.meta_refresh!r})",
                "This is a redirect wearing the wrong mechanism — return "
                "a real 301/302 instead, so crawlers and users never load "
                "the middle page",
            ))
        else:
            if url and delay is not None:
                kind = f"a {delay:g}s delayed refresh to {url}"
            elif url:
                kind = f"a refresh to {url} (delay not understood)"
            else:
                kind = "a periodic page reload"
            findings.append(Finding(
                "meta_refresh", "info", page.url,
                f"{kind} ({page.meta_refresh!r})",
                "A delayed meta refresh shows the user an intermediate "
                "page — if it reloads data, fetch it with JavaScript "
                "instead; if it redirects, use a 301",
            ))

    return findings
