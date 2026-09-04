"""C4. URL variants — the same page reachable under more than one address.

Every finding here is a duplicate-content or wasted-redirect problem that
lives in the *links*, not in the pages: the site works perfectly, it just
disagrees with itself about what its URLs are.

* internal links using ``http://`` on an ``https://`` site → ``warn``.
  Every click pays a redirect, and the link graph is split across two
  schemes;
* both ``/page`` and ``/page/`` crawled as real, distinct pages →
  ``warn``. When one redirects to the other this is normal and silent —
  the check only fires when both actually serve content;
* URLs differing only in path casing → ``warn``. Same page, two
  addresses, on any case-sensitive server;
* internal links carrying ``utm_*``/``gclid``/``fbclid`` → ``info``.
  Campaign parameters belong on inbound links, not on the site's own
  navigation, where they fragment analytics and can get indexed.
"""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from src.options import Options
from src.snapshot import (
    Finding,
    Snapshot,
    has_tracking_params,
    join_urls,
    judgable,
    normalize_url,
)


def _slash_twin(url: str) -> str | None:
    """The same URL with the trailing slash flipped, or None for the root."""
    parts = urlsplit(url)
    path = parts.path
    if path in ("", "/"):
        return None
    twin = path[:-1] if path.endswith("/") else path + "/"
    return urlunsplit((parts.scheme, parts.netloc, twin, parts.query, ""))


def _grouped(pairs: dict[str, list[str]], check: str, severity: str,
             detail, recommendation) -> list[Finding]:
    findings = []
    for target in sorted(pairs):
        sources = pairs[target]
        findings.append(Finding(
            check, severity, target,
            detail(target, sources),
            recommendation(target, sources),
            referrers=sources,
        ))
    return findings


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    findings: list[Finding] = []
    seed_https = normalize_url(snapshot.seed_url).startswith("https://")

    insecure: dict[str, list[str]] = {}
    tracked: dict[str, list[str]] = {}
    for page in snapshot.pages:
        for link in page.links_internal:
            if seed_https and link.lower().startswith("http://"):
                insecure.setdefault(link, []).append(page.url)
            if has_tracking_params(link):
                tracked.setdefault(link, []).append(page.url)

    findings += _grouped(
        insecure, "url_variants", "warn",
        lambda t, s: f"{len(s)} internal link(s) point at {t} over plain http",
        lambda t, s: ("Link to the https:// URL directly — every one of these "
                      "costs a redirect: " + join_urls(s)))

    findings += _grouped(
        tracked, "url_variants", "info",
        lambda t, s: (f"{len(s)} internal link(s) carry tracking parameters: "
                      f"{t}"),
        lambda t, s: ("Campaign parameters belong on inbound links; internally "
                      "they split analytics and can get indexed. On: "
                      + join_urls(s)))

    # Both variants crawled as real pages (neither redirects to the other).
    content_keys = {p.key for p in snapshot.all_pages if judgable(p)}
    seen_pairs: set[tuple[str, str]] = set()
    for key in sorted(content_keys):
        twin = _slash_twin(key)
        if twin is None or twin not in content_keys:
            continue
        pair = tuple(sorted((key, twin)))
        if pair in seen_pairs or not snapshot.selected(key):
            continue
        seen_pairs.add(pair)
        findings.append(Finding(
            "url_variants", "warn", pair[0],
            f"both {pair[0]} and {pair[1]} serve content — the same page "
            f"under two URLs",
            "Pick one form, redirect the other to it, and make the canonical "
            "agree — otherwise the two split each other's ranking signals",
            pages=list(pair),
        ))

    by_case: dict[str, list[str]] = {}
    for key in sorted(content_keys):
        by_case.setdefault(key.lower(), []).append(key)
    for variants in by_case.values():
        if len(variants) > 1 and any(map(snapshot.selected, variants)):
            findings.append(Finding(
                "url_variants", "warn", join_urls(variants),
                f"{len(variants)} URLs differ only in letter case",
                "URL paths are case-sensitive — settle on one form and "
                "redirect the others, or the same page competes with itself",
                pages=variants,
            ))

    return findings
