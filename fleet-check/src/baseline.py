"""src/baseline.py — the previous-run diff (the seo-checks pattern,
sized for a fleet): per URL, what moved between two fleet.json runs."""
from __future__ import annotations

import json
import os
from urllib.parse import urlsplit


def load_baseline(path: str) -> dict | None:
    """The previous run's fleet.json as {url: {tls_grade, cert_days,
    headers_grade, http_status}} — or None when unreadable."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    out: dict = {}
    for site in data.get("sites", []):
        url = site.get("url") or ""
        if url:
            out[normalize(url)] = site
    return out or None


def normalize(url: str) -> str:
    """The same shape parse_urls produces: scheme://host[:port] with
    non-default ports kept, so a diff compares like with like."""
    parts = urlsplit(url)
    if not parts.hostname:
        return url
    port = parts.port
    netloc = parts.hostname if port in (None, 80, 443) \
        else f"{parts.hostname}:{port}"
    return f"{parts.scheme}://{netloc}"


def _grade_rank(grade: str) -> int:
    """A+ best … F worst; compact/unknown grades don't rank."""
    order = ["A+", "A", "A-", "B", "B-", "C", "C-", "D", "D-", "E", "F"]
    return order.index(grade) if grade in order else 99


def diff_against_baseline(baseline: dict | None,
                          results: list) -> dict[str, dict]:
    """{url: {direction: better|worse|same, changes: [str]}} for the
    URLs present in both. New/gone sites are the report's job."""
    if not baseline:
        return {}
    out: dict[str, dict] = {}
    current = {normalize(r.url): r for r in results}
    for url, was in baseline.items():
        now = current.get(url)
        if now is None:
            continue  # gone — reported separately
        changes: list[str] = []
        better = worse = False
        if was.get("tls_grade") and now.tls_grade and \
                was["tls_grade"] != now.tls_grade:
            delta = _grade_rank(was["tls_grade"]) - _grade_rank(now.tls_grade)
            if delta > 0:
                better = True
                changes.append(f"TLS {was['tls_grade']} → {now.tls_grade}")
            elif delta < 0:
                worse = True
                changes.append(f"TLS {was['tls_grade']} → {now.tls_grade}")
        was_days, now_days = was.get("cert_days"), now.cert_days
        if was_days is not None and now_days is not None:
            if was_days >= 0 > now_days:
                worse = True
                changes.append(f"certificate expired ({was_days}d → "
                               f"{now_days}d)")
            elif was_days < 0 <= now_days:
                better = True
                changes.append(f"certificate renewed ({was_days}d → "
                               f"{now_days}d)")
        if was.get("headers_grade") and now.headers_grade and \
                was["headers_grade"] != now.headers_grade:
            delta = _grade_rank(was["headers_grade"]) \
                - _grade_rank(now.headers_grade)
            if delta > 0:
                better = True
                changes.append(f"headers {was['headers_grade']} → "
                               f"{now.headers_grade}")
            elif delta < 0:
                worse = True
                changes.append(f"headers {was['headers_grade']} → "
                               f"{now.headers_grade}")
        was_status, now_status = was.get("http_status"), now.http_status
        if was_status != now_status:
            if (was_status or 0) >= 400 > (now_status or 0):
                better = True
                changes.append(f"HTTP {was_status} → {now_status}")
            elif (was_status or 0) < 400 <= (now_status or 0):
                worse = True
                changes.append(f"HTTP {was_status} → {now_status}")
        if changes:
            direction = "better" if better and not worse else \
                "worse" if worse else "same"
            out[url] = {"direction": direction, "changes": changes}
    return out
