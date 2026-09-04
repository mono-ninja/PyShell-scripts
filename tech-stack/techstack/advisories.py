"""EOL and vulnerability lookups.

Two offline tables in ``advisories.yaml``:

  * ``eol``     — end-of-life dates per branch. A version whose branch EOL'd is
    flagged stale with the date, the way a client conversation needs ("PHP 7.4
    has had no support since 2022-11", not abstract "security").
  * ``vuln``    — vulnerable JS-library ranges (``VERSION_RULES``), with optional
    per-major ``ranges`` (Bootstrap 3.x / 4.x have different safe floors).

The file carries ``updated`` and the report shows it: these dates rot quarterly.
``--online-eol`` can refresh from endoflife.date, off by default — it is an
external request not everyone wants to make.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_DB_PATH = os.path.join(os.path.dirname(__file__), "advisories.yaml")


@dataclass
class Advisory:
    status: str               # "eol" | "vulnerable" | "outdated"
    detail: str
    cves: list[str]
    min_secure: str = ""


@lru_cache(maxsize=1)
def _load() -> dict:
    if yaml is None or not os.path.exists(_DB_PATH):
        return {"updated": "unknown", "eol": [], "vuln": []}
    with open(_DB_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def db_date() -> str:
    # PyYAML parses a bare ``2026-08-27`` as datetime.date; coerce to str.
    return str(_load().get("updated", "unknown"))


def _version_branch(version: str, branch: str) -> bool:
    """Does ``version`` belong to ``branch``? "7.4.33" ∈ "7.4", "16.20.0" ∈ "16"."""
    v = version.strip()
    return v == branch or v.startswith(branch + ".")


def check_eol(slug: str, version: Optional[str]) -> Optional[Advisory]:
    if not version:
        return None
    data = _load()
    today = date.today().isoformat()
    for entry in data.get("eol", []):
        if entry.get("slug") != slug:
            continue
        eol = entry.get("eol")
        if not eol:
            continue
        if _version_branch(version, str(entry.get("branch", ""))):
            if str(eol) <= today:
                note = entry.get("note") or f"EOL {eol}"
                return Advisory(status="eol", detail=note, cves=[])
    return None


def _vtuple(version: str) -> tuple[int, ...]:
    return tuple(int(x) if x.isdigit() else 0 for x in version.split("."))


def check_vuln(slug: str, version: Optional[str]) -> Optional[Advisory]:
    if not version:
        return None
    data = _load()
    for entry in data.get("vuln", []):
        if entry.get("slug") != slug:
            continue
        rx = re.compile(entry.get("regex", ""), re.I)
        m = rx.search(version)
        if not m:
            # version may already be clean "3.5.1"; try matching against it
            m = rx.search(slug + "-" + version)
            if not m:
                continue
        v = _vtuple(version)
        major = v[0] if v else 0
        min_secure = str(entry.get("min_secure", "0"))
        # Per-major override (Bootstrap 3.x vs 4.x).
        for rng in entry.get("ranges", []) or []:
            if int(rng.get("major", -1)) == major:
                min_secure = str(rng.get("min_secure", min_secure))
                break
        if v < _vtuple(min_secure):
            return Advisory(
                status="vulnerable",
                detail=f"vulnerable (< {min_secure})",
                cves=list(entry.get("cves", [])),
                min_secure=min_secure,
            )
    return None


def check(slug: str, version: Optional[str]) -> Optional[Advisory]:
    """Combine EOL + vuln checks; vuln takes precedence (more actionable)."""
    vuln = check_vuln(slug, version)
    if vuln:
        return vuln
    return check_eol(slug, version)


# ── Optional online refresh (endoflife.date) ─────────────────────────────────
# Best-effort, only when --online-eol is set. Maps our slugs to their products.
_EOL_PRODUCTS = {
    "php": "php",
    "nodejs": "nodejs",
    "nginx": "nginx",
    "python": "python",
    "drupal": "drupal",
    "joomla": "joomla",
    "rubyonrails": "rails",
}


def online_eol(slug: str, fetcher) -> Optional[str]:
    """Ask endoflife.date for the latest EOL info on a branch. May fail quietly."""
    product = _EOL_PRODUCTS.get(slug)
    if not product:
        return None
    try:
        resp = fetcher.get(f"https://endoflife.date/api/v1/products/{product}",
                           timeout=10)
    except Exception:
        return None
    if resp is None or resp.status_code >= 400:
        return None
    try:
        data = resp.json()
    except (ValueError, TypeError):
        return None
    # Returns a list of release cycles; we just summarise the newest EOL.
    cycles = data if isinstance(data, list) else data.get("cycles", [])
    future = [c for c in cycles if c.get("eol")]
    if future:
        newest = max(future, key=lambda c: c.get("eol", ""))
        return f"endoflife.date: {newest.get('cycle','?')} EOL {newest.get('eol')}"
    return None
