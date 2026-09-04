"""Version extraction and ranking — the harder half of detection.

Most technologies do not announce a version at all: 9 of 10 table rows stay
``unknown``, and that is a *visible state*, not an empty cell. ``unknown`` must
read as "version not determined", never as "version is fine".

Sources, most reliable first: js-global (render) > header > meta generator >
public file > filename > query param. The ``?ver=`` query parameter is a trap:
in WordPress the core rewrites it, so ``jquery.js?ver=6.4.3`` is the WP version,
not jQuery's. Such candidates are downgraded and flagged, never silently trusted.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

VERSION_SOURCES = {
    "js_global": "js-global",
    "header": "header",
    "meta": "meta-generator",
    "script": "filename",
    "stylesheet": "filename",
    "inline_script": "inline",
    "html": "html",
    "url_path": "url",
    "public": "public-file",
}

_VER_CLEAN = re.compile(r"\d[\w.\-]*")


@dataclass
class VersionCandidate:
    source: str                 # human-readable source label
    version: str
    reliability: int            # 0–100, higher = more trustworthy
    evidence: str
    ver_param_trap: Optional[str] = None   # set when version came from ?ver=


@dataclass
class VersionResult:
    version: Optional[str]
    source: str
    reliability: int
    evidence: str = ""
    note: str = ""

    @property
    def is_unknown(self) -> bool:
        return self.version is None

    def display(self) -> str:
        if self.is_unknown:
            return "unknown"
        return self.version


def _clean(raw: str) -> Optional[str]:
    m = _VER_CLEAN.search(raw or "")
    return m.group(0).rstrip(".-") if m else None


def pick_version(candidates: list[VersionCandidate]) -> VersionResult:
    """Choose the most trustworthy version, or return the explicit unknown state."""
    if not candidates:
        return VersionResult(version=None, source="unknown", reliability=0)

    real = [c for c in candidates if c.ver_param_trap is None]
    traps = [c for c in candidates if c.ver_param_trap is not None]

    def _key(c: VersionCandidate) -> tuple:
        v = _clean(c.version) or ""
        # higher reliability first, then a more specific (longer) version.
        return (-c.reliability, -len(v))

    if real:
        real.sort(key=_key)
        best = real[0]
        ver = _clean(best.version)
        return VersionResult(
            version=ver, source=best.source, reliability=best.reliability,
            evidence=best.evidence,
        )

    # Only ?ver= candidates: distrust, but still report with a warning.
    traps.sort(key=_key)
    best = traps[0]
    ver = _clean(best.version)
    return VersionResult(
        version=ver, source="query (?ver=)", reliability=best.reliability,
        evidence=best.evidence,
        note="?ver= in WordPress is usually the core version, not this library's",
    )


# ── Public-file probing (--probe-known-paths) ────────────────────────────────
# /composer.json, /CHANGELOG.txt, /readme.html — a high-reliability version
# source, but it is a probe — off by default.


def parse_public_file(path: str, body: str) -> Optional[VersionCandidate]:
    """Pull a version out of a fetched public file, if any."""
    name = path.rsplit("/", 1)[-1].lower()
    if name in ("package.json", "composer.json"):
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return None
        ver = data.get("version")
        if ver and isinstance(ver, str):
            return VersionCandidate(
                source="public-file", version=ver, reliability=85,
                evidence=f"{path}: version={ver}",
            )
        return None
    # readme.html (WordPress), CHANGELOG.txt, CHANGELOG.md — grep for a version.
    # "Версія" is deliberate input matching, not a report string: localized
    # WordPress installs label the row in Ukrainian, and this is a detector.
    m = re.search(r"(?:Version|Версія)\s*[:\-]?\s*(\d+\.\d+(?:\.\d+)?)", body, re.I)
    if m:
        return VersionCandidate(
            source="public-file", version=m.group(1), reliability=70,
            evidence=f"{path}: {m.group(0)}",
        )
    return None
