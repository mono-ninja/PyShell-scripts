"""Matcher: run compiled signatures against Evidence, accumulate confidence.

Unlike a binary matched / not-matched detector, every
signal carries a ``confidence`` and they combine as ``1 - Π(1 - cᵢ)``: one weak
signal (30%) stays under the threshold, two weak ones (~51%) cross it. The
evidence column records *what* matched, so a false positive is a visible
sillyness you can fix in tech.yaml, not a silent lie.

Detection runs per-page and aggregates — the same signal firing on five pages
counts once (no double-counting), but its evidence strings are collected from
all pages so the report can point at the checkout page, not just the homepage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .evidence import Evidence
from .signatures import Technology, Signal
from .versions import VersionCandidate, VERSION_SOURCES


def _trunc(s: str, n: int = 96) -> str:
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _match_signal(signal: Signal, ev: Evidence) -> list[tuple[str, Optional[str]]]:
    """Return ``[(evidence_str, version_or_None), ...]`` for this signal on this page."""
    out: list[tuple[str, Optional[str]]] = []
    w = signal.where

    def _ver(m: Optional[re.Match]) -> Optional[str]:
        if m and signal.version_group is not None:
            try:
                g = m.group(signal.version_group)
                if g:
                    return g
            except IndexError:
                pass
        return None

    if w == "header":
        val = ev.headers.get(signal.name, "")
        if val:
            m = signal.pattern.search(val)
            if m:
                out.append((f"{signal.name}: {_trunc(val)}", _ver(m)))
        return out

    if w == "cookie":
        if signal.name and signal.name in ev.cookies:
            out.append((f"cookie: {signal.name}", None))
        return out

    if w == "meta":
        val = ev.meta.get(signal.name, "")
        if val:
            m = signal.pattern.search(val)
            if m:
                out.append((f"<meta {signal.name}>: {_trunc(val)}", _ver(m)))
        return out

    if w == "html":
        m = signal.pattern.search(ev.html)
        if m:
            out.append((f"html: {_trunc(m.group(0))}", _ver(m)))
        return out

    if w == "script":
        for src in ev.scripts:
            m = signal.pattern.search(src)
            if m:
                out.append((f"script: {_trunc(src)}", _ver(m)))
        return out

    if w == "inline_script":
        blob = ev.inline_blob
        if blob:
            m = signal.pattern.search(blob)
            if m:
                out.append((f"inline: {_trunc(m.group(0))}", _ver(m)))
        return out

    if w == "stylesheet":
        for href in ev.stylesheets:
            m = signal.pattern.search(href)
            if m:
                out.append((f"css: {_trunc(href)}", _ver(m)))
        return out

    if w == "url_path":
        m = signal.pattern.search(ev.final_url or ev.url)
        if m:
            out.append((f"url: {_trunc(ev.final_url or ev.url)}", _ver(m)))
        return out

    if w == "js_global":
        val = ev.js_globals.get(signal.expr, "")
        if val:
            m = signal.pattern.search(val)
            if m:
                out.append((f"{signal.expr}: {_trunc(val)}", _ver(m)))
        return out

    return out


def _match_negative(where: str, pattern: re.Pattern, name: Optional[str], ev: Evidence) -> bool:
    w = where
    if w == "html":
        return bool(pattern.search(ev.html))
    if w == "script":
        return any(pattern.search(s) for s in ev.scripts)
    if w == "header":
        return bool(pattern.search(ev.headers.get(name, "")))
    if w == "meta":
        return bool(pattern.search(ev.meta.get(name, "")))
    if w == "inline_script":
        return bool(pattern.search(ev.inline_blob))
    if w == "stylesheet":
        return any(pattern.search(s) for s in ev.stylesheets)
    return False


@dataclass
class Detection:
    slug: str
    name: str
    categories: tuple[str, ...]
    confidence: float                 # 0–100
    derived: bool = False
    implied_by: Optional[str] = None  # slug of the source tech if derived
    evidence: list[str] = field(default_factory=list)
    version_candidates: list[VersionCandidate] = field(default_factory=list)
    cpe: str = ""
    website: str = ""
    note: str = ""


def detect_technology(
    tech: Technology, evidences: list[Evidence], rendered: bool
) -> Optional[Detection]:
    """Run all signals of one technology across all page evidences."""
    fired: list[tuple[Signal, list[str], Optional[str], Optional[str]]] = []
    for signal in tech.signals:
        if signal.requires_render and not rendered:
            continue
        ev_strs: list[str] = []
        version: Optional[str] = None
        version_estr: Optional[str] = None
        matched = False
        for ev in evidences:
            for estr, ver in _match_signal(signal, ev):
                matched = True
                ev_strs.append(estr)
                if ver and version is None:
                    version = ver
                    version_estr = estr
        if matched:
            fired.append((signal, ev_strs, version, version_estr))

    if not fired:
        return None

    # Negatives drop the technology outright.
    for neg in tech.negatives:
        for ev in evidences:
            if _match_negative(neg.where, neg.pattern, neg.name, ev):
                return None

    # Confidence: 1 - Π(1 - cᵢ/100), each distinct signal once.
    acc = 1.0
    for signal, _, _, _ in fired:
        acc *= (1.0 - signal.confidence / 100.0)
    confidence = round((1.0 - acc) * 100.0, 1)

    # Evidence strings (dedup, cap for the table).
    seen: set[str] = set()
    evidence: list[str] = []
    for _, ev_strs, _, _ in fired:
        for s in ev_strs:
            if s not in seen:
                seen.add(s)
                evidence.append(s)

    # Version candidates, ranked later by source reliability.
    candidates: list[VersionCandidate] = []
    for signal, _, version, ver_estr in fired:
        if not version or signal.version_group is None:
            continue
        source = VERSION_SOURCES.get(signal.where, "unknown")
        reliability = _reliability(signal.where)
        # ?ver= query-param trap: only flag if the matched script itself
        # carries ?ver=, not any unrelated script on the page.
        ver_param = None
        if signal.where == "script" and ver_estr and "?ver=" in ver_estr:
            ver_param = version
        candidates.append(VersionCandidate(
            source=source, version=version, reliability=reliability,
            evidence=(evidence[0] if evidence else ""), ver_param_trap=ver_param,
        ))

    return Detection(
        slug=tech.slug, name=tech.name, categories=tech.categories,
        confidence=confidence, evidence=evidence[:5],
        version_candidates=candidates, cpe=tech.cpe, website=tech.website,
    )


def _reliability(where: str) -> int:
    """Higher = more trustworthy. Used to rank version candidates."""
    return {
        "js_global": 90,
        "header": 80,
        "meta": 75,
        "inline_script": 55,
        "script": 50,       # filename — medium
        "stylesheet": 50,
        "html": 45,
        "url_path": 30,
    }.get(where, 20)
