"""Signature registry: load and compile ``tech.yaml`` once.

The base lives in YAML next to the module so updating it is a data edit, not a
code review. Regexes are
compiled once at startup — 150 technologies × 5 signals × 5 pages is ~3750
``re.search`` calls, and recompiling per page is not an option.

A signal that fails to compile is dropped with a warning rather than killing the
whole scan: one bad pattern must not blank out 149 good technologies.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is in requirements.txt
    yaml = None

_DB_PATH = os.path.join(os.path.dirname(__file__), "tech.yaml")
# Optional generated supplement: the GPL upstream base, kept in a cache OUTSIDE
# the repo. Curated tech.yaml wins on slug collision.
_GEN_DB_PATH = os.path.expanduser("~/.cache/techstack/tech.generated.yaml")

WHERE_VALUES = {
    "header", "cookie", "meta", "html", "script", "inline_script",
    "stylesheet", "url_path", "js_global",
}


@dataclass(frozen=True)
class Signal:
    where: str
    pattern: re.Pattern
    confidence: int
    version_group: Optional[int]
    name: Optional[str]      # header / cookie / meta key
    expr: Optional[str]      # js_global window path
    requires_render: bool


@dataclass(frozen=True)
class VersionHint:
    where: str
    pattern: re.Pattern
    kind: str


@dataclass(frozen=True)
class NegativeSignal:
    where: str
    pattern: re.Pattern
    name: Optional[str]


@dataclass(frozen=True)
class Technology:
    slug: str
    name: str
    categories: tuple[str, ...]
    website: str
    implies: tuple[str, ...]
    excludes: tuple[str, ...]
    cpe: str
    signals: tuple[Signal, ...]
    version_hints: tuple[VersionHint, ...]
    negatives: tuple[NegativeSignal, ...]


@dataclass(frozen=True)
class Category:
    id: str
    label: str
    order: int


def _compile(pattern: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pattern, re.I)
    except re.error as exc:
        from .pyshell_io import log
        log(f"techstack: dropping bad regex {pattern!r}: {exc}")
        return None


def _build_signal(raw: dict) -> Optional[Signal]:
    where = raw.get("where", "")
    if where not in WHERE_VALUES:
        return None
    rx = _compile(raw.get("pattern", ""))
    if rx is None:
        return None
    requires_render = raw.get("requires") == "render" or where == "js_global"
    return Signal(
        where=where,
        pattern=rx,
        confidence=int(raw.get("confidence", 50)),
        version_group=raw.get("version_group"),
        name=(raw.get("name") or "").lower() or None,
        expr=raw.get("expr"),
        requires_render=requires_render,
    )


def _build_tech(raw: dict) -> Optional[Technology]:
    slug = raw.get("slug")
    if not slug:
        return None
    signals = tuple(s for s in (_build_signal(x) for x in raw.get("signals", [])) if s)
    hints = tuple(
        VersionHint(where=h.get("where", ""), pattern=rx, kind=h.get("kind", ""))
        for h in raw.get("version_hints", [])
        if (rx := _compile(h.get("pattern", ""))) is not None
    )
    negatives = tuple(
        NegativeSignal(where=n.get("where", ""), pattern=rx, name=(n.get("name") or "").lower() or None)
        for n in raw.get("negative", [])
        if (rx := _compile(n.get("pattern", ""))) is not None
    )
    return Technology(
        slug=slug,
        name=raw.get("name", slug),
        categories=tuple(raw.get("categories", [])),
        website=raw.get("website", ""),
        implies=tuple(raw.get("implies", [])),
        excludes=tuple(raw.get("excludes", [])),
        cpe=raw.get("cpe", ""),
        signals=signals,
        version_hints=hints,
        negatives=negatives,
    )


@lru_cache(maxsize=1)
def load_registry() -> dict:
    """Compile ``tech.yaml`` and the optional generated supplement.

    The curated ``tech.yaml`` is authoritative. If ``~/.cache/techstack/
    tech.generated.yaml`` exists (produced by ``scripts/update_db.py``), its
    technologies are merged in — but only slugs absent from the curated set, so
    a curated signal is never overwritten by a lower-quality upstream one.
    """
    if yaml is None or not os.path.exists(_DB_PATH):
        return {"updated": "unknown", "categories": [], "technologies": [], "by_slug": {}}

    with open(_DB_PATH, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    cats = tuple(
        Category(id=c["id"], label=c.get("label", c["id"]), order=int(c.get("order", 999)))
        for c in data.get("categories", [])
    )
    techs = tuple(t for t in (_build_tech(x) for x in data.get("technologies", [])) if t)
    by_slug = {t.slug: t for t in techs}
    updated = data.get("updated", "unknown")
    gen_updated = None

    # Merge the generated supplement (curated wins).
    if os.path.exists(_GEN_DB_PATH):
        try:
            with open(_GEN_DB_PATH, "r", encoding="utf-8") as fh:
                gdata = yaml.safe_load(fh) or {}
        except Exception:
            gdata = {}
        gen_updated = gdata.get("updated")
        seen_cats = {c.id for c in cats}
        extra_cats = [
            Category(id=c["id"], label=c.get("label", c["id"]), order=int(c.get("order", 9999)))
            for c in gdata.get("categories", [])
            if c.get("id") and c["id"] not in seen_cats
        ]
        cats = cats + tuple(extra_cats)
        extra_techs = []
        for x in gdata.get("technologies", []):
            t = _build_tech(x)
            if t and t.slug not in by_slug:
                by_slug[t.slug] = t
                extra_techs.append(t)
        if extra_techs:
            techs = techs + tuple(extra_techs)

    return {
        "updated": updated,
        "generated_updated": str(gen_updated) if gen_updated else None,
        "categories": cats,
        "technologies": techs,
        "by_slug": by_slug,
    }


def db_date() -> str:
    # PyYAML parses a bare ``2026-08-27`` as datetime.date; coerce to str so it
    # never reaches json.dump (stack.json) as a non-serializable object.
    return str(load_registry().get("updated", "unknown"))


def generated_db_date() -> str | None:
    """Date of the optional generated supplement, or None if not installed."""
    return load_registry().get("generated_updated")


def categories() -> tuple[Category, ...]:
    return load_registry()["categories"]


def technologies() -> tuple[Technology, ...]:
    return load_registry()["technologies"]


def by_slug(slug: str) -> Optional[Technology]:
    return load_registry()["by_slug"].get(slug)


def category_label(cat_id: str) -> str:
    for c in categories():
        if c.id == cat_id:
            return c.label
    return cat_id
