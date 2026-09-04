#!/usr/bin/env python3
"""Download the upstream GPL-3.0 signature base into a cache OUTSIDE the repo.

Why a cache and not a commit: every live fork of the Wappalyzer base is GPL-3.0,
including the ones wearing an MIT badge. GPL-3.0's obligations turn on
*conveying*, not running, so a local tool that keeps the data in
``~/.cache/techstack/`` and never ships it is fine — committing it into the repo
would make the repo a derivative work, bloat git by ~3.7MB, and freeze the data
at commit time. This mirrors ``webanalyze -update``.

Source: ``enthec/webappanalyzer`` — the active community successor, ~7596
technologies. The schema is isomorphic to ours, so conversion is mostly
mechanical: ``headers``→``header``, ``scriptSrc``→``script``,
``css``→``stylesheet``, ``meta``→``meta``, ``cookies``→``cookie``,
``url``→``url_path``, ``dns``→``dns_cname``, ``js``→``js_global`` (render-only),
and the ``\\;version:\\1`` convention becomes ``version_group: 1``.

The curated ``techstack/tech.yaml`` always wins on slug collision — see
``signatures.load_registry``, which merges this generated file under the
curated one.

Run manually, not on every scan::

    python scripts/update_db.py

Output: ``~/.cache/techstack/tech.generated.yaml`` with ``updated`` and
``source``/``license`` metadata, shown in the report alongside the curated date.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import date
from urllib.request import Request, urlopen

try:
    import yaml
except ImportError:
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

RAW = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
CACHE_DIR = os.path.expanduser("~/.cache/techstack")
OUT_PATH = os.path.join(CACHE_DIR, "tech.generated.yaml")
LICENSE_NOTE = "GPL-3.0 — enthec/webappanalyzer (derived data, kept locally)"

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(name: str) -> str:
    s = _SLUG_RE.sub("-", name.lower().strip()).strip("-")
    return s or "unknown"


def _fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "techstack-update_db/0.1"})
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def _split_version(pattern: str) -> tuple[str, int | None]:
    """webappanalyzer writes ``\\;version:\\N`` inside the pattern. Split it off."""
    if "\\;version:" in pattern:
        rx, _, tail = pattern.partition("\\;version:")
        m = re.search(r"\\?(\d+)", tail)
        return rx, int(m.group(1)) if m else 1
    if ";version:" in pattern:
        rx, _, tail = pattern.partition(";version:")
        m = re.search(r"(\d+)", tail)
        return rx, int(m.group(1)) if m else 1
    return pattern, None


def _signal(where: str, pattern: str, *, name: str = "", expr: str = "",
            confidence: int = 50, requires_render: bool = False) -> dict | None:
    rx, vgroup = _split_version(pattern)
    rx = rx.strip()
    if not rx:
        return None
    sig = {"where": where, "pattern": rx, "confidence": confidence}
    if vgroup is not None:
        sig["version_group"] = vgroup
    if name:
        sig["name"] = name
    if expr:
        sig["expr"] = expr
    if requires_render:
        sig["requires"] = "render"
    return sig


def _convert_tech(name: str, raw: dict, cat_map: dict[int, str]) -> dict | None:
    slug = _slug(name)
    cats = []
    for c in raw.get("cats", []) or []:
        label = cat_map.get(int(c))
        cats.append(_slug(label) if label else f"cat-{c}")
    if not cats:
        return None

    signals: list[dict] = []

    def _add(sig):
        if sig:
            signals.append(sig)

    # headers: dict {name: pattern} or list of patterns (any header).
    headers = raw.get("headers")
    if isinstance(headers, dict):
        for hname, hpat in headers.items():
            if isinstance(hpat, list):
                for p in hpat:
                    _add(_signal("header", p, name=hname.lower(), confidence=60))
            else:
                _add(_signal("header", hpat, name=hname.lower(), confidence=60))
    elif isinstance(headers, list):
        for p in headers:
            _add(_signal("header", p, confidence=40))

    cookies = raw.get("cookies")
    if isinstance(cookies, dict):
        for cname, cpat in cookies.items():
            _add(_signal("cookie", cpat or ".", name=cname.lower(), confidence=50))
    elif isinstance(cookies, list):
        for c in cookies:
            _add(_signal("cookie", c or ".", name=_slug(c), confidence=40))

    meta = raw.get("meta")
    if isinstance(meta, dict):
        for mname, mpat in meta.items():
            _add(_signal("meta", mpat or ".", name=mname.lower(), confidence=60))

    for p in raw.get("html", []) or []:
        _add(_signal("html", p, confidence=50))
    for p in raw.get("scriptSrc", []) or []:
        _add(_signal("script", p, confidence=50))
    for p in raw.get("css", []) or []:
        _add(_signal("stylesheet", p, confidence=50))
    for p in raw.get("url", []) or []:
        _add(_signal("url_path", p, confidence=40))
    for p in raw.get("dns", []) or []:
        _add(_signal("url_path", p, confidence=30))

    js = raw.get("js")
    if isinstance(js, dict):
        for expr, jpat in js.items():
            _add(_signal("js_global", jpat, expr=expr, confidence=90, requires_render=True))

    if not signals:
        return None

    def _clean_refs(refs):
        out = []
        for r in refs or []:
            out.append(_slug(str(r).split("\\;")[0]))
        return out

    tech = {
        "slug": slug,
        "name": name,
        "categories": cats,
        "signals": signals,
        "implies": _clean_refs(raw.get("implies")),
        "excludes": _clean_refs(raw.get("excludes")),
    }
    if raw.get("cpe"):
        tech["cpe"] = raw["cpe"]
    if raw.get("website"):
        tech["website"] = raw["website"]
    return tech


def main() -> int:
    os.makedirs(CACHE_DIR, exist_ok=True)

    print("Fetching categories…")
    cat_map: dict[int, str] = {}
    try:
        cdata = json.loads(_fetch(f"{RAW}/categories.json"))
        if isinstance(cdata, dict):
            for cid, val in cdata.items():
                nm = val.get("name", str(cid)) if isinstance(val, dict) else str(val)
                cat_map[int(cid)] = nm
        elif isinstance(cdata, list):
            for val in cdata:
                cat_map[int(val["id"])] = val.get("name", str(val["id"]))
    except Exception as exc:
        print(f"  categories: {exc}", file=sys.stderr)
    print(f"  {len(cat_map)} categories")

    techs: list[dict] = []
    names = ["_"] + [chr(c) for c in range(ord("a"), ord("z") + 1)]
    for letter in names:
        url = f"{RAW}/technologies/{letter}.json"
        try:
            data = json.loads(_fetch(url))
        except Exception as exc:
            print(f"  {letter}.json: {exc}", file=sys.stderr)
            continue
        for name, raw in data.items():
            t = _convert_tech(name, raw, cat_map)
            if t:
                techs.append(t)
        print(f"  {letter}.json: {len(data)} entries")

    doc = {
        "version": 1,
        "updated": str(date.today()),
        "source": "enthec/webappanalyzer",
        "license": LICENSE_NOTE,
        "categories": [{"id": _slug(v), "label": v} for v in cat_map.values()],
        "technologies": techs,
    }
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        yaml.safe_dump(doc, fh, allow_unicode=True, sort_keys=False, width=1000)
    print(f"\nWrote {OUT_PATH}: {len(techs)} technologies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
