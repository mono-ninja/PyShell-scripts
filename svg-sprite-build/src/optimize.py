"""A5 — Optimize (deliberately conservative).

This is not SVGO. Path merging, transform collapsing and shape-to-path
conversion stay out of scope permanently. What this stage does is the cheap,
safe cleanup that never changes rendering:

* drop comments and ``<metadata>``;
* drop unreferenced ``<defs>`` children (after A6 made references stable);
* drop empty ``<g>`` elements (bottom-up, so cascading empties collapse);
* drop attributes equal to their SVG default — but only when no ancestor sets
  the same property, so an explicit ``stroke="none"`` overriding an inherited
  ``stroke="red"`` is kept (the bug a naive "strip defaults" would introduce);
* round ``d`` / ``points`` numerics to a configurable precision.

If real compression matters, shell out to ``npx svgo`` as a pre-pass — that is
what ``--svgo`` wires up in ``main.py``, not a reimplementation here.
"""
from __future__ import annotations

import re

from lxml import etree

from .model import Symbol

# Default attribute values. A value present here is a candidate for removal
# (subject to the inheritance check below).
_DEFAULTS: dict[str, set[str]] = {
    "fill": {"black", "#000", "#000000"},
    "stroke": {"none"},
    "stroke-width": {"1", "1.0", "1px"},
    "stroke-linecap": {"butt"},
    "stroke-linejoin": {"miter"},
    "fill-rule": {"nonzero"},
    "clip-rule": {"nonzero"},
    "opacity": {"1", "1.0"},
    "fill-opacity": {"1", "1.0"},
    "stroke-opacity": {"1", "1.0"},
}

_NUM_RE = re.compile(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")
_URL_REF_RE = re.compile(r"url\(\s*['\"]?#([^'\"\s)]+)['\"]?\s*\)")
_ANIM_TAGS = {"animate", "animateMotion", "animateTransform", "set", "animateColor"}


def _local(tag) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _iter_elements(body) -> list:
    out = []
    for top in body:
        if not isinstance(top.tag, str):
            continue
        out.extend(el for el in top.iter() if isinstance(el.tag, str))
    return out


def _drop_comments_and_metadata(body) -> None:
    to_remove = []
    for top in body:
        for el in top.iter():
            if el.tag is etree.Comment or _local(el.tag) == "metadata":
                to_remove.append(el)
    for el in to_remove:
        parent = el.getparent()
        if parent is not None:
            parent.remove(el)
        elif el in body:
            body.remove(el)


def _referenced_ids(body, root_attrs: dict) -> set[str]:
    refs: set[str] = set()
    values: list[str] = []
    for el in _iter_elements(body):
        tag = _local(el.tag)
        for attr, val in el.attrib.items():
            values.append(val)
            if tag in _ANIM_TAGS and attr in ("begin", "end"):
                for token in val.split(";"):
                    m = re.match(r"^([A-Za-z_][\w-]*)\.", token.strip())
                    if m:
                        refs.add(m.group(1))
    values.extend(v for v in root_attrs.values() if v)
    for v in values:
        if not v:
            continue
        if "url(" in v:
            refs.update(_URL_REF_RE.findall(v))
        elif "#" in v:
            refs.add(v.rpartition("#")[2])
    return refs


def _drop_unreferenced_defs(body, root_attrs: dict) -> None:
    refs = _referenced_ids(body, root_attrs)
    for defs in [el for el in _iter_elements(body) if _local(el.tag) == "defs"]:
        for child in list(defs):
            if not isinstance(child.tag, str):
                defs.remove(child)
                continue
            cid = child.get("id")
            if cid and cid not in refs:
                defs.remove(child)
        if len(defs) == 0:
            parent = defs.getparent()
            if parent is not None:
                parent.remove(defs)
            elif defs in body:
                body.remove(defs)


def _strip_empty_groups(container, is_body: bool) -> None:
    """Remove ``<g>`` with no element children, bottom-up."""
    for child in list(container):
        if isinstance(child.tag, str):
            _strip_empty_groups(child, False)
    for child in list(container):
        if not isinstance(child.tag, str):
            continue
        if _local(child.tag) == "g" and not any(isinstance(c.tag, str) for c in child):
            container.remove(child)


def _is_default(attr: str, val: str) -> bool:
    return val.strip() in _DEFAULTS.get(attr, ())


def _strip_defaults(el, inherited: dict) -> None:
    """Remove default-valued attrs that no ancestor sets (so they are not
    overriding an inherited non-default value)."""
    for attr in [a for a in list(el.attrib) if a in _DEFAULTS and _is_default(a, el.get(a, ""))]:
        if attr not in inherited:
            del el.attrib[attr]
    child_inherited = dict(inherited)
    for attr in el.attrib:
        if attr in _DEFAULTS:
            child_inherited[attr] = el.attrib[attr]
    for child in el:
        if isinstance(child.tag, str):
            _strip_defaults(child, child_inherited)


def _round_path_numerics(body, precision: int) -> None:
    def fmt(m: re.Match) -> str:
        n = float(m.group())
        s = f"{n:.{precision}f}".rstrip("0").rstrip(".")
        if s in ("", "-", "-0"):
            return "0"
        return s

    for el in _iter_elements(body):
        for attr in ("d", "points"):
            val = el.get(attr)
            if val:
                el.set(attr, _NUM_RE.sub(fmt, val))


def optimize(sym: Symbol, precision: int) -> None:
    body = sym.body
    root_attrs = sym.meta.get("root_attrs", {})

    _drop_comments_and_metadata(body)
    _drop_unreferenced_defs(body, root_attrs)
    _strip_empty_groups(body, is_body=True)
    for top in body:
        if isinstance(top.tag, str):
            inherited = {k: v for k, v in root_attrs.items() if k in _DEFAULTS}
            _strip_defaults(top, inherited)
    if precision >= 0:
        _round_path_numerics(body, precision)
