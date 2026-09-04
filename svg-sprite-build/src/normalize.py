"""A4 — Normalize.

Turns a parsed ``<svg>`` root into the ``Symbol``'s ``view_box``, ``body`` and
carried ``root_attrs``. The single most common visible bug in naive sprite
builders is losing the root ``fill="none"`` of an outline icon set (Lucide,
Feather) and watching every icon go solid; carrying the root presentation
attributes onto the ``<symbol>`` is what prevents that here.

What this stage does, in order:

* synthesize ``viewBox`` from ``width``/``height`` when missing (never guess);
* carry ``fill``, ``stroke``, ``stroke-width``, ``stroke-linecap``,
  ``stroke-linejoin``, ``fill-rule`` from the source ``<svg>`` onto the symbol;
* strip ``width``/``height`` so CSS controls size;
* optionally substitute ``currentColor`` when exactly one non-``none`` colour
  is used (duotone icons are left untouched and flagged);
* strip ``xml:space``, editor namespaces (``sodipodi:``, ``inkscape:``,
  ``figma:``) and ``<title>``/``<desc>``.
"""
from __future__ import annotations

import copy
import re

from .model import Symbol

# Presentation attributes carried from the source <svg> onto the <symbol>.
ROOT_ATTRS = (
    "fill",
    "stroke",
    "stroke-width",
    "stroke-linecap",
    "stroke-linejoin",
    "fill-rule",
)

# Editor / authoring-tool namespaces whose attributes and elements are dropped.
EDITOR_NAMESPACES = (
    "http://sodipodi.sourceforge.net/DTD/sodipodi-0.0.dtd",
    "http://www.inkscape.org/namespaces/inkscape",
    "http://www.figma.com/figma",
)

_XML_SPACE = "http://www.w3.org/XML/1998/namespace"

_NUM_RE = re.compile(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")
_URL_RE = re.compile(r"url\(\s*[^)]*\s*\)")


def _fmt_num(n: float) -> str:
    s = f"{n:.4f}".rstrip("0").rstrip(".")
    return s if s else "0"


def _local(tag) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _strip_editor_namespace(root) -> None:
    """Remove elements and attributes in editor namespaces, plus xml:space."""
    editor_set = set(EDITOR_NAMESPACES)
    # Elements to drop (e.g. <sodipodi:namedview>). Collect first, then remove.
    to_drop = []
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        ns = el.tag.rsplit("}", 1)[0] if "}" in el.tag else ""
        if ns in editor_set:
            to_drop.append(el)
    for el in to_drop:
        parent = el.getparent()
        if parent is not None:
            parent.remove(el)

    # Attributes in editor namespaces, and xml:space, on every element.
    for el in root.iter():
        for attr in list(el.attrib):
            ns = attr.rsplit("}", 1)[0] if "}" in attr else ""
            if ns in editor_set or attr == f"{{{_XML_SPACE}}}space":
                del el.attrib[attr]


def _strip_title_desc(root) -> None:
    to_drop = []
    for el in root.iter():
        if _local(el.tag) in ("title", "desc"):
            to_drop.append(el)
    for el in to_drop:
        parent = el.getparent()
        if parent is not None:
            parent.remove(el)


def _resolve_viewbox(root, sym: Symbol) -> str | None:
    """Return a viewBox string, synthesizing from width/height if needed."""
    vb = root.get("viewBox")
    if vb:
        return vb.strip()

    w = root.get("width")
    h = root.get("height")
    if w is not None and h is not None:
        mw = _NUM_RE.search(w)
        mh = _NUM_RE.search(h)
        if mw and mh:
            return f"0 0 {_fmt_num(float(mw.group()))} {_fmt_num(float(mh.group()))}"

    sym.warnings.append("no viewBox and no width/height to synthesize it from")
    return None


def _collect_colors(root) -> set[str]:
    """Distinct non-none, non-currentColor, non-url paint values on fill/stroke."""
    colors: set[str] = set()
    for el in root.iter():
        for attr in ("fill", "stroke"):
            val = el.get(attr)
            if not val:
                continue
            v = val.strip()
            low = v.lower()
            if low in ("none", "currentcolor", "inherit"):
                continue
            if _URL_RE.search(v):
                continue
            colors.add(v)
    return colors


def _substitute_current_color(root, color: str) -> None:
    for el in root.iter():
        for attr in ("fill", "stroke"):
            if el.get(attr) and el.get(attr).strip() == color:
                el.set(attr, "currentColor")


def normalize(sym: Symbol, current_color: bool, a11y_titles: bool) -> Symbol | None:
    """Normalize in place. Returns ``sym`` to keep, or ``None`` to skip.

    ``None`` means the icon is unusable (no viewBox) and should not appear in
    the sprite; its warnings stay in the result table.
    """
    root = sym.meta.get("root")
    if root is None:
        return None

    _strip_editor_namespace(root)
    _strip_title_desc(root)

    view_box = _resolve_viewbox(root, sym)
    if view_box is None:
        return None
    sym.view_box = view_box

    # currentColor substitution happens on the live tree before we split it
    # into body + carried attrs, so both see the same decision.
    if current_color:
        colors = _collect_colors(root)
        if len(colors) == 1:
            color = next(iter(colors))
            _substitute_current_color(root, color)
            sym.meta["current_color_substituted"] = True
        elif len(colors) > 1:
            sym.warnings.append("multicolour: currentColor not substituted")

    # Carry root presentation attrs onto the <symbol>; they are read off the
    # root here (after currentColor may have rewritten fill/stroke) and applied
    # by assemble. They are not part of `body` (the inner children).
    carried = {a: root.get(a) for a in ROOT_ATTRS if root.get(a) is not None}
    sym.meta["root_attrs"] = carried

    # Strip width/height so CSS controls size. Other root-only concerns
    # (viewBox already captured) are irrelevant to body.
    for attr in ("width", "height"):
        if root.get(attr) is not None:
            del root.attrib[attr]

    # body = inner content, deep-copied so the pipeline owns it independently
    # of the throwaway root.
    sym.body = [copy.deepcopy(child) for child in root]

    if a11y_titles:
        sym.meta["a11y_title"] = sym.meta.get("slug", sym.id)

    # The root is no longer needed; drop the reference so stages after this
    # cannot accidentally read from it.
    sym.meta.pop("root", None)
    return sym
