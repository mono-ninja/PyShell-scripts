"""B5 — geometry.

Font coordinates are Y-up with the origin on the baseline; SVG is Y-down from
the top-left. Each glyph is wrapped so the outline lands upright in the symbol:

    <symbol id="icon-user" viewBox="0 0 1000 1000" fill-rule="nonzero">
      <g transform="translate(0, 800) scale(1, -1)">
        <path d="…"/>
      </g>
    </symbol>

For ``--fit=advance`` (faithful) the viewBox is ``0 0 {advance} {upem}`` and the
translate is by ``ascent``. For ``--fit=bbox`` the viewBox is tightened to the
glyph's real bounding box (with optional padding) so the icon does not float in
a wide side-bearing.

``--flatten`` (default on) bakes the translate+scale into the path data via
``svgpathtools`` instead of shipping a wrapper ``<g>``. Smaller output, and it
prevents the transform interacting with CSS applied to the ``<use>``. Arcs —
which only appear in SVG fonts, since ``SVGPathPen`` emits quadratics for
``glyf`` — are converted to cubics first, because svgpathtools cannot
non-uniformly scale an ``Arc``.
"""
from __future__ import annotations

import re

import svgpathtools as spt
from lxml import etree

from .model import SVG_NS, FontMetrics, RawGlyph, Symbol
from .naming import NameBinding

_NUM_RE = re.compile(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")


def _fmt_num(s: str) -> str:
    try:
        v = float(s)
    except ValueError:
        return s
    if v == 0:
        v = 0.0
    r = round(v, 3)
    if r == int(r):
        return str(int(r))
    return f"{r:.3f}".rstrip("0").rstrip(".")


def _normalize_d(d: str) -> str:
    """Round transformed coordinates to 3 decimals and strip trailing zeros,
    so flattened output is small and byte-stable for golden-file tests."""
    return _NUM_RE.sub(lambda m: _fmt_num(m.group(0)), d)


def _font_bbox(path_d: str) -> tuple[float, float, float, float] | None:
    """Return (xmin, xmax, ymin, ymax) in font coordinates, or None for an
    empty outline."""
    if not path_d or not path_d.strip():
        return None
    try:
        p = spt.parse_path(path_d)
    except Exception:
        return None
    if not len(p):
        return None
    try:
        return p.bbox()  # (xmin, xmax, ymin, ymax)
    except Exception:
        return None


def _flipped_path_d(path_d: str, ascent: int) -> str:
    """Apply translate(0, ascent) scale(1, -1) to path data and return the
    re-serialized, normalized SVG path string."""
    p = spt.parse_path(path_d)
    # Arcs cannot be non-uniformly scaled; convert to cubics first. This is a
    # no-op for glyf outlines (SVGPathPen emits only M/L/Q/Z).
    p.approximate_arcs_with_cubics()
    p = p.scaled(1, -1, origin=0j).translated(complex(0, ascent))
    return _normalize_d(p.d())


def build_symbol(
    glyph: RawGlyph,
    metrics: FontMetrics,
    binding: NameBinding,
    *,
    flatten: bool = True,
    fit: str = "advance",
    fit_padding: int = 0,
) -> Symbol:
    """Turn one raw glyph into a :class:`Symbol` ready for the sprite."""
    warnings: list[str] = []
    upem = metrics.upem
    ascent = metrics.ascent
    advance = glyph.advance if glyph.advance > 0 else upem
    if glyph.advance <= 0:
        warnings.append("zero advance width; used units-per-em instead")

    path_d = glyph.path_d or ""
    bbox = _font_bbox(path_d)

    if fit == "bbox" and bbox is not None:
        fxmin, fxmax, fymin, fymax = bbox
        # Flip Y into SVG space: y' = ascent - y.
        sx_min, sx_max = fxmin, fxmax
        sy_min, sy_max = ascent - fymax, ascent - fymin
        pad = fit_padding
        vb_x = sx_min - pad
        vb_y = sy_min - pad
        vb_w = (sx_max - sx_min) + 2 * pad
        vb_h = (sy_max - sy_min) + 2 * pad
        view_box = f"{_fmt_num(str(vb_x))} {_fmt_num(str(vb_y))} {_fmt_num(str(vb_w))} {_fmt_num(str(vb_h))}"
    else:
        if fit == "bbox" and bbox is None:
            warnings.append("empty outline; bbox fit fell back to advance")
        view_box = f"0 0 {advance} {upem}"

    body: list = []
    if not path_d.strip():
        warnings.append("empty outline (space glyph)")
    else:
        if flatten:
            try:
                d = _flipped_path_d(path_d, ascent)
            except Exception as e:
                warnings.append(f"flatten failed ({e}); kept wrapper transform")
                d = None
            if d is not None:
                path_el = etree.Element(f"{{{SVG_NS}}}path")
                path_el.set("d", d)
                body.append(path_el)
        if not body:  # not flattened, or flatten failed
            g = etree.Element(f"{{{SVG_NS}}}g")
            g.set("transform", f"translate(0, {ascent}) scale(1, -1)")
            path_el = etree.SubElement(g, f"{{{SVG_NS}}}path")
            path_el.set("d", path_d)
            body.append(g)

    sprite_id = binding.sprite_id

    if binding.unnamed:
        warnings.append("unnamed glyph (fallback id)")

    cp = glyph.codepoint
    source = f"font:{metrics.family}#{f'U+{cp:04X}' if cp is not None else (glyph.ligature or glyph.glyph_name)}"

    meta = {
        "codepoint": f"U+{cp:04X}" if cp is not None else None,
        "ligature": glyph.ligature,
        "class": binding.class_name,
        "aliases": binding.aliases,
        "name_source": binding.source,
        "glyph_name": glyph.glyph_name,
    }
    return Symbol(
        id=sprite_id, view_box=view_box, body=body, source=source,
        warnings=warnings, meta=meta,
    )
