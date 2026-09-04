"""B2 — SVG-font path.

Parses the legacy ``<font><glyph>`` format (removed from browsers, but old
IcoMoon bundles still ship it). The outlines are already SVG paths, so no
coordinate conversion happens here — the ``d`` attribute is taken verbatim.
"""
from __future__ import annotations

from lxml import etree

from .model import FontMetrics, RawGlyph

_SVG_NS = "http://www.w3.org/2000/svg"


def _local(tag: str) -> str:
    return etree.QName(tag).localname if isinstance(tag, str) else ""


def _int_attr(elem, name: str, default: int) -> int:
    v = elem.get(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def _decode_unicode(attr: str | None) -> int | None:
    """Decode a glyph's ``unicode`` attribute into a codepoint.

    IcoMoon writes ``&#xe900;`` (a numeric entity). Some authors write the
    literal character. Both are handled.
    """
    if not attr:
        return None
    # lxml already resolves numeric entities, so attr may already be the
    # decoded character (e.g. "\ue900"). An explicit XML entity written by
    # hand as text would arrive literally as "&#xe900;" — handle that too.
    if attr.startswith("&#") and attr.endswith(";"):
        inner = attr[2:-1]
        try:
            base = 16 if inner.lower().startswith("x") else 10
            inner = inner[1:] if base == 16 else inner
            return int(inner, base)
        except ValueError:
            return None
    if len(attr) == 1:
        return ord(attr)
    # A single surrogate pair or multi-char sequence: take the first codepoint.
    return ord(attr[0]) if attr else None


class SVGFontError(Exception):
    pass


def parse_svg_font(path: str) -> tuple[FontMetrics, list[RawGlyph]]:
    """Read an SVG font file into metrics + raw glyphs.

    ``<missing-glyph>`` is skipped. Glyphs without a ``d`` (spaces) are kept
    so the codepoint map stays complete, but with an empty path.
    """
    parser = etree.XMLParser(recover=True, resolve_entities=True)
    tree = etree.parse(path, parser)
    root = tree.getroot()

    font = root.find(f".//{{{_SVG_NS}}}font")
    if font is None:
        font = root.find(".//font")
    if font is None:
        raise SVGFontError("No <font> element found.")

    font_advance = _int_attr(font, "horiz-adv-x", 0)

    face = font.find(f"{{{_SVG_NS}}}font-face")
    if face is None:
        face = font.find("font-face")
    if face is None:
        raise SVGFontError("No <font-face> element found.")

    upem = _int_attr(face, "units-per-em", 1000)
    ascent = _int_attr(face, "ascent", upem * 4 // 5)
    descent = _int_attr(face, "descent", -(upem - ascent))

    family = face.get("font-family", "") or font.get("id", "") or "svg-font"
    metrics = FontMetrics(upem=upem, ascent=ascent, descent=descent, family=family)

    glyphs: list[RawGlyph] = []
    for g in font:
        tag = _local(g.tag)
        if tag != "glyph":
            continue
        cp = _decode_unicode(g.get("unicode"))
        name = g.get("glyph-name") or g.get("name")
        d = g.get("d", "") or ""
        advance = _int_attr(g, "horiz-adv-x", font_advance or upem)
        glyphs.append(RawGlyph(codepoint=cp, glyph_name=name, path_d=d, advance=advance))

    return metrics, glyphs
