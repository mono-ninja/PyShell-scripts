"""B3 — binary-font path, and B0 — the licence gate.

Extracts outlines with fontTools. ``SVGPathPen`` emits quadratic ``Q`` commands
for ``glyf`` outlines; that is valid SVG and is left as-is. Contour direction
differs between ``glyf`` (outer clockwise) and CFF (outer counter-clockwise),
but nonzero winding handles both — :mod:`geometry` sets ``fill-rule="nonzero"``
explicitly. Composite glyphs are resolved by ``getGlyphSet()`` automatically.

fontTools' glyph order already resolves ``post``-table names (version 2.0), so
the glyph name carried on each :class:`RawGlyph` *is* the post name. For
``post`` version 3.0 fonts (no names) it is ``glyphNN`` — useless, which is why
B4 falls back to the CSS file or ligatures.

Colour fonts (``COLR``/``CPAL``) and ``SVG `` table fonts are detected and
refused with a clear message rather than half-supported.

B0 lives here too: the ``name`` table copyright and licence entries are read
and classified. The licence text is always returned so the runner can print it
as a status event; ``restrictive`` is True only when a restrictive licence is
declared, which is what gates output without ``--i-have-the-rights``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

from .model import FontMetrics, RawGlyph

# OpenType name-table IDs we care about.
NAME_COPYRIGHT = 0
NAME_FAMILY = 1
NAME_FULL = 4
NAME_LICENSE = 13
NAME_LICENSE_URL = 14

# Substitution lookup types.
_LIGATURE_SUBST = 4
_EXTENSION_SUBST = 7

# Licence classification markers. Permissive markers win: a copyright line may
# say "All rights reserved" even on an OFL font, so the licence field (nameID
# 13) is checked for permissive markers first.
_PERMISSIVE = (
    "open font license", "ofl", "sil open font", "apache", " mit ", "bsd",
    "public domain", "cc0", "unicode license", "ipa license",
)
_RESTRICTIVE = (
    "all rights reserved", "proprietary", "may not be redistributed",
    "may not redistribute", "cannot be redistributed", "do not redistribute",
    "no redistribution", "commercial license", "commercial use requires",
    "font awesome pro", "linearicons", "this font is not free",
    "for personal use only", "purchase", "do not modify",
)


@dataclass
class LicenceInfo:
    copyright: str = ""
    family: str = ""
    full_name: str = ""
    license: str = ""
    license_url: str = ""
    restrictive: bool = False
    classified: str = "unknown"  # "permissive" | "restrictive" | "unknown"

    def summary(self) -> str:
        parts = []
        if self.full_name:
            parts.append(self.full_name)
        if self.copyright:
            parts.append(f"© {self.copyright}")
        if self.license:
            parts.append(self.license)
        if self.license_url:
            parts.append(self.license_url)
        return " — ".join(parts)


@dataclass
class BinaryFont:
    metrics: FontMetrics
    glyphs: list[RawGlyph] = field(default_factory=list)
    # (ligature_string, glyph_name) for GSUB-reached icons.
    ligatures: list[tuple[str, str]] = field(default_factory=list)
    licence: LicenceInfo = field(default_factory=LicenceInfo)


class BinaryFontError(Exception):
    pass


def read_licence(font: TTFont) -> LicenceInfo:
    """Pull the copyright/family/licence strings out of the ``name`` table."""
    info = LicenceInfo()
    if "name" not in font:
        return info
    # Prefer Windows (platformID 3) English entries; fall back to any.
    best: dict[int, str] = {}
    for rec in font["name"].names:
        nid = rec.nameID
        try:
            val = rec.toUnicode()
        except Exception:
            continue
        if not val:
            continue
        pref = rec.platformID == 3 and rec.langID in (0x0409, 0x0C09)
        if nid not in best or pref:
            best[nid] = val
    info.copyright = best.get(NAME_COPYRIGHT, "")
    info.family = best.get(NAME_FAMILY, "")
    info.full_name = best.get(NAME_FULL, "")
    info.license = best.get(NAME_LICENSE, "")
    info.license_url = best.get(NAME_LICENSE_URL, "")
    _classify(info)
    return info


def _classify(info: LicenceInfo) -> None:
    hay = f"{info.license} {info.copyright} {info.license_url}".lower()
    if any(m in hay for m in _PERMISSIVE):
        info.classified = "permissive"
        info.restrictive = False
        return
    if any(m in hay for m in _RESTRICTIVE):
        info.classified = "restrictive"
        info.restrictive = True
        return
    info.classified = "unknown"
    info.restrictive = False


def extract_binary(path: str) -> BinaryFont:
    """Open a TTF/OTF/WOFF/WOFF2 and pull out metrics, outlines and names."""
    try:
        font = TTFont(path, lazy=False)
    except Exception as e:
        raise BinaryFontError(f"fontTools could not open {path}: {e}") from e

    _refuse_unsupported(font)

    head = font["head"]
    upem = head.unitsPerEm
    if "OS/2" in font:
        ascent = font["OS/2"].sTypoAscender or font["hhea"].ascent
        descent = font["OS/2"].sTypoDescender or font["hhea"].descent
    else:
        ascent = font["hhea"].ascent
        descent = font["hhea"].descent

    licence = read_licence(font)
    metrics = FontMetrics(upem=upem, ascent=ascent, descent=descent, family=licence.family)

    glyph_set = font.getGlyphSet()
    cmap = font.getBestCmap() or {}  # {codepoint: glyph_name}
    hmtx = font["hmtx"]

    # Reverse cmap for decoding GSUB ligature components back to characters.
    reverse_cmap: dict[str, str] = {}
    for cp, gn in cmap.items():
        reverse_cmap.setdefault(gn, chr(cp))

    seen_glyph_names: set[str] = set()
    glyphs: list[RawGlyph] = []

    # 1) cmap-reachable glyphs.
    for cp in sorted(cmap):
        gn = cmap[cp]
        if gn in seen_glyph_names:
            continue
        seen_glyph_names.add(gn)
        d, advance = _draw(glyph_set, hmtx, gn)
        glyphs.append(RawGlyph(
            codepoint=cp, glyph_name=gn, path_d=d, advance=advance,
        ))

    # 2) GSUB ligature-reached glyphs (Material Icons & descendants).
    ligatures = _walk_ligatures(font, reverse_cmap)
    for lig_str, gn in ligatures:
        if gn in seen_glyph_names:
            # Already extracted via cmap — just attach the ligature label.
            for g in glyphs:
                if g.glyph_name == gn:
                    g.ligature = lig_str
                    break
            continue
        seen_glyph_names.add(gn)
        d, advance = _draw(glyph_set, hmtx, gn)
        glyphs.append(RawGlyph(
            codepoint=None, glyph_name=gn, path_d=d, advance=advance,
            ligature=lig_str,
        ))

    return BinaryFont(metrics=metrics, glyphs=glyphs, ligatures=ligatures, licence=licence)


def _refuse_unsupported(font: TTFont) -> None:
    if "COLR" in font and "CPAL" in font:
        raise BinaryFontError(
            "This is a COLR/CPAL colour font. svg-sprite-from-font does not "
            "support colour fonts — extract the outlines with a tool that "
            "understands COLRv0/v1 instead."
        )
    if "SVG " in font:
        raise BinaryFontError(
            "This font has an 'SVG ' table (SVG-in-OpenType). Colour SVG "
            "tables are not supported; only monochrome outlines are."
        )


def _draw(glyph_set, hmtx, glyph_name: str) -> tuple[str, int]:
    """Return (path_d, advance) for one glyph. Empty path is fine for spaces."""
    pen = SVGPathPen(glyph_set)
    try:
        glyph_set[glyph_name].draw(pen)
    except KeyError:
        return "", 0
    d = pen.getCommands() or ""
    try:
        advance = int(hmtx[glyph_name][0])
    except KeyError:
        advance = 0
    return d, advance


def _walk_ligatures(font: TTFont, reverse_cmap: dict[str, str]) -> list[tuple[str, str]]:
    """Reconstruct ``"arrow"``-style ligatures from the ``GSUB`` table.

    Returns a list of ``(ligature_string, ligature_glyph_name)``. A ligature is
    only kept when every component glyph decodes to a character through the
    reverse cmap — chained lookups that touch non-cmap glyphs are skipped, which
    is the right thing for icon fonts (they map plain ASCII letters).
    """
    out: list[tuple[str, str]] = []
    if "GSUB" not in font:
        return out
    try:
        gsub = font["GSUB"].table
        lookups = gsub.LookupList.Lookup
    except Exception:
        return out

    def visit(lookup) -> None:
        for st in lookup.SubTable:
            sub = st
            # Unwrap extension substitutions (lookup type 7).
            while getattr(sub, "LookupType", None) == _EXTENSION_SUBST and sub.SubTable:
                sub = sub.SubTable[0]
            if not hasattr(sub, "ligatures"):
                continue
            for first, ligs in sub.ligatures.items():
                for lig in ligs:
                    components = [first, *lig.Component]
                    chars: list[str] = []
                    ok = True
                    for comp in components:
                        ch = reverse_cmap.get(comp)
                        if ch is None:
                            ok = False
                            break
                        chars.append(ch)
                    if ok and lig.LigGlyph:
                        out.append(("".join(chars), lig.LigGlyph))

    for lk in lookups:
        if lk.LookupType in (_LIGATURE_SUBST, _EXTENSION_SUBST):
            visit(lk)

    # De-duplicate, longest ligature first so "arrow" wins over a shorter
    # prefix if both map to the same glyph.
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for lig_str, gn in sorted(out, key=lambda x: -len(x[0])):
        key = (lig_str, gn)
        if key in seen:
            continue
        seen.add(key)
        unique.append((lig_str, gn))
    return unique
