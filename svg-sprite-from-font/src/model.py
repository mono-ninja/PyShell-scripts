"""Data contract shared by every stage.

The single public contract is :class:`Symbol` — every stage produces or
consumes it. ``RawGlyph`` and ``FontMetrics`` are the internal shapes passed
between extraction (B2/B3) and geometry (B5); they live here so the stages can
import them without circular dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field

SVG_NS = "http://www.w3.org/2000/svg"


@dataclass
class Symbol:
    """One icon, ready to nest into the sprite document.

    ``id`` already includes the sprite prefix (e.g. ``icon-user``).
    ``body`` is a list of lxml elements placed inside ``<symbol>``.
    ``source`` is a human-readable provenance string: ``font:<family>#<cp>``.
    ``warnings`` carries non-fatal problems (unnamed glyph, empty outline, ...).
    ``meta`` keeps the structured provenance used by the catalog and the result
    table: codepoint, ligature, original CSS class, name source.
    """

    id: str
    view_box: str
    body: list
    source: str
    warnings: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)


@dataclass
class RawGlyph:
    """A glyph outline plus the font metrics needed to place it.

    ``codepoint`` is None for glyphs reached only through GSUB ligatures
    (Material Icons and descendants) — those have no cmap entry of their own.
    ``path_d`` is verbatim SVG path data in the font's coordinate system
    (Y-up, origin on the baseline). ``advance`` is the horizontal advance from
    hmtx (or horiz-adv-x for an SVG font).
    """

    codepoint: int | None
    glyph_name: str | None
    path_d: str
    advance: int
    ligature: str | None = None


@dataclass
class FontMetrics:
    """The four numbers that turn font coordinates into an SVG viewBox."""

    upem: int
    ascent: int
    descent: int
    family: str = ""

    @property
    def em_height(self) -> int:
        return self.ascent - self.descent
