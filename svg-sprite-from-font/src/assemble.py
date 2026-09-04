"""B7 — assemble symbols into the sprite document."""
from __future__ import annotations

from lxml import etree

from .model import SVG_NS, Symbol


def assemble_sprite(symbols: list[Symbol]) -> etree._Element:
    """Build the hidden ``<svg>`` root with one ``<symbol>`` per icon.

    The root is ``display: none`` and ``aria-hidden`` so the inline sprite does
    not paint itself; icons are referenced via ``<use href="#id">``.
    """
    root = etree.Element(f"{{{SVG_NS}}}svg", nsmap={None: SVG_NS})
    root.set("style", "display: none")
    root.set("aria-hidden", "true")
    for s in symbols:
        sym = etree.SubElement(root, f"{{{SVG_NS}}}symbol")
        sym.set("id", s.id)
        sym.set("viewBox", s.view_box)
        sym.set("fill-rule", "nonzero")
        for el in s.body:
            sym.append(el)
    return root


def serialize_sprite(root: etree._Element) -> bytes:
    """Serialize the sprite to compact UTF-8 bytes with an XML declaration."""
    return etree.tostring(
        root, xml_declaration=True, encoding="UTF-8", pretty_print=False
    )


def sprite_body_xml(root: etree._Element) -> str:
    """The inner ``<svg>...</svg>`` markup without an XML declaration, for
    inlining into HTML/PHP where ``<?xml?>`` is invalid."""
    return etree.tostring(root, encoding="unicode", pretty_print=False)
