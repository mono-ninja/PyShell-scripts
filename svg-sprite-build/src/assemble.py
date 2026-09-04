"""A7 — Assemble.

Builds the sprite document: one outer ``<svg>`` (hidden by the zero-size
technique, never ``display:none`` — the latter breaks gradient and filter
references in some engines) containing one ``<symbol>`` per icon, each
carrying the root presentation attributes A4 preserved and the (already
deduped/optimized) body as its children.

The returned root element is serialized by ``emit_sprite``; this stage only
builds the tree so it stays free of I/O and PyShell concerns.
"""
from __future__ import annotations

from lxml import etree

from .model import Symbol
from .parse import SVG_NS, XLINK_NS

_HIDE_STYLE = "position:absolute;width:0;height:0;overflow:hidden"


def assemble(symbols: list[Symbol]) -> etree._Element:
    root = etree.Element(
        f"{{{SVG_NS}}}svg",
        nsmap={None: SVG_NS, "xlink": XLINK_NS},
    )
    root.set("aria-hidden", "true")
    root.set("style", _HIDE_STYLE)

    for sym in symbols:
        if not sym.view_box:
            continue
        sym_el = etree.SubElement(root, f"{{{SVG_NS}}}symbol")
        sym_el.set("id", sym.id)
        sym_el.set("viewBox", sym.view_box)
        for key, val in sym.meta.get("root_attrs", {}).items():
            sym_el.set(key, val)
        if sym.meta.get("a11y_title"):
            title = etree.SubElement(sym_el, f"{{{SVG_NS}}}title")
            title.text = sym.meta["a11y_title"]
        for child in sym.body:
            sym_el.append(child)

    return root
