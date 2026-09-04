"""B7 — write sprite.svg (atomic)."""
from __future__ import annotations

from lxml import etree

from .util import atomic_write


def emit_sprite(out_path: str, sprite_root: etree._Element) -> str:
    """Serialize and atomically write the sprite. Returns the written path."""
    data = etree.tostring(
        sprite_root, xml_declaration=True, encoding="UTF-8", pretty_print=False
    )
    atomic_write(out_path, data)
    return out_path
