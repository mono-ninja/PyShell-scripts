"""Emit sprite.svg.

Serializes the assembled sprite tree to a stable string — one ``<symbol>``
per line so ``git diff`` on the sprite is readable (changing one icon touches
one line group, not a reflowed block) — and writes it to ``--out`` and, when
running under PyShell, to ``PYSHELL_OUTPUT_DIR`` so the artifact cards can
show it.
"""
from __future__ import annotations

import os

from lxml import etree


def output_dir() -> str | None:
    """PyShell's scratch directory for artifacts, or ``None`` from a terminal."""
    return os.environ.get("PYSHELL_OUTPUT_DIR")


def write_artifact(out_dir: str, name: str, data: str | bytes) -> str:
    """Write ``name`` to ``out_dir`` and mirror it to PYSHELL_OUTPUT_DIR when
    that is set and distinct. Returns the primary path written."""
    binary = isinstance(data, bytes)
    primary = os.path.join(out_dir, name)
    os.makedirs(out_dir, exist_ok=True)
    with open(primary, "wb" if binary else "w", encoding=None if binary else "utf-8") as fh:
        fh.write(data)

    psd = output_dir()
    if psd and os.path.abspath(psd) != os.path.abspath(out_dir):
        os.makedirs(psd, exist_ok=True)
        with open(os.path.join(psd, name), "wb" if binary else "w",
                  encoding=None if binary else "utf-8") as fh:
            fh.write(data)
    return primary


def serialize_sprite(root) -> str:
    """Deterministic serialization: one symbol per line, no XML declaration."""
    s = etree.tostring(root, encoding="unicode", pretty_print=False)
    # Insert a newline before each <symbol> and before </svg> so each symbol
    # sits on its own line group. Safe: <symbol> cannot nest, and text content
    # is escaped so the literal substring never appears in a body.
    s = s.replace("><symbol", ">\n<symbol")
    s = s.replace("</symbol></svg>", "</symbol>\n</svg>")
    if not s.endswith("\n"):
        s += "\n"
    return s


def emit_sprite(root, out_dir: str) -> str:
    return write_artifact(out_dir, "sprite.svg", serialize_sprite(root))
