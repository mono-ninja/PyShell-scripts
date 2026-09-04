"""B1 — input triage.

Sniffs the font file and decides which extraction path owns it. EOT is
rejected outright (fontTools cannot read it; ask for the TTF instead).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from lxml import etree

# Binary container signatures. WOFF and WOFF2 have a fixed magic; TTF/OTF
# share the ``true``/``typ1``/``OTTO``/``0x00010000`` headers — rather than
# decode those, we trust the extension for the open formats and let fontTools
# raise on anything malformed.
_WOFF_MAGIC = b"wOFF"
_WOFF2_MAGIC = b"wOF2"


@dataclass(frozen=True)
class TriageResult:
    kind: str          # "svg" | "binary"
    format: str        # "svg-font" | "ttf" | "otf" | "woff" | "woff2"
    note: str = ""


class TriageError(Exception):
    """Unreadable or unsupported input."""


def _ext(path: str) -> str:
    return os.path.splitext(path)[1].lower().lstrip(".")


def triage(path: str) -> TriageResult:
    """Classify ``path`` into an extraction path.

    Raises :class:`TriageError` for ``.eot`` and for an ``.svg`` that does not
    actually contain a ``<font>`` element (a plain SVG icon is not a font).
    """
    if not os.path.isfile(path):
        raise TriageError(f"File not found: {path}")

    ext = _ext(path)
    if ext == "eot":
        raise TriageError(
            "Embedded OpenType (.eot) is not supported. Convert it to TTF "
            "(strip the EOT header) or supply the original .ttf/.woff."
        )

    if ext == "svg":
        return _triage_svg(path)

    if ext in ("ttf", "otf", "woff", "woff2"):
        return _triage_binary(path, ext)

    # Unknown extension: try sniffing the magic bytes as a last resort.
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:4] == _WOFF2_MAGIC:
        return TriageResult("binary", "woff2", "detected by magic bytes")
    if head[:4] == _WOFF_MAGIC:
        return TriageResult("binary", "woff", "detected by magic bytes")
    raise TriageError(f"Unrecognized font extension: .{ext}")


def _triage_svg(path: str) -> TriageResult:
    try:
        # SVG fonts are XML; parse recoverably so a stray entity does not kill
        # the whole read, but we still need the tree to find <font>.
        parser = etree.XMLParser(recover=True, resolve_entities=False)
        tree = etree.parse(path, parser)
    except etree.XMLSyntaxError as e:
        raise TriageError(f"Could not parse SVG file: {e}") from e

    root = tree.getroot()
    # <font> may live at the root or under <svg><defs><font> (IcoMoon bundles).
    font = root.find(".//{http://www.w3.org/2000/svg}font")
    if font is None:
        font = root.find(".//font")
    if font is None:
        raise TriageError(
            "This SVG has no <font> element — it is not an SVG font. "
            "svg-sprite-from-font reads icon fonts, not individual SVG icons."
        )
    return TriageResult("svg", "svg-font")


def _triage_binary(path: str, ext: str) -> TriageResult:
    with open(path, "rb") as fh:
        head = fh.read(8)
    if ext == "woff2" and head[:4] != _WOFF2_MAGIC:
        raise TriageError("File has a .woff2 extension but the wrong magic bytes.")
    if ext == "woff" and head[:4] != _WOFF_MAGIC:
        raise TriageError("File has a .woff extension but the wrong magic bytes.")
    fmt = ext
    if ext in ("ttf", "otf"):
        # ``OTTO`` => CFF-based OpenType; anything else is treated as TrueType
        # glyf by fontTools. We keep the user-facing label but let fontTools be
        # the source of truth for the outline flavor.
        if head[:4] == b"OTTO":
            fmt = "otf"
        else:
            fmt = "ttf"
    return TriageResult("binary", fmt)
