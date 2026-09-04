"""A2 — Parse and validate, and A3 — Symbol naming.

Parsing uses ``lxml.etree`` with entity expansion disabled: a malicious or
merely broken file with a billion-laughs payload must not blow the process up,
and one bad designer export must not kill a rebuild of 300 icons. Malformed
files are rejected individually and logged; the rest of the batch continues.

Naming (A3) slugifies each filename into a stable symbol id. Collisions are a
hard error — ``arrow_left.svg`` and ``arrow-left.svg`` in the same folder both
slugify to ``arrow-left`` and the sprite cannot contain two symbols with the
same id, so the run is aborted naming both source paths rather than silently
dropping one.
"""
from __future__ import annotations

import os
import re

from lxml import etree

from .model import Symbol

# Entity expansion / external access off. ``huge_tree`` stays False (the
# default) so a pathological file cannot exhaust memory, and ``no_network``
# stops the parser from fetching external DTDs.
_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    huge_tree=False,
    recover=False,
    remove_blank_text=False,
)

SVG_NS = "http://www.w3.org/2000/svg"
XLINK_NS = "http://www.w3.org/1999/xlink"


class NamingCollision(Exception):
    """Two source files slugify to the same symbol id (A3). Hard error."""


def parse_file(path: str) -> Symbol | None:
    """Parse one ``.svg`` file into a ``Symbol``.

    Returns ``None`` and is silent on success; on failure returns a ``Symbol``
    holding only ``source`` and a ``warnings`` entry describing the problem, so
    the caller can report it without a second stat. A ``None`` return means
    "skip, nothing to say" — currently never used, but kept for callers that
    only want well-formed files.

    The parsed root ``<svg>`` element is stashed in ``meta['root']`` for the
    normalize stage to read attributes off of.
    """
    sym = Symbol(source=path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        root = etree.fromstring(data, parser=_PARSER)
    except (etree.XMLSyntaxError, OSError) as exc:
        sym.warnings.append(f"parse error: {exc}")
        return sym

    if not isinstance(root.tag, str) or not root.tag.endswith("}svg"):
        sym.warnings.append("not an <svg> document")
        return sym

    sym.meta["root"] = root
    sym.meta["byte_size"] = len(data)
    return sym


def slugify(stem: str) -> str:
    """Lowercase, collapse separators to ``-``, strip a leading ``icon-``.

    Anything outside ``[a-z0-9-]`` is removed by the collapse step, so the
    result is always a valid slug (possibly empty, which the caller treats as
    a collision/error surface).
    """
    s = stem.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    s = s.removeprefix("icon-")
    return s.strip("-")


def assign_ids(symbols: list[Symbol], prefix: str) -> None:
    """Give each symbol its final id (prefix included) and hard-fail on
    collisions.

    Mutates ``symbol.id`` in place. Raises :class:`NamingCollision` naming the
    colliding source paths if two files slugify to the same id.
    """
    seen: dict[str, str] = {}
    for sym in symbols:
        stem = os.path.splitext(os.path.basename(sym.source))[0]
        slug = slugify(stem)
        if not slug:
            sym.warnings.append("empty slug after slugify")
            slug = "_"

        sym.id = f"{prefix}{slug}"
        sym.meta["slug"] = slug

        if sym.id in seen:
            raise NamingCollision(
                f"naming collision: {sym.source!r} and {seen[sym.id]!r} "
                f"both produce symbol id {sym.id!r}"
            )
        seen[sym.id] = sym.source
