"""The one build pipeline, free of PyShell concerns.

``main.py`` (PyShell entry point) and ``src/watch.py`` (local dev watcher) both
call :func:`build` here, so the discover → parse → naming → normalize → dedupe
→ optimize → assemble → emit sequence exists exactly once in this project —
only the wrapper differs.

Progress is reported through optional callbacks so the PyShell wrapper can map
each phase onto its slice of the 0–100 bar while the watcher ignores it. A
:class:`~src.parse.NamingCollision` propagates to the caller; everything else
(a malformed SVG, an icon with no viewBox) is recorded as a warning and the
batch continues.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .assemble import assemble
from .dedupe import dedupe
from .discover import discover
from .emit_catalog import emit_catalog
from .emit_sprite import emit_sprite, serialize_sprite
from .emit_wordpress import emit_wordpress
from .normalize import normalize
from .optimize import optimize
from .parse import assign_ids, parse_file

# Phase keys reported through ``on_progress``. The PyShell wrapper maps each to
# its (name, lo, hi) slice of the 0–100 bar.
PHASE_KEYS = ("discover", "parse", "normalize", "dedupe", "optimize", "assemble")


@dataclass
class BuildResult:
    total: int = 0          # discovered .svg files
    kept: int = 0           # symbols that made it into the sprite
    warnings: int = 0       # total warning count across all symbols
    sprite_path: str = ""
    sprite_size: int = 0
    catalog_path: str | None = None
    wordpress_path: str | None = None
    rows: list = field(default_factory=list)  # [id, basename, warnings] per file


def build(
    src_dir: str,
    out_dir: str,
    *,
    prefix: str = "icon-",
    current_color: bool = False,
    a11y_titles: bool = False,
    precision: int = 3,
    catalog: bool = True,
    wordpress: bool = False,
    on_progress=None,
    on_status=None,
) -> BuildResult:
    """Run the full pipeline. Raises :class:`NamingCollision` on an id clash."""
    def prog(phase: str, done: int, total: int, detail: str = "") -> None:
        if on_progress is not None:
            on_progress(phase, done, total, detail)

    def stat(msg: str) -> None:
        if on_status is not None:
            on_status(msg)

    paths = discover(src_dir)
    if not paths:
        return BuildResult()

    prog("discover", 1, 1)
    stat(f"Found {len(paths)} .svg file(s)")

    # --- A2 parse ---------------------------------------------------------
    symbols = []
    for i, p in enumerate(paths, 1):
        symbols.append(parse_file(p))
        prog("parse", i, len(paths), os.path.basename(p))

    parseable = [s for s in symbols if s.meta.get("root") is not None]
    failed = len(symbols) - len(parseable)
    if failed:
        stat(f"{failed} file(s) failed to parse")

    # --- A3 naming --------------------------------------------------------
    assign_ids(parseable, prefix)  # raises NamingCollision on clash

    # --- A4 normalize -----------------------------------------------------
    kept: list = []
    n = len(parseable)
    if n == 0:
        prog("normalize", 1, 1)
    else:
        for i, sym in enumerate(parseable, 1):
            if normalize(sym, current_color, a11y_titles) is not None:
                kept.append(sym)
            prog("normalize", i, n, sym.id)

    # --- A6 dedupe --------------------------------------------------------
    n = len(kept)
    if n == 0:
        prog("dedupe", 1, 1)
    else:
        for i, sym in enumerate(kept, 1):
            dedupe(sym)
            prog("dedupe", i, n, sym.id)

    # --- A5 optimize ------------------------------------------------------
    if n == 0:
        prog("optimize", 1, 1)
    else:
        for i, sym in enumerate(kept, 1):
            optimize(sym, precision)
            prog("optimize", i, n, sym.id)

    # --- A7 assemble + emit ----------------------------------------------
    root = assemble(kept)
    sprite_svg = serialize_sprite(root)
    sprite_path = emit_sprite(root, out_dir)

    total_steps = 1 + (1 if catalog else 0) + (1 if wordpress else 0)
    step = 1
    prog("assemble", step, total_steps, "sprite.svg")

    catalog_path = None
    if catalog:
        catalog_path = emit_catalog(kept, sprite_svg, out_dir)
        step += 1
        prog("assemble", step, total_steps, "catalog.html")

    wordpress_path = None
    if wordpress:
        wordpress_path = emit_wordpress(sprite_svg, out_dir)
        step += 1
        prog("assemble", step, total_steps, "sprite.php")

    rows = [
        [
            sym.id or "—",
            os.path.basename(sym.source),
            "; ".join(sym.warnings) if sym.warnings else "",
        ]
        for sym in symbols
    ]
    try:
        sprite_size = os.path.getsize(sprite_path)
    except OSError:
        sprite_size = 0

    return BuildResult(
        total=len(symbols),
        kept=len(kept),
        warnings=sum(len(s.warnings) for s in symbols),
        sprite_path=sprite_path,
        sprite_size=sprite_size,
        catalog_path=catalog_path,
        wordpress_path=wordpress_path,
        rows=rows,
    )
