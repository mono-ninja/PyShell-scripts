"""A1 — Discover.

Glob ``*.svg`` under the source folder and return the paths in a deterministic
order. Deterministic ordering is what makes the sprite diffable in git, which
is what makes it trustworthy: the same folder rebuilt twice yields the same
sprite byte for byte, so a diff is a real change and not a shuffle.

The order is byte order of the path relative to the source folder (the plan's
requirement). For valid UTF-8 this coincides with code-point order, but sorting
on the encoded bytes keeps the contract literal and unaffected by locale.
"""
from __future__ import annotations

import os


def discover(src_dir: str) -> list[str]:
    """Return absolute paths of ``*.svg`` files under ``src_dir``.

    Non-recursive (the plan's surface has no ``--recursive`` flag). Hidden
    files (leading dot) are excluded — design tools drop ``.DS_Store`` and
    temp files next to the real icons. Sorted by relative path in byte order.
    """
    if not os.path.isdir(src_dir):
        return []

    rel_paths: list[str] = []
    for name in os.listdir(src_dir):
        if name.startswith("."):
            continue
        if not name.lower().endswith(".svg"):
            continue
        full = os.path.join(src_dir, name)
        if not os.path.isfile(full):
            continue
        rel_paths.append(name)

    rel_paths.sort(key=lambda p: p.encode("utf-8"))
    return [os.path.join(src_dir, name) for name in rel_paths]
