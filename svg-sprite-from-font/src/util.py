"""Shared output helpers: atomic writes and artifact mirroring.

Every emitter writes its file atomically (write ``.tmp`` then ``os.replace``)
so a partial run never leaves a half-written artifact. The runner also copies
each artifact into ``PYSHELL_OUTPUT_DIR`` so the PyShell UI's artifact cards
can show it regardless of where the operator's ``--out`` points.
"""
from __future__ import annotations

import os
import shutil


def atomic_write(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically (tmp + rename)."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def atomic_write_text(path: str, text: str) -> None:
    atomic_write(path, text.encode("utf-8"))


def copy_to_output_dir(src: str, output_dir: str | None) -> str | None:
    """Copy ``src`` into ``output_dir`` (the PyShell artifact dir).

    Returns the destination path, or None if ``output_dir`` is unset or the
    source is already inside it. Errors are swallowed — the primary file in
    ``--out`` is what matters; the mirror is best-effort.
    """
    if not output_dir:
        return None
    if not os.path.isfile(src):
        return None
    out = os.path.abspath(output_dir)
    src_abs = os.path.abspath(src)
    if os.path.dirname(src_abs) == out:
        return None
    try:
        os.makedirs(out, exist_ok=True)
        dst = os.path.join(out, os.path.basename(src))
        shutil.copyfile(src_abs, dst)
        return dst
    except OSError:
        return None
