#!/usr/bin/env python3
"""svg-sprite-build/main.py — bundle a folder of SVG icons into one symbol sprite.

PyShell entry point. It optionally runs an ``npx svgo`` pre-pass, then calls
the single pipeline in :mod:`src.build`, mapping its phase progress onto one
0–100 bar and emitting a result table at the end. The pipeline itself knows
nothing of PyShell.

Exit codes:

* ``0`` — sprite built (files skipped for bad parse / missing viewBox stay in
  the table as warnings; that is not a failure);
* ``1`` — no ``.svg`` files found;
* ``2`` — bad arguments, or a naming collision (A3, hard error — the sprite
  cannot hold two symbols with the same id).
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from src.build import build
from src.parse import NamingCollision


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


# A1–A7 mapped onto one 0–100 bar. Keys match src.build.PHASE_KEYS.
PHASES = {
    "discover": ("Discovering", 0, 5),
    "parse": ("Parsing", 5, 25),
    "normalize": ("Normalizing", 25, 45),
    "dedupe": ("Deduping", 45, 70),
    "optimize": ("Optimizing", 70, 85),
    "assemble": ("Assembling", 85, 100),
}


class Phase:
    """Maps a phase's 0..1 progress onto a slice of the 0–100 bar, emitting at
    most one event per whole percent."""

    def __init__(self, name: str, lo: float, hi: float):
        self.name = name
        self.lo = lo
        self.hi = hi
        self._last = -1

    def report(self, done: int, total: int, detail: str = "") -> None:
        frac = done / total if total else 1.0
        pct = int(self.lo + (self.hi - self.lo) * frac)
        if pct == self._last:
            return
        self._last = pct
        msg = f"{self.name} — {detail}" if detail else self.name
        emit({"type": "progress", "pct": pct, "message": msg})

    def done(self) -> None:
        if self._last != int(self.hi):
            self._last = int(self.hi)
            emit({"type": "progress", "pct": int(self.hi), "message": self.name})


def run_svgo(src: str) -> str:
    """Optional pre-pass: optimize the whole folder with ``npx svgo`` into a
    temp dir. Returns the temp dir on success, or ``src`` unchanged on any
    failure so the run still completes."""
    tmp = tempfile.mkdtemp(prefix="svgo-")
    try:
        subprocess.run(
            ["npx", "--yes", "svgo", "-i", src, "-o", tmp],
            check=True, capture_output=True, timeout=120,
        )
        return tmp
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        print(
            f"warning: svgo pre-pass skipped ({exc}); using source files as-is",
            file=sys.stderr, flush=True,
        )
        return src


def main() -> int:
    parser = argparse.ArgumentParser(description="Bundle SVG icons into a symbol sprite")
    parser.add_argument("--src", required=True, help="Folder of .svg files")
    parser.add_argument("--prefix", default="icon-", help="Symbol ID prefix")
    parser.add_argument("--current-color", action="store_true",
                        help="Substitute currentColor when exactly one non-none colour is used")
    parser.add_argument("--a11y-titles", action="store_true",
                        help="Add a <title> from the filename slug to each symbol")
    parser.add_argument("--precision", type=int, default=3,
                        help="Decimals to round path numerics to (0–6)")
    parser.add_argument("--svgo", action="store_true", help="Run npx svgo as a pre-pass")
    parser.add_argument("--out", required=True, help="Output folder")
    parser.add_argument("--catalog", action="store_true",
                        help="Generate catalog.html (on by default in the PyShell form)")
    parser.add_argument("--wordpress", action="store_true",
                        help="Generate sprite.php (WordPress include)")
    args = parser.parse_args()

    # Introspection builds the form from argparse; no files are written.
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files written", flush=True)
        return 0

    if args.precision < 0 or args.precision > 6:
        print("error: --precision must be between 0 and 6", file=sys.stderr, flush=True)
        return 2

    src = os.path.abspath(args.src)
    out = os.path.abspath(args.out)
    if not os.path.isdir(src):
        print(f"error: source folder not found: {src}", file=sys.stderr, flush=True)
        return 2

    os.makedirs(out, exist_ok=True)
    print(f"Source: {src}\nOutput: {out}", flush=True)
    emit({"type": "progress", "pct": 0, "message": "Starting"})
    status("Discovering icons…")

    tmp_dir = None
    work_src = src
    if args.svgo:
        work_src = run_svgo(src)
        if work_src is not src:
            tmp_dir = work_src

    phases: dict[str, Phase] = {}

    def on_progress(phase: str, done: int, total: int, detail: str) -> None:
        name, lo, hi = PHASES[phase]
        p = phases.get(phase)
        if p is None:
            p = Phase(name, lo, hi)
            phases[phase] = p
        p.report(done, total, detail)

    def on_status(message: str) -> None:
        status(message)

    try:
        result = build(
            work_src, out,
            prefix=args.prefix,
            current_color=args.current_color,
            a11y_titles=args.a11y_titles,
            precision=args.precision,
            catalog=args.catalog,
            wordpress=args.wordpress,
            on_progress=on_progress,
            on_status=on_status,
        )
    except NamingCollision as exc:
        print(f"error: {exc}", file=sys.stderr, flush=True)
        status("naming collision — aborted")
        emit({"type": "progress", "pct": 100, "message": "Aborted"})
        return 2
    finally:
        # Land every phase that reported at its upper bound so the bar does not
        # freeze mid-phase on an error or an empty batch.
        for p in phases.values():
            p.done()
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    if result.total == 0:
        print("No .svg files found.", file=sys.stderr, flush=True)
        status("No icons found")
        emit({"type": "progress", "pct": 100, "message": "Done"})
        return 1

    emit({"type": "table", "columns": ["ID", "Source", "Warnings"], "rows": result.rows})

    arts = "`sprite.svg`"
    if result.catalog_path:
        arts += ", `catalog.html`"
    if result.wordpress_path:
        arts += ", `sprite.php`"
    emit({
        "type": "markdown",
        "content": (
            f"## Done\n\n"
            f"Built **{result.kept}** of {result.total} icon(s) into {arts}.\n\n"
            f"Output: `{out}`"
        ),
    })
    status(f"Built {result.kept} icons → {out}")
    emit({"type": "progress", "pct": 100, "message": "Done"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
