"""Local dev watcher — not a PyShell entry point.

Run from a terminal::

    python -m src.watch <src_dir> --out <out_dir>

Watches ``src_dir`` for ``.svg`` changes and rebuilds the sprite on a 300 ms
debounce (design tools write in bursts). Full rebuild every time — under a
second for a few hundred icons, and incremental rebuild is not worth the state
it demands. One log line per rebuild: timestamp, icon count, output size,
warning count.

This stays a nice-to-have for local iteration and is deliberately outside the
PyShell manifest (PyShell owns process lifecycle for exactly one Run; a
background watcher has no place in that model). It imports the same
:mod:`src.build` pipeline as ``main.py``, so there is exactly one build path.

Requires the ``watchdog`` package (``pip install watchdog``) — it is NOT in
``requirements.txt`` to keep the PyShell install lean.
"""
from __future__ import annotations

import argparse
import datetime
import os
import sys
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from .build import build
from .parse import NamingCollision


def rebuild(src: str, out: str, opts: dict) -> None:
    t0 = time.monotonic()
    try:
        res = build(src, out, **opts)
        dt = time.monotonic() - t0
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"[{ts}] {res.kept} icons, {res.sprite_size} B, "
            f"{res.warnings} warning(s) ({dt:.2f}s)",
            flush=True,
        )
    except NamingCollision as exc:
        print(f"[rebuild skipped] {exc}", flush=True)
    except Exception as exc:  # never let the watcher die on a build error
        print(f"[rebuild error] {exc}", flush=True)


class _Handler(FileSystemEventHandler):
    def __init__(self, src: str, out: str, opts: dict, debounce: float = 0.3):
        self.src = src
        self.out = out
        self.opts = opts
        self._debounce = debounce
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def _schedule(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(self._debounce, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self) -> None:
        rebuild(self.src, self.out, self.opts)

    def on_any_event(self, event) -> None:
        if event.is_directory:
            return
        if not event.src_path.lower().endswith(".svg"):
            return
        self._schedule()


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch and rebuild an SVG sprite")
    parser.add_argument("src_dir", help="Folder of .svg files to watch")
    parser.add_argument("--out", required=True, help="Output folder")
    parser.add_argument("--prefix", default="icon-")
    parser.add_argument("--current-color", action="store_true")
    parser.add_argument("--a11y-titles", action="store_true")
    parser.add_argument("--precision", type=int, default=3)
    parser.add_argument("--no-catalog", dest="catalog", action="store_false", default=True)
    parser.add_argument("--wordpress", action="store_true")
    args = parser.parse_args()

    src = os.path.abspath(args.src_dir)
    out = os.path.abspath(args.out)
    if not os.path.isdir(src):
        print(f"error: source folder not found: {src}", file=sys.stderr, flush=True)
        return 2

    os.makedirs(out, exist_ok=True)
    opts = {
        "prefix": args.prefix,
        "current_color": args.current_color,
        "a11y_titles": args.a11y_titles,
        "precision": args.precision,
        "catalog": args.catalog,
        "wordpress": args.wordpress,
    }

    rebuild(src, out, opts)  # initial build

    observer = Observer()
    observer.schedule(_Handler(src, out, opts), src, recursive=False)
    observer.start()
    print(f"Watching {src} — Ctrl-C to stop", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
