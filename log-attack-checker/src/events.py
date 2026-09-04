"""PyShell integration: structured events, progress UI, shared console and logger.

PyShell runs scripts over pipes, not a PTY, so rich/tqdm animation cannot
draw. Detect it via PYSHELL_OUTPUT_DIR (always set by PyShell) and fall back
to a tty check. Structured events (``emit``) are the supported way to show
progress.
"""
import json
import logging
import os
import sys

from rich.console import Console
from rich.progress import (BarColumn, DownloadColumn, Progress, SpinnerColumn,
                           TextColumn, TimeRemainingColumn)
from rich.theme import Theme

# --- PyShell integration -----------------------------------------------------
# PyShell runs scripts over pipes, not a PTY, so rich/tqdm animation cannot draw.
# Detect it via PYSHELL_OUTPUT_DIR (always set by PyShell) and fall back to a
# tty check. Structured events (emit) are the supported way to show progress.
UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ
PLAIN = UNDER_PYSHELL or not sys.stderr.isatty()

def emit(event: dict) -> None:
    """Send one structured event to stderr for PyShell. No-op in a real terminal.

    One event = one line, never pretty-printed. ``progress``/``table``/``chart``
    /``markdown``/``status`` replace the previous value of their kind.
    """
    if not UNDER_PYSHELL:
        return
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)

logging.basicConfig(level=logging.WARNING if UNDER_PYSHELL else logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ninjaLog")

custom_theme = Theme({"info": "cyan", "warning": "yellow", "danger": "bold red", "success": "green"})
console = Console(theme=custom_theme, no_color=PLAIN, force_terminal=not PLAIN, highlight=not PLAIN)

def get_output_dir(cfg) -> str:
    """Artifacts go to PYSHELL_OUTPUT_DIR under PyShell, else cfg.output_dir.

    The directory is created when missing: PyShell always provides an existing
    one, but a manually exported PYSHELL_OUTPUT_DIR or an ``-o`` path may not
    exist yet, and the report writers would crash on open().
    """
    directory = os.environ.get("PYSHELL_OUTPUT_DIR") or cfg.output_dir or "."
    os.makedirs(directory, exist_ok=True)
    return directory


class ProgressUi:
    """Unified progress: rich Progress in a terminal, JSON events under PyShell.

    Used as a context manager so the merge loop keeps its indentation regardless
    of which backend is active.
    """

    def __init__(self, total_size: int, cons, label: str = "Analyzing"):
        self.total = total_size
        self.bytes_done = 0
        self.lines_done = 0
        self.last_pct = -1
        self._rich = None
        self._task = None
        if UNDER_PYSHELL:
            emit({"type": "status", "message": label})
        else:
            self._rich = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                DownloadColumn(),
                TimeRemainingColumn(),
                console=cons,
                transient=True,
            )
            self._rich.__enter__()
            self._task = self._rich.add_task(f"[cyan]{label}...", total=total_size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def advance(self, n_bytes: int, lines: int) -> None:
        self.bytes_done += n_bytes
        self.lines_done = lines
        if self._rich is not None:
            self._rich.update(self._task, advance=n_bytes)
        else:
            pct = int(2 + 73 * self.bytes_done / self.total) if self.total else 2
            if pct != self.last_pct:
                self.last_pct = pct
                emit({"type": "progress", "pct": pct, "message": f"Parsing — {lines:,} lines"})

    def close(self) -> None:
        if self._rich is not None:
            self._rich.__exit__(None, None, None)
