"""PyShell structured-event IO.

PyShell parses JSON lines from **stderr** and renders them as native UI:
progress bar, status line, table, markdown report, chart. Plain `print()` goes
to stdout and appears in the log view.

Rules (see _reference/authoring-guide.md §12):
  * every event carries `"pyshell": true`
  * one event = one line (never pretty-printed)
  * `flush=True` is mandatory
  * `pct` is 0–100 (percent, not fraction)
  * progress/table/markdown/chart/status **replace** the previous value
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any

_event_counts: dict[str, int] = {}


def emit(event: dict[str, Any]) -> None:
    """Send one structured event to stderr."""
    event["pyshell"] = True
    _event_counts[event["type"]] = _event_counts.get(event["type"], 0) + 1
    print(json.dumps(event, ensure_ascii=False), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def progress(pct: float, message: str = "") -> None:
    emit({"type": "progress", "pct": round(pct, 2), "message": message})


def log(message: str) -> None:
    """Plain log line to stdout (LogView)."""
    print(message, flush=True)


class Phase:
    """Maps a phase's own 0..1 progress onto a slice of the single 0–100 bar.

    There is one progress bar, so multi-stage work shares it. Each phase owns a
    span (say 10–70) and only reports inside it, keeping the bar monotonic.
    Emits at most one event per whole percent.
    """

    def __init__(self, name: str, lo: float, hi: float):
        self.name = name
        self.lo = lo
        self.hi = hi
        self._last = -1

    def report(self, done: int, total: int, detail: str = "") -> None:
        fraction = done / total if total else 1.0
        pct = int(self.lo + (self.hi - self.lo) * fraction)
        if pct == self._last:
            return
        self._last = pct
        msg = f"{self.name} — {detail}" if detail else self.name
        progress(pct, msg)

    def done(self) -> None:
        if self._last != int(self.hi):
            self._last = int(self.hi)
            progress(int(self.hi), self.name)


def finish_progress() -> None:
    """The bar does not reset itself — always land on 100."""
    progress(100, "Done")


def event_counts() -> dict[str, int]:
    return dict(_event_counts)


class TimedThrottle:
    """Rate limiter for high-frequency events (e.g. live charts)."""

    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self._last = 0.0

    def ready(self) -> bool:
        now = time.monotonic()
        if now - self._last >= self.min_interval:
            self._last = now
            return True
        return False
