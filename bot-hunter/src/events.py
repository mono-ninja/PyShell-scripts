"""PyShell structured events — progress, tables, charts, markdown.

PyShell runs scripts over pipes, not a PTY, so ``rich``/``tqdm`` progress bars
cannot redraw a line.  Instead, a script emits JSON events on stderr and PyShell
renders them natively (progress bar, table, chart, markdown report).

Every event is one JSON object on one line with ``"pyshell": true``.  Outside
PyShell the events degrade to plain JSON log lines on stderr — harmless in a
terminal.
"""

import json
import os
import sys

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ


def emit(event: dict) -> None:
    """Send one structured event to PyShell (JSON on stderr, single line)."""
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    """One-line status shown under the progress bar. Replaces previous."""
    emit({"type": "status", "message": message})


def progress(pct: float, message: str = "") -> None:
    """Progress bar at *pct* (0-100). Replaces previous."""
    emit({"type": "progress", "pct": round(pct, 1), "message": message})


def table(columns: list[str], rows: list[list]) -> None:
    """Summary table. Replaces previous — send complete, not per-row."""
    emit({"type": "table", "columns": columns, "rows": rows})


def chart(chart_type: str, title: str, labels: list, series: list) -> None:
    """Chart (``"line"`` or ``"bar"``). Replaces previous — send complete."""
    emit({
        "type": "chart",
        "chart_type": chart_type,
        "title": title,
        "labels": labels,
        "series": series,
    })


def markdown(content: str) -> None:
    """Markdown report in the Results tab. Replaces previous."""
    emit({"type": "markdown", "content": content})


class Phase:
    """Map a phase's own 0..1 progress onto a slice of the single 0-100 bar.

    There is one progress bar, so multi-stage work has to share it.  Each phase
    owns a span (say 10-70) and only ever reports inside it, keeping the bar
    monotonic.  Emits at most one event per whole percent.
    """

    def __init__(self, name: str, lo: float, hi: float):
        self.name = name
        self.lo = lo
        self.hi = hi
        self._last_pct = -1

    def report(self, done: int, total: int, detail: str = "") -> None:
        fraction = done / total if total else 1.0
        pct = int(self.lo + (self.hi - self.lo) * fraction)
        if pct == self._last_pct:
            return
        self._last_pct = pct
        message = f"{self.name} - {detail}" if detail else self.name
        progress(pct, message)

    def done(self) -> None:
        """Land exactly on the phase's upper bound."""
        if self._last_pct != int(self.hi):
            self._last_pct = int(self.hi)
            progress(int(self.hi), self.name)
