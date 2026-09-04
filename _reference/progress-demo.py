#!/usr/bin/env python3
# /// script
# [tool.pyshell]
# id = "com.pyshell.example.progress"
# name = "Progress Demo"
# description = "Structured events done right: throttled progress, phases, summary table"
# python = ">=3.11"
#
# [tool.pyshell.outputs]
# artifacts = ["*.csv"]
#
# [[tool.pyshell.inputs]]
# key = "items"
# type = "int"
# label = "Items to check"
# help = "Try 50000 — the event count stays at ~100 either way"
# default = 2000
# min = 1
# max = 200000
# group = "Workload"
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--items"
# style = "space"
#
# [[tool.pyshell.inputs]]
# key = "fail_rate"
# type = "int"
# label = "Failure rate (%)"
# help = "Share of items that fail, so the summary table has something in it"
# default = 12
# min = 0
# max = 100
# group = "Workload"
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--fail-rate"
# style = "space"
#
# [[tool.pyshell.inputs]]
# key = "slow"
# type = "bool"
# label = "Animate"
# help = "Pause briefly on each update so the progress bar is watchable"
# default = true
# group = "Workload"
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--slow"
# style = "flag"
# ///
"""progress-demo.py — how to report progress in PyShell.

PyShell runs scripts over pipes, not a PTY, so `rich` and `tqdm` cannot draw a
progress bar here: anything redrawing a line with \\r piles up into one giant
line that only appears once the process exits. Instead, a script emits JSON
events on stderr and PyShell renders them natively.

What this example demonstrates, in order:

  1. Detecting PyShell so terminal-drawing libraries can be switched off.
  2. An indeterminate phase — a count you do not know yet is a `status`, not a
     made-up percentage.
  3. Throttling — one event per whole percent instead of one per item. Events
     are not batched, and they count against the job's output cap like any other
     line, so a tight loop would otherwise flood the UI.
  4. Several phases mapped onto the single 0–100 bar.
  5. A summary table, emitted once and complete (it replaces, it does not append).
  6. Finishing at exactly 100.
  7. Writing an artifact into PYSHELL_OUTPUT_DIR.

Run it from a terminal too — it degrades to plain log lines.
"""
import argparse
import csv
import json
import os
import random
import sys
import time

# PyShell always sets PYSHELL_OUTPUT_DIR, which makes it the reliable way to
# tell we are not attached to a terminal-drawing UI.
UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ
PLAIN = UNDER_PYSHELL or not sys.stderr.isatty()

# This is where `rich` / `tqdm` would be gated, e.g.:
#     for item in tqdm(items, disable=PLAIN): ...
#     console = Console(no_color=PLAIN, force_terminal=False)

# Counters, only so the script can show what throttling bought.
EVENTS = {"progress": 0, "status": 0, "table": 0}


def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    EVENTS[event["type"]] = EVENTS.get(event["type"], 0) + 1
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


class Phase:
    """Maps a phase's own 0..1 progress onto a slice of the single 0–100 bar.

    There is one progress bar, so multi-stage work has to share it. Each phase
    owns a span (say 10–70) and only ever reports inside it, which keeps the bar
    monotonic instead of restarting per stage.

    Emits at most one event per whole percent: the bar cannot show more than
    that, and every event is a separate IPC message.
    """

    def __init__(self, name: str, lo: float, hi: float, animate: bool = False):
        self.name = name
        self.lo = lo
        self.hi = hi
        self.animate = animate
        self._last_pct = -1

    def report(self, done: int, total: int, detail: str = "") -> None:
        fraction = done / total if total else 1.0
        pct = int(self.lo + (self.hi - self.lo) * fraction)
        if pct == self._last_pct:
            return
        self._last_pct = pct
        message = f"{self.name} — {detail}" if detail else self.name
        emit({"type": "progress", "pct": pct, "message": message})
        if self.animate:
            time.sleep(0.04)

    def done(self) -> None:
        """Land exactly on the phase's upper bound."""
        if self._last_pct != int(self.hi):
            self._last_pct = int(self.hi)
            emit({"type": "progress", "pct": int(self.hi), "message": self.name})


def discover(count: int) -> list[str]:
    """A phase whose size is not known up front.

    Inventing a percentage here would make the bar run backwards once the real
    total arrived, so this reports with `status` instead.
    """
    status("Discovering items…")
    time.sleep(0.4)
    items = [f"item-{i:06d}" for i in range(1, count + 1)]
    status(f"Found {len(items)} items")
    return items


def check(name: str, fail_rate: int) -> tuple[str, int, str]:
    size = random.randint(120, 90_000)
    ok = random.randint(1, 100) > fail_rate
    return (name, size, "OK" if ok else "FAILED")


def write_report(rows: list[tuple[str, int, str]]) -> str | None:
    """Artifacts go to PYSHELL_OUTPUT_DIR, never next to the script."""
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        print("PYSHELL_OUTPUT_DIR is not set — skipping the report", flush=True)
        return None

    path = os.path.join(out_dir, "report.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["item", "size_bytes", "status"])
        writer.writerows(rows)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Progress reporting demo")
    parser.add_argument("--items", type=int, default=2000)
    parser.add_argument("--fail-rate", type=int, default=12)
    parser.add_argument("--slow", action="store_true")
    args = parser.parse_args()

    random.seed(1234)  # reproducible output for a demo

    print(f"PyShell detected: {UNDER_PYSHELL}", flush=True)
    print(f"Checking {args.items} items, ~{args.fail_rate}% expected to fail", flush=True)

    # Phase 1 has no measurable size, so it gets no share of the bar.
    items = discover(args.items)

    # Phases 2 and 3 split the bar between them.
    checking = Phase("Checking", 0, 90, animate=args.slow)
    reporting = Phase("Writing report", 90, 100, animate=args.slow)

    rows: list[tuple[str, int, str]] = []
    failures: list[tuple[str, int, str]] = []

    for i, name in enumerate(items, 1):
        row = check(name, args.fail_rate)
        rows.append(row)
        if row[2] == "FAILED":
            failures.append(row)
        # Called every iteration; only actually emits ~90 times.
        checking.report(i, len(items), f"{i}/{len(items)}")
    checking.done()

    reporting.report(0, 1)
    path = write_report(rows)
    reporting.done()

    # A table is a summary, not a log: it replaces whatever was there, so send it
    # once and complete. Showing all 2000 rows would be unreadable anyway — the
    # failures are the interesting part, and the full set is in the CSV.
    shown = failures[:50]
    emit({
        "type": "table",
        "columns": ["Item", "Size", "Status"],
        "rows": [[name, f"{size:,} B", state] for name, size, state in shown],
    })

    # The bar does not reset itself; a successful run left at 97% looks broken.
    emit({"type": "progress", "pct": 100, "message": "Done"})
    status(f"{len(rows) - len(failures)} passed, {len(failures)} failed")

    if len(failures) > len(shown):
        print(f"Table shows {len(shown)} of {len(failures)} failures", flush=True)
    if path:
        print(f"Wrote {path}", flush=True)

    # The point of the exercise: iterations vs events actually sent.
    print(
        f"\n{len(items)} iterations produced "
        f"{EVENTS['progress']} progress events, "
        f"{EVENTS['status']} status events, {EVENTS['table']} table",
        flush=True,
    )
    # Exit 0: the run itself succeeded. Findings belong in the table, not in the
    # exit code — otherwise every demo run shows up red in History.
    return 0


if __name__ == "__main__":
    sys.exit(main())
