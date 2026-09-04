#!/usr/bin/env python3
# /// script
# [tool.pyshell]
# id = "com.pyshell.example.report"
# name = "Report Demo"
# description = "Rich results: a live chart during the run, a markdown report at the end"
# python = ">=3.11"
#
# [tool.pyshell.outputs]
# result = "markdown"
#
# [[tool.pyshell.inputs]]
# key = "samples"
# type = "int"
# label = "Samples per endpoint"
# help = "The chart is resent in full on every update — see how few events that still takes"
# default = 40
# min = 5
# max = 500
# group = "Workload"
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--samples"
# style = "space"
#
# [[tool.pyshell.inputs]]
# key = "final_chart"
# type = "choice"
# label = "Final chart"
# help = "A chart replaces the previous one, so only this last emit survives the run"
# default = "bar"
# group = "Presentation"
# options = [
#   { value = "bar", label = "Bar — average and p95 per endpoint" },
#   { value = "line", label = "Line — keep the sampling timeline" },
# ]
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--final-chart"
# style = "space"
#
# [[tool.pyshell.inputs]]
# key = "slow"
# type = "bool"
# label = "Animate"
# help = "Pause between samples so the chart can be watched filling up"
# default = true
# group = "Presentation"
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--slow"
# style = "flag"
# ///
"""report-demo.py — producing a chart and a markdown report from a script.

`progress-demo.py` covers the progress bar and the summary table. This one
covers the other two result kinds, and the rules that are easy to get wrong:

  1. **Both kinds replace, they do not append.** Every `chart` event overwrites
     the previous chart, every `markdown` event overwrites the previous report.
     Whatever is emitted last is what the user is left looking at — which is why
     `--final-chart` decides between the live timeline and a summary here.
  2. **A chart is always sent whole.** There is no "append a point" event, so a
     live chart means resending every label and every series each time. That is
     cheap in code and expensive in bytes, hence:
  3. **Throttle, and window.** Structured events count toward the same output
     cap as log lines (50 MB / 500k lines per job), and a chart event is far
     from small. This script samples hundreds of times but emits ~1 chart per
     second, each showing only the last `WINDOW` samples — an unbounded
     timeline is both expensive to send and a solid band to look at.
  4. **Markdown is a safe subset, not a web page.** Headings, lists, tables,
     code blocks, links, bold/italic. No HTML — it is escaped, not rendered —
     and links open in the OS browser instead of navigating the app.
  5. **Declare what you produce.** `[tool.pyshell.outputs] result = "markdown"`
     lets PyShell label the Results tab before the script has ever run.

No network and no dependencies: the latencies are generated from a fixed seed,
so two runs with the same inputs produce the same report.

Run it from a terminal too — the events degrade to plain JSON log lines.
"""
import argparse
import json
import os
import random
import statistics
import sys
import time

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ

# Endpoints to "measure": (path, typical ms, jitter ms). The spread is what
# makes the chart worth looking at — four identical series would prove nothing.
ENDPOINTS = [
    ("/", 14, 5),
    ("/static/app.js", 9, 3),
    ("/api/search", 52, 22),
    ("/api/login", 96, 34),
]

# One chart per second at most. The UI cannot show more, and every event is a
# separate IPC message that also counts against the job's output cap.
CHART_INTERVAL = 1.0

# How many samples the live chart shows. PyShell thins the X labels so they
# never collide, but it still draws every point — a few hundred of them turn
# the line into a solid band. A scrolling window is what a monitor wants
# anyway: the recent shape, not all of history. The summary chart at the end
# is what carries the totals.
WINDOW = 60

EVENTS = {"progress": 0, "status": 0, "chart": 0, "markdown": 0}


def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    EVENTS[event["type"]] = EVENTS.get(event["type"], 0) + 1
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def p95(values: list[float]) -> float:
    """Nearest-rank p95 — no interpolation, so a 5-sample run still works."""
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))
    return ordered[idx]


def timeline_chart(taken: int, samples: dict[str, list[float]], title: str) -> dict:
    """The whole chart, rebuilt from scratch, over the last `WINDOW` samples.

    `labels` are shared by every series, and `series[i].values[j]` lines up with
    `labels[j]` — so the window has to be applied to both, in step.
    """
    first = max(0, taken - WINDOW)
    return {
        "type": "chart",
        "chart_type": "line",
        "title": title,
        "labels": [f"#{i}" for i in range(first + 1, taken + 1)],
        "series": [
            {"name": path, "values": values[first:taken]} for path, values in samples.items()
        ],
    }


def summary_chart(samples: dict[str, list[float]]) -> dict:
    """Two series over the same labels render as grouped bars."""
    paths = list(samples)
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": "Latency by endpoint (ms)",
        "labels": paths,
        "series": [
            {"name": "avg", "values": [round(statistics.fmean(samples[p]), 1) for p in paths]},
            {"name": "p95", "values": [round(p95(samples[p]), 1) for p in paths]},
        ],
    }


def markdown_report(samples: dict[str, list[float]], budget: float) -> str:
    """Build the report as one string and emit it once, complete.

    Sending it per-section would work — each event replaces the last — but the
    user would watch the report flicker through half-written states.
    """
    rows = []
    for path, values in samples.items():
        avg = statistics.fmean(values)
        rows.append((path, avg, p95(values), max(values), avg > budget))

    over = [r for r in rows if r[4]]
    slowest = max(rows, key=lambda r: r[1])

    lines = [
        "## Latency report",
        "",
        f"{len(rows)} endpoints × {len(next(iter(samples.values())))} samples, "
        f"budget **{budget:.0f} ms** average.",
        "",
        "| Endpoint | Avg | p95 | Max | Verdict |",
        "| --- | --- | --- | --- | --- |",
    ]
    for path, avg, p95_ms, worst, breached in rows:
        verdict = "❌ over budget" if breached else "✅ within budget"
        lines.append(f"| `{path}` | {avg:.1f} ms | {p95_ms:.1f} ms | {worst:.1f} ms | {verdict} |")

    lines += ["", "### Findings", ""]
    if over:
        # Flat, not nested: the renderer treats an indented bullet as a sibling,
        # so nesting here would only look wrong in the app.
        lines.append(f"- **{len(over)} endpoint(s) over the {budget:.0f} ms budget:** "
                     + ", ".join(f"`{path}` ({avg:.1f} ms)" for path, avg, *_ in over))
    else:
        lines.append(f"- Every endpoint stayed under the {budget:.0f} ms budget.")
    lines.append(f"- Slowest overall: `{slowest[0]}` at {slowest[1]:.1f} ms average.")
    lines.append(
        f"- Spread between fastest and slowest: "
        f"{slowest[1] - min(r[1] for r in rows):.1f} ms."
    )

    lines += [
        "",
        "### Reproducing",
        "",
        "```bash",
        f"python report-demo.py --samples {len(next(iter(samples.values())))} --final-chart bar",
        "```",
        "",
        "The manifest at the top of this file is "
        "[PEP 723](https://peps.python.org/pep-0723/) inline metadata. Absolute links "
        "open in the browser; a relative one like `docs/scripting.md` stays plain text.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Chart and markdown result demo")
    parser.add_argument("--samples", type=int, default=40)
    parser.add_argument("--final-chart", choices=["bar", "line"], default="bar")
    parser.add_argument("--slow", action="store_true")
    args = parser.parse_args()

    random.seed(20260826)  # a demo that changes every run is a bad demo
    budget = 50.0

    print(f"PyShell detected: {UNDER_PYSHELL}", flush=True)
    print(f"Sampling {len(ENDPOINTS)} endpoints × {args.samples} times", flush=True)

    samples: dict[str, list[float]] = {path: [] for path, _, _ in ENDPOINTS}
    status("Warming up…")
    time.sleep(0.3)

    last_chart = 0.0
    for i in range(1, args.samples + 1):
        for path, base, jitter in ENDPOINTS:
            # A little upward drift so the timeline has a shape to it.
            drift = (i / args.samples) * base * 0.35
            samples[path].append(round(random.gauss(base + drift, jitter), 1))

        # Progress is cheap and monotonic; the chart is not, so they are
        # throttled separately. Sampling gets 0–90, the report gets 90–100.
        emit({
            "type": "progress",
            "pct": int(i / args.samples * 90),
            "message": f"Sampling — {i}/{args.samples}",
        })

        now = time.monotonic()
        if now - last_chart >= CHART_INTERVAL:
            last_chart = now
            emit(timeline_chart(i, samples, f"Latency over time (sample {i}/{args.samples})"))

        if args.slow:
            time.sleep(0.05)

    status("Building report…")
    emit({"type": "progress", "pct": 95, "message": "Building report"})

    # The last chart wins. `bar` throws away the timeline in favour of a
    # summary; `line` keeps the timeline and just completes it.
    if args.final_chart == "bar":
        emit(summary_chart(samples))
    else:
        emit(timeline_chart(args.samples, samples, "Latency over time (complete)"))

    emit({"type": "markdown", "content": markdown_report(samples, budget)})
    emit({"type": "progress", "pct": 100, "message": "Done"})

    slowest = max(samples, key=lambda p: statistics.fmean(samples[p]))
    status(f"Slowest: {slowest} ({statistics.fmean(samples[slowest]):.1f} ms avg)")

    # What the throttling bought: samples taken vs charts actually sent.
    print(
        f"\n{args.samples} samples per endpoint produced "
        f"{EVENTS['chart']} chart events and {EVENTS['markdown']} markdown event",
        flush=True,
    )
    # Exit 0: measuring slow endpoints is a successful run. A breached budget
    # belongs in the report, not in the exit code.
    return 0


if __name__ == "__main__":
    sys.exit(main())
