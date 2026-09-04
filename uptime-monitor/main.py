#!/usr/bin/env python3
"""uptime-monitor/main.py — watch a URL live, for minutes.

Polls one URL at a fixed interval for a fixed duration and streams what
it sees: a **scrolling latency chart** (the PyShell chart event is
replaced wholesale on every check — each emission carries the whole
window, so the Results tab redraws as a live monitor), a status line
with the running uptime and percentiles, and a final report with the
downtime intervals spelled out.

Every check is classified three ways — **up** (a 2xx/3xx answer), an
**HTTP error** (the server answered 4xx/5xx — it's reachable, the
endpoint isn't) and **down** (timeout or connection error: nothing
answered). Uptime counts only the first; the report keeps all three
honest and separate.

Latency is the wall time of the whole request — DNS, connect, TLS, wait
— the number a user experiences. On the chart, a down check draws as 0
(a chart needs a number; the table and report keep the truth).

Real traffic: this script sends one GET per interval to the target for
as long as you ask. Point it at your own endpoints. Exit codes:
0 = the monitoring completed (downtime is a result, not a failure —
even 100% of it, as long as the target ever answered at all),
1 = the target never answered anything (DNS, refused: there was nothing
to monitor), 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit

import requests

USER_AGENT = "PyShell-uptime-monitor/1.0"


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# Data model + classification
# ---------------------------------------------------------------------------

@dataclass
class Sample:
    offset: float            # seconds since the run started
    up: bool                 # 2xx/3xx
    status_code: int | None  # None when nothing answered
    latency_ms: float | None
    error: str = ""          # timeout / connection error / ""


@dataclass
class Stats:
    checks: int = 0
    up: int = 0
    http_errors: int = 0
    down: int = 0
    uptime_pct: float = 0.0
    p50_ms: float | None = None
    p95_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    intervals: list[tuple[float, float, int]] = field(default_factory=list)
    # (from_offset, to_offset, check_count) — runs of not-up samples


def classify_sample(status_code: int | None, error: str) -> tuple[bool, str]:
    """(up, error-label) — the three-way split lives here: an HTTP error
    is a *reachable* failure (code set, no error); down is no answer at
    all (error set). Redirects are followed, so the code is final."""
    if error:
        return False, error
    if status_code is not None and status_code < 400:
        return True, ""
    return False, ""


def percentile(sorted_values: list[float], p: float) -> float | None:
    """Linear-interpolation percentile over a sorted list — same shape
    server-timing uses, so the two reports read alike."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (p / 100) * (len(sorted_values) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = rank - lo
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac


def compute_stats(samples: list[Sample]) -> Stats:
    stats = Stats(checks=len(samples))
    latencies = sorted(s.latency_ms for s in samples if s.up)
    stats.up = sum(1 for s in samples if s.up)
    stats.http_errors = sum(1 for s in samples
                            if not s.up and not s.error and s.status_code)
    stats.down = sum(1 for s in samples if s.error)
    stats.uptime_pct = round(100 * stats.up / stats.checks) if samples else 0.0
    stats.p50_ms = percentile(latencies, 50)
    stats.p95_ms = percentile(latencies, 95)
    stats.avg_ms = (sum(latencies) / len(latencies)) if latencies else None
    stats.max_ms = max(latencies) if latencies else None

    # Downtime intervals: runs of consecutive not-up samples.
    run_start: float | None = None
    run_len = 0
    for s in samples + [Sample(offset=float("inf"), up=True,
                               status_code=None, latency_ms=None)]:
        if not s.up:
            if run_start is None:
                run_start = s.offset
            run_len += 1
        elif run_start is not None:
            stats.intervals.append((run_start, s.offset, run_len))
            run_start, run_len = None, 0
    return stats


# ---------------------------------------------------------------------------
# One check
# ---------------------------------------------------------------------------

def check_once(url: str, timeout: float) -> Sample:
    """One GET, timed as the user experiences it (wall time, not
    response.elapsed — DNS and TLS belong in the number)."""
    start = time.monotonic()
    code, error = None, ""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True,
                            headers={"User-Agent": USER_AGENT})
        code = resp.status_code
    except requests.Timeout:
        error = "timeout"
    except requests.RequestException as exc:
        error = f"{type(exc).__name__}"
    latency_ms = round((time.monotonic() - start) * 1000, 1)
    up, _ = classify_sample(code, error)
    return Sample(offset=0.0, up=up, status_code=code,
                  latency_ms=latency_ms if not error else None,
                  error=error)


# ---------------------------------------------------------------------------
# Live chart + report
# ---------------------------------------------------------------------------

def build_chart_event(samples: list[Sample]) -> dict:
    """The scrolling window: labels are wall-clock times, one latency
    series; a down check draws as 0 (the chart needs a number — the
    status line and the report keep the truth)."""
    labels = [f"{int(s.offset)}s" for s in samples]
    values = [round(s.latency_ms) if s.up else 0 for s in samples]
    return {
        "type": "chart",
        "chart_type": "line",
        "title": "Latency (ms) — down checks draw as 0",
        "labels": labels,
        "series": [{"name": "latency ms", "values": values}],
    }


def build_report(url: str, stats: Stats, samples: list[Sample]) -> str:
    head = (f"## {'✅' if stats.uptime_pct == 100 else '⚠️'} "
            f"{stats.uptime_pct}% uptime over {stats.checks} check(s)")
    lines = [head, "", f"`{url}`", ""]

    lines.append(f"- Up: **{stats.up}** · HTTP errors: {stats.http_errors} · "
                 f"down: {stats.down}")
    if stats.p50_ms is not None:
        lines.append(f"- Latency (up checks): p50 **{stats.p50_ms:.0f} ms** · "
                     f"p95 {stats.p95_ms:.0f} ms · avg {stats.avg_ms:.0f} ms · "
                     f"max {stats.max_ms:.0f} ms")

    if stats.intervals:
        lines += ["", "**Not-up intervals**", ""]
        for start, end, count in stats.intervals:
            lines.append(f"- {start:.0f}s – {end:.0f}s ({count} check(s))")
    lines += [""]

    if stats.checks and stats.up == 0:
        lines += ["The endpoint answered nothing usable for the whole run.",
                  ""]
        if stats.http_errors == 0 and stats.down > 0:
            lines.append("_Nothing ever answered — check the URL, DNS and "
                         "whether the host is up at all (IP Search, "
                         "Server Timing)._")
        else:
            lines.append("_The server is reachable but every answer was an "
                         "HTTP error — the endpoint, not the network "
                         "(HTTP Request shows the full response)._")
        lines.append("")
    elif stats.uptime_pct < 100:
        lines.append("_For the slow-answer cases: Server Timing breaks "
                     "latency into DNS/TCP/TLS/TTFB phases; TLS Audit "
                     "checks the certificate._")
        lines.append("")

    lines.append(f"_{stats.checks} GET request(s) sent, one per interval, "
                 f"redirects followed._")
    lines.append("")
    return "\n".join(lines)


def build_table_event(stats: Stats) -> dict:
    row = lambda label, value: [label, str(value)]  # noqa: E731
    return {
        "type": "table",
        "columns": ["Metric", "Value"],
        "rows": [
            row("Checks", stats.checks),
            row("Up", stats.up),
            row("HTTP errors", stats.http_errors),
            row("Down (timeout/connection)", stats.down),
            row("Uptime", f"{stats.uptime_pct}%"),
            row("p50 latency", f"{stats.p50_ms:.0f} ms" if stats.p50_ms is not None else "—"),
            row("p95 latency", f"{stats.p95_ms:.0f} ms" if stats.p95_ms is not None else "—"),
            row("Max latency", f"{stats.max_ms:.0f} ms" if stats.max_ms is not None else "—"),
            row("Not-up intervals", len(stats.intervals)),
        ],
    }


# ---------------------------------------------------------------------------
# Main — the monitoring loop
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Uptime Monitor — poll a URL for minutes and watch "
                    "it live")
    parser.add_argument("--url", required=True, help="URL to monitor")
    parser.add_argument("--duration", type=int, default=60,
                        help="how long to monitor, seconds (default 60)")
    parser.add_argument("--interval", type=int, default=5,
                        help="seconds between checks (default 5)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="per-check timeout (default 5)")
    return parser


def validate_url(url: str) -> str | None:
    """An error message, or None when the URL is usable."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return f"{url!r} is not a parsable URL"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return (f"{url!r} needs a scheme and host "
                f"(https://example.com/…)")
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no checks are made", flush=True)
        return 0

    problem = validate_url(args.url)
    if problem:
        print(f"✗ {problem}", file=sys.stderr, flush=True)
        return 2
    if args.interval > args.duration:
        print("✗ --interval must not exceed --duration "
              "(there would be nothing to watch)", file=sys.stderr, flush=True)
        return 2

    log(f"Monitoring {args.url} for {args.duration}s, one check every "
        f"{args.interval}s (timeout {args.timeout}s)")
    status(f"Monitoring {args.url} · {args.duration}s · every {args.interval}s")

    samples: list[Sample] = []
    started = time.monotonic()
    next_tick = started
    check_no = 0

    while True:
        now = time.monotonic()
        elapsed = now - started
        if elapsed >= args.duration:
            break

        sample = check_once(args.url, args.timeout)
        sample.offset = round(now - started, 1)
        samples.append(sample)
        check_no += 1

        # The live window: chart + status + progress, once per check.
        emit(build_chart_event(samples))
        stats = compute_stats(samples)
        running = (f"check {check_no} · {'up' if sample.up else 'down'}"
                   + (f" · {sample.status_code}" if sample.status_code else "")
                   + (f" · {sample.latency_ms:.0f} ms" if sample.up else "")
                   + f" · uptime {stats.uptime_pct}%")
        status(running)
        emit({"type": "progress",
              "pct": min(99, round(100 * sample.offset / args.duration)),
              "message": f"{running}"})
        log(f"  {sample.offset:6.1f}s  "
            f"{'up' if sample.up else 'DOWN':4}  "
            f"{sample.status_code or '—':>3}  "
            f"{f'{sample.latency_ms:8.1f} ms' if sample.up else sample.error}")

        # Pace to the interval — the check's own time counts inside it.
        next_tick += args.interval
        sleep_for = next_tick - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)

    if not samples:
        print("✗ the duration was too short for a single check",
              file=sys.stderr, flush=True)
        return 1

    stats = compute_stats(samples)

    if stats.up == 0 and stats.http_errors == 0:
        # Nothing ever answered — there was nothing to monitor.
        print(f"✗ {args.url} never answered "
              f"({samples[0].error or 'no response'}) — check the URL, DNS "
              f"and host first", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Monitoring failed\n\n❌ **{args.url}** never answered a "
              f"single check ({samples[0].error}) — an unreachable target "
              f"is not a monitoring result, it's a prerequisite problem."})
        status(f"Failed: {samples[0].error or 'no response'}")
        return 1

    report = build_report(args.url, stats, samples)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(stats))
    emit({"type": "markdown", "content": report})

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "uptime_samples.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"url": args.url,
                       "duration": args.duration,
                       "interval": args.interval,
                       "stats": asdict(stats),
                       "samples": [asdict(s) for s in samples]},
                      fh, indent=2, ensure_ascii=False)
        with open(os.path.join(output_dir, "report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(report + "\n")

    summary = f"{stats.uptime_pct}% uptime"
    if stats.p50_ms is not None:
        summary += f" · p50 {stats.p50_ms:.0f} ms"
    status(summary)
    log(f"← {summary} over {stats.checks} check(s)")
    # Downtime is a result, not a failure — the run monitored what it
    # saw, and it saw something answer at least once.
    return 0


if __name__ == "__main__":
    sys.exit(main())
