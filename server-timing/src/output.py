"""Output formatters and PyShell structured events.

Four stdout formats:

  human       aligned table with p50/p95/max per phase, ANSI color, disabled
              when stdout is not a tty, ``NO_COLOR`` is set, or under PyShell
  json        machine-readable, all percentiles, times in seconds
  csv         one summary row per URL, append-safe for time-series accumulation
  prometheus  text exposition for the node_exporter textfile collector

Under PyShell (``PYSHELL_OUTPUT_DIR`` set) the formatters additionally emit
structured JSON events on stderr — ``table``, ``chart`` and ``status`` — once
at the end of a run, regardless of the chosen stdout format. Progress during
the series is emitted from ``__main__``.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone

from .stats import PHASES, PhaseStats, SeriesStats

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ


# ── PyShell event emitter ──────────────────────────────────────────────────


def emit(event: dict) -> None:
    """Send one structured event to stderr for the PyShell ResultView.

    Rules (_reference/authoring-guide.md): one event per line, ``"pyshell": true`` mandatory,
    ``flush=True`` mandatory, never pretty-printed.
    """
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


# ── Formatting helpers ─────────────────────────────────────────────────────


def ms(seconds: float | None) -> str:
    """Format a duration in seconds as milliseconds, e.g. ``184.6ms``."""
    if seconds is None:
        return "—"
    return f"{seconds * 1000:.1f}ms"


def ms_raw(value: float | None) -> str:
    """Format a value that is already in milliseconds (Server-Timing ``dur``)."""
    if value is None:
        return "—"
    return f"{value:.1f}ms"


def size_fmt(num_bytes: int) -> str:
    """Format a byte count as ``48.2 KB``."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / 1024 / 1024:.1f} MB"


class Color:
    """Tiny ANSI wrapper that no-ops when color is disabled."""

    def __init__(self, enabled: bool):
        self.on = enabled

    def _w(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def bold(self, text: str) -> str:
        return self._w(text, "1")

    def dim(self, text: str) -> str:
        return self._w(text, "2")

    def cyan(self, text: str) -> str:
        return self._w(text, "36")

    def yellow(self, text: str) -> str:
        return self._w(text, "33")


def _color_enabled() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    if UNDER_PYSHELL:
        return False
    return sys.stdout.isatty()


# ── Human ──────────────────────────────────────────────────────────────────


def format_human(stats_list: list[SeriesStats], color: bool | None = None) -> str:
    """Render one or more URL runs as the human table."""
    if color is None:
        color = _color_enabled()
    c = Color(color)
    out: list[str] = []
    for stats in stats_list:
        out.append(_human_block(stats, c))
    return "\n".join(out)


def _human_block(stats: SeriesStats, c: Color) -> str:
    lines: list[str] = []

    header = (
        f"{stats.url}  (n={stats.n}, "
        f"cache-bust: {'on' if stats.cache_bust else 'off'}, "
        f"keep-alive: {'on' if stats.reuse else 'off'})"
    )
    lines.append(c.bold(header))

    if stats.small_sample and stats.n > 0:
        lines.append(c.yellow(
            f"! N={stats.n} — percentiles are not representative on such a small sample"
        ))
    lines.append("")  # blank line between header and table

    # Build aligned table rows for phases that exist.
    # Columns: phase, p50, p95, max, mean (mean in dim).
    rows: list[tuple[str, str, str, str, str, bool]] = []
    for phase in PHASES:
        ps = stats.phases.get(phase)
        if ps is None:
            continue
        is_server = phase == "server"
        is_total = phase == "total"
        rows.append((
            phase,
            ms(ps.p50),
            ms(ps.p95),
            ms(ps.max),
            ms(ps.mean),
            is_server or is_total,
        ))

    if rows:
        col0 = max(len("phase"), max(len(r[0]) for r in rows))
        headers = ("phase", "p50", "p95", "max", "mean")
        width_val = max(
            max(len(headers[1]), len(headers[2]), len(headers[3]), len(headers[4])),
            max(max(len(r[1]), len(r[2]), len(r[3]), len(r[4])) for r in rows),
        )

        def fmt_row(label: str, v1: str, v2: str, v3: str, v_mean: str,
                    emph: bool) -> str:
            lbl = c.bold(label.ljust(col0)) if emph else label.ljust(col0)
            cells = "  ".join(v.rjust(width_val) for v in (v1, v2, v3))
            mean_cell = c.dim(v_mean.rjust(width_val))
            line = f"{lbl}  {c.bold(cells) if emph else cells}  {mean_cell}"
            if label == "server":
                line += "   " + c.dim("← pure server time")
            return line

        hdr = (
            f"{'phase'.ljust(col0)}  "
            f"{'p50'.rjust(width_val)}  "
            f"{'p95'.rjust(width_val)}  "
            f"{'max'.rjust(width_val)}  "
            f"{c.dim('mean'.rjust(width_val))}"
        )
        lines.append(c.bold(hdr))
        for label, v1, v2, v3, v_mean, emph in rows:
            lines.append(fmt_row(label, v1, v2, v3, v_mean, emph))

    # Server-Timing line.
    if stats.server_timing:
        parts = [f"{name} {ms_raw(ps.p95)} p95" for name, ps in stats.server_timing.items()]
        lines.append("")
        lines.append(f"Server-Timing:  {' · '.join(parts)}")

    # Status + size line.
    status_parts = [f"{code}×{cnt}" for code, cnt in sorted(stats.status_codes.items())]
    if stats.n < stats.total:
        status_parts.append(f"errors×{stats.total - stats.n}")
    line = f"statuses: {' · '.join(status_parts)} · size: {size_fmt(stats.total_size)}"
    lines.append(line)

    # DNS cache note.
    if stats.phases.get("dns") is not None:
        lines.append(c.dim("Note: the dns phase may be cached by the OS"))

    return "\n".join(lines)


# ── JSON ───────────────────────────────────────────────────────────────────


def _phase_to_dict(ps: PhaseStats) -> dict:
    return {
        "n": ps.n,
        "min": ps.min,
        "max": ps.max,
        "mean": ps.mean,
        "stdev": ps.stdev,
        "p50": ps.p50,
        "p90": ps.p90,
        "p95": ps.p95,
        "p99": ps.p99,
    }


def format_json(stats_list: list[SeriesStats]) -> str:
    """Render all runs as a JSON document (times in seconds, server_timing in ms)."""
    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": "srvtime",
        "units": {"phases": "seconds", "server_timing": "milliseconds"},
        "runs": [_stats_to_dict(s) for s in stats_list],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _stats_to_dict(stats: SeriesStats) -> dict:
    return {
        "url": stats.url,
        "n": stats.n,
        "total": stats.total,
        "success_rate": stats.success_rate,
        "cache_bust": stats.cache_bust,
        "reuse": stats.reuse,
        "small_sample": stats.small_sample,
        "status_codes": {str(k): v for k, v in stats.status_codes.items()},
        "total_size": stats.total_size,
        "phases": {
            phase: _phase_to_dict(ps)
            for phase in PHASES
            if (ps := stats.phases.get(phase)) is not None
        },
        "server_timing": {
            name: _phase_to_dict(ps) for name, ps in stats.server_timing.items()
        },
    }


# ── CSV ────────────────────────────────────────────────────────────────────

_CSV_COLUMNS: list[str] = (
    ["timestamp", "url", "n", "total", "success_rate", "cache_bust", "reuse"]
    + [f"{stat}_{phase}"
       for phase in PHASES
       for stat in ("p50", "p95", "p99", "max")]
    + ["total_size"]
)


def format_csv(stats_list: list[SeriesStats]) -> str:
    """Return the CSV text (header + one row per URL) for a run."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUMNS)
    for stats in stats_list:
        writer.writerow(_csv_row(stats))
    return buf.getvalue()


def _csv_row(stats: SeriesStats) -> list[str]:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    row: list[str] = [
        ts, stats.url, str(stats.n), str(stats.total),
        f"{stats.success_rate:.4f}",
        str(stats.cache_bust), str(stats.reuse),
    ]
    for phase in PHASES:
        ps = stats.phases.get(phase)
        if ps is None:
            row += ["", "", "", ""]
        else:
            row += [f"{ps.p50:.6f}", f"{ps.p95:.6f}", f"{ps.p99:.6f}", f"{ps.max:.6f}"]
    row.append(str(stats.total_size))
    return row


def write_csv(stats_list: list[SeriesStats], path: str) -> None:
    """Append rows to the CSV if it exists (time-series accumulation), else create."""
    exists = os.path.exists(path) and os.path.getsize(path) > 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(_CSV_COLUMNS)
        for stats in stats_list:
            writer.writerow(_csv_row(stats))


# ── Prometheus ─────────────────────────────────────────────────────────────

_PROM_PHASES = ["dns", "connect", "tls", "server", "transfer", "total"]


def format_prometheus(stats_list: list[SeriesStats]) -> str:
    """Render runs in the Prometheus text exposition format."""
    lines: list[str] = []
    for stats in stats_list:
        labels_url = _prom_label(stats.url)
        for phase in _PROM_PHASES:
            ps = stats.phases.get(phase)
            if ps is None:
                continue
            name = f"srvtime_{phase}_seconds"
            lines.append(f"# HELP {name} {phase} phase response time")
            lines.append(f"# TYPE {name} summary")
            for q, val in (("0.5", ps.p50), ("0.9", ps.p90),
                           ("0.95", ps.p95), ("0.99", ps.p99)):
                lines.append(
                    f'{name}{{url={labels_url},quantile="{q}"}} {val:.6f}'
                )
            lines.append(f'{name}_count{{url={labels_url}}} {ps.n}')
            lines.append(f'{name}_sum{{url={labels_url}}} {ps.mean * ps.n:.6f}')

        for metric, ps in stats.server_timing.items():
            name = f"srvtime_server_timing_{_prom_metric_name(metric)}_milliseconds"
            lines.append(f"# HELP {name} Server-Timing metric {metric}")
            lines.append(f"# TYPE {name} summary")
            for q, val in (("0.5", ps.p50), ("0.9", ps.p90),
                           ("0.95", ps.p95), ("0.99", ps.p99)):
                lines.append(
                    f'{name}{{url={labels_url},quantile="{q}"}} {val:.6f}'
                )
            lines.append(f'{name}_count{{url={labels_url}}} {ps.n}')
            lines.append(f'{name}_sum{{url={labels_url}}} {ps.mean * ps.n:.6f}')

        sr_name = "srvtime_success_rate"
        lines.append(f"# HELP {sr_name} Fraction of requests that succeeded")
        lines.append(f"# TYPE {sr_name} gauge")
        lines.append(f'{sr_name}{{url={labels_url}}} {stats.success_rate:.4f}')
    return "\n".join(lines) + "\n"


def _prom_label(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def _prom_metric_name(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in name)
    if safe and safe[0].isdigit():
        safe = "_" + safe
    return safe


# ── PyShell structured events (sent once at end of run) ────────────────────


def emit_pyshell_events(stats_list: list[SeriesStats]) -> None:
    """Emit ``table``, ``chart`` and ``status`` events for the ResultView.

    Each event type is sent once, at the end, replacing any prior value (plan
    §5 M5). With one URL that's the detailed per-phase table/chart. With
    several URLs (``urls_extra``), sending one table/chart per URL
    would mean only the *last* one survives — table and chart replace, they
    don't accumulate — so multiple URLs are combined into a single table
    (one row per URL×phase) and a single chart (``total`` p50/p95 per URL)
    instead.
    """
    if not UNDER_PYSHELL or not stats_list:
        return
    if len(stats_list) == 1:
        stats = stats_list[0]
        emit(_table_event(stats))
        emit(_chart_event(stats))
        p95 = stats.phases.get("total")
        p95_txt = ms(p95.p95) if p95 else "—"
        emit({"type": "status", "message":
              f"srvtime: {stats.url} — {stats.n}/{stats.total} OK, p95 {p95_txt}"})
        return

    emit(_combined_table_event(stats_list))
    emit(_combined_chart_event(stats_list))
    ok = sum(1 for s in stats_list if s.n > 0)
    emit({"type": "status", "message":
          f"srvtime: {ok}/{len(stats_list)} targets measured"})


def _table_event(stats: SeriesStats) -> dict:
    rows: list[list[str]] = []
    for phase in PHASES:
        ps = stats.phases.get(phase)
        if ps is None:
            continue
        rows.append([phase, ms(ps.p50), ms(ps.p95), ms(ps.max)])
    return {
        "type": "table",
        "columns": ["phase", "p50", "p95", "max"],
        "rows": rows,
    }


def _combined_table_event(stats_list: list[SeriesStats]) -> dict:
    """One table row per URL×phase — the multi-URL alternative to _table_event."""
    rows: list[list[str]] = []
    for stats in stats_list:
        for phase in PHASES:
            ps = stats.phases.get(phase)
            if ps is None:
                continue
            rows.append([stats.url, phase, ms(ps.p50), ms(ps.p95), ms(ps.max)])
    return {
        "type": "table",
        "columns": ["URL", "phase", "p50", "p95", "max"],
        "rows": rows,
    }


def _combined_chart_event(stats_list: list[SeriesStats]) -> dict:
    """One bar per URL of the ``total`` phase — the multi-URL alternative to _chart_event."""
    labels: list[str] = []
    p50: list[float] = []
    p95: list[float] = []
    for stats in stats_list:
        total = stats.phases.get("total")
        labels.append(stats.url)
        p50.append(round(total.p50 * 1000, 2) if total is not None else 0.0)
        p95.append(round(total.p95 * 1000, 2) if total is not None else 0.0)
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": "total — p50 / p95 per target (ms)",
        "labels": labels,
        "series": [
            {"name": "p50", "values": p50},
            {"name": "p95", "values": p95},
        ],
    }


def _chart_event(stats: SeriesStats) -> dict:
    labels: list[str] = []
    p50: list[float] = []
    p95: list[float] = []
    for phase in PHASES:
        ps = stats.phases.get(phase)
        if ps is None:
            continue
        labels.append(phase)
        p50.append(round(ps.p50 * 1000, 2))
        p95.append(round(ps.p95 * 1000, 2))
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": f"{stats.url} — p50 / p95 by phase (ms)",
        "labels": labels,
        "series": [
            {"name": "p50", "values": p50},
            {"name": "p95", "values": p95},
        ],
    }


# ── Artifact writer ────────────────────────────────────────────────────────


def write_artifacts(
    stats_list: list[SeriesStats],
    output_dir: str,
    fmt: str,
) -> list[str]:
    """Write the artifact file(s) for the chosen format into ``output_dir``.

    Returns the paths written. ``human`` writes no artifact.
    """
    written: list[str] = []
    if fmt == "json":
        path = os.path.join(output_dir, "srvtime.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(format_json(stats_list))
        written.append(path)
    elif fmt == "csv":
        path = os.path.join(output_dir, "srvtime.csv")
        write_csv(stats_list, path)
        written.append(path)
    elif fmt == "prometheus":
        path = os.path.join(output_dir, "srvtime.prom")
        with open(path, "w", encoding="utf-8") as f:
            f.write(format_prometheus(stats_list))
        written.append(path)
    return written


def render_stdout(stats_list: list[SeriesStats], fmt: str) -> str:
    """Return the stdout text for the chosen format."""
    if fmt == "json":
        return format_json(stats_list)
    if fmt == "csv":
        return format_csv(stats_list)
    if fmt == "prometheus":
        return format_prometheus(stats_list)
    return format_human(stats_list)
