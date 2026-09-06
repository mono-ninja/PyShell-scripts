"""src/report.py — the live chart, the phase table, the degradation
report, the artifacts."""
from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import asdict

from .engine import RequestResult
from .phases import PhaseSpec

# Degradation thresholds — the report's vocabulary.
P95_FACTOR = 3.0        # phase p95 over 3× the baseline p95
ERROR_RATE_PCT = 5.0    # or errors over 5% of the phase's requests


def percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (p / 100) * (len(ordered) - 1)
    lo, hi = int(rank), min(int(rank) + 1, len(ordered) - 1)
    frac = rank - lo
    return ordered[lo] + (ordered[hi] - ordered[lo]) * frac


def phase_stats(results: list[RequestResult],
                phase_key: str) -> dict:
    """The per-phase numbers the table and thresholds read."""
    rows = [r for r in results if r.phase_key == phase_key]
    latencies = [r.latency_ms for r in rows if r.latency_ms is not None]
    errors = [r for r in rows if r.error or (r.status is not None
                                             and r.status >= 500)]
    span = (rows[-1].offset - rows[0].offset) if len(rows) > 1 else None
    return {
        "requests": len(rows),
        "ok": len(rows) - len(errors),
        "errors": len(errors),
        "error_pct": round(100 * len(errors) / len(rows), 1) if rows else 0.0,
        "p50_ms": round(percentile(latencies, 50), 1)
        if latencies else None,
        "p95_ms": round(percentile(latencies, 95), 1)
        if latencies else None,
        "max_ms": round(max(latencies), 1) if latencies else None,
        "achieved_rps": round(len(rows) / span, 1)
        if span and span > 0 else None,
    }


def degradation_findings(plan: list[PhaseSpec],
                         results: list[RequestResult]) -> list[str]:
    """Phase verdicts against the baseline. No baseline phase → no
    verdicts, just the honest note (handled by the caller)."""
    baseline_key = next((p.key for p in plan if p.key == "baseline"), None)
    findings: list[str] = []
    if baseline_key is None:
        return findings
    base_stats = phase_stats(results, baseline_key)
    base_p95 = base_stats["p95_ms"]
    for phase in plan:
        if phase.key == "baseline":
            continue
        stats = phase_stats(results, phase.key)
        if not stats["requests"]:
            continue
        reasons = []
        if base_p95 and stats["p95_ms"] and \
                stats["p95_ms"] > P95_FACTOR * base_p95:
            reasons.append(f"p95 {stats['p95_ms']:.0f} ms > "
                           f"{P95_FACTOR:.0f}× baseline "
                           f"({base_p95:.0f} ms)")
        if stats["error_pct"] > ERROR_RATE_PCT:
            reasons.append(f"error rate {stats['error_pct']}%")
        if reasons:
            findings.append(f"{phase.label}: " + "; ".join(reasons))
    return findings


def build_chart_event(results: list[RequestResult], t0: float) -> dict:
    """The live window: per-second average latency and request count —
    the whole chart every time (replaced wholesale)."""
    per_second: dict[int, list[RequestResult]] = defaultdict(list)
    for r in results:
        per_second[int(r.offset)].append(r)
    if not per_second:
        return {"type": "chart", "chart_type": "line", "title": "Load",
                "labels": [], "series": []}
    seconds = sorted(per_second)
    # A rolling window keeps the chart readable on long runs.
    window = seconds[-120:]
    labels = [f"{s}s" for s in window]
    latencies, counts = [], []
    for s in window:
        rows = per_second[s]
        vals = [r.latency_ms for r in rows if r.latency_ms is not None]
        latencies.append(round(sum(vals) / len(vals)) if vals else 0)
        counts.append(len(rows))
    return {
        "type": "chart",
        "chart_type": "line",
        "title": "Avg latency (ms) and req/s per second",
        "labels": labels,
        "series": [
            {"name": "latency ms", "values": latencies},
            {"name": "req/s", "values": counts},
        ],
    }


def build_table_event(plan: list[PhaseSpec],
                      results: list[RequestResult], target_rps: int) -> dict:
    rows = []
    for phase in plan:
        s = phase_stats(results, phase.key)
        rows.append([
            phase.label,
            s["requests"],
            f"{s['achieved_rps'] or '—'}/{target_rps}",
            f"{s['p50_ms']:.0f}" if s["p50_ms"] is not None else "—",
            f"{s['p95_ms']:.0f}" if s["p95_ms"] is not None else "—",
            f"{s['error_pct']}%",
        ])
    return {
        "type": "table",
        "columns": ["Phase", "Requests", "RPS (achieved/target)",
                    "p50 (ms)", "p95 (ms)", "Errors"],
        "rows": rows,
    }


def build_markdown(base: str, plan: list[PhaseSpec],
                   results: list[RequestResult], target_rps: int,
                   elapsed: float) -> str:
    findings = degradation_findings(plan, results)
    head = f"## {'🟠' if findings else '🟢'} " \
           f"{len(results)} request(s), {elapsed:.0f}s" \
           + (f" — {len(findings)} degradation flag(s)" if findings
              else " — no degradation flags")
    lines = [head, "", f"`{base}` · {target_rps} req/s target per phase",
             ""]

    lines += ["| Phase | Requests | RPS | p50 | p95 | Max | Errors |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for phase in plan:
        s = phase_stats(results, phase.key)
        lines.append(
            f"| {phase.label} | {s['requests']} | "
            f"{s['achieved_rps'] or '—'} | "
            f"{s['p50_ms'] or '—'} | {s['p95_ms'] or '—'} | "
            f"{s['max_ms'] or '—'} | {s['error_pct']}% |")
    lines.append("")

    if findings:
        lines += ["**Degradation flags**", ""]
        for f in findings:
            lines.append(f"- 🟠 {f}")
        lines += ["",
                  "_A flagged phase means the site's cost for that path "
                  "collapses under load (or its protection is shedding "
                  "it). Cache the expensive paths, or size the "
                  "origin/CDN for the real peak._", ""]
    else:
        lines += ["_No phase crossed the thresholds (p95 > "
                  f"{P95_FACTOR:.0f}× baseline, errors > "
                  f"{ERROR_RATE_PCT:.0f}%)._", ""]

    if not any(p.key == "baseline" for p in plan):
        lines.append("_No baseline phase in this plan — the degradation "
                     "thresholds need one; the numbers above stand "
                     "alone._")
        lines.append("")

    lines.append("_Measure the unloaded baseline with [Server Timing]"
                 "(../server-timing) (phase breakdown), watch the "
                 "requests' side of the story in your logs with "
                 "[Log Attack Checker](../log-attack-checker), and "
                 "re-run here after any caching change — before/after "
                 "is the whole point._")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(base: str, plan: list[PhaseSpec],
                    results: list[RequestResult], target_rps: int,
                    elapsed: float, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "target": base,
        "target_rps": target_rps,
        "elapsed_s": round(elapsed, 1),
        "plan": [p.key for p in plan],
        "phase_stats": {p.key: phase_stats(results, p.key)
                        for p in plan},
        "degradation": degradation_findings(plan, results),
        "requests": [asdict(r) for r in results],
    }
    with open(os.path.join(out_dir, "loadtest_results.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report + "\n")
