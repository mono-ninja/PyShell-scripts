"""Percentiles and aggregation for a series of measurements.

Nearest-rank percentiles (no interpolation): rank = ceil(P/100 * N), value =
sorted[rank-1]. This is transparent on small samples — p50 of two values is the
smaller one, not an invented midpoint. p50/p90/p95/p99, min, max,
sample stdev and mean are computed; the mean is reported but always after the
percentiles since it hides the tail.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .probe import Result

# Phase order matches the human table. ``tls`` is None for http://.
PHASES: list[str] = ["dns", "connect", "tls", "server", "transfer", "total"]

# Percentiles reported; p50/p95 are the headline numbers, p90/p99 available to
# the machine-readable formats.
PERCENTILES: list[float] = [50, 90, 95, 99]


@dataclass(frozen=True)
class PhaseStats:
    """Aggregate of a single phase (or Server-Timing metric) across a series."""

    n: int
    min: float
    max: float
    mean: float
    stdev: float
    p50: float
    p90: float
    p95: float
    p99: float


@dataclass(frozen=True)
class SeriesStats:
    """Aggregate of one URL's series."""

    url: str
    n: int                       # successful measurements
    total: int                   # all attempts (success + failure)
    success_rate: float
    status_codes: dict[int, int]
    phases: dict[str, PhaseStats | None]
    server_timing: dict[str, PhaseStats]
    total_size: int              # bytes summed over successful results
    cache_bust: bool
    reuse: bool
    small_sample: bool           # True when n < 10 — percentiles not representative


# ── Pure helpers ───────────────────────────────────────────────────────────


def percentile(values: list[float], p: float) -> float | None:
    """Nearest-rank percentile of a list of floats.

    Returns None for an empty list. The input is sorted in place defensively.
    """
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    rank = math.ceil(p / 100.0 * n)
    if rank < 1:
        rank = 1
    elif rank > n:
        rank = n
    return ordered[rank - 1]


def phase_stats(values: list[float]) -> PhaseStats | None:
    """Build :class:`PhaseStats` from a list of phase durations (seconds)."""
    if not values:
        return None
    n = len(values)
    mean = sum(values) / n
    if n >= 2:
        var = sum((v - mean) ** 2 for v in values) / (n - 1)
        stdev = math.sqrt(var)
    else:
        stdev = 0.0
    return PhaseStats(
        n=n,
        min=min(values),
        max=max(values),
        mean=mean,
        stdev=stdev,
        p50=percentile(values, 50) or 0.0,
        p90=percentile(values, 90) or 0.0,
        p95=percentile(values, 95) or 0.0,
        p99=percentile(values, 99) or 0.0,
    )


def _phase_values(results: list[Result], phase: str) -> list[float]:
    """Extract a phase's values from successful results."""
    out: list[float] = []
    for r in results:
        if r.error is not None:
            continue
        value = getattr(r.timing, phase)
        if value is None:
            continue
        out.append(float(value))
    return out


# ── Aggregation ────────────────────────────────────────────────────────────


def aggregate(
    results: list[Result],
    *,
    url: str,
    cache_bust: bool,
    reuse: bool,
) -> SeriesStats:
    """Aggregate a series of :class:`Result` into :class:`SeriesStats`.

    Failed results (``error`` set) are excluded from phase/metric statistics but
    counted in ``total`` and ``success_rate``.
    """
    total = len(results)
    successful = [r for r in results if r.error is None]
    n = len(successful)

    status_codes: dict[int, int] = {}
    for r in results:
        if r.error is not None:
            continue
        status_codes[r.status] = status_codes.get(r.status, 0) + 1

    phases: dict[str, PhaseStats | None] = {}
    for phase in PHASES:
        values = _phase_values(successful, phase)
        phases[phase] = phase_stats(values)

    # Server-Timing: gather each metric across the successful results that had it.
    metric_values: dict[str, list[float]] = {}
    for r in successful:
        for name, dur in r.server_timing.items():
            metric_values.setdefault(name, []).append(dur)
    server_timing = {
        name: ps
        for name, values in metric_values.items()
        if (ps := phase_stats(values)) is not None
    }

    total_size = sum(r.size for r in successful)

    return SeriesStats(
        url=url,
        n=n,
        total=total,
        success_rate=(n / total) if total else 0.0,
        status_codes=status_codes,
        phases=phases,
        server_timing=server_timing,
        total_size=total_size,
        cache_bust=cache_bust,
        reuse=reuse,
        small_sample=n < 10,
    )


def p95_of_total(stats: SeriesStats) -> float | None:
    """p95 of the ``total`` phase in seconds, or None if no successful runs."""
    phase = stats.phases.get("total")
    return phase.p95 if phase is not None else None
