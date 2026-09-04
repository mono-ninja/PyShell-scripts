#!/usr/bin/env python3
"""srvtime — main.py: argparse, series orchestration, exit codes.

PyShell entry point. Runs as ``python main.py`` (how PyShell launches it) and
as a plain CLI. The implementation lives in the :mod:`src` package; this file
only wires arguments to it, drives the series, and emits PyShell events.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from src import errors, output, probe, stats
from src.probe import ProbeConfig, Prober

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ALL_FAILED = 2
EXIT_ARG_ERROR = 3

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ


# ── argparse with exit code 3 for argument errors ──────────────────────────


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):
        sys.stderr.write(f"error: {message}\n\n")
        self.print_usage(sys.stderr)
        sys.exit(EXIT_ARG_ERROR)


def parse_args(argv=None) -> argparse.Namespace:
    p = _Parser(
        prog="srvtime",
        description="Measure server response time with phase breakdown and percentiles.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("urls", nargs="*",
                   help="one or more target URLs")
    p.add_argument("-n", "--count", type=int, default=20, metavar="N",
                   help="number of measurements (default: 20)")
    p.add_argument("-w", "--warmup", type=int, default=3, metavar="K",
                   help="warmup requests, not counted (default: 3)")
    p.add_argument("--delay", type=float, default=0.2, metavar="SEC",
                   help="pause between requests in seconds (default: 0.2)")
    p.add_argument("--cache-bust", action="store_true",
                   help="add a random ?_cb=<uuid> query parameter")
    p.add_argument("--reuse", action="store_true",
                   help="reuse the connection (keep-alive) instead of a fresh\n"
                        "one per request")
    p.add_argument("--gzip", action="store_true",
                   help="allow gzip-compressed responses (default: identity)")
    p.add_argument("--method", choices=["GET", "HEAD", "POST"], default="GET",
                   help="HTTP method (default: GET)")
    p.add_argument("--header", action="append", default=[], metavar="'K: V'",
                   help="custom request header, repeatable")
    p.add_argument("--headers-file", default=None, metavar="FILE",
                   help="file with one 'K: V' header per line")
    p.add_argument("--urls-file", default=None, metavar="FILE",
                   help="file with additional URLs, one per line")
    p.add_argument("--data", default=None, metavar="FILE",
                   help="request body read from FILE (no @ prefix)")
    p.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                   help="per-request timeout in seconds (default: 10)")
    p.add_argument("--insecure", action="store_true",
                   help="skip TLS certificate verification")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--ipv4", action="store_true", help="force IPv4")
    g.add_argument("--ipv6", action="store_true", help="force IPv6")
    p.add_argument("--format", choices=["human", "json", "csv", "prometheus"],
                   default="human", help="output format (default: human)")
    p.add_argument("--threshold-p95", type=float, default=None, metavar="MS",
                   help="exit 1 if p95 of total exceeds this many milliseconds")
    return p.parse_args(argv)


# ── Helpers ────────────────────────────────────────────────────────────────


def _read_lines(path: str) -> list[str]:
    lines: list[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    return lines


def _collect_urls(args) -> list[str]:
    urls: list[str] = list(args.urls)
    if args.urls_file:
        urls.extend(_read_lines(args.urls_file))
    seen: set[str] = set()
    ordered: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


def _collect_headers(args) -> dict[str, str]:
    raw: list[str] = list(args.header)
    if args.headers_file:
        raw.extend(_read_lines(args.headers_file))
    headers: dict[str, str] = {}
    for line in raw:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def _build_path(base_path: str, cache_bust: bool) -> str:
    if not cache_bust:
        return base_path
    parts = urlsplit(base_path)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query.append(("_cb", uuid4().hex))
    return urlunsplit(("", "", parts.path, urlencode(query), parts.fragment))


def _make_reporter(total: int, url: str, base_pct: int, span: int):
    """Progress reporter that emits at most once per whole percent.

    PyShell keeps one progress bar: with several URLs each one maps onto a
    slice of the 0–100 bar so the percentage keeps climbing instead of
    resetting per URL.
    """
    last = -1

    def report(done: int) -> None:
        nonlocal last
        frac = done / total if total else 1.0
        pct = int(base_pct + span * frac)
        if pct == last:
            return
        last = pct
        output.emit({"type": "progress", "pct": pct,
                     "message": f"{done}/{total} · {url}"})

    return report


def _noop_report(_done: int) -> None:
    pass


# ── Series ─────────────────────────────────────────────────────────────────


def run_series(
    prober: Prober,
    *,
    count: int,
    warmup: int,
    delay: float,
    reuse: bool,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    cache_bust: bool,
    report,
) -> list[probe.Result]:
    """Run warmup + measured series for one URL. Never raises."""
    results: list[probe.Result] = []
    total_attempts = warmup + count
    early_fails = 0

    for i in range(total_attempts):
        is_warmup = i < warmup
        path = _build_path(prober.base_path, cache_bust)
        result = prober.probe(
            method=method, path=path, headers=headers,
            body=body, reuse=reuse,
        )
        attempt = i + 1

        if attempt <= 3 and result.error is not None:
            early_fails += 1

        if not is_warmup:
            results.append(result)
            report(len(results))

        # Abort early only if the first 3 attempts all failed — a wrong URL or
        # an unreachable host produces exactly this pattern.
        if attempt == 3 and early_fails == 3:
            break

        if i < total_attempts - 1:
            time.sleep(delay)

    return results


# ── main ───────────────────────────────────────────────────────────────────


def main(argv=None) -> int:
    args = parse_args(argv)

    # PyShell introspection: parse args, then exit before any network I/O (M0).
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        return EXIT_OK

    urls = _collect_urls(args)
    if not urls:
        sys.stderr.write("error: at least one URL is required\n")
        return EXIT_ARG_ERROR

    headers = _collect_headers(args)
    body: bytes | None = None
    if args.data:
        try:
            body = Path(args.data).read_bytes()
        except OSError as exc:
            sys.stderr.write(f"error: cannot read --data file: {exc}\n")
            return EXIT_ARG_ERROR

    config = ProbeConfig(
        timeout=args.timeout,
        insecure=args.insecure,
        ipv4=args.ipv4,
        ipv6=args.ipv6,
        gzip=args.gzip,
    )

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    all_stats: list[stats.SeriesStats] = []
    any_success = False

    # Each URL owns an equal slice of the 0–100 bar so progress is monotonic
    # across the whole run instead of resetting per URL.
    span = 100 / len(urls) if urls else 100

    for idx, url in enumerate(urls):
        base_pct = int(idx * span)
        if UNDER_PYSHELL:
            output.emit({"type": "status", "message": f"srvtime → {url}"})
        try:
            prober = Prober(url, config)
        except errors.SrvtimeError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return EXIT_ARG_ERROR

        report = (
            _make_reporter(args.count, url, base_pct, int(span))
            if UNDER_PYSHELL else _noop_report
        )
        if UNDER_PYSHELL:
            report(0)

        results = run_series(
            prober,
            count=args.count,
            warmup=args.warmup,
            delay=args.delay,
            reuse=args.reuse,
            method=args.method,
            headers=headers,
            body=body,
            cache_bust=args.cache_bust,
            report=report,
        )
        prober.close()

        series = stats.aggregate(
            results, url=url, cache_bust=args.cache_bust, reuse=args.reuse,
        )
        all_stats.append(series)
        if series.n > 0:
            any_success = True

        if UNDER_PYSHELL:
            report(args.count)

    # stdout output (and artifact files) for the chosen format.
    text = output.render_stdout(all_stats, args.format)
    if text:
        print(text)
    output.write_artifacts(all_stats, output_dir, args.format)

    # PyShell structured events: table, chart, status — once, at the end.
    output.emit_pyshell_events(all_stats)
    if UNDER_PYSHELL:
        output.emit({"type": "progress", "pct": 100, "message": "Done"})

    # Exit codes.
    if not any_success:
        return EXIT_ALL_FAILED
    if args.threshold_p95 is not None:
        for s in all_stats:
            phase = s.phases.get("total")
            if phase is not None and phase.p95 * 1000 > args.threshold_p95:
                return EXIT_THRESHOLD
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
