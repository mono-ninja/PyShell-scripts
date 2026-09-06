#!/usr/bin/env python3
"""load-test/main.py — thin entry point; the engine lives in src/.

Phased load against **a site you own**, at a rate you set. Each phase
holds a steady requests-per-second while the Results tab redraws a
live chart (the uptime-monitor pattern: the whole window, every
second — latency per second plus errors), and the final report grades
each phase against the baseline: p95 latency, error rate, achieved
rate, and the **degradation thresholds** (p95 over 3× baseline, or
errors over 5%).

The port of the NinjaLoadTest idea, reshaped for the collection's
contract:

- **Own target only.** Without `--i-own-this-target` the run refuses
  to start — loading a site you don't control is an attack, whatever
  the intent.
- **No credentials, ever.** The login phase fetches the login *page*
  (it's expensive — sessions, nonces) and never submits anything. The
  XML-RPC phase sends a minimal `system.listMethods` POST — no
  amplification payloads, no credential lists.
- **No locust.** A small purpose-built engine: `requests` in a worker
  pool, paced to the target rate — one dependency, full control over
  the events.

Exit codes: 0 = the plan ran (degradation is a finding), 1 = the
target never answered (nothing to load), 2 = bad arguments (no
ownership confirmation, impossible plan, empty custom paths).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib.parse import urlsplit, urlunsplit

import requests

from src.engine import RequestResult, run_phase, worker_session
from src.events import emit, log, status
from src.phases import PhaseSpec, build_plan
from src.report import (
    build_chart_event, build_markdown, build_table_event,
    degradation_findings, write_artifacts,
)

USER_AGENT = "PyShell-load-test/1.0"
MAX_PLAN_SECONDS = 1500   # the manifest timeout is 1800 — headroom


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_url(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return f"{url!r} is not a parsable URL"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return f"{url!r} needs a scheme and host (https://example.com/…)"
    return None


def normalize_base(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Load Test — phased load against a site you own, "
                    "at a rate you set")
    parser.add_argument("--url", required=True,
                        help="the target (yours)")
    parser.add_argument("--i-own-this-target", action="store_true",
                        help="the ownership contract — without it the "
                             "run refuses to start")
    parser.add_argument("--phase", action="append", default=[],
                        choices=["baseline", "search", "rest", "login",
                                 "xmlrpc", "custom"],
                        help="phase to run; repeatable (default "
                             "baseline+search)")
    parser.add_argument("--custom-paths", default="",
                        help="paths for the custom phase, one per line")
    parser.add_argument("--rps", type=int, default=10,
                        help="target requests per second (default 10)")
    parser.add_argument("--duration", type=int, default=30,
                        help="seconds per phase (default 30)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout (default 10)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no load is generated", flush=True)
        return 0

    if not args.i_own_this_target:
        print("✗ this script only loads targets you own. Re-run with "
              "--i-own-this-target (the form checkbox) to confirm — "
              "loading a site you don't control is an attack, whatever "
              "the intent.", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Refused\n\n⛔ This script generates real load. It "
              "only runs against a target you own or are explicitly "
              "permitted to load-test — confirm with "
              "**I own this target** and re-run."})
        return 2

    problem = validate_url(args.url)
    if problem:
        print(f"✗ {problem}", file=sys.stderr, flush=True)
        return 2
    base = normalize_base(args.url)

    custom_paths = [p.strip() for p in
                    (args.custom_paths or "").splitlines() if p.strip()]
    try:
        plan = build_plan(args.phase or ["baseline", "search"],
                          custom_paths)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    total_seconds = len(plan) * args.duration
    if total_seconds > MAX_PLAN_SECONDS:
        print(f"✗ the plan needs {total_seconds}s; the cap is "
              f"{MAX_PLAN_SECONDS}s ({len(plan)} phase(s) × "
              f"{args.duration}s). Lower --duration or drop phases.",
              file=sys.stderr, flush=True)
        return 2

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    # A single reachability check before generating any load.
    status(f"Pre-flight check on {base}")
    try:
        resp = session.get(base, timeout=args.timeout)
    except requests.RequestException as exc:
        print(f"✗ {base} never answered ({type(exc).__name__}) — there "
              "was nothing to load", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Refused\n\n❌ **{base}** didn't answer the pre-flight "
              f"GET ({type(exc).__name__}). Loading an unreachable "
              f"target is meaningless — fix reachability first "
              "([IP Search](../ip-search), [Server Timing]"
              "(../server-timing))."})
        return 1
    if resp.status_code >= 500:
        print(f"✗ {base} answered HTTP {resp.status_code} on the "
              "pre-flight GET — the site is already down; loading it "
              "further is not a test", file=sys.stderr, flush=True)
        return 1

    log(f"Pre-flight: HTTP {resp.status_code} in "
        f"{resp.elapsed.total_seconds() * 1000:.0f} ms — loading {base}")
    log(f"Plan: {len(plan)} phase(s) × {args.duration}s at "
        f"{args.rps} req/s = "
        f"{len(plan) * args.duration * args.rps} request(s) total")

    worker_session.configure(USER_AGENT)

    all_results: list[RequestResult] = []
    t0 = time.monotonic()
    for i, phase in enumerate(plan, 1):
        banner = f"Phase {i}/{len(plan)} — {phase.label} " \
                 f"({args.rps} req/s × {args.duration}s)"
        log(f"  ── {banner}")
        status(banner)

        def live_chart(done: list[RequestResult], phase_no=i) -> None:
            """The whole window, every second — the uptime-monitor
            pattern."""
            emit(build_chart_event(all_results + done, t0))

        results = run_phase(phase, base, args.rps, args.duration,
                            args.timeout,
                            progress=lambda pct, msg: emit(
                                {"type": "progress", "pct": pct,
                                 "message": f"{phase.label}: {msg}"}),
                            on_second=live_chart)
        all_results.extend(results)

    elapsed = time.monotonic() - t0
    report = build_markdown(base, plan, all_results, args.rps,
                            elapsed)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(plan, all_results, args.rps))
    emit({"type": "markdown", "content": report})
    write_artifacts(base, plan, all_results, args.rps, elapsed, report)

    findings = degradation_findings(plan, all_results)
    summary = (f"{len(all_results)} request(s) over {elapsed:.0f}s · "
               + (f"{len(findings)} degradation flag(s)"
                  if findings else "no degradation flags"))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
