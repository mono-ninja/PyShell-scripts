"""ssh-log-check — entry point.

Thin argparse front for the src/ package; the logic lives in
`src.formats` (per-file format detection + line parsing),
`src.analysis` (aggregation, brute-force flags, the
failures-then-success chain), `src.geoip` (optional ip-api batch) and
`src.report` (markdown, fail2ban jail, events).
"""
from __future__ import annotations

import argparse
import os
import sys

from src.analysis import Analyzer
from src.events import emit, log, status
from src.formats import iter_log_files, parse_file
from src.geoip import fetch_geo
from src.report import (
    build_fail2ban_conf,
    build_markdown,
    build_table_event,
    write_artifacts,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SSH Log Check — brute-force IPs, tried users and "
                    "compromised-account wins from sshd logs")
    parser.add_argument("--logs-dir", required=True,
                        help="folder with the sshd logs (auth.log, secure, "
                             "journald JSON, macOS log-show text, .gz ok)")
    parser.add_argument("--whitelist", default="",
                        help="comma- or space-separated IPs to exclude")
    parser.add_argument("--bruteforce-threshold", type=int, default=5,
                        help="failed attempts per IP to flag it (default 5)")
    parser.add_argument("--top-n", type=int, default=20,
                        help="rows per table (default 20)")
    parser.add_argument("--skip-geoip", action="store_true",
                        help="fully offline run (no ip-api lookup)")
    parser.add_argument("--geoip-limit", type=int, default=100,
                        help="distinct IPs to geo-enrich (default 100)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files are read", flush=True)
        return 0

    logs_dir = args.logs_dir
    if not os.path.isdir(logs_dir):
        print(f"✗ {logs_dir!r} is not a folder", file=sys.stderr, flush=True)
        return 2

    whitelist = {ip.strip() for ip in
                 args.whitelist.replace(",", " ").split() if ip.strip()}

    files = list(iter_log_files(logs_dir))
    if not files:
        print(f"✗ no log files found in {logs_dir}", file=sys.stderr,
              flush=True)
        return 1

    analyzer = Analyzer(whitelist=whitelist,
                        bruteforce_threshold=args.bruteforce_threshold)
    total_lines = 0
    parsed_files = 0

    log(f"Analyzing {len(files)} file(s) from {logs_dir}")
    for i, path in enumerate(files, 1):
        name = os.path.basename(path)
        status(f"Parsing {name} ({i}/{len(files)})")
        emit({"type": "progress", "pct": int(5 + 90 * (i - 1) / len(files)),
              "message": f"{name}"})
        stats = parse_file(path, analyzer)
        total_lines += stats.lines
        if stats.matched or stats.lines == 0:
            parsed_files += 1
            kind = stats.format or "empty"
            log(f"  {name}: {stats.lines:,} line(s), "
                f"{stats.matched:,} sshd event(s) · {kind}")
        else:
            log(f"  {name}: {stats.lines:,} line(s), 0 sshd events · "
                f"skipped ({stats.format or 'unknown format'})")
    emit({"type": "progress", "pct": 95, "message": "Aggregating"})

    if analyzer.events == 0:
        print("✗ no sshd events found in any file — expected auth.log / "
              "secure / journald JSON / macOS log-show text with sshd "
              "messages", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Nothing to analyze\n\nNo sshd events were found in the "
              "given files. The parsers understand: Linux `auth.log` / "
              "`secure` (plain or `.gz`), `journalctl -u ssh -o json` "
              "exports, and macOS `log show` text."})
        return 1

    # Optional geo enrichment — the busiest offenders first, capped.
    geo: dict[str, dict] = {}
    if not args.skip_geoip:
        top_ips = analyzer.top_offender_ips(args.geoip_limit)
        if top_ips:
            status(f"GeoIP for {len(top_ips)} IP(s) via ip-api.com")
            geo = fetch_geo(top_ips)
            if not geo:
                log("  ⚠️ GeoIP lookup failed (offline?) — continuing "
                    "without it")

    report = build_markdown(analyzer, geo, args.top_n)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(analyzer, geo, args.top_n))
    emit({"type": "markdown", "content": report})
    write_artifacts(analyzer, geo, report,
                    build_fail2ban_conf(analyzer, args.top_n))

    wins = len(analyzer.compromised_candidates())
    summary = (f"{analyzer.events:,} events · "
               f"{len(analyzer.bruteforce_ips())} brute-force IP(s) · "
               f"{wins} success-after-failure chain(s)")
    status(summary)
    log(f"← {summary}")
    # Findings are results; a riddled log is exactly what the operator
    # came to see. Exit 0.
    return 0


if __name__ == "__main__":
    sys.exit(main())
