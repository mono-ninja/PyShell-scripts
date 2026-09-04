#!/usr/bin/env python3
"""log-attack-checker/main.py — thin CLI entry point.

Apache/Nginx access log security analyzer for WordPress sites: parses raw
logs in parallel across CPU cores, classifies attack patterns, detects
coordinated threats (brute force, floods, attack chains, compromised
accounts) and writes HTML/Markdown/JSON reports with a server-hardening
plan. All logic lives in ``src/`` — this file only parses arguments and
calls ``analyze_logs``.

Under PyShell (``PYSHELL_OUTPUT_DIR`` set) progress/table/chart/markdown
events are streamed on stderr and the three reports go to the artifacts
directory. Exit codes:

* ``0`` — analysis finished (attacks found are a result, not a failure);
* ``1`` — fatal error: logs directory missing or no ``.log`` files found;
* ``2`` — invalid arguments (argparse usage error, e.g. a threshold below its
  minimum — see ``validate_args``).
"""
import argparse
import os
import sys

from src.analysis import analyze_logs


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ninjaLog",
        description="Apache/Nginx access log security analyzer for WordPress sites",
    )
    p.add_argument("-d", "--logs-dir", default="logs", help="Directory with .log files (default: logs)")
    p.add_argument("-o", "--output-dir", default=".", help="Output directory for reports (default: .)")
    p.add_argument("-s", "--site", default="", help="Site domain or URL (e.g. example.com) — used in cURL commands; IP is auto-resolved and shown in terminal, excluded from reports")
    p.add_argument("-w", "--whitelist", nargs="*", metavar="IP", default=[], help="IP addresses to exclude from analysis — space- or comma-separated (e.g. -w 1.2.3.4 5.6.7.8 or -w 1.2.3.4,5.6.7.8)")
    p.add_argument("--bruteforce-threshold", type=int, default=5, help="401s within window to flag brute force")
    p.add_argument("--wp-login-post-threshold", type=int, default=10, help="POSTs to wp-login.php within window")
    p.add_argument("--notfound-flood-threshold", type=int, default=50, help="404s within window to flag scanner")
    p.add_argument("--wp-cron-flood-threshold", type=int, default=20, help="wp-cron.php hits within window")
    p.add_argument("--attack-chain-min-vectors", type=int, default=3, help="Min distinct WP attack types for chain")
    p.add_argument("--time-window-minutes", type=int, default=5, help="Sliding window in minutes")
    p.add_argument("--rate-limit-threshold", type=int, default=100, help="Requests per window to flag rate limit")
    p.add_argument("--geoip-limit", type=int, default=20, help="Max IPs for GeoIP lookup")
    p.add_argument("--skip-geoip", action="store_true", help="Skip GeoIP lookups")
    p.add_argument("--large-response-bytes", type=int, default=100000, help="Response size threshold for exfiltration")
    p.add_argument("--attack-burst-factor", type=float, default=10.0, help="Multiplier over avg for burst detection")
    return p


# (M2) Minimum accepted value for every numeric knob, as (dest, flag, min).
# Zero/negative thresholds flip detector semantics from "N events in the
# window" to ">= 1 event ever" — every IP with a single matching request gets
# flagged and the report silently turns into garbage. These floors mirror the
# min bounds pyshell.yaml already enforces on the generated form, so a direct
# CLI run cannot go below what the form allows.
ARG_MINIMUMS = (
    ("bruteforce_threshold", "--bruteforce-threshold", 1),
    ("wp_login_post_threshold", "--wp-login-post-threshold", 1),
    ("notfound_flood_threshold", "--notfound-flood-threshold", 1),
    ("wp_cron_flood_threshold", "--wp-cron-flood-threshold", 1),
    ("attack_chain_min_vectors", "--attack-chain-min-vectors", 1),
    ("time_window_minutes", "--time-window-minutes", 1),
    ("rate_limit_threshold", "--rate-limit-threshold", 1),
    ("geoip_limit", "--geoip-limit", 1),
    ("large_response_bytes", "--large-response-bytes", 1),
    ("attack_burst_factor", "--attack-burst-factor", 1.0),
)


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject thresholds below their floor with a usage error (exit 2)."""
    for dest, flag, minimum in ARG_MINIMUMS:
        value = getattr(args, dest)
        if value < minimum:
            parser.error(f"{flag} must be >= {minimum} (got {value}); "
                         f"lower values invert detector semantics")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    # Introspection imports the module and runs it; skip the heavy work so the
    # schema can be extracted within the time budget.
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        return 0
    validate_args(parser, args)
    return 0 if analyze_logs(args) else 1


if __name__ == "__main__":
    sys.exit(main())
