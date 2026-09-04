#!/usr/bin/env python3
"""BotHunter - SEO Log Analyzer.

Detects bot activity, optimises crawl budget, and identifies scrapers/DDoS
patterns from web server logs.  Works as a PyShell script (structured events,
artifacts in PYSHELL_OUTPUT_DIR) and as a standalone CLI.

Usage:
    python main.py --domain example.com
    python main.py --logs-dir /var/log/nginx --domain example.com
    python main.py --domain example.com --format json
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

from src.events import (
    UNDER_PYSHELL, emit, status, progress, table, chart, markdown,
)
from src.parser import discover_log_files, LOG_EXTENSIONS
from src.analyzer import analyze_logs, build_google_rate_limit
from src.robots import build_robots_txt
from src.blocking import build_blocking_rules, write_blocking_files
from src.report import (
    write_json_report, write_html_report, build_markdown_report,
    build_bot_table, build_disguised_table, build_blocking_table,
    build_category_chart, build_status_chart,
)

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from src import __version__


# ─── Config ────────────────────────────────────────────────────

# Shipped default config; also the argparse default for --config.  A missing
# DEFAULT is a soft case (fresh checkout without config), a missing
# user-supplied path is a hard error.
_DEFAULT_CONFIG = 'botHunter_config.yaml'


def load_config(config_file: str = _DEFAULT_CONFIG) -> dict:
    """Load YAML config from *config_file*.

    Defaults to ``botHunter_config.yaml`` (the file that actually ships in
    this repo).  A missing user-supplied path is an error, not a silent
    fallback; a missing default config simply returns ``{}`` so the tool
    still runs with CLI flags only.
    """
    if not _YAML_AVAILABLE:
        # Warn if a config file exists but PyYAML is not installed.
        if Path(config_file).exists():
            print(f"Warning: '{config_file}' exists but PyYAML is not installed — "
                  f"config ignored.", file=sys.stderr)
        return {}
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        if config_file != _DEFAULT_CONFIG:   # explicitly supplied by the user
            print(f"Error: config file not found: {config_file}", file=sys.stderr)
            raise SystemExit(1)
        return {}


# ─── CLI ───────────────────────────────────────────────────────

def parse_args():
    ap = argparse.ArgumentParser(
        description='BotHunter - SEO Log Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python main.py --domain example.com                    HTML report
  python main.py --domain example.com --format json      JSON report
  python main.py --logs-dir /var/log/nginx -d site.com   custom logs folder
  python main.py --domain example.com --verbose          detailed output
""",
    )
    ap.add_argument("--logs-dir", "-l", default="logs", metavar="DIR",
                    help="Logs directory, scanned recursively (default: ./logs)")
    ap.add_argument("--domain", "-d", default=None, metavar="DOMAIN",
                    help="Domain to analyze (or set in config)")
    ap.add_argument("--output", "-o", default=None, metavar="FILE",
                    help="Output report path. The --format flag decides the content "
                         "(html/json); with --format both, both files are written "
                         "beside this path sharing its stem (default: <date>_<domain>.<ext>)")
    ap.add_argument("--format", "-f", choices=["html", "json", "both"], default=None,
                    help="Output format (default: html)")
    ap.add_argument("--max-lines", type=int, default=None, metavar="NUM",
                    help="Max lines per file (0 = unlimited)")
    ap.add_argument("--no-blocking", action="store_true",
                    help="Skip blocking rules generation")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Verbose output")
    ap.add_argument("--config", default=_DEFAULT_CONFIG, metavar="FILE",
                    help=f"Config file (default: {_DEFAULT_CONFIG})")
    ap.add_argument("--version", action="version", version=f"BotHunter {__version__}")
    return ap.parse_args()


# ─── Main ──────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()

    # Introspection builds the form from argparse; no logs are read.
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no logs read", flush=True)
        return 0

    # Configure logging so per-file read errors from analyzer.py are visible.
    # Under PyShell, keep it stderr-only (PyShell parses stderr for events).
    logging.basicConfig(
        level=logging.WARNING,
        format='%(levelname)s: %(message)s',
        stream=sys.stderr,
    )
    config = load_config(args.config)

    domain = args.domain or config.get('domain')
    if not domain:
        print("Error: domain required - use --domain or set 'domain' in config",
              file=sys.stderr)
        return 1

    fmt = args.format or config.get('format', 'html')
    max_lines = args.max_lines if args.max_lines is not None else int(config.get('max_lines', 0))
    generate_blocking = not args.no_blocking

    # Output directory: PYSHELL_OUTPUT_DIR under PyShell, reports/ otherwise
    output_dir = Path(os.environ.get('PYSHELL_OUTPUT_DIR', 'reports'))
    if not UNDER_PYSHELL:
        output_dir.mkdir(exist_ok=True)

    # ── Find log files ──
    logs_dir = Path(args.logs_dir)
    if not logs_dir.exists():
        print(f"Error: directory not found: {logs_dir.resolve()}", file=sys.stderr)
        return 1

    status("Discovering log files...")
    log_files, skipped_files = discover_log_files(logs_dir)
    if not log_files:
        print(f"No log files found in '{logs_dir}'. "
              f"Supported: {', '.join(sorted(LOG_EXTENSIONS))}", file=sys.stderr)
        return 1

    total_size = sum(f.stat().st_size for f in log_files)
    print(f"Domain: {domain}", flush=True)
    print(f"Log files: {len(log_files)} ({total_size / 1024 / 1024:.2f} MB)", flush=True)
    if skipped_files:
        print(f"Skipped {skipped_files} non-log file(s) in '{logs_dir}'", flush=True)
    status(f"Found {len(log_files)} log files ({total_size / 1024 / 1024:.1f} MB)")

    if args.verbose:
        for f in log_files:
            kb = f.stat().st_size / 1024
            print(f"  {kb:.1f} KB  {f.relative_to(logs_dir)}", flush=True)

    # ── Analyse (parsing 0-80%, detection 80-85%) ──
    def progress_cb(pct: float, msg: str) -> None:
        progress(pct, msg)

    try:
        stats = analyze_logs(
            log_files,
            max_lines=max_lines,
            progress_callback=progress_cb,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 1

    # ── Post-analysis: rate limit, robots.txt, blocking rules (85-95%) ──
    progress(86, "Building Google rate-limit analysis")
    stats['google_rate_limit'] = build_google_rate_limit(stats['bots'])

    progress(89, "Generating robots.txt recommendations")
    stats['robots_txt'] = build_robots_txt(stats['bots'], stats['top_404_urls'], domain=domain)

    generated_at = datetime.now().isoformat()

    if generate_blocking:
        progress(92, "Building blocking rules")
        conf_fname = f"{domain}_block.conf"
        stats['blocking_rules'] = build_blocking_rules(
            stats['bots'],
            stats['disguised_bots'],
            stats['suspicious_subnets'],
            domain=domain,
            generated_at=generated_at,
            conf_filename=conf_fname,
        )

    progress(94, "Writing reports")

    report = {
        'meta': {
            'domain':       domain,
            'generated_at': generated_at,
            'version':      __version__,
            'logs_dir':     str(logs_dir.resolve()),
            'log_files':    [str(f.relative_to(logs_dir)) for f in log_files],
        },
        'stats': stats,
    }

    # ── Write artifacts ──
    # --format decides WHAT is written; --output decides WHERE.  With
    # --format both, both reports are written beside --output sharing its
    # stem.  An explicit extension/format conflict gets a warning instead of
    # the old silent behaviour where the extension overrode --format.
    artifacts: list[Path] = []
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_dir = output_path.parent
        base_name = output_path.stem
        ext = output_path.suffix.lower()
        if fmt == 'both':
            html_path = artifact_dir / f"{base_name}.html"
            json_path = artifact_dir / f"{base_name}.json"
            write_html_report(report, html_path)
            write_json_report(report, json_path)
            artifacts.extend([html_path, json_path])
            if ext not in ('', '.json', '.html'):
                print(f"Warning: --output extension '{ext}' ignored for --format both; "
                      f"wrote '{html_path.name}' and '{json_path.name}' from its stem",
                      file=sys.stderr)
        else:
            if ext in ('.json', '.html') and ext != f'.{fmt}':
                print(f"Warning: --output extension '{ext}' does not match "
                      f"--format {fmt}; the {fmt} report is written to '{output_path}'",
                      file=sys.stderr)
            if fmt == 'json':
                write_json_report(report, output_path)
            else:
                write_html_report(report, output_path)
            artifacts.append(output_path)
    else:
        artifact_dir = output_dir
        base_name = f"{datetime.now().strftime('%Y-%m-%d')}_{domain}"
        if fmt in ('html', 'both'):
            html_path = artifact_dir / f"{base_name}.html"
            write_html_report(report, html_path)
            artifacts.append(html_path)

        if fmt in ('json', 'both'):
            json_path = artifact_dir / f"{base_name}.json"
            write_json_report(report, json_path)
            artifacts.append(json_path)

    if generate_blocking and stats.get('blocking_rules'):
        blocking = stats['blocking_rules']
        if (blocking.get('blocked_ips') or blocking.get('blocked_subnets')
                or blocking.get('blocked_uas')):
            base_path = artifact_dir / base_name
            nginx_path, htaccess_path = write_blocking_files(blocking, base_path)
            artifacts.extend([nginx_path, htaccess_path])

    robots = stats.get('robots_txt', {})
    if robots.get('content'):
        robots_path = artifact_dir / f"{base_name}.robots.txt"
        with open(robots_path, 'w', encoding='utf-8') as f:
            f.write(robots['content'])
        artifacts.append(robots_path)

    # ── Emit PyShell structured results (95-100%) ──
    progress(96, "Building result tables")

    # Bot activity table
    bot_tbl = build_bot_table(stats)
    if bot_tbl:
        table(bot_tbl['columns'], bot_tbl['rows'])

    # Disguised bots table
    dis_tbl = build_disguised_table(stats)
    if dis_tbl:
        table(dis_tbl['columns'], dis_tbl['rows'])

    # Blocking rules table
    blk_tbl = build_blocking_table(stats)
    if blk_tbl:
        table(blk_tbl['columns'], blk_tbl['rows'])

    # Category distribution chart
    cat_chart = build_category_chart(stats)
    if cat_chart:
        chart(cat_chart['chart_type'], cat_chart['title'],
              cat_chart['labels'], cat_chart['series'])

    # Status codes chart
    st_chart = build_status_chart(stats)
    if st_chart:
        chart(st_chart['chart_type'], st_chart['title'],
              st_chart['labels'], st_chart['series'])

    # Markdown report
    progress(98, "Building markdown report")
    md_report = build_markdown_report(report)
    markdown(md_report)

    # ── Done ──
    progress(100, "Done")
    status(f"Analyzed {stats['total_requests']:,} requests from {len(log_files)} files")

    # Print artifact paths to stdout
    for a in artifacts:
        print(f"Wrote {a}", flush=True)

    # Brief CLI summary
    bot_pct = stats['bot_requests'] / stats['total_requests'] * 100 if stats['total_requests'] else 0
    print(f"\nTotal: {stats['total_requests']:,} | "
          f"Bots: {stats['bot_requests']:,} ({bot_pct:.1f}%) | "
          f"Unique bots: {len(stats['bots'])}", flush=True)
    if stats.get('disguised_bot_requests'):
        print(f"Disguised bots: {stats['disguised_bot_requests']:,} requests", flush=True)
    if stats.get('skipped_files'):
        print(f"Skipped files: {len(stats['skipped_files'])} (see stderr for details)",
              flush=True)

    return 0


if __name__ == '__main__':
    sys.exit(main())
