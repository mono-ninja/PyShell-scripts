#!/usr/bin/env python3
"""wp-audit/main.py — thin entry point; the rulebook lives in rules.yaml.

SAST over a WordPress site's **own code**: the themes and plugins in
`wp-content` (the default scan root when present — core is not your
code), against a curated rulebook of the signatures that matter —
SQLi, XSS, eval-obfuscation (the injected-malware classics), object
injection, SSRF, access-control gaps. Rules are **YAML data** in the
documented schema; bring your own with `--custom-rules`.

Reads files only: nothing is executed, nothing leaves the machine.

Exit codes: 0 = the scan ran (findings are results), 1 = no PHP files
to scan, 2 = bad arguments (unreadable folder, a malformed rule
file), 3 = the opt-in `--fail-on` CI gate.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from src.events import emit, log, status
from src.report import build_markdown, build_table_event, write_artifacts
from src.rules import RuleError, load_rules
from src.scanner import (
    iter_php_files, scan_file, scan_root_for, sort_findings,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WP Audit — SAST over a WordPress site's own code "
                    "(themes and plugins), rulebook as YAML data")
    parser.add_argument("--site-dir", required=True,
                        help="the site folder (wp-content is the default "
                             "scan root)")
    parser.add_argument("--whole-tree", action="store_true",
                        help="scan every PHP file, core included")
    parser.add_argument("--custom-rules", default="",
                        help="extra rules in the documented YAML schema")
    parser.add_argument("--max-files", type=int, default=20000,
                        help="safety cap on the file count")
    parser.add_argument("--fail-on", choices=["none", "critical", "any"],
                        default="none",
                        help="exit 3 gate for CI (default: findings are "
                             "not failures)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files are scanned", flush=True)
        return 0

    site_dir = Path(args.site_dir).resolve()
    if not site_dir.is_dir():
        print(f"✗ {args.site_dir!r} is not a folder", file=sys.stderr,
              flush=True)
        return 2

    try:
        rules = load_rules(args.custom_rules)
    except RuleError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    root = scan_root_for(site_dir, args.whole_tree)
    scan_label = str(root.relative_to(site_dir.parent)) \
        if root != site_dir else str(site_dir)

    status(f"Scanning {scan_label} with {len(rules)} rule(s)")
    emit({"type": "progress", "pct": 2,
          "message": f"collecting PHP files under {scan_label}"})
    files = iter_php_files(root, args.max_files)
    truncated = len(files) >= args.max_files
    if not files:
        print(f"✗ no PHP files under {scan_label}", file=sys.stderr,
              flush=True)
        emit({"type": "markdown", "content":
              f"## Nothing to scan\n\nNo PHP files under `{scan_label}`. "
              f"A WordPress site folder (with wp-content) or a plugin "
              f"folder is what this script reads."})
        return 1
    log(f"  {len(files)} PHP file(s) under {scan_label}"
        + (" (cap reached — partial scan)" if truncated else ""))

    findings = []
    for i, path in enumerate(files, 1):
        findings.extend(scan_file(path, root, rules))
        if i % 25 == 0 or i == len(files):
            emit({"type": "progress",
                  "pct": 2 + int(96 * i / len(files)),
                  "message": f"{i}/{len(files)} · {len(findings)} "
                             f"finding(s)"})

    findings = sort_findings(findings)
    report = build_markdown(scan_label, len(files), findings, truncated)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(findings))
    emit({"type": "markdown", "content": report})
    write_artifacts(scan_label, len(files), findings, report)

    critical = sum(1 for f in findings if f.severity == "critical")
    summary = (f"{len(findings)} finding(s) over {len(files)} file(s)"
               f" · {critical} critical")
    status(summary)
    log(f"← {summary}")
    if findings and args.fail_on == "any":
        return 3
    if critical and args.fail_on == "critical":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
