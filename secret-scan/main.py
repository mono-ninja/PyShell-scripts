#!/usr/bin/env python3
"""secret-scan/main.py — thin entry point; the rulebook lives in
rules.yaml.

Credential leaks in a codebase or config folder: AWS keys, GitHub/
GitLab/npm tokens, Slack and Telegram tokens, Google and Stripe keys,
SendGrid, private key PEMs, credentials inside URLs and database
URLs, framework SECRET_KEYs, generic secret assignments, committed
`.env` files — against the curated rulebook (the wp-audit engine,
YAML rules; bring your own with `--custom-rules`).

Two modes, one engine and one masking contract:

- **working tree** (default) — the files you are about to commit;
  `.git` itself, lockfiles and dependency dirs are skipped.
- **history** — every line ever *added*, walked via the system
  `git log --all -p` (streamed, commit-attributed): the rotated key
  removed three commits ago still lives in every clone. Same rules,
  same masking, merge commits not diffed, lockfile noise skipped.

The masking contract: every finding is masked at capture time —
`AKIAIO…(+14 chars)` — so no log, table, report or artifact ever
repeats the secret it found.

Exit codes: 0 = the scan ran (findings are results, and they are
masked), 1 = nothing scannable under the target, 2 = bad arguments
(unreadable folder, a malformed rule file, history mode outside a
git repo), 3 = the opt-in `--fail-on` CI gate.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from src.events import emit, log, status
from src.history import (
    DEFAULT_MAX_COMMITS,
    GitUnavailable,
    NotAGitRepo,
    dedup_history,
    scan_history,
)
from src.report import build_markdown, build_table_event, write_artifacts
from src.rules import RuleError, load_rules
from src.scanner import iter_text_files, scan_file, sort_findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secret Scan — credential leaks in a codebase or "
                    "config folder, rulebook as YAML data, findings "
                    "masked everywhere")
    parser.add_argument("--target", required=True,
                        help="the folder to scan")
    parser.add_argument("--mode", choices=["tree", "history"],
                        default="tree",
                        help="working tree (default) or the full git "
                             "history (every line ever added, "
                             "commit-attributed)")
    parser.add_argument("--max-commits", type=int,
                        default=DEFAULT_MAX_COMMITS,
                        help="history mode: safety cap on the commit "
                             "count (default 5000)")
    parser.add_argument("--custom-rules", default="",
                        help="extra rules in the documented YAML schema")
    parser.add_argument("--max-files", type=int, default=20000,
                        help="safety cap on the file count (tree mode)")
    parser.add_argument("--fail-on", choices=["none", "critical", "any"],
                        default="none",
                        help="exit 3 gate for CI (default: findings are "
                             "not failures)")
    return parser


def run_tree(target: Path, rules, args) -> tuple[list, int, list[str],
                                                 int | None]:
    files, notes = iter_text_files(target, args.max_files)
    truncated = any("cap" in n for n in notes)
    if not files:
        return [], 0, notes, None
    log(f"  {len(files)} file(s) under {target}"
        + (" (cap reached — partial scan)" if truncated else ""))
    findings = []
    for i, path in enumerate(files, 1):
        findings.extend(scan_file(path, target, rules))
        if i % 50 == 0 or i == len(files):
            emit({"type": "progress",
                  "pct": 2 + int(96 * i / len(files)),
                  "message": f"{i}/{len(files)} · {len(findings)} "
                             f"finding(s)"})
    return sort_findings(findings), len(files), notes, None


def run_history(target: Path, rules, args) -> tuple[list, int, list[str],
                                                    int | None]:
    result = scan_history(target, rules, args.max_commits)
    findings = dedup_history(result.findings)
    findings = sort_findings(findings)
    notes = result.notes
    if result.truncated:
        notes.insert(0, result.notes[0])
    log(f"  {result.commits} commit(s) · {result.added_lines} added "
        f"line(s) · {len(findings)} unique finding(s)")
    return findings, 0, notes, result.commits


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files are scanned", flush=True)
        return 0

    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"✗ {args.target!r} is not a folder", file=sys.stderr,
              flush=True)
        return 2

    try:
        rules = load_rules(args.custom_rules)
    except RuleError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    history = args.mode == "history"
    status(f"Scanning {target} ({args.mode}) with {len(rules)} rule(s)")
    emit({"type": "progress", "pct": 2,
          "message": f"collecting {'commits' if history else 'files'} "
                     f"under {target}"})

    try:
        if history:
            findings, files_scanned, notes, commits = run_history(
                target, rules, args)
        else:
            findings, files_scanned, notes, commits = run_tree(
                target, rules, args)
    except (NotAGitRepo, GitUnavailable) as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Cannot scan the history\n\n❌ {exc}"})
        return 2 if isinstance(exc, NotAGitRepo) else 1

    if not history and files_scanned == 0:
        print(f"✗ no scannable files under {target}", file=sys.stderr,
              flush=True)
        emit({"type": "markdown", "content":
              f"## Nothing to scan\n\nNo text files under `{target}` "
              f"(after the documented skips: .git, lockfiles, "
              f"dependency dirs, binary-looking files)."})
        return 1

    report = build_markdown(str(target), files_scanned, findings,
                            notes, history=history,
                            commits=commits or 0)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(findings, history=history))
    emit({"type": "markdown", "content": report})
    write_artifacts(str(target), files_scanned, findings, notes,
                    report, history=history, commits=commits or 0)

    critical = sum(1 for f in findings if f.severity == "critical")
    scope = (f"{commits} commit(s)" if history
             else f"{files_scanned} file(s)")
    summary = (f"{len(findings)} finding(s) over {scope} · "
               f"{critical} critical · all masked")
    status(summary)
    log(f"← {summary}")
    if findings and args.fail_on == "any":
        return 3
    if critical and args.fail_on == "critical":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
