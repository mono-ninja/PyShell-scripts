"""src/scanner.py — file discovery and the rule engine.

Every text file under the target is a subject (secrets hide in
configs, scripts, docs as much as in code). Skipped by name:
dependency and cache dirs, and the lockfiles — their integrity
hashes are false-positive factories, not leaks. `.git` is skipped
too: **history** scanning (an old commit still holds the rotated
key) is a job for dedicated tools; this script reads the working
tree you are about to commit.

The masking contract: the finding's `line_text` carries the trigger
line with the secret's span (match group `mask_group`) replaced by
`first-chars…(+N)`. The full value never enters a Finding, so no
report, log or artifact can repeat the leak.

Files that look binary (a NUL in the first 8 KB) or are huge
(> 5 MB) are skipped with a note — minified bundles are data, not
config.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .rules import Rule, SEVERITY_ORDER

SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor",
             "__pycache__", ".idea", ".venv", "venv", ".tox",
             ".mypy_cache", ".pytest_cache", ".next", ".cache",
             "dist", "build", "target", "site-packages", "bower_components"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml",
              "composer.lock", "poetry.lock", "Pipfile.lock",
              "Cargo.lock", "go.sum", "Gemfile.lock", ".DS_Store",
              "package-lock.json.orig"}
MAX_FILE_BYTES = 5 * 1024 * 1024
BINARY_SNIFF_BYTES = 8192


@dataclass
class Finding:
    rule_id: str
    severity: str
    secret_type: str
    message: str
    file: str            # path relative to the scan root
    line_no: int         # 1-based
    line_text: str       # the trigger line, SECRET MASKED
    # history mode only (empty in tree mode):
    commit: str = ""             # the sha that introduced the line
    commit_date: str = ""        # author date, YYYY-MM-DD
    commit_subject: str = ""


def mask_secret(value: str) -> str:
    """'AKIAIOSFODNN7EXAMPLE' -> 'AKIAIO…(+14)'. Never the full value."""
    if len(value) <= 8:
        return "…"
    return f"{value[:6]}…(+{len(value) - 6} chars)"


def iter_text_files(root: Path, max_files: int) -> tuple[list[Path],
                                                          list[str]]:
    """Every candidate file under root (sorted, deterministic) plus
    the notes about what was skipped and why."""
    files: list[Path] = []
    notes: list[str] = []
    skipped_locks = 0
    skipped_big = 0
    skipped_binary = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in SKIP_FILES:
                skipped_locks += 1
                continue
            full = Path(dirpath) / name
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    skipped_big += 1
                    continue
                with open(full, "rb") as fh:
                    if b"\x00" in fh.read(BINARY_SNIFF_BYTES):
                        skipped_binary += 1
                        continue
            except OSError:
                continue
            files.append(full)
            if len(files) >= max_files:
                notes.append(f"file cap ({max_files}) reached — partial "
                             "scan")
                return files, notes
    if skipped_locks:
        notes.append(f"{skipped_locks} lockfile(s) skipped — integrity "
                     "hashes, not leaks")
    if skipped_big:
        notes.append(f"{skipped_big} file(s) over "
                     f"{MAX_FILE_BYTES // (1024 * 1024)} MB skipped")
    if skipped_binary:
        notes.append(f"{skipped_binary} binary-looking file(s) skipped")
    notes.append(".git skipped in working-tree mode — run the history "
                 "mode (--mode history) for the commits themselves")
    return files, notes


def check_line(rules: list[Rule], lines: list[str], i: int,
               rel_file: str) -> list[Finding]:
    """All findings for line index i (0-based). Pure."""
    line = lines[i]
    findings: list[Finding] = []
    for rule in rules:
        if not rule.applies_to(rel_file):
            continue
        m = rule.match_re.search(line)
        if not m:
            continue
        if rule.exclude_re:
            window = lines[i:i + 1 + rule.exclude_window]
            if any(rule.exclude_re.search(w) for w in window):
                continue
        if rule.source_patterns:
            lo = max(0, i - rule.source_window)
            before = lines[lo:i]
            if not any(p.search(b) for b in before
                       for p in rule.source_patterns):
                continue
        try:
            secret = m.group(rule.mask_group)
            start, end = m.span(rule.mask_group)
        except IndexError:
            secret, start, end = m.group(0), m.span(0)
        masked = line[:start] + mask_secret(secret) + line[end:]
        findings.append(Finding(
            rule_id=rule.id, severity=rule.severity,
            secret_type=rule.secret_type, message=rule.message,
            file=rel_file, line_no=i + 1, line_text=masked.strip()))
    return findings


def scan_file(path: Path, root: Path, rules: list[Rule]) -> list[Finding]:
    """One file through the engine; unreadable files are skipped
    quietly (permission noise is not the scan's subject)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    rel = str(path.relative_to(root))
    findings: list[Finding] = []
    for i in range(len(lines)):
        findings.extend(check_line(rules, lines, i, rel))
    return findings


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Severity first, then file/line — the remediation order."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity],
                                           f.file, f.line_no))
