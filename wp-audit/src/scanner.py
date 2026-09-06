"""src/scanner.py — file discovery and the rule engine.

The scan root decision: when the site folder contains `wp-content/`,
**that's the default target** — themes and plugins are the operator's
code; `wp-admin` and `wp-includes` are WordPress core, shipped
thousands of times over and not the audit's subject. `--whole-tree`
overrides deliberately.

The engine walks line by line; per rule: match on the line, exclusion
on the line or up to `exclude_window` after it, `require_source`
within `source_window` before it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .rules import Rule, SEVERITY_ORDER

SKIP_DIRS = {".git", "node_modules", "vendor", ".svn", "__pycache__",
             ".idea", ".DS_Store"}


@dataclass
class Finding:
    rule_id: str
    severity: str
    vuln_type: str
    message: str
    file: str            # path relative to the scan root
    line_no: int         # 1-based
    line_text: str       # the trigger line, stripped


def iter_php_files(root: Path, max_files: int) -> list[Path]:
    """Every PHP file under root, core dirs skipped by name only when
    they'd be noise (SKIP_DIRS), sorted for a deterministic report."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.lower().endswith(".php"):
                files.append(Path(dirpath) / name)
                if len(files) >= max_files:
                    return files
    return files


def scan_root_for(site_dir: Path, whole_tree: bool) -> Path:
    """wp-content when present (the operator's code), else the tree."""
    wp_content = site_dir / "wp-content"
    if not whole_tree and wp_content.is_dir():
        return wp_content
    return site_dir


def check_line(rules: list[Rule], lines: list[str], i: int,
               rel_file: str) -> list[Finding]:
    """All findings for line index i (0-based). Pure — the engine's
    core, tests live here."""
    line = lines[i]
    findings: list[Finding] = []
    for rule in rules:
        if not rule.applies_to(rel_file):
            continue
        if not rule.match_re.search(line):
            continue
        # Exclusion: the trigger line or up to exclude_window after.
        if rule.exclude_re is not None:
            window_end = min(len(lines), i + 1 + rule.exclude_window)
            if any(rule.exclude_re.search(lines[j])
                   for j in range(i, window_end)):
                continue
        # require_source: one pattern within source_window before.
        if rule.source_patterns:
            window_start = max(0, i - rule.source_window)
            before = "\n".join(lines[window_start:i])
            if not any(p.search(before) for p in rule.source_patterns):
                continue
        findings.append(Finding(
            rule_id=rule.id, severity=rule.severity,
            vuln_type=rule.vuln_type, message=rule.message,
            file=rel_file, line_no=i + 1,
            line_text=line.strip()[:200]))
    return findings


def scan_file(path: Path, root: Path,
              rules: list[Rule]) -> list[Finding]:
    """One file through the engine. Read errors become zero findings —
    an unreadable file is reported by the walker, not faked here."""
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
    """Severity first, then file/line — the report's order."""
    return sorted(findings,
                  key=lambda f: (SEVERITY_ORDER.get(f.severity, 99),
                                 f.file, f.line_no))
