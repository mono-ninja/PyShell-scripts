"""src/report.py — the table event, the markdown story and the
artifacts. The masking contract holds through here: findings arrive
pre-masked, so every surface (screen, report, JSON) shows
`AKIAIO…(+14 chars)`, never the key itself."""
from __future__ import annotations

import json
import os
from collections import Counter

from .scanner import Finding

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                 "low": "⚪"}


def build_table_event(findings: list[Finding], top_n: int = 50,
                      history: bool = False) -> dict:
    rows = []
    for f in findings[:top_n]:
        row = [
            SEVERITY_ICON.get(f.severity, "") + " " + f.severity,
            f.secret_type,
            f.file,
            f.line_no,
            f.line_text,
        ]
        if history:
            row.append((f.commit[:8] if f.commit else "") +
                       (f" · {f.commit_date}" if f.commit_date
                        else ""))
        rows.append(row)
    if len(findings) > top_n:
        more = ["", "",
                f"… {len(findings) - top_n} more",
                "", ""]
        if history:
            more.append("")
        rows.append(more)
    columns = ["severity", "type", "file", "line", "finding"] + \
        (["commit"] if history else [])
    return {"type": "table", "columns": columns, "rows": rows}


def build_markdown(scan_label: str, files_scanned: int,
                   findings: list[Finding], notes: list[str],
                   history: bool = False,
                   commits: int = 0) -> str:
    counts = Counter(f.severity for f in findings)
    types = Counter(f.secret_type for f in findings)
    scope = (f"{commits} commit(s) walked" if history
             else f"{files_scanned} file(s) scanned")
    out = [f"# Secret Scan — Report\n",
           f"`{scan_label}` · {'git history' if history else 'working tree'}"
           f" · {scope} · "
           f"**{len(findings)} finding(s)**: "
           f"{counts.get('critical', 0)} critical, "
           f"{counts.get('high', 0)} high, "
           f"{counts.get('medium', 0)} medium.\n"]

    if not findings:
        if history:
            out.append("No credential-shaped strings matched the "
                       "rulebook in the entire history. That is good — "
                       "and it is not a guarantee: rotate anything you "
                       "suspect.\n")
        else:
            out.append("No credential-shaped strings matched the "
                       "rulebook in the working tree. That is good — "
                       "and it is not a guarantee: rotate anything you "
                       "suspect, and remember the skipped places (see "
                       "Notes).\n")
    else:
        out.append("**Every value below is masked** — the report shows "
                   "the first characters and the length only, never the "
                   "secret itself; open the file at the line to see it.\n")
        if history:
            out.append("These lines live in git history: the secret is "
                       "in every clone, even where the working tree no "
                       "longer has it. **Rotate first**, purge second.\n")
        out.append("\n## Findings\n")
        current_file = None
        for f in findings:
            if f.file != current_file:
                out.append(f"\n### {f.file}\n")
                current_file = f.file
            out.append(f"- {SEVERITY_ICON.get(f.severity, '')} **line "
                       f"{f.line_no}** · {f.secret_type} · "
                       f"`{f.line_text}`")
            if history and f.commit:
                out.append(f"  - introduced by `{f.commit[:12]}` "
                           f"({f.commit_date}) — _{f.commit_subject}_")
            out.append(f"  - {f.message}")

        out.append("\n## What to do now\n")
        out.append("1. **Rotate first, delete second.** A key in git "
                   "history stays in git history even after the file is "
                   "fixed — treat every finding here as public and "
                   "rotate it at the provider.")
        out.append("2. Move the real values to environment variables or "
                   "a secrets manager; commit the `.example` file "
                   "instead of the `.env` one.")
        out.append("3. Purge the history if the leak was pushed "
                   "(`git filter-repo` or the provider's tooling) — "
                   "deleting the current file is not enough.")

    if types:
        out.append("\n## By type\n")
        for secret_type, n in types.most_common():
            out.append(f"- {secret_type}: {n}")

    if notes:
        out.append("\n## Notes\n")
        for note in notes:
            out.append(f"- {note}")

    out.append("\n## Skipped by design\n")
    if history:
        out.append("- Merge commits are not diffed (plain `git log -p`) "
                   "— content belongs to the commit that introduced it.")
        out.append("- Binary files — git emits no hunks for them.")
        out.append("- Lockfiles (basename match) — integrity hashes, "
                   "not leaks.")
    else:
        out.append("- `.git/` — the working tree only; switch the mode "
                   "to **history** to walk the commits themselves.")
        out.append("- Lockfiles (`package-lock.json` and friends) — "
                   "integrity hashes look like secrets to every regex, "
                   "and they are not.")
    out.append("- Related: **WP Audit** scans the same tree for code "
               "vulnerabilities; **Password Check** tests the rotated "
               "passwords against the HIBP corpus before you commit "
               "to them.")
    return "\n".join(out)


def write_artifacts(scan_label: str, files_scanned: int,
                    findings: list[Finding], notes: list[str],
                    report: str, history: bool = False,
                    commits: int = 0) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "scan": scan_label,
        "mode": "history" if history else "tree",
        "files_scanned": files_scanned,
        "commits_scanned": commits,
        "findings": [{
            "rule_id": f.rule_id, "severity": f.severity,
            "secret_type": f.secret_type, "message": f.message,
            "file": f.file, "line_no": f.line_no,
            "line_text_masked": f.line_text,
            "commit": f.commit, "commit_date": f.commit_date,
            "commit_subject": f.commit_subject,
        } for f in findings],
        "notes": notes,
        "masked": True,
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)
