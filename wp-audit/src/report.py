"""src/report.py — table, markdown, artifacts."""
from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import asdict

from .rules import SEVERITY_ORDER
from .scanner import Finding, sort_findings

SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                 "low": "⚪"}

ADVICE = {
    "SQL_INJECTION": "Every dynamic fragment goes through "
                     "`$wpdb->prepare()` — the flagged lines interpolate "
                     "instead.",
    "XSS": "Wrap output in `esc_html`/`esc_attr`/`esc_url` at the "
           "moment of echoing, not somewhere earlier.",
    "CODE_EXECUTION": "eval/shell-exec in a theme or plugin is either a "
                      "bug or injected malware — open the file and "
                      "decide which before anything else.",
    "FILE_OPERATIONS": "Constrain paths to known roots "
                       "(`plugin_dir_path`, `wp_upload_dir`) and validate "
                       "uploads against `wp_check_filetype`.",
    "OBJECT_INJECTION": "Never `unserialize()` request data; JSON is "
                        "the safe transport.",
    "SSRF": "Validate fetched URLs with `wp_http_validate_url()` and an "
            "allowlist of hosts.",
    "OPEN_REDIRECT": "Redirect only to URLs you built "
                     "(`home_url`, `admin_url`) or explicitly allowed.",
    "ACCESS_CONTROL": "Nonce checks on every AJAX handler; a "
                      "`permission_callback` on every REST route — "
                      "WordPress defaults both to *public*.",
    "HEADER_INJECTION": "Sanitize every wp_mail argument that can carry "
                        "user input (`sanitize_email`, "
                        "`sanitize_text_field`).",
    "HARDCODED_SECRETS": "Secrets live in env/config outside the tree, "
                         "never in committed code.",
}


def build_table_event(findings: list[Finding], top_n: int = 50) -> dict:
    rows = []
    for f in sort_findings(findings)[:top_n]:
        rows.append([SEVERITY_ICON.get(f.severity, "") + " " + f.severity,
                     f"{f.file}:{f.line_no}",
                     f.rule_id, f.message])
    return {
        "type": "table",
        "columns": ["Severity", "File:line", "Rule", "Finding"],
        "rows": rows,
    }


def build_markdown(scan_label: str, files_scanned: int,
                   findings: list[Finding], truncated_files: bool) -> str:
    by_sev = Counter(f.severity for f in findings)
    by_type = Counter(f.vuln_type for f in findings)
    critical = by_sev.get("critical", 0)
    head = (f"## 🔴 {critical} critical, "
            f"{by_sev.get('high', 0)} high, "
            f"{by_sev.get('medium', 0)} medium" if findings
            else "## 🟢 No findings")
    lines = [head, "", f"`{scan_label}` · {files_scanned} PHP file(s) "
             f"scanned · {len(findings)} finding(s)", ""]

    if truncated_files:
        lines.append("_⚠️ the file cap was reached — the scan is partial. "
                     "Raise --max-files for a full pass._")
        lines.append("")

    if findings:
        lines += ["| Category | Count |", "| --- | --- |"]
        for vuln_type, count in by_type.most_common():
            lines.append(f"| {vuln_type.replace('_', ' ').title()} "
                         f"| {count} |")
        lines.append("")

        ordered = sort_findings(findings)
        for f in ordered[:80]:
            lines.append(f"### {SEVERITY_ICON.get(f.severity, '')} "
                         f"`{f.file}:{f.line_no}` — {f.rule_id}")
            lines.append("")
            lines.append(f"```php")
            lines.append(f.line_text)
            lines.append("```")
            lines.append("")
            lines.append(f"{f.message} · _{f.vuln_type}_")
            lines.append("")
        if len(ordered) > 80:
            lines.append(f"_… {len(ordered) - 80} more in findings.json._")
            lines.append("")

        lines.append("**What to do with each category**")
        lines.append("")
        for vuln_type in by_type:
            advice = ADVICE.get(vuln_type)
            if advice:
                lines.append(f"- **{vuln_type.replace('_', ' ').title()}**"
                             f" — {advice}")
        lines.append("")

        if critical:
            lines.append("_Start with the critical CODE_EXECUTION rows: "
                         "in a theme or plugin they're more often "
                         "injected malware than bugs. Compare against a "
                         "clean copy of the theme/plugin, and check what "
                         "the requests looked like in your logs "
                         "([Log Attack Checker](../log-attack-checker))._")
            lines.append("")
    else:
        lines.append("_No rule matched — the scanned code is clean by "
                     "this rulebook's lights. Pair with "
                     "[WP Exposure Check](../wp-exposure-check) for the "
                     "HTTP surface and [CVE Check](../cve-check) for the "
                     "known-vulnerable versions._")
        lines.append("")

    lines.append("_Reads files only; nothing was executed, nothing left "
                 "the machine._")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(scan_label: str, files_scanned: int,
                    findings: list[Finding], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "scan": scan_label,
        "files_scanned": files_scanned,
        "counts": {"total": len(findings),
                   **{f"severity_{k}": sum(1 for f in findings
                                           if f.severity == k)
                      for k in SEVERITY_ORDER}},
        "by_type": dict(Counter(f.vuln_type for f in findings)),
        "findings": [asdict(f) for f in sort_findings(findings)],
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report + "\n")
