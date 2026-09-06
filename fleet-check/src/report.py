"""src/report.py — chart, table, markdown, artifacts."""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
from dataclasses import asdict

from .baseline import normalize

GRADE_ORDER = ["A+", "A", "A-", "B", "B-", "C", "C-", "D", "D-", "E",
               "F"]


def build_chart_event(results: list) -> dict:
    """Grade distribution: TLS and headers counts per letter. Compact
    values are excluded (they're not grades) — the note says so."""
    tls = Counter(r.tls_grade for r in results
                  if r.tls_mode == "full" and r.tls_grade)
    headers = Counter(r.headers_grade for r in results
                      if r.headers_mode == "full" and r.headers_grade)
    letters = [g for g in GRADE_ORDER if g in tls or g in headers]
    if not letters:
        return {"type": "chart", "chart_type": "bar",
                "title": "Grades (install the sibling scripts for "
                         "full grades)",
                "labels": [], "series": []}
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": "TLS and security-headers grade distribution "
                 "(full checks)",
        "labels": letters,
        "series": [
            {"name": "TLS", "values": [tls.get(g, 0) for g in letters]},
            {"name": "Headers", "values": [headers.get(g, 0)
                                           for g in letters]},
        ],
    }


def build_table_event(results: list, changes: dict | None) -> dict:
    rows = []
    for r in results:
        change = (changes or {}).get(normalize(r.url))
        mark = ""
        if change:
            mark = {"better": "↑", "worse": "↓", "same": "≈"
                    }[change["direction"]]
        rows.append([
            r.host,
            r.http_status if r.http_status else "—",
            (r.tls_grade + ("*" if r.tls_mode == "compact" else ""))
            if r.tls_grade else r.tls_label,
            r.cert_label,
            (r.headers_grade + ("*" if r.headers_mode == "compact" else ""))
            if r.headers_grade else "—",
            r.wp_version or "—",
            "✓" if r.sitemap else "✗" if r.sitemap is False else "—",
            mark or "—",
        ])
    return {
        "type": "table",
        "columns": ["Site", "HTTP", "TLS", "Cert", "Headers", "WP",
                    "Sitemap", "Δ"],
        "rows": rows,
    }


def build_markdown(results: list, modes: dict, changes: dict) -> str:
    up = [r for r in results if r.reachable]
    down = [r for r in results if not r.reachable]
    expiring = [r for r in up if r.cert_days is not None
                and 0 <= r.cert_days < 21]
    expired = [r for r in up if r.cert_days is not None
               and r.cert_days < 0]
    weak_tls = [r for r in up if r.tls_mode == "full"
                and r.tls_grade and r.tls_grade not in ("A", "A+")]
    weak_headers = [r for r in up if r.headers_mode == "full"
                    and r.headers_grade and _rank(r.headers_grade) >= 3]
    no_sitemap = [r for r in up if r.sitemap is False]

    head = f"## {'🔴' if (expired or down) else '🟢'} {len(up)}/{len(results)} up"
    lines = [head, ""]

    lines.append(f"- Reachable: **{len(up)}/{len(results)}** · "
                 f"expired certs: {len(expired)} · expiring <21d: "
                 f"{len(expiring)}")
    lines.append(f"- TLS below A: {len(weak_tls)} · headers below B: "
                 f"{len(weak_headers)} · without sitemap.xml: "
                 f"{len(no_sitemap)}")
    lines.append("")

    lines += ["| Site | HTTP | TLS | Cert | Headers | WP | Sitemap | Δ |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in results:
        change = changes.get(normalize(r.url))
        mark = ""
        if change:
            mark = {"better": "↑", "worse": "↓", "same": "≈"
                    }[change["direction"]]
        rows_tls = (f"{r.tls_grade}{'*' if r.tls_mode == 'compact' else ''}"
                    if r.tls_grade else r.tls_label)
        rows_hdr = (f"{r.headers_grade}"
                    f"{'*' if r.headers_mode == 'compact' else ''}"
                    if r.headers_grade else "—")
        lines.append(
            f"| {r.host} | {r.http_status or '—'} | {rows_tls} | "
            f"{r.cert_label} | {rows_hdr} | {r.wp_version or '—'} | "
            f"{'✓' if r.sitemap else '✗' if r.sitemap is False else '—'} "
            f"| {mark or '—'} |")
    lines.append("")

    if expired:
        lines.append("**Expired certificates**")
        lines.append("")
        for r in expired:
            lines.append(f"- 🔴 {r.host} — expired "
                         f"{abs(r.cert_days)} day(s) ago")
        lines.append("")
    if expiring:
        lines.append("**Expiring within 21 days**")
        lines.append("")
        for r in expiring:
            lines.append(f"- ⏰ {r.host} — {r.cert_days} day(s) left")
        lines.append("")
    if down:
        lines.append("**Unreachable**")
        lines.append("")
        for r in down:
            lines.append(f"- ✗ {r.host} — {r.http_status or 'no answer'}"
                         + (f" ({'; '.join(r.errors[:2])})" if r.errors
                            else ""))
        lines.append("")

    if changes:
        better = {u: c for u, c in changes.items()
                  if c["direction"] == "better"}
        worse = {u: c for u, c in changes.items()
                 if c["direction"] == "worse"}
        if better:
            lines.append("**Improved since the baseline**")
            lines.append("")
            for url, c in better.items():
                lines.append(f"- ↑ {url}: {'; '.join(c['changes'])}")
            lines.append("")
        if worse:
            lines.append("**Slipped since the baseline**")
            lines.append("")
            for url, c in worse.items():
                lines.append(f"- ↓ {url}: {'; '.join(c['changes'])}")
            lines.append("")

    compact_modes = [name for name, mode in modes.items()
                     if mode == "compact"]
    if compact_modes:
        lines.append("_\\* compact values_ — the sibling script wasn't "
                     "installed for "
                     f"{', '.join(compact_modes)}: a minimal built-in ran "
                     "instead (cert days + verification, a five-key "
                     "header grade, the generator-tag WP version). "
                     "Install the siblings for the full grades — PyShell "
                     "pulls them automatically from this script's "
                     "**Needs** chain.")
        lines.append("")

    lines.append("_Follow-ups: [TLS Audit](../tls-audit) and [Security "
                 "Headers](../security-headers) dig into one site; "
                 "[CVE Check](../cve-check) takes a Tech Stack snapshot "
                 "to the vulnerability lists; [Fleet Check] yourself "
                 "again after fixes and diff against this run's "
                 "fleet.json._")
    lines.append("")
    return "\n".join(lines)


def _rank(grade: str) -> int:
    return GRADE_ORDER.index(grade) if grade in GRADE_ORDER else 99


def write_artifacts(results: list, modes: dict, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "modes": modes,
        "sites": [asdict(r) for r in results],
    }
    with open(os.path.join(out_dir, "fleet.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "fleet.csv"), "w", newline="",
              encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["site", "http", "tls", "tls_mode", "cert_days",
                         "cert_note", "headers", "headers_mode",
                         "wp_version", "tech_count", "sitemap"])
        for r in results:
            writer.writerow([r.host, r.http_status, r.tls_grade,
                             r.tls_mode, r.cert_days, r.cert_note,
                             r.headers_grade, r.headers_mode,
                             r.wp_version, r.tech_count, r.sitemap])
    if report:
        with open(os.path.join(out_dir, "report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(report + "\n")
