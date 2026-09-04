"""Sorting, rendering and artifact writing.

Kept out of ``main.py`` so the CLI stays argument plumbing. Three surfaces
share one sorted list of findings: the PyShell ``table`` event, the
markdown report (also saved as ``report.md``), and the optional
``report.html``.

Everything user-facing is **capped**; ``findings.json`` never is. A 500-page
site can produce thousands of findings, and a markdown table with 4000 rows
is not a report — but a CI job reading the JSON wants every one of them.
"""
from __future__ import annotations

import csv
import html
import io
import json
import os
from dataclasses import asdict

SEVERITY_RANK = {"fail": 0, "warn": 1, "info": 2}
SEVERITY_ICON = {"fail": "❌", "warn": "⚠️", "info": "ℹ️"}

# Rows past this land in findings.csv / findings.json only.
MAX_TABLE_ROWS = 300
MAX_TOP_FINDINGS = 10
FINDINGS_SCHEMA = 1


def counts(findings: list) -> dict[str, int]:
    return {s: sum(1 for f in findings if f.severity == s)
            for s in ("fail", "warn", "info")}


def sort_findings(findings: list, check_order: list[str]) -> list:
    """Highest-value first: fail before warn before info, and within a tier
    by check priority (broken links and failed canonicals before info-level
    meta-length notes)."""
    rank = {name: i for i, name in enumerate(check_order)}
    rank.setdefault("external_links", len(rank))
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 9),
                                           rank.get(f.check, 99),
                                           f.page))


def esc_cell(val, max_len: int = 160) -> str:
    s = str(val).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _header(snapshot, findings, diff) -> list[str]:
    crawled = (snapshot.crawled_at.isoformat() if snapshot.crawled_at
               else "unknown date")
    caveats = ""
    if snapshot.capped:
        caveats += (f" · ⚠ capped crawl ({snapshot.pages_crawled} of "
                    f"{snapshot.pages_discovered} pages)")
    if snapshot.partial:
        caveats += f" · ⚠ partial crawl ({snapshot.stopped_reason or 'stopped early'})"
    if snapshot.include_paths or snapshot.exclude_paths:
        caveats += (f" · filtered to {len(snapshot.pages)} of "
                    f"{len(snapshot.all_pages)} pages")

    c = counts(findings)
    lines = [
        f"## SEO checks — {len(findings)} finding(s)",
        "",
        f"`{snapshot.seed_url}` · snapshot crawled {crawled}{caveats}",
        "",
        (f"❌ {c['fail']} fail · ⚠️ {c['warn']} warn · ℹ️ {c['info']} info"),
    ]
    if diff is not None:
        lines += ["", (f"🆕 {len(diff.new)} new · ✅ {len(diff.fixed)} fixed · "
                       f"➖ {diff.unchanged} unchanged "
                       f"(vs `{os.path.basename(diff.baseline_path)}`)")]
    return lines


def _table(findings, diff, limit: int = MAX_TABLE_ROWS) -> list[str]:
    marked = diff is not None
    head = ["| Check | Severity | Page | Detail | Fix |",
            "| --- | --- | --- | --- | --- |"]
    if marked:
        head = ["| New | Check | Severity | Page | Detail | Fix |",
                "| --- | --- | --- | --- | --- | --- |"]
    lines = list(head)
    for f in findings[:limit]:
        cells = [esc_cell(f.check), f"{SEVERITY_ICON[f.severity]} {f.severity}",
                 esc_cell(f.page), esc_cell(f.detail),
                 esc_cell(f.recommendation)]
        if marked:
            cells.insert(0, "🆕" if diff.is_new(f) else "")
        lines.append("| " + " | ".join(cells) + " |")
    if len(findings) > limit:
        note = (f"*…and {len(findings) - limit} more — see "
               f"`findings.csv` / `findings.json`.*")
        lines += ["", note]
    return lines


def _by_page(findings, limit: int = MAX_TABLE_ROWS) -> list[str]:
    order: dict[str, list] = {}
    for f in findings:
        order.setdefault(f.page, []).append(f)
    lines: list[str] = []
    for page, group in list(order.items())[:limit]:
        lines += ["", f"#### {page}", ""]
        for f in group:
            lines.append(f"- {SEVERITY_ICON[f.severity]} **{f.check}** — "
                         f"{esc_cell(f.detail)}")
            if f.recommendation:
                lines.append(f"  → {esc_cell(f.recommendation)}")
    if len(order) > limit:
        note = (f"*…and {len(order) - limit} more pages — see "
               f"`findings.csv` / `findings.json`.*")
        lines += ["", note]
    return lines


def build_markdown(snapshot, findings, *, diff=None,
                   group_by: str = "check") -> str:
    lines = _header(snapshot, findings, diff)

    if diff is not None and diff.fixed:
        lines += ["", "### Fixed since the baseline", ""]
        for record in diff.fixed[:MAX_TOP_FINDINGS]:
            lines.append(f"- ✅ **{record.get('check', '?')}** — "
                         f"{esc_cell(record.get('page', ''))}: "
                         f"{esc_cell(record.get('detail', ''))}")
        if len(diff.fixed) > MAX_TOP_FINDINGS:
            lines.append(f"- *…and {len(diff.fixed) - MAX_TOP_FINDINGS} more.*")

    if findings:
        lines += ["", "### Highest-value findings", ""]
        for f in findings[:MAX_TOP_FINDINGS]:
            marker = "🆕 " if diff is not None and diff.is_new(f) else ""
            lines.append(
                f"{marker}{SEVERITY_ICON[f.severity]} **{f.check}** — "
                f"{esc_cell(f.page)}"
                f"\n  {esc_cell(f.detail)}"
                + (f"\n  → {esc_cell(f.recommendation)}"
                   if f.recommendation else ""))

        if group_by == "page":
            lines += ["", "### All findings, by page"] + _by_page(findings)
        else:
            lines += ["", "### All findings", ""] + _table(findings, diff)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_HEAD = """<!doctype html>
<meta charset="utf-8">
<title>SEO checks — {title}</title>
<style>
 :root {{ color-scheme: light dark; --bg:#fff; --fg:#1a1a1a; --line:#e3e3e3;
          --muted:#666; --head:#f6f6f6; }}
 @media (prefers-color-scheme: dark) {{
   :root {{ --bg:#161616; --fg:#e8e8e8; --line:#333; --muted:#999; --head:#1f1f1f; }}
 }}
 body {{ background:var(--bg); color:var(--fg); margin:0; padding:2rem 1.5rem;
         font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
 h1 {{ font-size:1.4rem; margin:0 0 .25rem; }}
 .meta {{ color:var(--muted); margin-bottom:1rem; }}
 .counts button {{ font:inherit; cursor:pointer; margin-right:.4rem;
    padding:.3rem .7rem; border:1px solid var(--line); border-radius:999px;
    background:transparent; color:inherit; }}
 .counts button[aria-pressed="true"] {{ background:var(--head); font-weight:600; }}
 table {{ border-collapse:collapse; width:100%; margin-top:1rem; }}
 th,td {{ border-bottom:1px solid var(--line); padding:.5rem .6rem;
          text-align:left; vertical-align:top; }}
 th {{ background:var(--head); position:sticky; top:0; cursor:pointer;
       white-space:nowrap; }}
 td.page {{ word-break:break-all; max-width:22rem; }}
 tr.fail td:first-child {{ border-left:3px solid #d33; }}
 tr.warn td:first-child {{ border-left:3px solid #e69500; }}
 tr.info td:first-child {{ border-left:3px solid #888; }}
 .wrap {{ overflow-x:auto; }}
</style>
"""

_HTML_TAIL = """<script>
const rows = [...document.querySelectorAll('tbody tr')];
const state = new Set(['fail','warn','info']);
document.querySelectorAll('.counts button').forEach(b => b.onclick = () => {
  const s = b.dataset.sev;
  state.has(s) ? state.delete(s) : state.add(s);
  b.setAttribute('aria-pressed', state.has(s));
  rows.forEach(r => { r.hidden = !state.has(r.className); });
});
document.querySelectorAll('th').forEach((th, i) => th.onclick = () => {
  const body = th.closest('table').tBodies[0];
  const dir = th.dataset.dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
  [...body.rows]
    .sort((a, b) => (dir === 'asc' ? 1 : -1) *
      a.cells[i].textContent.localeCompare(b.cells[i].textContent))
    .forEach(r => body.appendChild(r));
});
</script>
"""


def build_html(snapshot, findings, *, diff=None) -> str:
    e = html.escape
    c = counts(findings)
    out = [_HTML_HEAD.format(title=e(snapshot.seed_url or "report")),
           f"<h1>SEO checks — {len(findings)} finding(s)</h1>",
           f'<div class="meta">{e(snapshot.seed_url)} · snapshot crawled '
           f'{e(snapshot.crawled_at.isoformat() if snapshot.crawled_at else "unknown date")}'
           + (f' · capped ({snapshot.pages_crawled} of '
              f'{snapshot.pages_discovered} pages)' if snapshot.capped else '')
           + '</div>',
           '<div class="counts">'
           + "".join(f'<button data-sev="{s}" aria-pressed="true">'
                     f'{SEVERITY_ICON[s]} {c[s]} {s}</button>'
                     for s in ("fail", "warn", "info"))
           + '</div>']
    if diff is not None:
        out.append(f'<div class="meta">🆕 {len(diff.new)} new · '
                   f'✅ {len(diff.fixed)} fixed · ➖ {diff.unchanged} unchanged '
                   f'(vs {e(os.path.basename(diff.baseline_path))})</div>')

    out.append('<div class="wrap"><table><thead><tr>'
               '<th>Check</th><th>Severity</th><th>Page</th>'
               '<th>Detail</th><th>Fix</th></tr></thead><tbody>')
    for f in findings:
        new = "🆕 " if diff is not None and diff.is_new(f) else ""
        out.append(
            f'<tr class="{f.severity}"><td>{new}{e(f.check)}</td>'
            f'<td>{SEVERITY_ICON[f.severity]} {f.severity}</td>'
            f'<td class="page">{e(f.page)}</td><td>{e(f.detail)}</td>'
            f'<td>{e(f.recommendation)}</td></tr>')
    out.append("</tbody></table></div>")
    out.append(_HTML_TAIL)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

def findings_document(snapshot, findings, meta: dict) -> dict:
    """``findings.json`` — the machine-readable artifact.

    Carries enough context to stand on its own: which site, which crawl,
    which checks. Without that, two runs are indistinguishable and the
    ``--baseline`` diff has nothing to anchor to.
    """
    return {
        "schema": FINDINGS_SCHEMA,
        "tool": {"name": "seo-checks", "version": "1.1"},
        "snapshot": {
            "seed_url": snapshot.seed_url,
            "crawled_at": (snapshot.crawled_at.isoformat()
                           if snapshot.crawled_at else None),
            "schema": snapshot.schema,
            "capped": snapshot.capped,
            "partial": snapshot.partial,
            "pages_crawled": snapshot.pages_crawled,
            "pages_discovered": snapshot.pages_discovered,
            "pages_checked": len(snapshot.pages),
        },
        "run": meta,
        "counts": counts(findings),
        "findings": [asdict(f) for f in findings],
    }


def _csv_text(findings) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["check", "severity", "page", "detail", "recommendation"])
    for f in findings:
        writer.writerow([f.check, f.severity, f.page, f.detail,
                         f.recommendation])
    return buf.getvalue()


def write_artifacts(out_dirs, document: dict, findings, report_md: str,
                    report_html: str | None) -> list[str]:
    """Write every artifact into each distinct directory.

    Raises ``OSError``; the caller turns that into exit code 1 rather than
    a traceback — an unwritable output folder is a normal thing to get
    wrong, not a crash.
    """
    files = {
        "findings.json": json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        "findings.csv": _csv_text(findings),
        "report.md": report_md + "\n",
    }
    if report_html is not None:
        files["report.html"] = report_html + "\n"

    written: list[str] = []
    seen: set[str] = set()
    for out_dir in out_dirs:
        if not out_dir:
            continue
        target = os.path.abspath(out_dir)
        if target in seen:
            continue
        seen.add(target)
        os.makedirs(target, exist_ok=True)
        for name, data in files.items():
            path = os.path.join(target, name)
            # newline="" so the csv writer's \r\n survives unmangled.
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(data)
        written.append(target)
    return written
