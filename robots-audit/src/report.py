"""Report assembly — findings.json, report.md, the table event.

The markdown report is both the Results-tab content and the artifact;
findings.json is the machine-readable twin (same shape as
seo-checks' — check, severity, detail, recommendation). The parsed
document itself lands in robots_parsed.json so a later run (or another
script) can consume the groups without re-parsing.
"""
from __future__ import annotations

from dataclasses import asdict

from src.checks import AuditInput, Finding
from src.parser import RobotsDoc

SEVERITY_ICON = {"info": "ℹ️", "warn": "⚠️", "fail": "❌"}
SEVERITY_RANK = {"fail": 0, "warn": 1, "info": 2}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_RANK[f.severity])


def counts(findings: list[Finding]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f.severity == s)
            for s in ("info", "warn", "fail")}


def build_markdown(data: AuditInput, findings: list[Finding]) -> str:
    c = counts(findings)
    what = data.source.final_url or data.source.note.split(":")[0] \
        if data.source.note else "robots.txt"
    lines = [
        f"## Robots audit — {data.source.origin or what}",
        "",
        (f"❌ {c['fail']} fail · ⚠️ {c['warn']} warn · ℹ️ {c['info']} info"),
        "",
    ]

    findings = sort_findings(findings)
    if findings:
        lines += ["| Severity | Check | Detail | Fix |", "| --- | --- | --- | --- |"]
        for f in findings:
            detail = f.detail.replace("|", "\\|")[:220]
            fix = f.recommendation.replace("|", "\\|")[:160]
            lines.append(f"| {SEVERITY_ICON[f.severity]} {f.severity} "
                         f"| {f.check} | {detail} | {fix} |")
        lines.append("")

    # --- test URLs ------------------------------------------------------
    if data.tests:
        lines += ["### URL tests", "",
                  f"Checked against the rules for `{data.user_agent}`:", "",
                  "| URL | Verdict | Decided by |", "| --- | --- | --- |"]
        for t in data.tests:
            verdict = "✅ allowed" if t.allowed else "❌ disallowed"
            lines.append(f"| `{t.url}` | {verdict} | {t.deciding} |")
        lines.append("")

    # --- sitemaps ---------------------------------------------------------
    if data.doc is not None and data.doc.sitemaps:
        lines += ["### Sitemap directives", ""]
        for check in data.sitemap_checks:
            mark = "✅" if check.ok else "❌"
            lines.append(f"- {mark} `{check.url}` — {check.detail}")
        if not data.sitemap_checks:
            for url, lineno in data.doc.sitemaps:
                lines.append(f"- `{url}` (line {lineno})")
        lines.append("")

    # --- the rules, as parsed -------------------------------------------------
    if data.doc is not None and data.doc.groups:
        lines += ["### Groups as parsed", ""]
        for group in data.doc.groups:
            agents = ", ".join(group.user_agents)
            lines.append(f"- **{agents}** ({len(group.rules)} rule(s))"
                         + (f" · Crawl-delay: {group.crawl_delay:g}s"
                            if group.crawl_delay is not None else ""))
            for rule in group.rules[:8]:
                shown = rule.path if rule.path else "(empty = allow all)"
                lines.append(f"  - {rule.verb.capitalize()}: {shown}")
            if len(group.rules) > 8:
                lines.append(f"  - (+{len(group.rules) - 8} more — "
                             f"robots_parsed.json has all of them)")
        lines.append("")

    return "\n".join(lines)


def build_table_event(findings: list[Finding]) -> dict:
    ordered = sort_findings(findings)
    return {
        "type": "table",
        "columns": ["Severity", "Check", "Detail", "Fix"],
        "rows": [[f"{SEVERITY_ICON[f.severity]} {f.severity}", f.check,
                  f.detail[:200], f.recommendation[:200]] for f in ordered],
    }


def findings_document(data: AuditInput, findings: list[Finding]) -> dict:
    return {
        "source": {"origin": data.source.origin,
                   "status": data.source.status,
                   "final_url": data.source.final_url,
                   "note": data.source.note},
        "user_agent": data.user_agent,
        "counts": counts(findings),
        "findings": [asdict(f) for f in findings],
        "tests": [asdict(t) for t in data.tests],
        "sitemaps": [asdict(s) for s in data.sitemap_checks],
    }


def parsed_document(doc: RobotsDoc) -> dict:
    return {
        "size_bytes": doc.size_bytes,
        "truncated": doc.truncated,
        "groups": [{
            "user_agents": g.user_agents,
            "crawl_delay": g.crawl_delay,
            "rules": [asdict(r) for r in g.rules],
        } for g in doc.groups],
        "sitemaps": [{"url": url, "line": line} for url, line in doc.sitemaps],
        "notes": [asdict(n) for n in doc.notes],
    }
