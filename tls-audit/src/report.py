"""Score, grade, and the markdown report.

Deliberately identical in shape to ``security-headers``: a weighted
0–100 score where pass earns full credit, warn half, fail none, and
informational findings (severity 0) stay out of the denominator; the
same letter buckets; the same report skeleton (grade headline, counts,
top fixes, findings table). The two scripts are a pair — headers in the
HTTP layer, this one in the transport — and their reports should read
as one system, not two dialects.
"""
from __future__ import annotations

from dataclasses import asdict

from src.checks import Facts, Finding

# Letter-grade buckets, same shape as security-headers.
GRADES = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]

# Credit a status earns toward the weighted score: pass = full, warn =
# half, fail = none. Severity-0 findings (informational) stay out of
# the denominator entirely.
CREDIT = {"pass": 1.0, "warn": 0.5, "fail": 0.0}

STATUS_ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌"}
GRADE_ICON = {"A+": "🛡️", "A": "✅", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}


def score_findings(findings: list[Finding]) -> int | None:
    """Weighted sum normalized to 0–100. None when nothing is scored."""
    total = sum(f.severity for f in findings if f.severity > 0)
    if not total:
        return None
    earned = sum(f.severity * CREDIT[f.status]
                 for f in findings if f.severity > 0)
    return round(100 * earned / total)


def grade_for(score: int | None) -> str:
    if score is None:
        return "—"
    for floor, letter in GRADES:
        if score >= floor:
            return letter
    return "F"


def esc_cell(val: str, max_len: int = 160) -> str:
    """Escape a value for a markdown table cell."""
    s = str(val).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def top_fixes(findings: list[Finding], n: int = 3) -> list[Finding]:
    scored_down = [f for f in findings
                   if f.status == "fail" and f.recommendation]
    return sorted(scored_down, key=lambda f: -f.severity)[:n]


def _subject_line(facts: Facts) -> str:
    """'CN issued by ISSUER-CN' — the one-line certificate identity."""
    cert = facts.parsed
    if not cert:
        return ""
    subject, issuer = cert.subject_cn, cert.issuer_cn
    if subject and issuer:
        return f"`{subject}` issued by `{issuer}`"
    return f"`{subject or issuer or 'certificate'}`"


def build_report(facts: Facts, findings: list[Finding],
                 score: int | None, grade: str, connections: int) -> str:
    counts = {s: sum(1 for f in findings if f.status == s)
              for s in ("pass", "warn", "fail")}
    lines = [
        f"## {GRADE_ICON.get(grade, '')} Grade {grade} — {score if score is not None else 'n/a'}/100",
        "",
        f"`{facts.host}:{facts.port}` · {facts.collect.version or '—'} · "
        f"{facts.collect.cipher or '—'}"
        + (f" · {_subject_line(facts)}" if facts.parsed else ""),
        "",
        (f"✅ {counts['pass']} pass · ⚠️ {counts['warn']} warn · "
         f"❌ {counts['fail']} fail"),
    ]

    fixes = top_fixes(findings)
    if fixes:
        lines += ["", "### Top fixes", ""]
        for f in fixes:
            lines.append(f"**{f.check}** — {f.recommendation}")

    lines += ["", "### Findings", "",
              "| Check | Status | Detail | Fix |", "| --- | --- | --- | --- |"]
    for f in findings:
        lines.append(f"| {esc_cell(f.check)} | {STATUS_ICON[f.status]} {f.status} "
                     f"| {esc_cell(f.detail) or '—'} | {esc_cell(f.recommendation) or '—'} |")

    # Certificate summary — the facts an operator quotes in a ticket,
    # kept out of the findings table where they'd repeat the checks.
    cert = facts.parsed
    if cert:
        lines += ["", "### Certificate", ""]
        if cert.not_before:
            lines.append(f"- Not before: {cert.not_before:%Y-%m-%d %H:%M UTC}")
        if cert.not_after:
            lines.append(f"- Not after: {cert.not_after:%Y-%m-%d %H:%M UTC}")
        key = facts.pub_key
        if key:
            what = f"{key.key_type} {key.key_bits}-bit" if key.key_bits else key.key_type
            if key.curve:
                what += f", {key.curve}"
            lines.append(f"- Public key: {what}")
        if facts.signature:
            lines.append(f"- Signature: {facts.signature.label}")
        if cert.dns_sans:
            shown = ", ".join(f"`{s}`" for s in cert.dns_sans[:12])
            more = f" (+{len(cert.dns_sans) - 12} more)" if len(cert.dns_sans) > 12 else ""
            lines.append(f"- SANs: {shown}{more}")
        if cert.ip_sans:
            lines.append(f"- IP SANs: {', '.join(cert.ip_sans[:6])}")
        if cert.parse_notes:
            lines.append(f"- Parse notes: {'; '.join(cert.parse_notes)}")

    lines += ["", f"_{connections} TLS connection(s) made, no HTTP requests sent._", ""]
    return "\n".join(lines)
