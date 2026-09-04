#!/usr/bin/env python3
"""security-headers/main.py — Security Headers.

One HTTP GET to a target URL, one graded checklist out. Fetches the URL
(following a bounded redirect chain and recording the header set at every
hop — a security header dropped after a redirect is itself a finding),
checks each header family against a pass/warn/fail/missing checklist, and
turns the weighted result into a 0–100 score and a letter grade.

Passive by design: one request (or a bounded redirect chain), nothing sent
that a normal browser visit wouldn't already trigger. No scanning, no
fuzzing, no probing beyond reading headers the origin already returns.

Structured events are emitted on stderr so PyShell renders them natively.
Artifacts are written to PYSHELL_OUTPUT_DIR: ``headers_raw.json`` (headers
exactly as received, every hop — the raw evidence), ``findings.json`` (the
finding list, machine-readable for CI), and ``report.md`` (the markdown
result, saved).

Run from a terminal too — the events degrade to plain JSON log lines.
"""
import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from typing import Literal
from urllib.parse import urljoin, urlsplit

import requests

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ

DEFAULT_UA = "PyShell-SecurityHeadersAudit/1.0 (+passive header check)"
MAX_HOPS = 10

# HSTS is only meaningful once the max-age crosses ~6 months — anything
# shorter can be brute-forced out by an attacker who keeps a subdomain
# pinned at http.
HSTS_MIN_MAX_AGE = 15768000  # 182 days

# Total weight of the Set-Cookie family, split across however many cookies
# arrived (check_cookies). Same tier as X-Frame-Options/Referrer-Policy (6
# each) rather than above every core header: cookie-flag hygiene is a real
# finding, but reference tools like securityheaders.com don't grade cookies
# at all, and this repo's own audit against a real site showed a single
# non-session cookie missing HttpOnly outweighing HSTS — disproportionate
# for what's usually the least security-critical header family here.
COOKIE_FAMILY_WEIGHT = 6.0

# Headers whose disappearance along the redirect chain is worth surfacing.
# Keys are lowercase (HeadersView.names() is lowercase); values are the
# canonical spellings for display.
SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}

# Letter-grade buckets, same shape as securityheaders.com.
GRADES = [(95, "A+"), (85, "A"), (70, "B"), (55, "C"), (40, "D"), (0, "F")]

# Credit a status earns toward the weighted score: pass = full, warn = half,
# everything else = none. Severity-0 findings (informational) stay out of
# the denominator entirely.
CREDIT = {"pass": 1.0, "warn": 0.5, "fail": 0.0, "missing": 0.0}


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One check result: what was sent, how it scores, what to send instead."""
    header: str
    status: Literal["pass", "warn", "fail", "missing"]
    severity: float      # weight toward the score; 0 = informational, unscored
    detail: str          # what was actually sent, verbatim
    recommendation: str  # what to send instead, ready to paste into a config


@dataclass
class Hop:
    """One response in the redirect chain (the only response when no chain)."""
    url: str
    status: int
    headers: list[list[str]]  # raw (name, value) pairs, duplicates preserved


class HeadersView:
    """Case-insensitive read access over a hop's raw header pairs.

    Built from the raw list rather than ``requests``' merged dict so duplicate
    ``Set-Cookie`` lines survive — merging them is exactly what a cookie-flag
    audit must not do.
    """

    def __init__(self, pairs: list[list[str]] | list[tuple[str, str]]):
        self.pairs = [[k, v] for k, v in pairs]

    def get(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.pairs:
            if k.lower() == low:
                return v
        return None

    def get_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.pairs if k.lower() == low]

    def names(self) -> set[str]:
        return {k.lower() for k, _ in self.pairs}


# ---------------------------------------------------------------------------
# A1. Fetch — full redirect-chain header capture
# ---------------------------------------------------------------------------

def fetch_chain(url: str, *, headers: dict[str, str], timeout: int,
                follow: bool, verify: bool) -> list[Hop]:
    """GET the URL, recording the header set at every redirect hop.

    Manual redirect following (not ``allow_redirects=True``) because the
    point is the header set *at each hop* — requests would only expose the
    final response plus a history of bare URLs.

    Raises ``requests.RequestException`` (or ``ValueError`` for a bad URL)
    on failure — the caller turns that into a single error report.
    """
    hops: list[Hop] = []
    current = url
    for _ in range(MAX_HOPS):
        resp = requests.get(current, headers=headers, timeout=timeout,
                            allow_redirects=False, verify=verify)
        hops.append(Hop(
            url=current,
            status=resp.status_code,
            headers=[[k, v] for k, v in resp.raw.headers.items()],
        ))
        if not follow or resp.status_code not in (301, 302, 303, 307, 308):
            break
        location = resp.headers.get("Location")
        if not location:
            break
        current = urljoin(current, location)
    else:
        # Loop exhausted: the chain is longer than MAX_HOPS. The last hop is
        # a redirect we deliberately did not follow — keep it as the final
        # evidence and let the caller note the truncation.
        pass
    return hops


def parse_header_block(raw: str | None) -> dict[str, str]:
    """Parse a "Key: Value"-per-line block of extra request headers."""
    headers: dict[str, str] = {}
    if not raw or not raw.strip():
        return headers
    for lineno, line in enumerate(raw.strip().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"header line {lineno} has no ':' separator: {line!r}")
        key, _, val = line.partition(":")
        headers[key.strip()] = val.strip()
    return headers


# ---------------------------------------------------------------------------
# A2. Header checks — one function per family
# ---------------------------------------------------------------------------

def check_hsts(hv: HeadersView, is_https: bool) -> list[Finding]:
    value = hv.get("Strict-Transport-Security")
    if value is None:
        if not is_https:
            # No HSTS on a plain-HTTP origin is not a finding — the header
            # only means anything on an HTTPS response in the first place.
            return [Finding("Strict-Transport-Security", "pass", 0,
                            "not sent (http origin — HSTS applies to HTTPS only)",
                            "")]
        return [Finding("Strict-Transport-Security", "missing", 10,
                        "not sent",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains")]

    if not is_https:
        return [Finding("Strict-Transport-Security", "warn", 10,
                        f"{value!r} — sent over HTTP, where browsers ignore it",
                        "Serve the site on HTTPS; HSTS is only honored on HTTPS responses")]

    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return [Finding("Strict-Transport-Security", "fail", 10,
                        f"{value!r} — no max-age directive",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    max_age = int(match.group(1))
    if max_age == 0:
        return [Finding("Strict-Transport-Security", "fail", 10,
                        f"{value!r} — max-age=0 explicitly disables HSTS",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    note = ""
    if "includesubdomains" not in value.lower():
        note = " (no includeSubDomains)"
    if max_age < HSTS_MIN_MAX_AGE:
        return [Finding("Strict-Transport-Security", "warn", 10,
                        f"{value!r} — max-age {max_age}s is under the ~6-month floor"
                        f"{note}",
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains")]
    return [Finding("Strict-Transport-Security", "pass", 10,
                    f"{value!r}{note}", "")]


def _csp_directives(value: str) -> dict[str, list[str]]:
    """CSP value → {directive: [tokens]}. Unknown directives are kept as-is."""
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            out[tokens[0].lower()] = tokens[1:]
    return out


def check_csp(hv: HeadersView, _is_https: bool) -> list[Finding]:
    value = hv.get("Content-Security-Policy")
    if value is None:
        return [Finding("Content-Security-Policy", "missing", 20,
                        "not sent",
                        "Content-Security-Policy: default-src 'self'; "
                        "script-src 'self'; style-src 'self'; img-src 'self'; "
                        "object-src 'none'; frame-ancestors 'none'; base-uri 'self'")]

    d = _csp_directives(value)
    has_default = "default-src" in d
    has_full_fetch = all(k in d for k in ("script-src", "style-src", "img-src"))
    if not has_default and not has_full_fetch:
        return [Finding("Content-Security-Policy", "warn", 20,
                        f"{value!r} — no default-src and the fetch directives are incomplete",
                        "Start from `default-src 'self'` and loosen per directive as needed")]

    # unsafe-inline / unsafe-eval in a script directive with no nonce or
    # hash to fall back on is the classic "CSP in name only" posture.
    script_src = d.get("script-src") or d.get("default-src") or []
    has_nonce_or_hash = any(
        t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
        for t in script_src
    )
    unsafe = [t for t in script_src
              if t in ("'unsafe-inline'", "'unsafe-eval'")]
    if unsafe and not has_nonce_or_hash:
        return [Finding("Content-Security-Policy", "warn", 20,
                        f"{value!r} — {'/'.join(unsafe)} in a script directive, "
                        "no nonce/hash fallback",
                        "Replace 'unsafe-inline' with a per-request nonce "
                        "('nonce-…') or sha256 hashes; drop 'unsafe-eval' unless "
                        "the app genuinely eval()s")]

    return [Finding("Content-Security-Policy", "pass", 20, f"{value!r}", "")]


def check_xcto(hv: HeadersView, _is_https: bool) -> list[Finding]:
    value = hv.get("X-Content-Type-Options")
    if value is None:
        return [Finding("X-Content-Type-Options", "missing", 6, "not sent",
                        "X-Content-Type-Options: nosniff")]
    if value.strip().lower() == "nosniff":
        return [Finding("X-Content-Type-Options", "pass", 6, f"{value!r}", "")]
    return [Finding("X-Content-Type-Options", "fail", 6,
                    f"{value!r} — must be exactly `nosniff`",
                    "X-Content-Type-Options: nosniff")]


def check_xfo(hv: HeadersView, _is_https: bool) -> list[Finding]:
    value = hv.get("X-Frame-Options")
    csp = hv.get("Content-Security-Policy")
    csp_frames = "frame-ancestors" in _csp_directives(csp) if csp else False

    if value is None:
        if csp_frames:
            # frame-ancestors supersedes XFO in every modern browser —
            # covered is covered.
            return [Finding("X-Frame-Options", "pass", 6,
                            "not sent — superseded by CSP `frame-ancestors`", "")]
        return [Finding("X-Frame-Options", "missing", 6, "not sent",
                        "X-Frame-Options: DENY (or add `frame-ancestors 'none'` "
                        "to your CSP)")]
    v = value.strip().lower()
    if v in ("deny", "sameorigin"):
        return [Finding("X-Frame-Options", "pass", 6, f"{value!r}", "")]
    if v == "allowall":
        return [Finding("X-Frame-Options", "fail", 6,
                        f"{value!r} — ALLOWALL permits any site to frame this one",
                        "X-Frame-Options: DENY")]
    return [Finding("X-Frame-Options", "warn", 6,
                    f"{value!r} — unrecognized value",
                    "X-Frame-Options: DENY or SAMEORIGIN")]


def check_referrer_policy(hv: HeadersView, _is_https: bool) -> list[Finding]:
    value = hv.get("Referrer-Policy")
    if value is None:
        return [Finding("Referrer-Policy", "missing", 6, "not sent",
                        "Referrer-Policy: strict-origin-when-cross-origin")]
    v = value.strip().lower()
    if v == "unsafe-url":
        return [Finding("Referrer-Policy", "fail", 6,
                        f"{value!r} — sends full URL + credentials to every origin",
                        "Referrer-Policy: strict-origin-when-cross-origin")]
    valid = {"no-referrer", "no-referrer-when-downgrade", "same-origin",
             "strict-origin", "strict-origin-when-cross-origin",
             "origin", "origin-when-cross-origin"}
    if v not in valid:
        return [Finding("Referrer-Policy", "warn", 6,
                        f"{value!r} — unrecognized value",
                        "Referrer-Policy: strict-origin-when-cross-origin")]
    return [Finding("Referrer-Policy", "pass", 6, f"{value!r}", "")]


def check_permissions_policy(hv: HeadersView, _is_https: bool) -> list[Finding]:
    value = hv.get("Permissions-Policy")
    if value is None:
        # Most sites still don't send it — informational weight only, per
        # the plan: presence earns a little, absence is not a hard fail.
        return [Finding("Permissions-Policy", "missing", 3, "not sent",
                        "Permissions-Policy: camera=(), microphone=(), "
                        "geolocation=()")]
    return [Finding("Permissions-Policy", "pass", 3, f"{value!r}", "")]


def check_coop(hv: HeadersView, _is_https: bool) -> list[Finding]:
    # Weight 2, same "informational, most sites don't send it yet" tier as
    # Permissions-Policy (weight 3) — COOP is newer and even less deployed
    # in the wild. It was originally weighted 4 (parity with X-Frame-Options/
    # Referrer-Policy), which let a well-configured site missing only this
    # and CORP get dragged down a full letter grade for two headers the
    # reference grading tools don't treat as core requirements either.
    value = hv.get("Cross-Origin-Opener-Policy")
    if value is None:
        return [Finding("Cross-Origin-Opener-Policy", "missing", 2, "not sent",
                        "Cross-Origin-Opener-Policy: same-origin")]
    v = value.strip().lower()
    if v == "same-origin":
        return [Finding("Cross-Origin-Opener-Policy", "pass", 2, f"{value!r}", "")]
    if v == "same-origin-allow-popups":
        return [Finding("Cross-Origin-Opener-Policy", "warn", 2,
                        f"{value!r} — popups keep a reference to this window",
                        "Cross-Origin-Opener-Policy: same-origin")]
    return [Finding("Cross-Origin-Opener-Policy", "fail", 2,
                    f"{value!r} — explicitly open", "same-origin")]


def check_corp(hv: HeadersView, _is_https: bool) -> list[Finding]:
    # See check_coop — same informational-tier weight and the same reasoning.
    value = hv.get("Cross-Origin-Resource-Policy")
    if value is None:
        return [Finding("Cross-Origin-Resource-Policy", "missing", 2, "not sent",
                        "Cross-Origin-Resource-Policy: same-origin")]
    v = value.strip().lower()
    if v in ("same-origin", "same-site"):
        return [Finding("Cross-Origin-Resource-Policy", "pass", 2, f"{value!r}", "")]
    if v == "cross-origin":
        return [Finding("Cross-Origin-Resource-Policy", "warn", 2,
                        f"{value!r} — resource deliberately embeddable cross-origin",
                        "same-origin (unless the resource is meant to be embedded)")]
    return [Finding("Cross-Origin-Resource-Policy", "fail", 2,
                    f"{value!r} — unrecognized value", "same-origin")]


def check_cookies(hv: HeadersView, _is_https: bool) -> list[Finding]:
    """One finding per Set-Cookie line — the flags must be read per cookie."""
    raw = hv.get_all("Set-Cookie")
    if not raw:
        return []  # no cookies: no scored finding, no free credit either

    findings: list[Finding] = []
    # The family is worth COOKIE_FAMILY_WEIGHT points total, split across
    # whatever cookies arrived, so ten cookies don't dwarf HSTS in the score.
    weight = COOKIE_FAMILY_WEIGHT / len(raw)
    for line in raw:
        name, _, rest = line.partition("=")
        attrs = {p.strip().split("=", 1)[0].lower()
                 for p in rest.split(";") if p.strip()}
        missing = [flag for flag in ("secure", "httponly", "samesite")
                   if flag not in attrs]
        if not missing:
            findings.append(Finding(
                f"Set-Cookie: {name.strip()}", "pass", weight,
                f"{line!r} — Secure, HttpOnly, SameSite all set", ""))
        elif "secure" in missing or "httponly" in missing:
            findings.append(Finding(
                f"Set-Cookie: {name.strip()}", "fail", weight,
                f"{line!r} — missing {', '.join(missing)}",
                f"Set-Cookie: {line}; Secure; HttpOnly; SameSite=Lax"))
        else:
            findings.append(Finding(
                f"Set-Cookie: {name.strip()}", "warn", weight,
                f"{line!r} — missing SameSite",
                f"Set-Cookie: {line}; SameSite=Lax"))
    return findings


def check_server_leak(hv: HeadersView, _is_https: bool) -> list[Finding]:
    """Version strings in Server / X-Powered-By — informational, unscored."""
    findings: list[Finding] = []
    for name in ("Server", "X-Powered-By"):
        value = hv.get(name)
        if value is None:
            continue
        if re.search(r"\d", value):
            findings.append(Finding(
                name, "warn", 0,
                f"{value!r} — version string leaked",
                f"Strip the version: send `{name}` with no version, or omit it"))
        else:
            findings.append(Finding(name, "pass", 0, f"{value!r} — no version", ""))
    if not findings:
        findings.append(Finding("Server / X-Powered-By", "pass", 0,
                                "neither sent", ""))
    return findings


def check_xss_protection(hv: HeadersView, _is_https: bool) -> list[Finding]:
    """X-XSS-Protection gets a note, never a score.

    The modern guidance is to omit it entirely: the auditor is deprecated,
    and on old IE it could itself introduce an XSS vector.
    """
    value = hv.get("X-XSS-Protection")
    if value is None:
        return [Finding("X-XSS-Protection", "pass", 0,
                        "not sent (recommended — the auditor is deprecated)", "")]
    v = value.strip().lower()
    if v == "0":
        return [Finding("X-XSS-Protection", "pass", 0,
                        f"{value!r} — explicitly disabled", "")]
    if v.startswith("1;"):
        return [Finding("X-XSS-Protection", "pass", 0,
                        f"{value!r} — deprecated; best removed entirely",
                        "Omit the header; use CSP instead")]
    if v == "1":
        return [Finding("X-XSS-Protection", "warn", 0,
                        f"{value!r} — deprecated, and enables the auditor "
                        "without mode=block",
                        "Omit the header; use CSP instead")]
    return [Finding("X-XSS-Protection", "warn", 0,
                    f"{value!r} — unrecognized value", "Omit the header")]


def check_duplicate_headers(hv: HeadersView, _is_https: bool) -> list[Finding]:
    """Flag a security header sent more than once by the origin.

    Informational (severity 0) — the value-correctness checks above already
    score whichever occurrence ``hv.get()`` picks (the first one); this is
    about the repetition itself. Even byte-identical duplicates are worth
    surfacing: they mean two layers (CDN, security plugin, origin config)
    are independently setting the same header, which is a maintenance smell
    on its own and a sign the layers can silently drift apart — exactly what
    happened on the real site that prompted this check, where a duplicated
    Strict-Transport-Security carried different max-age/preload values
    between the two occurrences.
    """
    findings: list[Finding] = []
    for display in SECURITY_HEADERS.values():
        values = hv.get_all(display)
        if len(values) < 2:
            continue
        unique = list(dict.fromkeys(values))
        note = "identical" if len(unique) == 1 else "differing"
        findings.append(Finding(
            display, "warn", 0,
            f"sent {len(values)} times, {note} values: {values!r}",
            "Send it from exactly one layer (origin, CDN, or security "
            "plugin) — duplicates can silently drift apart"))
    return findings


ALL_CHECKS = [
    check_hsts, check_csp, check_xcto, check_xfo, check_referrer_policy,
    check_permissions_policy, check_coop, check_corp, check_cookies,
    check_server_leak, check_xss_protection, check_duplicate_headers,
]


def check_chain_drops(hops: list[Hop]) -> list[Finding]:
    """Flag security headers present on an earlier hop but gone at the final.

    A header attached at the origin and stripped by a CDN edge (or vice
    versa) is invisible to any tool that only looks at the last response.
    """
    if len(hops) < 2:
        return []
    final = HeadersView(hops[-1].headers).names()
    dropped: set[str] = set()
    for hop in hops[:-1]:
        for name in HeadersView(hop.headers).names() & SECURITY_HEADERS.keys():
            if name not in final:
                dropped.add(SECURITY_HEADERS[name])
    if not dropped:
        return []
    names = ", ".join(sorted(dropped))
    return [Finding("Redirect chain", "warn", 0,
                    f"present on an earlier hop, absent on the final response: {names}",
                    "Check which layer (origin, CDN, middleware) strips the header")]


# ---------------------------------------------------------------------------
# A3. Score → grade
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Report & artifacts
# ---------------------------------------------------------------------------

STATUS_ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌", "missing": "❌"}

GRADE_ICON = {"A+": "🛡️", "A": "✅", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}


def esc_cell(val: str, max_len: int = 160) -> str:
    """Escape a value for a markdown table cell."""
    s = str(val).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def top_fixes(findings: list[Finding], n: int = 3) -> list[Finding]:
    scored_down = [f for f in findings
                   if f.status in ("fail", "missing") and f.recommendation]
    return sorted(scored_down, key=lambda f: -f.severity)[:n]


def build_report(url: str, hops: list[Hop], findings: list[Finding],
                 score: int | None, grade: str) -> str:
    counts = {s: sum(1 for f in findings if f.status == s)
              for s in ("pass", "warn", "fail", "missing")}
    lines = [
        f"## {GRADE_ICON.get(grade, '')} Grade {grade} — {score if score is not None else 'n/a'}/100",
        "",
        f"`{url}`" + (f" · {len(hops)} hops (final: `{hops[-1].url}`)"
                      if len(hops) > 1 else ""),
        "",
        (f"✅ {counts['pass']} pass · ⚠️ {counts['warn']} warn · "
         f"❌ {counts['fail'] + counts['missing']} fail/missing"),
    ]

    fixes = top_fixes(findings)
    if fixes:
        lines += ["", "### Top fixes", ""]
        for f in fixes:
            lines.append(f"**{f.header}** — `{f.recommendation}`")

    lines += ["", "### Findings", "",
              "| Header | Status | Detail | Fix |", "| --- | --- | --- | --- |"]
    for f in findings:
        lines.append(f"| {esc_cell(f.header)} | {STATUS_ICON[f.status]} {f.status} "
                     f"| {esc_cell(f.detail) or '—'} | {esc_cell(f.recommendation) or '—'} |")

    if len(hops) > 1:
        lines += ["", "### Redirect chain", ""]
        for i, hop in enumerate(hops, 1):
            lines.append(f"- {i}. `{hop.status}` `{hop.url}`")

    return "\n".join(lines)


def write_artifacts(hops: list[Hop], findings: list[Finding],
                    score: int | None, grade: str, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return

    raw = [{"url": h.url, "status": h.status, "headers": h.headers} for h in hops]
    with open(os.path.join(out_dir, "headers_raw.json"), "w", encoding="utf-8") as fh:
        json.dump({"hops": raw}, fh, indent=2, ensure_ascii=False)

    payload = {
        "score": score,
        "grade": grade,
        "findings": [asdict(f) for f in findings],
    }
    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def audit(hops: list[Hop]) -> tuple[list[Finding], int | None, str]:
    """Run every check against the final hop. Pure — used by tests too."""
    hv = HeadersView(hops[-1].headers)
    is_https = urlsplit(hops[-1].url).scheme == "https"
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(hv, is_https))
    findings.extend(check_chain_drops(hops))
    score = score_findings(findings)
    return findings, score, grade_for(score)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Security Headers — grade a URL's security headers")
    parser.add_argument("--url", required=True, help="URL to audit")
    parser.add_argument("--follow-redirects", action="store_true",
                        help="Follow the redirect chain (PyShell passes the "
                             "flag when the toggle is on; a bare terminal "
                             "run audits exactly one response)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Per-request timeout in seconds")
    parser.add_argument("--user-agent", default=DEFAULT_UA,
                        help="User-Agent to send (some WAFs drop bare python-requests)")
    parser.add_argument("--headers", default=None,
                        help="Extra request headers, one 'Key: Value' per line "
                             "(e.g. a session Cookie for authenticated pages)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification (internal/staging hosts)")
    args = parser.parse_args()

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no request sent", flush=True)
        return 0

    try:
        extra_headers = parse_header_block(args.headers)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    headers = {"User-Agent": args.user_agent, **extra_headers}

    print(f"Auditing {args.url}", flush=True)
    status(f"Fetching {args.url}…")

    try:
        hops = fetch_chain(args.url, headers=headers, timeout=args.timeout,
                           follow=args.follow_redirects, verify=not args.insecure)
    except requests.RequestException as exc:
        kind = "timeout" if isinstance(exc, requests.Timeout) else "request error"
        message = f"{type(exc).__name__}: {exc}"
        print(f"✗ {message}", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Audit failed\n\n❌ **{esc_cell(message)}** · _{kind}_"})
        status(f"Failed: {kind}")
        return 1

    for i, hop in enumerate(hops, 1):
        status(f"Hop {i}: {hop.status} {hop.url}")

    final = hops[-1]
    print(f"← {final.status} {final.url} ({len(hops)} hop(s))", flush=True)

    emit({"type": "progress", "pct": 30, "message": "Checking headers"})
    findings, score, grade = audit(hops)
    emit({"type": "progress", "pct": 90, "message": "Scoring"})

    emit({
        "type": "table",
        "columns": ["Header", "Status", "Detail", "Fix"],
        "rows": [[f.header, f"{STATUS_ICON[f.status]} {f.status}",
                  f.detail[:200], f.recommendation[:200]] for f in findings],
    })

    report = build_report(args.url, hops, findings, score, grade)
    emit({"type": "markdown", "content": report})

    write_artifacts(hops, findings, score, grade, report)
    emit({"type": "progress", "pct": 100, "message": f"Grade {grade}"})
    status(f"Grade {grade} · score {score if score is not None else 'n/a'}")

    # A response arrived, so the audit succeeded — an F is a successful
    # audit that found a bad result, not a script failure.
    return 0


if __name__ == "__main__":
    sys.exit(main())
