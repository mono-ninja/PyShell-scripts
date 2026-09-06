"""src/checks.py — the per-site pipeline: full (sibling invocation) or
compact (built-in), never silently mixed.

**Full mode** runs the sibling script's main.py as a child process —
the guide's *invocation* variant of `needs` — with
`PYSHELL_OUTPUT_DIR` pointed at a temp dir, then parses its artifacts:
tls-audit's `findings.json` (grade) + `tls_raw.json` (certificate
expiry), security-headers' `findings.json` (grade), tech-stack's
`stack.json` (technologies + the WordPress version). The real
detection logic, no duplication.

**Compact mode** (the sibling not installed — `needs` is an
expectation, not a block) runs a minimal built-in: certificate days
via the `ssl` stdlib, a five-key header-presence grade (clearly not
the sibling's letter grade — labeled compact everywhere), the
generator-tag WordPress version. Sitemap presence is always the same
inline GET.
"""
from __future__ import annotations

import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

USER_AGENT = "PyShell-fleet-check/1.0"
SUBPROCESS_TIMEOUT = 240          # one sibling run per site, generous
HEADERS_KEYS = ("strict-transport-security", "content-security-policy",
                "x-content-type-options", "x-frame-options",
                "referrer-policy")
GENERATOR_WP_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+'
    r'content=["\']WordPress\s+([0-9][0-9A-Za-z.\-]*)', re.IGNORECASE)


@dataclass
class SiteResult:
    url: str
    host: str
    reachable: bool = False
    http_status: int | None = None
    tls_grade: str = ""            # letter, full mode only
    tls_mode: str = ""             # full | compact | "" (not checked)
    cert_days: int | None = None
    cert_note: str = ""            # "verified", "unverified", "no TLS"…
    headers_grade: str = ""        # letter (full) or compact letter
    headers_mode: str = ""
    headers_score: int | None = None
    wp_version: str = ""
    tech_count: int | None = None
    tech_mode: str = ""
    sitemap: bool | None = None
    homepage_title_note: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def tls_label(self) -> str:
        if self.tls_mode == "full":
            return self.tls_grade or "?"
        if self.tls_mode == "compact":
            return self.cert_note or "compact"
        return "—"

    @property
    def cert_label(self) -> str:
        if self.cert_days is None:
            return self.cert_note or "—"
        if self.cert_days < 0:
            return f"EXPIRED {-self.cert_days}d ago"
        return f"{self.cert_days}d"


# ---------------------------------------------------------------------------
# Sibling invocation (full mode)
# ---------------------------------------------------------------------------

def _run_sibling(folder: str, script_args: list[str],
                 timeout: int) -> tuple[dict, list[str]]:
    """One sibling run into a fresh temp PYSHELL_OUTPUT_DIR.
    (parsed_json_by_filename, errors)."""
    with tempfile.TemporaryDirectory(prefix="fleetcheck-") as tmp:
        env = dict(os.environ)
        env["PYSHELL_OUTPUT_DIR"] = tmp
        cmd = [sys.executable, os.path.join(folder, "main.py"),
               *script_args]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                  env=env, cwd=folder)
        except subprocess.TimeoutExpired:
            return {}, ["sibling timeout"]
        except OSError as exc:
            return {}, [f"sibling failed to start ({type(exc).__name__})"]
        parsed: dict = {}
        errors: list[str] = []
        if proc.returncode not in (0,):
            errors.append(f"exit {proc.returncode}")
        for name in ("findings.json", "tls_raw.json", "stack.json"):
            path = os.path.join(tmp, name)
            if os.path.exists(path):
                try:
                    with open(path, encoding="utf-8") as fh:
                        parsed[name] = json.load(fh)
                except (OSError, ValueError):
                    errors.append(f"unreadable {name}")
        return parsed, errors


def full_tls_check(url: str, deps: dict, result: SiteResult,
                   timeout: int) -> None:
    parsed, errors = _run_sibling(
        deps["com.pyshell.tlsaudit"], ["--target", url], timeout)
    result.errors += errors
    findings = parsed.get("findings.json") or {}
    raw = parsed.get("tls_raw.json") or {}
    result.tls_mode = "full"
    if findings.get("grade"):
        result.tls_grade = str(findings["grade"])
    cert = raw.get("certificate") or {}
    not_after = cert.get("not_after")
    if not_after:
        result.cert_days = _days_left(not_after)
        result.cert_note = "verified" if result.tls_grade else "checked"


def full_headers_check(url: str, deps: dict, result: SiteResult,
                       timeout: int) -> None:
    parsed, errors = _run_sibling(
        deps["com.pyshell.securityheaders"], ["--url", url], timeout)
    result.errors += errors
    findings = parsed.get("findings.json") or {}
    result.headers_mode = "full"
    if findings.get("grade"):
        result.headers_grade = str(findings["grade"])
    if findings.get("score") is not None:
        result.headers_score = int(findings["score"])


def full_tech_check(url: str, deps: dict, result: SiteResult,
                    timeout: int) -> None:
    parsed, errors = _run_sibling(
        deps["com.pyshell.techstack"],
        ["--url", url, "--versions", "--delay", "0.2"], timeout)
    result.errors += errors
    stack = parsed.get("stack.json") or {}
    result.tech_mode = "full"
    techs = stack.get("technologies") or []
    result.tech_count = len(techs)
    for tech in techs:
        slug = (tech.get("slug") or "").lower()
        if slug == "wordpress":
            version = tech.get("version")
            if version and version != "unknown":
                result.wp_version = str(version)
            break


# ---------------------------------------------------------------------------
# Compact checks (built-in, labeled)
# ---------------------------------------------------------------------------

def _days_left(when: str) -> int | None:
    """Days until expiry. Two shapes: ISO (tls_raw.json's not_after)
    and OpenSSL ('Sep  4 12:00:00 2026 GMT' — getpeercert's notAfter)."""
    if not when:
        return None
    text = when.strip()
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed - datetime.now(timezone.utc)).days


def compact_tls_check(url: str, result: SiteResult,
                      timeout: int) -> None:
    """The ssl-stdlib handshake: expiry + verification. No grade — a
    compact check must not pass itself off as the sibling's letter."""
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    result.tls_mode = "compact"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if cert:
                    result.cert_days = _days_left(cert.get("notAfter", ""))
                    result.cert_note = "verified"
                else:
                    result.cert_note = "no cert info"
    except ssl.SSLCertVerificationError:
        result.cert_note = "UNVERIFIED"
    except (ssl.SSLError, socket.timeout, OSError):
        result.cert_note = "no TLS"


def compact_headers_check(url: str, result: SiteResult,
                          session: requests.Session, timeout: int,
                          homepage_headers: dict | None = None) -> None:
    """Five key headers → a compact A–E presence grade (5=A … ≤1=E).
    Labeled compact: not the sibling's weighted letter."""
    headers = homepage_headers or {}
    if homepage_headers is None:
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            headers = resp.headers
        except requests.RequestException:
            result.headers_mode = "compact"
            return
    present = sum(1 for k in HEADERS_KEYS if k in headers)
    result.headers_mode = "compact"
    result.headers_score = present
    result.headers_grade = {5: "A", 4: "B", 3: "C", 2: "D"}.get(present, "E")


def compact_tech_check(html: str, result: SiteResult) -> None:
    """The generator-tag WordPress version — the one-line version of
    what tech-stack does properly."""
    result.tech_mode = "compact"
    m = GENERATOR_WP_RE.search(html or "")
    if m:
        result.wp_version = m.group(1)


# ---------------------------------------------------------------------------
# Sitemap (always inline)
# ---------------------------------------------------------------------------

def check_sitemap(url: str, session: requests.Session,
                  timeout: int) -> bool | None:
    try:
        resp = session.get(url.rstrip("/") + "/sitemap.xml",
                           timeout=timeout, allow_redirects=True)
        return resp.status_code == 200 and \
            ("<urlset" in resp.text[:5000]
             or "<sitemapindex" in resp.text[:5000])
    except requests.RequestException:
        return None


# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------

def check_site(url: str, session: requests.Session, timeout: int,
               deps: dict) -> SiteResult:
    """One site through everything. Never raises: every failure is a
    fact in the result."""
    host = urlsplit(url).hostname or url
    result = SiteResult(url=url, host=host)
    html = ""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        result.http_status = resp.status_code
        result.reachable = resp.status_code < 400
        html = resp.text or ""
        headers = resp.headers  # CaseInsensitiveDict — keep it that way
    except requests.RequestException as exc:
        result.errors.append(f"homepage: {type(exc).__name__}")
        return result

    # TLS: full via the sibling when installed.
    if "com.pyshell.tlsaudit" in deps:
        full_tls_check(url, deps, result, SUBPROCESS_TIMEOUT)
        if result.cert_days is None:
            compact_tls_check(url, result, timeout)
    else:
        compact_tls_check(url, result, timeout)

    # Security headers: full via the sibling when installed.
    if "com.pyshell.securityheaders" in deps:
        full_headers_check(url, deps, result, SUBPROCESS_TIMEOUT)
        if not result.headers_grade:
            compact_headers_check(url, result, session, timeout, headers)
    else:
        compact_headers_check(url, result, session, timeout, headers)

    # Tech / WP version: full via the sibling when installed.
    if "com.pyshell.techstack" in deps:
        full_tech_check(url, deps, result, SUBPROCESS_TIMEOUT)
        if not result.wp_version:
            compact_tech_check(html, result)
    else:
        compact_tech_check(html, result)

    result.sitemap = check_sitemap(url, session, timeout)
    return result
