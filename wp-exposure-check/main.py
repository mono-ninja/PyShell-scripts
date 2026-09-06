#!/usr/bin/env python3
"""wp-exposure-check/main.py — which WordPress doors does a site leave open?

A passive exposure check for WordPress sites: one plain GET per well-known
endpoint, each answered with a verdict and the fix. No POSTs, no login
attempts, no payloads — the same requests a scanner's very first recon
burst makes, so you see what it sees.

Endpoints, one GET each:

- ``/wp-json/wp/v2/users`` (+ the ``?rest_route=`` spelling as a fallback
  when the pretty route is blocked) — **REST user enumeration**: the logins
  a brute-force attack would try.
- ``/xmlrpc.php`` — answering 405 "accepts POST requests only" means the
  interface is live: pingback DoS and credential-stuffing amplification.
- ``/readme.html`` — ships with every WP install, names the exact version.
- ``/wp-content/debug.log`` — a debug log left inside the webroot.
- ``/wp-content/uploads/`` — directory listing of uploaded media.
- ``/wp-login.php`` — reachable? (informational: normal for WP, the
  brute-force context is what [Log Attack Checker](../log-attack-checker)
  adds.)
- the homepage ``<meta name="generator">`` tag — another version leak.

The homepage is fetched once first: it confirms the target is reachable
(exit 1 when it isn't — there was nothing to check) and collects the
WordPress markers. Exit codes: 0 = the check ran (exposures are
findings, not failures), 1 = the target never answered, 2 = bad
arguments, 3 = the opt-in ``--fail-on any`` CI gate.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit, urlunsplit

import requests

USER_AGENT = "PyShell-wp-exposure-check/1.0"

# Severity buckets, same vocabulary the Security family uses.
SEV_HIGH = "high"
SEV_MEDIUM = "medium"
SEV_INFO = "info"

STATUS_ICON = {
    "exposed": "🔴",
    "protected": "🟢",
    "not found": "⚪",
    "unknown": "🟡",
    "error": "⚫",
}
SEVERITY_ICON = {SEV_HIGH: "🔴", SEV_MEDIUM: "🟠", SEV_INFO: "🔵"}


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    key: str                 # machine id, e.g. "rest_users"
    label: str               # human label, e.g. "REST user enumeration"
    status: str              # exposed | protected | not found | unknown | error
    severity: str            # high | medium | info
    evidence: str            # what was actually seen (logins, version, size)
    fix: str                 # how to close it
    url: str = ""            # the URL that was asked
    detail: str = ""         # error text when status == "error"


@dataclass
class Facts:
    reachable: bool = False
    http_status: int | None = None
    wp_markers: list[str] = field(default_factory=list)  # evidence of WP-ness
    generator_version: str = ""


def is_exposure(result: CheckResult) -> bool:
    """An exposure is a check that came back 'exposed' — a protected,
    absent or unknown endpoint is a good (or at least not bad) answer."""
    return result.status == "exposed"


# ---------------------------------------------------------------------------
# Parsing helpers (pure — tests live on these)
# ---------------------------------------------------------------------------

GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+'
    r'content=["\']WordPress\s+([0-9][0-9A-Za-z.\-]*)', re.IGNORECASE)
README_VERSION_RE = re.compile(
    r'Version\s+([0-9]+(?:\.[0-9]+)+(?:-[A-Za-z0-9.]+)?)', re.IGNORECASE)
INDEX_OF_RE = re.compile(r"<title[^>]*>\s*Index of\b", re.IGNORECASE)
XMLRPC_LIVE_RE = re.compile(r"accepts\s+POST\s+requests", re.IGNORECASE)


def parse_generator_version(html: str) -> str:
    """The WP version from a homepage <meta name=generator> tag, or ''."""
    m = GENERATOR_RE.search(html or "")
    return m.group(1) if m else ""


def parse_readme_version(html: str) -> str:
    """The version named by a readme.html page, or ''."""
    m = README_VERSION_RE.search(html or "")
    return m.group(1) if m else ""


def parse_users_payload(body: str) -> list[str]:
    """Slugs from a wp/v2/users JSON array. Unknown shapes → []."""
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    slugs = []
    for entry in data:
        if isinstance(entry, dict) and entry.get("slug"):
            slugs.append(str(entry["slug"]))
    return slugs


def looks_like_uploads_listing(html: str) -> bool:
    """An Apache/nginx 'Index of' directory listing page."""
    return bool(INDEX_OF_RE.search(html or ""))


def looks_like_log(body: str) -> bool:
    """Heuristic: a debug.log answers with content that reads like one —
    timestamped PHP lines. A bare 200 with an HTML page (a soft-404) must
    not count as a leaked log."""
    if not body or "<html" in body[:2048].lower():
        return False
    return bool(re.search(r"\[\d{2}-[A-Za-z]{3}-\d{4}[^\]]*\]", body[:4096]))


def detect_wp_markers(html: str) -> list[str]:
    """Cheap evidence the site is WordPress at all. Empty list = maybe
    it isn't, and the report says so honestly."""
    markers = []
    if not html:
        return markers
    if "wp-content" in html or "wp-includes" in html:
        markers.append("wp-content/wp-includes asset paths")
    if "/wp-json" in html or "rest_route" in html:
        markers.append("wp-json REST link")
    if "wp-login.php" in html:
        markers.append("wp-login link")
    if parse_generator_version(html):
        markers.append(f"generator meta tag (WordPress {parse_generator_version(html)})")
    return markers


# ---------------------------------------------------------------------------
# Endpoint checks — one GET each, all passive
# ---------------------------------------------------------------------------

def _get(session: requests.Session, url: str, timeout: int
         ) -> tuple[requests.Response | None, str]:
    """One GET. (response, error-label) — never raises."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        return resp, ""
    except requests.RequestException as exc:
        return None, type(exc).__name__


def check_rest_users(session: requests.Session, base: str, timeout: int
                     ) -> CheckResult:
    """wp/v2/users — the enumeration brute force feeds on."""
    url = base.rstrip("/") + "/wp-json/wp/v2/users"
    result = CheckResult(
        key="rest_users", label="REST user enumeration",
        status="unknown", severity=SEV_HIGH, evidence="", fix="", url=url)
    resp, err = _get(session, url, timeout)
    # The ?rest_route= spelling of the same endpoint — tried only when the
    # pretty route is closed, because a filter can block one and not the other.
    if resp is None or resp.status_code in (401, 403, 404):
        alt = base.rstrip("/") + "/?rest_route=/wp/v2/users"
        alt_resp, alt_err = _get(session, alt, timeout)
        if alt_resp is not None and (resp is None
                                     or alt_resp.status_code < resp.status_code
                                     or alt_resp.status_code == 200):
            resp, err, url = alt_resp, alt_err, alt

    if resp is None:
        result.status, result.detail = "error", err
        result.fix = "Check reachability — the endpoint didn't answer."
        return result
    result.url = url
    code = resp.status_code
    if code == 200:
        slugs = parse_users_payload(resp.text)
        if slugs:
            result.status = "exposed"
            result.evidence = f"{len(slugs)} login(s): " + ", ".join(slugs[:10]) \
                + ("…" if len(slugs) > 10 else "")
        else:
            # 200 but not a users payload — likely a soft-404 page; the
            # endpoint isn't enumerating, but "protected" would overclaim.
            result.status = "unknown"
            result.evidence = "answered 200 without a user list (likely a soft-404)"
    elif code in (401, 403):
        result.status, result.evidence = "protected", f"answered {code} (requires auth / blocked)"
    elif code == 404:
        result.status, result.evidence = "not found", "answered 404"
    else:
        result.status, result.evidence = "unknown", f"answered {code}"
    result.fix = ("Remove the users endpoint from public REST: a filter on "
                  "`rest_endpoints` unsetting `/wp/v2/users`, or a security "
                  "plugin — block both the pretty route and `?rest_route=`.")
    return result


def check_xmlrpc(session: requests.Session, base: str, timeout: int
                 ) -> CheckResult:
    """xmlrpc.php — a GET is enough: '405 accepts POST only' = the
    interface is live."""
    url = base.rstrip("/") + "/xmlrpc.php"
    result = CheckResult(
        key="xmlrpc", label="XML-RPC interface",
        status="unknown", severity=SEV_MEDIUM, evidence="", fix="", url=url)
    resp, err = _get(session, url, timeout)
    if resp is None:
        result.status, result.detail = "error", err
        result.fix = "Check reachability — the endpoint didn't answer."
        return result
    code = resp.status_code
    if code in (200, 405) and XMLRPC_LIVE_RE.search(resp.text or ""):
        result.status = "exposed"
        result.evidence = ("live (answers "
                           + ("405 'accepts POST requests only'" if code == 405
                              else "200 'accepts POST requests only'") + ")")
    elif code in (403, 404, 405):
        # 405 without the live marker, 403/404 — blocked or absent.
        result.status = "protected" if code == 403 else "not found"
        result.evidence = f"answered {code}"
    elif 300 <= code < 400:
        result.status, result.evidence = "unknown", f"redirected ({code})"
    else:
        result.status, result.evidence = "unknown", f"answered {code}"
    result.fix = ("Deny or restrict xmlrpc.php unless a service needs it "
                  "(Jetpack does) — nginx `location = /xmlrpc.php { deny all; }` "
                  "or the same in .htaccess; watch login attempts in "
                  "[Log Attack Checker](../log-attack-checker) first.")
    return result


def check_readme(session: requests.Session, base: str, timeout: int
                 ) -> CheckResult:
    """readme.html — names the exact WP version."""
    url = base.rstrip("/") + "/readme.html"
    result = CheckResult(
        key="readme", label="readme.html version leak",
        status="unknown", severity=SEV_MEDIUM, evidence="", fix="", url=url)
    resp, err = _get(session, url, timeout)
    if resp is None:
        result.status, result.detail = "error", err
        result.fix = "Check reachability — the endpoint didn't answer."
        return result
    code = resp.status_code
    version = parse_readme_version(resp.text or "") if code == 200 else ""
    if code == 200 and version:
        result.status = "exposed"
        result.evidence = f"readable, names version {version}"
    elif code == 200:
        result.status, result.evidence = "unknown", "answered 200 but no version found"
    elif code == 403:
        result.status, result.evidence = "protected", "answered 403"
    else:
        result.status, result.evidence = "not found", f"answered {code}"
    result.fix = ("Delete readme.html after every update, or block it — "
                  "nginx `location = /readme.html { deny all; }`; the version "
                  "it names feeds the CVE lists [CVE Check](../cve-check) walks.")
    return result


def check_debug_log(session: requests.Session, base: str, timeout: int
                    ) -> CheckResult:
    """wp-content/debug.log — a log left inside the webroot."""
    url = base.rstrip("/") + "/wp-content/debug.log"
    result = CheckResult(
        key="debug_log", label="debug.log in the webroot",
        status="unknown", severity=SEV_HIGH, evidence="", fix="", url=url)
    resp, err = _get(session, url, timeout)
    if resp is None:
        result.status, result.detail = "error", err
        result.fix = "Check reachability — the endpoint didn't answer."
        return result
    code = resp.status_code
    if code == 200:
        if looks_like_log(resp.text or ""):
            result.status = "exposed"
            size = len(resp.content or b"")
            result.evidence = f"downloadable ({size:,} bytes of log lines)"
        else:
            # A soft-404: some themes render any URL as 200 HTML.
            result.status, result.evidence = "not found", "answered 200 with a page, not a log"
    elif code == 403:
        result.status, result.evidence = "protected", "answered 403"
    else:
        result.status, result.evidence = "not found", f"answered {code}"
    result.fix = ("Keep WP_DEBUG_LOG off in production; if you must log, "
                  "write outside the webroot or block the file — nginx "
                  r"`location ~ /debug\.log { deny all; }`.")
    return result


def check_uploads_listing(session: requests.Session, base: str, timeout: int
                          ) -> CheckResult:
    """wp-content/uploads/ — a browsable media directory."""
    url = base.rstrip("/") + "/wp-content/uploads/"
    result = CheckResult(
        key="uploads_listing", label="uploads directory listing",
        status="unknown", severity=SEV_MEDIUM, evidence="", fix="", url=url)
    resp, err = _get(session, url, timeout)
    if resp is None:
        result.status, result.detail = "error", err
        result.fix = "Check reachability — the endpoint didn't answer."
        return result
    code = resp.status_code
    if code == 200:
        if looks_like_uploads_listing(resp.text or ""):
            result.status = "exposed"
            result.evidence = "directory listing is on (an 'Index of' page)"
        else:
            result.status, result.evidence = "protected", "answered 200 with a plain page (listing off)"
    elif code == 403:
        result.status, result.evidence = "protected", "answered 403 (listing blocked)"
    else:
        result.status, result.evidence = "not found", f"answered {code}"
    result.fix = ("Turn listing off — `.htaccess`: `Options -Indexes`; "
                  "nginx: `autoindex off;` (the default — don't enable it).")
    return result


def check_wp_login(session: requests.Session, base: str, timeout: int
                   ) -> CheckResult:
    """wp-login.php — informational: reachable is normal, the risk is the
    brute force that follows, which Log Attack Checker measures."""
    url = base.rstrip("/") + "/wp-login.php"
    result = CheckResult(
        key="wp_login", label="wp-login.php reachable",
        status="unknown", severity=SEV_INFO, evidence="", fix="", url=url)
    resp, err = _get(session, url, timeout)
    if resp is None:
        result.status, result.detail = "error", err
        result.fix = "Check reachability — the endpoint didn't answer."
        return result
    code = resp.status_code
    if code == 200 and "user_login" in (resp.text or "").lower():
        result.status = "exposed"
        result.evidence = "login form served"
    elif code == 200:
        result.status, result.evidence = "unknown", "answered 200 without a login form"
    elif code == 404:
        result.status, result.evidence = "not found", "answered 404"
    elif 300 <= code < 400:
        result.status, result.evidence = "protected", f"redirected away ({code})"
    else:
        result.status, result.evidence = "protected", f"answered {code}"
    result.fix = ("Reachable is normal for WordPress. What turns it into a "
                  "risk is unthrottled attempts — [Log Attack Checker]"
                  "(../log-attack-checker) shows whether any are landing; "
                  "rate-limit or move login behind a proxy when they do.")
    return result


def check_generator(facts: Facts) -> CheckResult:
    """The homepage generator meta — decided from the already-fetched
    homepage, so this check costs no extra request."""
    result = CheckResult(
        key="generator", label="generator meta version leak",
        status="not found", severity=SEV_INFO, evidence="no generator tag on the homepage",
        fix=("Remove the tag — `remove_action('wp_head', 'wp_generator')` in "
             "functions.php; version hints feed the CVE lists "
             "[CVE Check](../cve-check) walks."),
        url="(homepage)")
    if facts.generator_version:
        result.status = "exposed"
        result.evidence = f"meta tag names WordPress {facts.generator_version}"
    return result


ALL_CHECKS = [
    ("rest_users", "REST user enumeration", check_rest_users),
    ("xmlrpc", "XML-RPC interface", check_xmlrpc),
    ("readme", "readme.html version leak", check_readme),
    ("debug_log", "debug.log in the webroot", check_debug_log),
    ("uploads_listing", "uploads directory listing", check_uploads_listing),
    ("wp_login", "wp-login.php reachable", check_wp_login),
]


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_table_event(results: list[CheckResult]) -> dict:
    rows = []
    for r in results:
        rows.append([
            f"{STATUS_ICON.get(r.status, '')} {r.status}",
            r.label,
            r.evidence or r.detail or "—",
        ])
    return {
        "type": "table",
        "columns": ["Status", "Check", "What was seen"],
        "rows": rows,
    }


def build_report(url: str, facts: Facts, results: list[CheckResult]) -> str:
    exposures = [r for r in results if is_exposure(r)]
    head = (f"## 🔴 {len(exposures)} exposure(s)" if exposures
            else "## 🟢 No exposures found")
    lines = [head, "", f"`{url}`", ""]

    if facts.wp_markers:
        lines.append(f"- WordPress markers on the homepage: "
                     f"{'; '.join(facts.wp_markers)}")
    else:
        lines.append("- ⚠️ no WordPress markers found on the homepage — "
                     "this may not be a WordPress site; the endpoint "
                     "verdicts below still stand on their own.")
    lines.append("")

    lines += ["| Check | Status | What was seen | How to close it |",
              "| --- | --- | --- | --- |"]
    for r in results:
        icon = STATUS_ICON.get(r.status, "")
        fix = r.fix if r.status == "exposed" else "—"
        evidence = r.evidence or r.detail or "—"
        lines.append(f"| {r.label} | {icon} {r.status} | {evidence} | {fix} |")
    lines.append("")

    if exposures:
        lines.append("**Fix first, in this order**")
        lines.append("")
        for r in sorted(exposures, key=lambda x: (x.severity != SEV_HIGH,
                                                  x.severity != SEV_MEDIUM)):
            lines.append(f"- {SEVERITY_ICON.get(r.severity, '')} **{r.label}** "
                         f"({r.severity}) — {r.fix}")
        lines.append("")
        lines.append("_Then see what the attacks that exploit these look "
                     "like in your logs: [Log Attack Checker]"
                     "(../log-attack-checker)._")
    else:
        lines.append("_Every endpoint answered closed or absent — the doors "
                     "this script knows about are shut. Watch the logs "
                     "anyway: [Log Attack Checker](../log-attack-checker)._")
    lines.append("")
    lines.append(f"_{len(results)} passive GET(s) sent, redirects followed; "
                 "no POSTs, no login attempts._")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WP Exposure Check — which WordPress doors a site "
                    "leaves open, one passive GET per endpoint")
    parser.add_argument("--url", required=True, help="base URL of the site")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout in seconds (default 10)")
    parser.add_argument("--fail-on", choices=["none", "any"], default="none",
                        help="exit 3 when exposures are found (CI gate; "
                             "default: findings are not failures)")
    return parser


def validate_url(url: str) -> str | None:
    """An error message, or None when the URL is usable."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return f"{url!r} is not a parsable URL"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return (f"{url!r} needs a scheme and host "
                f"(https://example.com/…)")
    return None


def normalize_base(url: str) -> str:
    """Scheme + host only — endpoints hang off the root, not a deep path."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no requests are made", flush=True)
        return 0

    problem = validate_url(args.url)
    if problem:
        print(f"✗ {problem}", file=sys.stderr, flush=True)
        return 2
    base = normalize_base(args.url)

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    # Phase 1 — the homepage: reachability + WP markers + generator.
    status(f"Fetching homepage of {base}")
    resp, err = _get(session, base, args.timeout)
    facts = Facts()
    if resp is not None:
        facts.reachable = True
        facts.http_status = resp.status_code
        html = resp.text or ""
        facts.wp_markers = detect_wp_markers(html)
        facts.generator_version = parse_generator_version(html)
    if resp is None:
        print(f"✗ {base} never answered ({err}) — there was nothing to "
              f"check", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Check failed\n\n❌ **{base}** never answered ({err}) — "
              f"an unreachable target is a prerequisite problem, not a "
              f"finding. Verify the URL with [IP Search](../ip-search) or "
              f"[Server Timing](../server-timing) first."})
        return 1
    if facts.http_status is not None and facts.http_status >= 400:
        print(f"✗ {base} answered HTTP {facts.http_status} on the homepage — "
              f"a broken site can't be exposure-checked",
              file=sys.stderr, flush=True)
        return 1

    markers = ", ".join(facts.wp_markers) if facts.wp_markers \
        else "no WordPress markers found"
    log(f"Homepage: HTTP {facts.http_status} · {markers}")
    emit({"type": "progress", "pct": 10, "message": "Homepage fetched"})

    # Phase 2 — one GET per endpoint.
    results: list[CheckResult] = []
    total = len(ALL_CHECKS) + 1  # +1 for the generator verdict
    for i, (key, label, fn) in enumerate(ALL_CHECKS):
        status(f"Checking {label}")
        result = fn(session, base, args.timeout)
        results.append(result)
        icon = STATUS_ICON.get(result.status, "")
        log(f"  {icon} {label:<28} {result.status:<10} "
            f"{result.evidence or result.detail or ''}")
        emit({"type": "progress",
              "pct": 10 + int(85 * (i + 1) / total),
              "message": f"{label}: {result.status}"})

    # The generator check reads the homepage we already have — no request.
    results.append(check_generator(facts))
    icon = STATUS_ICON.get(results[-1].status, "")
    log(f"  {icon} {'generator meta version leak':<28} {results[-1].status:<10} "
        f"{results[-1].evidence}")
    emit({"type": "progress", "pct": 95, "message": "Building report"})

    report = build_report(base, facts, results)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(results))
    emit({"type": "markdown", "content": report})

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        payload = {
            "url": base,
            "wordpress_markers": facts.wp_markers,
            "generator_version": facts.generator_version or None,
            "exposure_count": sum(1 for r in results if is_exposure(r)),
            "findings": [asdict(r) for r in results],
        }
        with open(os.path.join(output_dir, "findings.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        with open(os.path.join(output_dir, "report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(report + "\n")

    exposures = sum(1 for r in results if is_exposure(r))
    status(f"{exposures} exposure(s) over {len(results)} checks")
    log(f"← {exposures} exposure(s) over {len(results)} checks")

    if exposures and args.fail_on == "any":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
