#!/usr/bin/env python3
"""csp-audit/main.py — how strong the Content-Security-Policy is.

Security Headers grades CSP by presence (one line, one grade); this
script is the whole dive behind that line, the Google CSP Evaluator
shape:

- **unsafe-inline / unsafe-eval** — where they appear (script-src
  directly or via default-src inheritance), with the nonce nuance:
  alongside a nonce or hash, modern browsers *ignore* unsafe-inline
  in script-src — that pairing is reported as transitional, not as
  the hole it would otherwise be.
- **Wildcards** — `*`, `http:`, `https:` scheme sources, and bare
  subdomain wildcards (`*.example.com`) in script-src: every host
  on the planet (or the subdomain's tenants) is inside.
- **Bypass hosts** — the allowlist entries that can serve
  attacker-controlled or arbitrary script: unpkg, jsdelivr,
  raw.githubusercontent, the JSONP family, public buckets — a
  curated YAML (the tech.yaml/rules.yaml precedent), each with its
  reason.
- **Foundational directives** — `base-uri` (missing = injected
  `<base>` hijacks every relative URL), `object-src` (or
  default-src), `frame-ancestors` (cross-checked against
  X-Frame-Options from the same response), `form-action`,
  `upgrade-insecure-requests`.
- **strict-dynamic** — the presence that makes host allowlists
  obsolete (scripts propagate trust themselves).
- **Report-Only vs enforced** — the same fetch's two policies
  diffed: what is reported but not blocked (the "I report what I
  tolerate" shape), and what is enforced but never reported.

One fetch; every verdict names the directive and the source.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests
import yaml

USER_AGENT = "PyShell-csp-audit/1 (+CSP policy diagnostics)"
BYPASS_PATH = Path(__file__).resolve().parent / "bypass_hosts.yaml"

FETCH_DIRECTIVES = {"script-src", "style-src", "img-src", "font-src",
                    "connect-src", "media-src", "worker-src",
                    "frame-src", "child-src", "manifest-src",
                    "object-src", "prefetch-src"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ----------------------------------------------------------------- parsing

def parse_policy(value: str) -> dict[str, list[str]]:
    """'default-src 'self'; script-src *.x.com' →
    {'default-src': ["'self'"], 'script-src': ['*.x.com']}"""
    out: dict[str, list[str]] = {}
    for part in (value or "").split(";"):
        tokens = part.split()
        if not tokens:
            continue
        out[tokens[0].lower()] = tokens[1:]
    return out


def effective_sources(policy: dict, directive: str) -> tuple[str,
                                                              list[str]]:
    """(directive-that-answered, its sources) — fetch directives
    inherit default-src."""
    if directive in policy:
        return directive, policy[directive]
    if directive in FETCH_DIRECTIVES and "default-src" in policy:
        return f"default-src→{directive}", policy["default-src"]
    return directive, []


def host_of(source: str) -> str:
    """'https://cdn.example.com/x' → 'cdn.example.com';
    scheme:/keyword sources → ''."""
    if source.startswith(("'", "data:", "blob:", "filesystem:")):
        return ""
    host = re.sub(r"^[a-z]+://", "", source).split("/")[0]
    host = host.split("@")[-1].split(":")[0]
    return host.lower().strip(".")


def load_bypasses() -> list[dict]:
    data = yaml.safe_load(BYPASS_PATH.read_text(encoding="utf-8")) \
        or {}
    return data.get("hosts") or []


def matches_bypass(source_host: str, entry_host: str) -> bool:
    pattern = entry_host.lstrip("*.").lower()
    sh = source_host.lower()
    return sh == entry_host.lower() or sh.endswith("." + pattern) \
        or sh == pattern


# ----------------------------------------------------------------- findings

def analyze_policy(policy: dict, bypasses: list[dict],
                   headers: dict | None = None) -> list[dict]:
    """Findings for one parsed policy; each is
    {severity, check, detail} — severity: critical|warning|info|good."""
    findings: list[dict] = []

    def add(severity: str, check: str, detail: str):
        findings.append({"severity": severity, "check": check,
                         "detail": detail})

    if not policy:
        add("info", "policy",
            "no directives parsed — an empty policy blocks nothing")
        return findings

    # unsafe-* with the nonce nuance
    src_directive, script_sources = effective_sources(policy,
                                                      "script-src")
    has_nonce = any(s.startswith("'nonce-") for s in script_sources)
    has_hash = any(s.startswith("'sha") for s in script_sources)
    if "'unsafe-eval'" in script_sources:
        add("critical", "unsafe-eval",
            f"{src_directive} allows 'unsafe-eval' — eval(), new "
            "Function(), injected string→code: the XSS playground "
            "reopens")
    if "'unsafe-inline'" in script_sources:
        if has_nonce or has_hash:
            add("info", "unsafe-inline",
                f"'unsafe-inline' in {src_directive} alongside a "
                "nonce/hash — modern browsers ignore it there; it "
                "only still applies on ancient ones (the "
                "transitional shape)")
        else:
            add("critical", "unsafe-inline",
                f"{src_directive} allows 'unsafe-inline' without a "
                "nonce/hash — any injected <script> runs; the policy "
                "does not defend against XSS at all")

    # wildcards in script-src
    wild = [s for s in script_sources
            if s in ("*", "http:", "https:", "http://*", "https://*")]
    if wild:
        add("critical", "wildcard",
            f"{src_directive} includes {', '.join(wild)} — every "
            "host on the planet may serve script")
    subdomain_wild = [s for s in script_sources
                      if s.startswith("*.") and host_of(s)]
    for s in subdomain_wild:
        add("warning", "wildcard",
            f"{src_directive} includes {s} — every tenant of that "
            "domain is inside the script allowlist")

    # bypass hosts
    for entry in bypasses:
        for s in script_sources:
            h = host_of(s)
            if h and matches_bypass(h, entry["host"]):
                add("warning", "bypass-host",
                    f"{s} in {src_directive} — {entry['reason']}")
                break

    # style-src unsafe-inline (milder than script)
    style_dir, style_sources = effective_sources(policy, "style-src")
    if "'unsafe-inline'" in style_sources and not has_nonce:
        add("info", "style-inline",
            f"{style_dir} allows 'unsafe-inline' style — milder than "
            "the script hole (data exfiltration via CSS attributes "
            "is still a thing)")

    # foundational directives
    if "base-uri" not in policy:
        add("warning", "base-uri",
            "no base-uri — an injected <base> element silently "
            "rewrites every relative URL on the page; 'self' here "
            "is one line")
    obj_dir, obj_sources = effective_sources(policy, "object-src")
    if not obj_sources:
        add("info", "object-src",
            "no object-src (and no default-src to inherit) — "
            "<object>/<embed> plugins are unrestricted")
    elif "'none'" in obj_sources:
        add("good", "object-src", "object-src 'none' — plugins off")
    if "frame-ancestors" not in policy:
        xfo = (headers or {}).get("X-Frame-Options", "")
        if xfo:
            add("info", "frame-ancestors",
                f"no frame-ancestors, but X-Frame-Options: {xfo} "
                "covers old browsers only — frame-ancestors is the "
                "CSP-native clickjacking guard")
        else:
            add("warning", "frame-ancestors",
                "neither frame-ancestors nor X-Frame-Options — "
                "nothing tells browsers not to frame this page")
    if "form-action" not in policy:
        add("info", "form-action",
            "no form-action — an injected form can submit "
            "credentials anywhere")
    if "upgrade-insecure-requests" not in policy:
        add("info", "upgrade-insecure-requests",
            "no upgrade-insecure-requests — http:// subresources "
            "stay http://")

    # strict-dynamic
    if "'strict-dynamic'" in script_sources:
        add("good", "strict-dynamic",
            "'strict-dynamic' — scripts you allow may load more "
            "scripts; the host allowlist matters less (keep it "
            "anyway for old browsers)")

    if not any(f["severity"] == "critical" for f in findings) \
            and has_nonce:
        add("good", "nonce",
            "nonce-based script-src — the modern shape")
    return findings


def diff_report_only(enforced: dict, report_only: dict) -> list[dict]:
    """What Report-Only tolerates that the enforced policy blocks,
    and the reverse."""
    out: list[dict] = []
    directives = sorted(set(enforced) | set(report_only))
    for d in directives:
        enforced_src = enforced.get(d) or []
        reported_src = report_only.get(d) or []
        if d not in report_only:
            continue
        only_reported = [s for s in reported_src
                         if s not in enforced_src]
        only_enforced = [s for s in enforced_src
                         if s not in reported_src]
        if only_reported:
            out.append({
                "severity": "warning", "check": "report-only",
                "detail": f"{d}: {', '.join(only_reported)} are "
                          "tolerated under Report-Only but blocked "
                          "enforced — you are *reporting* violations "
                          "you already prevent, or eyeing a "
                          "loosening"})
        if only_enforced and not only_reported:
            out.append({
                "severity": "info", "check": "report-only",
                "detail": f"{d}: {', '.join(only_enforced)} enforced "
                          "but absent from the report — the report "
                          "doesn't cover what the real policy does"})
    return out


# -------------------------------------------------------------------- report

ICON = {"critical": "🔴", "warning": "🟠", "info": "ℹ️", "good": "🟢"}


def verdict_of(findings: list[dict]) -> str:
    if any(f["severity"] == "critical" for f in findings):
        return "🔴 script-src wide open"
    if any(f["severity"] == "warning" for f in findings):
        return "🟠 holes to close"
    if any(f["severity"] == "good" for f in findings):
        return "🟢 strict"
    return "🟡 present, plain"


def build_table_event(findings: list[dict]) -> dict:
    rows = [[ICON[f["severity"]] + " " + f["severity"],
             f["check"], f["detail"][:90]]
            for f in findings]
    return {"type": "table", "columns": ["severity", "check",
                                         "detail"], "rows": rows}


def build_markdown(url: str, raw: str, findings: list[dict],
                   report_only_raw: str,
                   ro_diffs: list[dict]) -> str:
    verdict = verdict_of(findings)
    out = [f"# CSP Audit — Report\n",
           f"URL: `{url}` · verdict: **{verdict}**\n",
           f"Policy (`{' '.join(raw.split())[:400]}`…):\n"]
    for f in findings:
        out.append(f"- {ICON[f['severity']]} **{f['check']}** — "
                   f"{f['detail']}")
    if report_only_raw:
        out.append(f"\n## Report-Only twin\n")
        out.append(f"`{' '.join(report_only_raw.split())[:300]}`…\n")
        if ro_diffs:
            for d in ro_diffs:
                out.append(f"- {ICON[d['severity']]} **{d['check']}**"
                           f" — {d['detail']}")
        else:
            out.append("- identical to the enforced policy source-"
                       "for-source — the report sees what the "
                       "policy does")
    out.append("\n## The shape to aim for\n")
    out.append("- `script-src 'nonce-…' 'strict-dynamic'` — a fresh "
               "nonce per response, no host list to rot.")
    out.append("- `base-uri 'self'`, `object-src 'none'`, "
               "`frame-ancestors 'self'` — the one-liners that close "
               "the classic injection paths.")
    out.append("- Report-Only for the *trial* of a stricter policy, "
               "never as the resting state: reporting is not "
               "blocking.")
    out.append("\n## Related\n")
    out.append("- **Security Headers** — the presence grades; this "
               "script is the deep dive behind its CSP line.")
    out.append("- **CORS Check** — the other deep-dive sibling (the "
               "Access-Control family).")
    return "\n".join(out)


def write_artifacts(url: str, raw: str, findings: list[dict],
                    report_only_raw: str, ro_diffs: list[dict],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "url": url, "policy_raw": raw,
        "policy": parse_policy(raw),
        "report_only_raw": report_only_raw,
        "findings": findings, "report_only_diffs": ro_diffs,
        "verdict": verdict_of(findings),
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CSP Audit — the Content-Security-Policy deep "
                    "dive: unsafe-*, wildcards, bypass hosts, "
                    "missing foundations, Report-Only diff")
    parser.add_argument("--url", required=True,
                        help="the page whose CSP to dissect")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no requests are made", flush=True)
        return 0

    url = args.url.strip()
    if not re.match(r"^https?://", url):
        print("✗ the URL must start with http:// or https://",
              file=sys.stderr, flush=True)
        return 2

    log(f"Dissecting the CSP of {url}")
    status("one fetch")
    try:
        resp = requests.get(url, timeout=args.timeout,
                            allow_redirects=True,
                            headers={"User-Agent": USER_AGENT})
    except requests.RequestException as exc:
        print(f"✗ cannot reach {url}: {exc}", file=sys.stderr,
              flush=True)
        return 1

    raw = resp.headers.get("Content-Security-Policy", "")
    report_only_raw = resp.headers.get(
        "Content-Security-Policy-Report-Only", "")
    if not raw and not report_only_raw:
        print(f"✗ no Content-Security-Policy header on {url} — "
              "nothing to dissect (Security Headers grades this as "
              "missing)", file=sys.stderr, flush=True)
        return 1

    bypasses = load_bypasses()
    policy = parse_policy(raw)
    findings = analyze_policy(policy, bypasses,
                              dict(resp.headers))
    ro_diffs: list[dict] = []
    if report_only_raw:
        ro_policy = parse_policy(report_only_raw)
        ro_diffs = diff_report_only(policy, ro_policy)

    emit({"type": "progress", "pct": 100, "message": "Done"})
    report = build_markdown(url, raw, findings, report_only_raw,
                            ro_diffs)
    emit(build_table_event(findings + ro_diffs))
    emit({"type": "markdown", "content": report})
    write_artifacts(url, raw, findings, report_only_raw, ro_diffs,
                    report)

    summary = f"{verdict_of(findings)} · {len(findings)} finding(s)"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

