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
- **Wildcards and scheme sources** — `*`, `http:`, `https:`, bare
  subdomain wildcards (`*.example.com`) and `data:` in script-src:
  every host on the planet (or the subdomain's tenants, or any
  injected data: URL) is inside.
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
  tolerate" shape), what is enforced but never reported, and the
  page that carries *only* a Report-Only policy — a trial, not a
  defense.

One fetch; every verdict names the directive and the source.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from html import unescape
from pathlib import Path

import requests
import yaml

USER_AGENT = "PyShell-csp-audit/1 (+CSP policy diagnostics)"
BYPASS_PATH = Path(__file__).resolve().parent / "bypass_hosts.yaml"

FETCH_DIRECTIVES = {"script-src", "style-src", "img-src", "font-src",
                    "connect-src", "media-src", "worker-src",
                    "frame-src", "child-src", "manifest-src",
                    "object-src", "prefetch-src"}

SCHEME_SOURCE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:$")
SCHEME_PREFIX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

META_TAG = re.compile(r"<meta\b[^>]*>", re.I)
META_ATTR = re.compile(
    r"""([a-zA-Z:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""")
HEAD_END = re.compile(r"</head\s*>", re.I)
# what a <meta> policy may say but no browser will honour
META_IGNORED = {"frame-ancestors", "report-uri", "sandbox"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ----------------------------------------------------------------- parsing

def split_policies(value: str) -> list[str]:
    """One header value may carry several policies, comma-separated
    — and repeated CSP headers reach us joined the same way. Each
    policy is enforced on its own; a source has to pass all of
    them."""
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def meta_policies(html: str) -> tuple[list[str], list[str]]:
    """(enforced, report-only) policies declared in the document
    head by `<meta http-equiv=…>` — the other delivery browsers
    honour, and the one a header-only audit misses."""
    head = html or ""
    end = HEAD_END.search(head)
    if end:
        head = head[:end.start()]
    enforced: list[str] = []
    reported: list[str] = []
    for tag in META_TAG.findall(head):
        attrs = {}
        for a in META_ATTR.finditer(tag):
            value = a.group(2) or a.group(3) or a.group(4) or ""
            attrs[a.group(1).lower()] = unescape(value).strip()
        equiv = attrs.get("http-equiv", "").lower()
        content = attrs.get("content", "")
        if not content:
            continue
        if equiv == "content-security-policy":
            enforced.append(content)
        elif equiv == "content-security-policy-report-only":
            reported.append(content)
    return enforced, reported


def strip_meta_ignored(policy: dict) -> tuple[dict, list[str]]:
    """A <meta> policy's frame-ancestors / report-uri / sandbox are
    dropped by browsers — drop them here too, and say which."""
    kept = {d: s for d, s in policy.items() if d not in META_IGNORED}
    dropped = [d for d in policy if d in META_IGNORED]
    return kept, dropped


def parse_policy(value: str) -> dict[str, list[str]]:
    """'default-src 'self'; script-src *.x.com' →
    {'default-src': ["'self'"], 'script-src': ['*.x.com']}

    A directive repeated inside one policy keeps its **first**
    occurrence — the rest is what browsers ignore."""
    out: dict[str, list[str]] = {}
    for part in (value or "").split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in out:
            continue
        out[name] = tokens[1:]
    return out


def duplicate_directives(value: str) -> list[str]:
    """The directive names a policy repeats — browsers keep the
    first and drop the rest, so a repeat is nearly always a
    mistake."""
    seen: set[str] = set()
    dups: list[str] = []
    for part in (value or "").split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name in seen and name not in dups:
            dups.append(name)
        seen.add(name)
    return dups


def merge_policies(policies: list[dict]) -> dict[str, list[str]]:
    """Union of sources per directive — the flat shape the artifacts
    show when a response carries more than one policy."""
    out: dict[str, list[str]] = {}
    for policy in policies:
        for directive, sources in policy.items():
            bucket = out.setdefault(directive, [])
            for source in sources:
                if source not in bucket:
                    bucket.append(source)
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


def restricts(policy: dict, directive: str) -> bool:
    """Does the policy say anything at all about this directive —
    itself, or through default-src?"""
    return directive in policy or (directive in FETCH_DIRECTIVES
                                   and "default-src" in policy)


def has_keyword(sources: list[str], keyword: str) -> bool:
    """CSP keyword-sources are ASCII case-insensitive: 'NONE' is
    'none'."""
    return any(s.lower() == keyword for s in sources)


def has_prefix(sources: list[str], prefix: str) -> bool:
    return any(s.lower().startswith(prefix) for s in sources)


def header_of(headers, name: str) -> str:
    """Header lookup that survives a plain dict — HTTP field names
    are case-insensitive, `dict(resp.headers)` is not."""
    for key, value in (headers or {}).items():
        if key.lower() == name.lower():
            return value
    return ""


def host_of(source: str) -> str:
    """'https://cdn.example.com/x' → 'cdn.example.com';
    scheme-only ('https:', 'data:') and keyword sources → ''."""
    if source.startswith("'") or SCHEME_SOURCE.match(source):
        return ""
    host = SCHEME_PREFIX.sub("", source).split("/")[0]
    host = host.split("@")[-1].split(":")[0]
    return host.lower().strip(".")


def load_bypasses() -> list[dict]:
    """The curated list; a missing or malformed file costs the
    bypass check, not the run."""
    try:
        data = yaml.safe_load(BYPASS_PATH.read_text(encoding="utf-8")) \
            or {}
    except (OSError, yaml.YAMLError) as exc:
        log(f"! {BYPASS_PATH.name} unreadable ({exc}) — the bypass-"
            "host check is skipped")
        return []
    entries = data.get("hosts") if isinstance(data, dict) else None
    out = []
    for entry in entries or []:
        if isinstance(entry, dict) and entry.get("host") \
                and entry.get("reason"):
            out.append(entry)
    return out


def matches_bypass(source_host: str, entry_host: str) -> bool:
    """A wildcard entry ('*.github.io') covers the domain and its
    subdomains; a bare entry ('unpkg.com') matches exactly."""
    sh = source_host.lower().strip(".")
    eh = entry_host.lower().strip().strip(".")
    if eh.startswith("*."):
        base = eh[2:]
        return sh == eh or sh == base or sh.endswith("." + base)
    return sh == eh


# ----------------------------------------------------------------- findings

def analyze_policy(policy: dict, bypasses: list[dict],
                   headers=None) -> list[dict]:
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
    has_nonce = has_prefix(script_sources, "'nonce-")
    has_hash = has_prefix(script_sources, "'sha")
    if has_keyword(script_sources, "'unsafe-eval'"):
        add("critical", "unsafe-eval",
            f"{src_directive} allows 'unsafe-eval' — eval(), new "
            "Function(), injected string→code: the XSS playground "
            "reopens")
    if has_keyword(script_sources, "'unsafe-inline'"):
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
    if has_keyword(script_sources, "'unsafe-hashes'"):
        add("warning", "unsafe-hashes",
            f"{src_directive} allows 'unsafe-hashes' — hashed inline "
            "event handlers run again; a hash was supposed to pin "
            "the code, not to reopen onclick=")

    # wildcards and scheme sources in script-src
    wild = [s for s in script_sources
            if s.lower() in ("*", "http:", "https:", "http://*",
                             "https://*", "//*")]
    if wild:
        add("critical", "wildcard",
            f"{src_directive} includes {', '.join(wild)} — every "
            "host on the planet may serve script")
    data_src = [s for s in script_sources if s.lower() == "data:"]
    if data_src:
        add("critical", "scheme-source",
            f"{src_directive} includes data: — an injected "
            "data:text/javascript URL is script the policy blesses")
    loose_scheme = [s for s in script_sources
                    if s.lower() in ("blob:", "filesystem:")]
    if loose_scheme:
        add("warning", "scheme-source",
            f"{src_directive} includes {', '.join(loose_scheme)} — "
            "script built at runtime from a URL the page creates "
            "sidesteps the allowlist")
    subdomain_wild = [s for s in script_sources
                      if host_of(s).startswith("*.")]
    for s in subdomain_wild:
        add("warning", "wildcard",
            f"{src_directive} includes {s} — every tenant of that "
            "domain is inside the script allowlist")

    # bypass hosts — one finding per source, the first entry that
    # explains it (the specific entries come first in the YAML)
    for s in script_sources:
        h = host_of(s)
        if not h:
            continue
        for entry in bypasses:
            if matches_bypass(h, entry["host"]):
                add("warning", "bypass-host",
                    f"{s} in {src_directive} — {entry['reason']}")
                break

    # style-src unsafe-inline (milder than script) — its own nonce
    style_dir, style_sources = effective_sources(policy, "style-src")
    style_nonce = has_prefix(style_sources, "'nonce-") \
        or has_prefix(style_sources, "'sha")
    if has_keyword(style_sources, "'unsafe-inline'") \
            and not style_nonce:
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
    elif has_keyword(obj_sources, "'none'"):
        add("good", "object-src",
            f"{obj_dir} is 'none' — plugins off")
    if "frame-ancestors" not in policy:
        xfo = header_of(headers, "X-Frame-Options")
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
    if has_keyword(script_sources, "'strict-dynamic'"):
        add("good", "strict-dynamic",
            "'strict-dynamic' — scripts you allow may load more "
            "scripts; the host allowlist matters less (keep it "
            "anyway for old browsers)")

    if not any(f["severity"] == "critical" for f in findings) \
            and has_nonce:
        add("good", "nonce",
            "nonce-based script-src — the modern shape")
    return findings


def analyze_policies(policies: list[dict], bypasses: list[dict],
                     headers=None) -> list[dict]:
    """Several policies in one response are each enforced on their
    own: a hole is only real when *every* policy leaves it open, and
    one policy's good property counts for the whole response."""
    if not policies:
        return []
    per = [analyze_policy(p, bypasses, headers) for p in policies]
    if len(per) == 1:
        return per[0]

    def key(f: dict) -> tuple:
        return (f["severity"], f["check"], f["detail"])

    common = set(key(f) for f in per[0])
    for findings in per[1:]:
        common &= set(key(f) for f in findings)
    out: list[dict] = []
    seen: set[tuple] = set()
    for findings in per:
        for f in findings:
            k = key(f)
            if k in seen:
                continue
            if f["severity"] == "good" or k in common:
                seen.add(k)
                out.append(f)
    return out


def duplicate_findings(header_value: str) -> list[dict]:
    """One info per directive a policy repeats."""
    out: list[dict] = []
    seen: set[str] = set()
    for policy_str in split_policies(header_value):
        for name in duplicate_directives(policy_str):
            if name in seen:
                continue
            seen.add(name)
            out.append({
                "severity": "info", "check": "duplicate-directive",
                "detail": f"{name} appears more than once in one "
                          "policy — browsers keep the first "
                          "occurrence and ignore the rest, so the "
                          "later one is dead text"})
    return out


def diff_report_only(enforced: dict, report_only: dict) -> list[dict]:
    """What Report-Only tolerates that the enforced policy blocks,
    what the enforced policy does without ever reporting it, and the
    directives that live on one side only."""
    out: list[dict] = []
    for d in sorted(set(enforced) | set(report_only)):
        _, enforced_src = effective_sources(enforced, d)
        _, reported_src = effective_sources(report_only, d)
        in_enforced = restricts(enforced, d)
        in_reported = restricts(report_only, d)
        if in_enforced and not in_reported:
            out.append({
                "severity": "info", "check": "report-only",
                "detail": f"{d}: enforced but absent from the report "
                          "(no default-src to inherit either) — the "
                          "report doesn't cover what the real policy "
                          "does"})
            continue
        if in_reported and not in_enforced:
            shown = ", ".join(reported_src) or "(empty)"
            out.append({
                "severity": "info", "check": "report-only",
                "detail": f"{d}: {shown} is reported but the "
                          "enforced policy "
                          "doesn't restrict this directive at all — "
                          "a restriction still in trial"})
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


def no_csp_findings(headers=None) -> list[dict]:
    """The page declares no policy at all — the audit still has
    something to say, and it belongs in the report."""
    out = [{
        "severity": "critical", "check": "no-csp",
        "detail": "no Content-Security-Policy header and no "
                  "<meta http-equiv> policy in the document — "
                  "nothing restricts where script, style, frames or "
                  "forms may come from; every injected <script> that "
                  "lands, runs"}]
    xfo = header_of(headers, "X-Frame-Options")
    if xfo:
        out.append({
            "severity": "info", "check": "frame-ancestors",
            "detail": f"X-Frame-Options: {xfo} still blocks framing "
                      "— it is the only header-level guard left on "
                      "this response"})
    else:
        out.append({
            "severity": "warning", "check": "frame-ancestors",
            "detail": "neither frame-ancestors nor X-Frame-Options "
                      "— nothing tells browsers not to frame this "
                      "page either"})
    return out


def verdict_of(findings: list[dict], enforced: bool = True,
               present: bool = True) -> str:
    if not present:
        return "🔴 no CSP at all"
    if not enforced:
        return "🟠 report-only — nothing is enforced"
    if any(f["severity"] == "critical" for f in findings):
        return "🔴 script-src wide open"
    if any(f["severity"] == "warning" for f in findings):
        return "🟠 holes to close"
    if any(f["severity"] == "good"
           and f["check"] in ("nonce", "strict-dynamic")
           for f in findings):
        return "🟢 strict"
    return "🟡 present, plain"


def build_table_event(findings: list[dict]) -> dict:
    rows = [[ICON[f["severity"]] + " " + f["severity"],
             f["check"],
             f["detail"][:90] + ("…" if len(f["detail"]) > 90 else "")]
            for f in findings]
    return {"type": "table", "columns": ["severity", "check",
                                         "detail"], "rows": rows}


def squash(value: str, limit: int = 400) -> str:
    return " ".join((value or "").split())[:limit]


def build_markdown(ctx: dict) -> str:
    """The report is the deliverable — including the run that found
    no policy at all."""
    findings = ctx["findings"]
    verdict = verdict_of(findings, ctx["enforced"], ctx["present"])
    out = [f"# CSP Audit — Report\n",
           f"URL: `{ctx['url']}` · verdict: **{verdict}**\n"]

    if not ctx["present"]:
        out.append("No `Content-Security-Policy` header on this "
                   "response and no `<meta http-equiv=\"Content-"
                   "Security-Policy\">` in the document — there is "
                   "no policy to dissect. Security Headers grades "
                   "the absence; what follows is what the deep dive "
                   "can still say about this response.\n")
    elif ctx["enforced"]:
        if ctx["header_raw"]:
            out.append(f"Policy (`{squash(ctx['header_raw'])}`…):\n")
        for meta_raw in ctx["meta_raw"]:
            out.append("Policy delivered by `<meta http-equiv>` "
                       f"(`{squash(meta_raw)}`…):\n")
    else:
        out.append("No enforced `Content-Security-Policy` on this "
                   "response — the findings below describe the "
                   "**Report-Only** policy, which browsers report "
                   "and never block:\n")
        out.append(f"`{squash(ctx['report_only_raw'])}`…\n")

    for f in findings:
        out.append(f"- {ICON[f['severity']]} **{f['check']}** — "
                   f"{f['detail']}")

    if ctx["report_only_raw"] and ctx["enforced"]:
        out.append(f"\n## Report-Only twin\n")
        out.append(f"`{squash(ctx['report_only_raw'], 300)}`…\n")
        if ctx["report_only_diffs"]:
            for d in ctx["report_only_diffs"]:
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
    out.append("- The **header**, not `<meta>`: a meta policy only "
               "covers what the parser reads after the tag, and "
               "frame-ancestors, report-uri and sandbox are ignored "
               "there.")
    out.append("- Report-Only for the *trial* of a stricter policy, "
               "never as the resting state: reporting is not "
               "blocking.")
    out.append("\n## Related\n")
    out.append("- **Security Headers** — the presence grades; this "
               "script is the deep dive behind its CSP line.")
    out.append("- **CORS Check** — the other deep-dive sibling (the "
               "Access-Control family).")
    return "\n".join(out)


def write_artifacts(ctx: dict, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "url": ctx["url"],
        "requested_url": ctx["requested_url"],
        "present": ctx["present"],
        "enforced": ctx["enforced"],
        "policy_raw": ctx["header_raw"],
        "meta_policy_raw": ctx["meta_raw"],
        "policy": merge_policies(ctx["policies"]),
        "policies": ctx["policies"],
        "report_only_raw": ctx["report_only_raw"],
        "meta_report_only_raw": ctx["meta_report_only_raw"],
        "report_only_policy":
            merge_policies(ctx["report_only_policies"]),
        "findings": ctx["findings"],
        "report_only_diffs": ctx["report_only_diffs"],
        "verdict": verdict_of(ctx["findings"], ctx["enforced"],
                              ctx["present"]),
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


def meta_notes(meta_parsed: list[dict], meta_dropped: list[str],
               meta_report_only: list[str],
               header_policies: list[dict]) -> list[dict]:
    """What the <meta> delivery costs, said once per response."""
    notes: list[dict] = []
    if meta_parsed:
        alone = not header_policies
        notes.append({
            "severity": "warning" if alone else "info",
            "check": "meta-policy",
            "detail": ("the policy is delivered by <meta http-equiv>"
                       + (" only" if alone else " as well")
                       + " — a meta policy covers what the parser "
                       "reads after the tag, so anything above it is "
                       "unprotected, and it cannot carry "
                       "frame-ancestors, report-uri or sandbox; the "
                       "header covers the whole response")})
    if meta_dropped:
        notes.append({
            "severity": "warning", "check": "meta-ignored-directive",
            "detail": f"{', '.join(meta_dropped)} declared inside a "
                      "<meta> policy — browsers drop it there, so it "
                      "protects nothing until it moves to the "
                      "header"})
    if meta_report_only:
        notes.append({
            "severity": "warning", "check": "meta-report-only",
            "detail": "a <meta http-equiv=\"Content-Security-Policy-"
                      "Report-Only\"> policy is ignored by browsers "
                      "— Report-Only exists only as a header, so "
                      "this one reports nothing"})
    return notes


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
    if args.timeout < 1:
        print("✗ --timeout must be at least 1 second",
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

    final_url = resp.url or url
    if final_url != url:
        log(f"→ redirected to {final_url} — its headers are what "
            "follows")

    raw = resp.headers.get("Content-Security-Policy", "")
    report_only_raw = resp.headers.get(
        "Content-Security-Policy-Report-Only", "")
    html = ""
    if "html" in header_of(resp.headers, "Content-Type").lower():
        html = resp.text
    meta_raw, meta_report_only_raw = meta_policies(html)

    header_policies = [parse_policy(p) for p in split_policies(raw)]
    ro_policies = [parse_policy(p)
                   for p in split_policies(report_only_raw)]
    meta_parsed: list[dict] = []
    meta_dropped: list[str] = []
    for policy_str in meta_raw:
        for one in split_policies(policy_str):
            kept, dropped = strip_meta_ignored(parse_policy(one))
            meta_parsed.append(kept)
            meta_dropped += [d for d in dropped
                             if d not in meta_dropped]

    policies = header_policies + meta_parsed
    enforced = bool(policies)
    present = bool(policies or ro_policies)
    analyzed = policies if enforced else ro_policies

    bypasses = load_bypasses()
    if present:
        findings = analyze_policies(analyzed, bypasses, resp.headers)
    else:
        findings = no_csp_findings(resp.headers)

    notes: list[dict] = []
    if present and not enforced:
        notes.append({
            "severity": "warning", "check": "report-only-only",
            "detail": "only Content-Security-Policy-Report-Only is "
                      "set — every violation below is reported and "
                      "none is blocked; the findings describe a "
                      "trial policy, not a defense"})
    if len(analyzed) > 1:
        notes.append({
            "severity": "info", "check": "multiple-policies",
            "detail": f"the response carries {len(analyzed)} "
                      "policies — each is enforced on its own, so a "
                      "source has to pass all of them; only the "
                      "holes every policy leaves open are reported "
                      "below"})
    notes += meta_notes(meta_parsed, meta_dropped,
                        meta_report_only_raw, header_policies)
    findings = notes + findings

    for value in (([raw] + meta_raw) if enforced
                  else [report_only_raw]):
        for dup in duplicate_findings(value):
            if dup not in findings:
                findings.append(dup)

    ro_diffs: list[dict] = []
    if enforced and ro_policies:
        ro_diffs = diff_report_only(merge_policies(policies),
                                    merge_policies(ro_policies))

    ctx = {
        "url": final_url, "requested_url": url,
        "header_raw": raw, "meta_raw": meta_raw,
        "report_only_raw": report_only_raw,
        "meta_report_only_raw": meta_report_only_raw,
        "policies": policies, "report_only_policies": ro_policies,
        "present": present, "enforced": enforced,
        "findings": findings, "report_only_diffs": ro_diffs,
    }

    emit({"type": "progress", "pct": 100, "message": "Done"})
    report = build_markdown(ctx)
    emit(build_table_event(findings + ro_diffs))
    emit({"type": "markdown", "content": report})
    write_artifacts(ctx, report)

    summary = f"{verdict_of(findings, enforced, present)} · " \
              f"{len(findings)} finding(s)"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
