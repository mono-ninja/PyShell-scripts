#!/usr/bin/env python3
"""cors-check/main.py — is the CORS policy actually strict?

Security Headers grades CORS by presence; this script is the deep
dive: a short series of GET/OPTIONS requests with a **spoofed
Origin** header, watching how the server's Access-Control answers
behave — the port of the NinjaChek CORS security lab's matrix:

1. **Reflection** — `Origin: https://attacker.example` answered with
   `Access-Control-Allow-Origin: https://attacker.example` means the
   server trusts *whoever asks*; with
   `Access-Control-Allow-Credentials: true` that is the critical
   shape (any site reads the victim's authenticated responses).
2. **The null origin** — `Origin: null` reflected means sandboxed
   iframes and `file://` pages get in.
3. **Wildcard + credentials** — `*` together with
   `Allow-Credentials: true`: browsers ignore the combination, but
   it is the signature of a broken config that one refactor away
   from reflection.
4. **Prefix/suffix matching** — the `indexOf`/regex traps:
   `Origin: https://api.example.com.attacker.io` and
   `Origin: https://not-really-example.com` accepted against a
   whitelist that meant `example.com`.
5. **Preflight** — OPTIONS with an `Access-Control-Request-Method`:
   does the echo allow everything asked?
6. **Vary: Origin** — a reflecting response without `Vary: Origin`
   is cache-poisoning food: a shared cache can serve one visitor's
   ACAO to another.

**Why no ownership gate** (unlike Load Test / Port Check): these are
a handful of ordinary GET/OPTIONS requests with one custom header —
the same traffic any browser produces. Nothing is fuzzed, nothing is
exploited, no payloads are sent; the docs say so plainly.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

import requests

USER_AGENT = "PyShell-cors-check/1 (+CORS policy diagnostics)"

ATTACKER_ORIGIN = "https://attacker.example"


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------- analysis

def acao_of(headers) -> str:
    return (headers.get("Access-Control-Allow-Origin") or "").strip()


def acac_of(headers) -> str:
    return (headers.get("Access-Control-Allow-Credentials") or "").strip()


def verdict_reflection(origin_sent: str, headers) -> str:
    """secure | reflected | reflected+credentials | null-accepted |
    wildcard | none (no CORS headers at all)."""
    acao = acao_of(headers)
    acac = acac_of(headers).lower()
    if not acao:
        return "none"
    if acao == "*":
        return "wildcard"
    if origin_sent == "null" and acao == "null":
        return "null-accepted"
    if acao == origin_sent:
        return "reflected+credentials" if acac == "true" else "reflected"
    return "secure"


def registrable_of(host: str) -> str:
    """The last two labels — the string a sloppy whitelist matches on.
    IP literals and single-label hosts have no registrable domain; the
    whole host stands in, so every trap still carries the host string."""
    parts = host.split(".")
    if len(parts) < 2 or ":" in host or re.fullmatch(r"[0-9.]+", host):
        return host
    return ".".join(parts[-2:])


def confusable_origins(url: str) -> list[tuple[str, str]]:
    """(label, origin) pairs built from the target's own host — the
    indexOf/regex-bypass shapes."""
    host = urlsplit(url).hostname or "example.com"
    registrable = registrable_of(host)
    return [
        ("suffix trap", f"https://{host}.attacker.io"),
        ("prefix trap", f"https://not-really-{registrable}"),
        ("substring trap", f"https://{registrable}attacker.io"),
    ]


def preflight_verdict(headers) -> str:
    """echo-everything | allows-methods | origin-only | none."""
    methods = (headers.get("Access-Control-Allow-Methods") or "").strip()
    if not methods:
        return "origin-only" if acao_of(headers) else "none"
    if "*" in methods:
        return "echo-everything"
    return "allows-methods"


def vary_origin(headers) -> bool:
    return "origin" in (headers.get("Vary") or "").lower()


# --------------------------------------------------------------------- probe

def probe(url: str, timeout: int) -> dict:
    """The whole series; returns the findings-ready result dict."""
    session = requests.Session()
    out: dict = {"url": url, "checks": [], "verdict": "", "notes": []}

    def get(origin: str | None):
        headers = {"User-Agent": USER_AGENT}
        if origin is not None:
            headers["Origin"] = origin
        return session.get(url, timeout=timeout, headers=headers,
                           allow_redirects=True)

    def add(name: str, result: str, detail: str,
            severity: str = "info"):
        out["checks"].append({"check": name, "result": result,
                              "detail": detail, "severity": severity})

    # 1 — baseline: what does the endpoint say unprompted?
    resp = get(None)
    out["status"] = resp.status_code
    base = {"acao": acao_of(resp.headers),
            "acac": acac_of(resp.headers),
            "vary": vary_origin(resp.headers)}
    out["baseline"] = base

    # 2 — reflection with an unrelated origin
    resp = get(ATTACKER_ORIGIN)
    reflect_headers = resp.headers
    v = verdict_reflection(ATTACKER_ORIGIN, reflect_headers)
    if v == "reflected+credentials":
        add("reflection", v,
            f"Origin {ATTACKER_ORIGIN} answered with "
            f"`Access-Control-Allow-Origin: {acao_of(resp.headers)}` "
            "and credentials — any site reads authenticated "
            "responses", "critical")
    elif v == "reflected":
        add("reflection", v,
            f"Origin {ATTACKER_ORIGIN} reflected back — no whitelist "
            "is actually checked", "high")
    elif v == "wildcard":
        # credentials usually surface only on the Origin-carrying
        # answer — most frameworks emit no CORS headers at all for the
        # baseline request, so the baseline alone under-reports this
        creds = (acac_of(resp.headers).lower() == "true"
                 or base["acac"].lower() == "true")
        if creds:
            add("wildcard+credentials", v,
                "`*` with `Allow-Credentials: true` — browsers ignore "
                "the combo, but the config is one step from "
                "reflection", "high")
        else:
            add("wildcard", v,
                "`*` — every origin may read the responses "
                "(fine for public data, wrong for anything "
                "per-user)", "warning")
    else:
        add("reflection", v,
            "the attacker origin is not reflected — the whitelist "
            "held" if v == "secure" else
            "no Access-Control-Allow-Origin in the answer")
    reflection_verdict = v

    # 3 — the null origin
    resp = get("null")
    v_null = verdict_reflection("null", resp.headers)
    if v_null == "null-accepted":
        sev = "high" if acac_of(resp.headers).lower() == "true" \
            else "warning"
        add("null origin", v_null,
            "`Origin: null` accepted — sandboxed iframes and file:// "
            "pages are inside the trust boundary", sev)
    else:
        add("null origin", "rejected",
            "the null origin is not accepted", "info")

    # 4 — prefix/suffix/substring traps
    for label, origin in confusable_origins(url):
        try:
            resp = get(origin)
        except requests.RequestException as exc:
            out["notes"].append(f"{label} request failed: {exc}")
            continue
        v = verdict_reflection(origin, resp.headers)
        if v in ("reflected", "reflected+credentials"):
            add(label, v,
                f"`Origin: {origin}` accepted — the whitelist matches "
                "by substring/prefix/suffix, not by domain; the "
                "attacker registers the confusable name and is in",
                "high" if v == "reflected" else "critical")
        else:
            add(label, "secure",
                f"`Origin: {origin}` not accepted", "info")

    # 5 — preflight
    try:
        resp = session.options(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": USER_AGENT,
                     "Origin": ATTACKER_ORIGIN,
                     "Access-Control-Request-Method": "DELETE"})
        pv = preflight_verdict(resp.headers)
        if pv == "echo-everything":
            add("preflight", pv,
                "OPTIONS echoes `*` methods — the preflight gate is "
                "open to every verb", "warning")
        elif pv == "allows-methods":
            methods = resp.headers.get("Access-Control-Allow-Methods",
                                       "")
            add("preflight", pv,
                f"preflight answers methods: {methods}", "info")
        elif pv == "origin-only":
            add("preflight", pv,
                "the preflight answers an origin but names no "
                "methods — non-simple requests stay blocked", "info")
        else:
            add("preflight", pv,
                "no preflight CORS answer — non-simple requests are "
                "not enabled", "info")
    except requests.RequestException as exc:
        out["notes"].append(f"preflight request failed: {exc}")

    # 6 — Vary: Origin on the reflecting answer
    if reflection_verdict.startswith("reflected"):
        # step 2's answer *is* the reflecting one — no second request
        if not vary_origin(reflect_headers):
            add("vary", "missing",
                "a per-origin answer without `Vary: Origin` — a "
                "shared cache can pin one visitor's ACAO onto "
                "everyone's copy (cache poisoning food)", "warning")
        else:
            add("vary", "present", "Vary: Origin present", "info")

    severities = [c["severity"] for c in out["checks"]]
    if "critical" in severities:
        out["verdict"] = "🔴 reflected + credentials"
    elif "high" in severities:
        out["verdict"] = "🟠 misconfigured"
    elif "warning" in severities:
        out["verdict"] = "🟡 loose but guarded"
    else:
        out["verdict"] = "🟢 strict"
    return out


# -------------------------------------------------------------------- report

def build_table_event(result: dict) -> dict:
    rows = [[c["check"], c["result"], c["severity"],
             c["detail"][:80]]
            for c in result["checks"]]
    return {"type": "table",
            "columns": ["check", "result", "severity", "detail"],
            "rows": rows}


def build_markdown(result: dict) -> str:
    vary = "includes Origin" if result["baseline"]["vary"] else "absent"
    out = ["# CORS Check — Report\n",
           f"URL: `{result['url']}` · status {result.get('status')}"
           f" · verdict: **{result['verdict']}**\n",
           f"Baseline (no Origin sent): "
           f"ACAO `{result['baseline']['acao'] or '—'}` · "
           f"credentials `{result['baseline']['acac'] or '—'}` · "
           f"Vary {vary}\n"]
    out.append("A handful of GET/OPTIONS requests with a spoofed "
               "Origin — the traffic any browser produces, no "
               "payloads. What the answers reveal:\n")
    for c in result["checks"]:
        icon = {"critical": "🔴", "high": "🟠",
                "warning": "🟡"}.get(c["severity"], "ℹ️")
        out.append(f"- {icon} **{c['check']}** — {c['result']}: "
                   f"{c['detail']}")
    if result["notes"]:
        out.append("")
        for n in result["notes"]:
            out.append(f"- ⚫ {n}")
    out.append("\n## How a strict CORS setup answers\n")
    out.append("- An exact-origin whitelist: the answer echoes *only* "
               "the whitelisted origin, `Vary: Origin` on every "
               "per-origin response.")
    out.append("- Credentials only together with an exact origin — "
               "never with `*`, never with reflection.")
    out.append("- Domain matching by parsed host, not by substring "
               "(`endsWith`/`indexOf` is the bug this script "
               "probes for).")
    out.append("\n## Related\n")
    out.append("- **Security Headers** — the header-presence grades; "
               "this script is the deep dive behind its CORS line.")
    out.append("- **CSP Audit** — the same deep-dive shape for the "
               "Content-Security-Policy header.")
    return "\n".join(out)


def write_artifacts(result: dict, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def bounded_timeout(value: str) -> int:
    """The manifest promises 3–60; argparse promises the same."""
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a whole number of seconds")
    if not 3 <= seconds <= 60:
        raise argparse.ArgumentTypeError(
            f"{seconds} is out of range — the timeout is 3–60 seconds")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CORS Check — is the CORS policy strict: "
                    "reflection, null origin, wildcard+credentials, "
                    "prefix/suffix traps, preflight, Vary")
    parser.add_argument("--url", required=True,
                        help="the URL to probe")
    parser.add_argument("--timeout", type=bounded_timeout, default=15,
                        help="per-request timeout in seconds (3–60, default 15)")
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

    log(f"Probing the CORS policy of {url}")
    status("spoofed-origin series")
    emit({"type": "progress", "pct": 10, "message": "baseline"})
    try:
        result = probe(url, args.timeout)
    except requests.RequestException as exc:
        print(f"✗ cannot reach {url}: {exc}", file=sys.stderr,
              flush=True)
        return 1
    emit({"type": "progress", "pct": 100, "message": "Done"})

    report = build_markdown(result)
    emit(build_table_event(result))
    emit({"type": "markdown", "content": report})
    write_artifacts(result, report)

    summary = result["verdict"]
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
