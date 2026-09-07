#!/usr/bin/env python3
"""takeover-check/main.py — which of your subdomains can be hijacked.

Subdomain Search finds the subdomains, CT Log Check the former
ones — this script asks the question neither of them does: **which
of them points at a resource somebody else can claim?**

The shapes it reads:

- a **CNAME to an unclaimed cloud resource** — the classic dangling
  delegation: `assets.example.com → example-assets.s3.amazonaws.com`
  where the bucket no longer exists.  Whoever creates that bucket
  (or the Heroku app, the GitHub Pages repo, the Shopify shop…)
  owns your subdomain's content.
- **NXDOMAIN on the CNAME target** — the target name itself no
  longer resolves: the strongest dangling hint, visible before any
  HTTP.
- the **response marker** — the provider's own "nothing here" page
  (each fingerprint carries its marker text), compared against one
  GET of the candidate.
- the **closed-vs-open nuance** — several providers fixed the hole
  (Fastly, Vercel, Netlify, WordPress.com require domain
  verification now); a match on a closed service is its own answer
  in the report, never a silent skip.

**The passivity contract:** DNS queries and one GET per candidate,
a body-marker comparison — nothing else.  The script never
registers a resource, never "confirms" a takeover by claiming one;
it shows the signs and links the provider's documentation.  The
difference between diagnosing a hole and exploiting it is exactly
the line this script does not cross.

Fingerprints are YAML data (the tech.yaml precedent) — the
takeover flags will age as providers add verification; flipping
them is a data edit, not a code change.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import dns.exception
import dns.resolver
import requests
import yaml

FINGERPRINTS_PATH = Path(__file__).resolve().parent \
    / "takeover_fingerprints.yaml"
CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
USER_AGENT = ("PyShell-takeover-check/1 (+subdomain takeover "
              "diagnostics; passive)")


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# -------------------------------------------------------------- fingerprints

def load_fingerprints() -> list[dict]:
    data = yaml.safe_load(FINGERPRINTS_PATH.read_text(
        encoding="utf-8")) or {}
    return data.get("fingerprints") or []


def match_fingerprint(cname_target: str,
                      fingerprints: list[dict]) -> dict | None:
    """The fingerprint whose CNAME suffix fits the target."""
    target = (cname_target or "").strip().rstrip(".").lower()
    if not target:
        return None
    for fp in fingerprints:
        for suffix in fp.get("cname") or []:
            suffix = suffix.strip().rstrip(".").lower()
            if target == suffix or target.endswith(suffix):
                return fp
    return None


# --------------------------------------------------------------------- DNS

class Resolver:
    """CNAME + existence queries, wrapped small for testability."""

    def __init__(self, timeout: int):
        self.timeout = timeout

    def query(self, name: str, rdtype: str):
        return dns.resolver.resolve(name, rdtype,
                                    lifetime=self.timeout)

    def cname_of(self, name: str) -> str:
        try:
            answers = self.query(name, "CNAME")
            return str(answers[0].target).rstrip(".")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.exception.DNSException):
            return ""

    def exists(self, name: str) -> str:
        """'ok' | 'nxdomain' | 'error' — does the name resolve at
        all (any A/AAAA/CNAME)?"""
        for rdtype in ("A", "AAAA", "CNAME"):
            try:
                self.query(name, rdtype)
                return "ok"
            except dns.resolver.NXDOMAIN:
                return "nxdomain"
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                    dns.exception.Timeout, dns.exception.DNSException):
                continue
        return "error"


# ------------------------------------------------------------------ probing

def probe_candidate(host: str, resolver: Resolver,
                    fingerprints: list[dict],
                    session: requests.Session,
                    timeout: int) -> dict:
    """One candidate: CNAME → fingerprint match → target existence
    → the marker GET. Pure diagnosis; nothing is ever claimed."""
    out = {"host": host, "cname": "", "service": "",
           "target_state": "", "marker": "", "verdict": "",
           "note": "", "docs": ""}
    out["cname"] = resolver.cname_of(host)
    if not out["cname"]:
        out["verdict"] = "no CNAME"
        return out
    fp = match_fingerprint(out["cname"], fingerprints)
    if fp is None:
        out["verdict"] = "cname outside the fingerprint list"
        out["note"] = f"→ {out['cname']}"
        return out
    out["service"] = fp["service"]
    out["docs"] = fp.get("docs", "")
    out["target_state"] = resolver.exists(out["cname"])
    if out["target_state"] == "nxdomain":
        out["verdict"] = "dangling — target is NXDOMAIN"
        out["note"] = (f"the CNAME target {out['cname']} does not "
                       "resolve at all — the resource is gone; "
                       "whoever recreates it owns your subdomain")
        return out
    # one GET: the marker comparison
    marker_found = False
    try:
        r = session.get(f"https://{host}/", timeout=timeout,
                        headers={"User-Agent": USER_AGENT},
                        allow_redirects=True)
        marker_found = fp.get("marker", "") in (r.text or "")
    except requests.RequestException as exc:
        out["note"] = f"GET failed: {exc}"
    if marker_found:
        if fp.get("takeover"):
            out["verdict"] = "marker matches — likely claimable"
            out["note"] = (f"the {fp['service']} target answers "
                           f"with its unclaimed marker "
                           f"(“{fp.get('marker', '')}”) — the signs "
                           "of a takeover are present")
        else:
            out["verdict"] = "marker matches — service closed the hole"
            out["note"] = (f"{fp['service']} requires domain "
                           "verification to claim a custom domain "
                           "now — the dangling shape is exposed, "
                           "the takeover is not")
    else:
        out["verdict"] = "fingerprint target, no marker"
        out["note"] = (f"points at {fp['service']} but the "
                       "unclaimed-marker page did not answer — the "
                       "resource probably exists and is served")
    return out


# -------------------------------------------------------------- the feed

def collect_from_feed(domain: str, timeout: int,
                      max_subdomains: int) -> list[str]:
    """Hostnames from the crt.sh feed (the ct-log-check client),
    filtered to the domain, capped."""
    r = requests.get(CRTSH_URL.format(domain=domain), timeout=timeout,
                     headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    payload = r.json()
    suffix = "." + domain.lower()
    hosts: set[str] = set()
    for row in payload if isinstance(payload, list) else []:
        for name in (row.get("name_value") or "").splitlines():
            name = name.strip().lower().rstrip(".")
            if name.endswith(suffix) and "*" not in name:
                hosts.add(name)
    return sorted(hosts)[:max_subdomains]


def read_subdomains_file(path: str) -> list[str]:
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip().lower().rstrip(".")
        if line and not line.startswith("#"):
            out.append(line)
    return out


# -------------------------------------------------------------------- report

VERDICT_ICON = {"dangling — target is NXDOMAIN": "🔴",
                "marker matches — likely claimable": "🔴",
                "marker matches — service closed the hole": "🟠",
                "fingerprint target, no marker": "⚪",
                "cname outside the fingerprint list": "⚫",
                "no CNAME": "⚫"}


def build_table_event(results: list[dict]) -> dict:
    rows = [[r["host"], r["cname"][:50],
             r["service"] or "—",
             VERDICT_ICON.get(r["verdict"], "") + " " + r["verdict"]]
            for r in results if r["verdict"] != "no CNAME"]
    return {"type": "table",
            "columns": ["host", "cname", "service", "verdict"],
            "rows": rows[:60]}


def build_markdown(domain: str, results: list[dict]) -> str:
    dangerous = [r for r in results
                 if r["verdict"].startswith(("dangling",
                                             "marker matches — "
                                             "likely"))]
    closed = [r for r in results
              if r["verdict"] == "marker matches — service closed "
                                 "the hole"]
    out = [f"# Takeover Check — Report\n",
           f"Domain: **{domain}** · {len(results)} candidate(s) "
           f"probed · **{len(dangerous)} with takeover signs** · "
           f"{len(closed)} exposed-but-closed\n",
           "DNS queries and one GET per candidate — the signs of a "
           "takeover, never a takeover: nothing was registered, "
           "nothing was claimed. The fix list below is yours to "
           "act on.\n"]

    for r in results:
        if r["verdict"] == "no CNAME":
            continue
        icon = VERDICT_ICON.get(r["verdict"], "⚫")
        out.append(f"- {icon} **{r['host']}** → "
                   f"`{r['cname']}` ({r['service'] or 'unrecognized'}):"
                   f" {r['verdict']}"
                   + (f" — {r['note']}" if r["note"] else ""))
    if dangerous:
        out.append("\n## What to do about the red ones\n")
        out.append("- The delegation is the problem, not the "
                   "provider: remove the CNAME or recreate the "
                   "resource in **your** account.")
        out.append("- A CNAME you no longer use should be deleted, "
                   "not parked — parked delegations are exactly "
                   "what this report found.")
        out.append("- The provider's own domain docs are linked in "
                   "findings.json per finding.")
    out.append("\n## Related\n")
    out.append("- **Subdomain Search** — the passive inventory; "
               "run this script on its output (`--subdomains-file`).")
    out.append("- **CT Log Check** — the historical names: a cert "
               "for a gone subdomain often means a gone CNAME.")
    out.append("- **Port Check / FW Audit** — the exposure side of "
               "the same hygiene.")
    return "\n".join(out)


def write_artifacts(domain: str, results: list[dict],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"domain": domain, "results": results}, fh,
                  ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Takeover Check — subdomain CNAMEs vs the "
                    "unclaimed-resource fingerprints: signs shown, "
                    "never a takeover performed")
    parser.add_argument("--domain", required=True,
                        help="the registrable domain")
    parser.add_argument("--subdomains-file", default="",
                        help="a list of hostnames (one per line) — "
                             "skips the feed collection")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-probe timeout in seconds")
    parser.add_argument("--max-subdomains", type=int, default=500,
                        help="cap on candidates from the feed")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no lookups are made", flush=True)
        return 0

    domain = args.domain.strip().lower().rstrip(".")
    if not re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", domain) \
            or "." not in domain:
        print(f"✗ {args.domain!r} is not a domain name",
              file=sys.stderr, flush=True)
        return 2

    # candidates: the file when given, else the feed
    if args.subdomains_file:
        if not os.path.isfile(args.subdomains_file):
            print(f"✗ {args.subdomains_file}: file not found",
                  file=sys.stderr, flush=True)
            return 2
        hosts = [h for h in read_subdomains_file(args.subdomains_file)
                 if h == domain or h.endswith("." + domain)]
        source = os.path.basename(args.subdomains_file)
    else:
        status("collecting subdomains from crt.sh")
        emit({"type": "progress", "pct": 5, "message": "crt.sh"})
        try:
            hosts = collect_from_feed(domain, args.timeout,
                                      args.max_subdomains)
        except (requests.RequestException, ValueError) as exc:
            print(f"✗ cannot collect subdomains: {exc}",
                  file=sys.stderr, flush=True)
            return 1
        source = "crt.sh"
    if not hosts:
        print(f"✗ no subdomain candidates for {domain}",
              file=sys.stderr, flush=True)
        return 1
    log(f"{len(hosts)} candidate(s) from {source}")

    fingerprints = load_fingerprints()
    resolver = Resolver(args.timeout)
    session = requests.Session()

    results = []
    for i, host in enumerate(hosts, 1):
        r = probe_candidate(host, resolver, fingerprints, session,
                            args.timeout)
        results.append(r)
        if r["verdict"] not in ("no CNAME",):
            icon = VERDICT_ICON.get(r["verdict"], "⚫")
            log(f"  {icon} {host}: {r['verdict']}")
        emit({"type": "progress", "pct": 5 + int(95 * i / len(hosts)),
              "message": f"{i}/{len(hosts)} · {host}"})

    report = build_markdown(domain, results)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(results))
    emit({"type": "markdown", "content": report})
    write_artifacts(domain, results, report)

    dangerous = sum(1 for r in results
                    if r["verdict"].startswith(("dangling",
                                                "marker matches — "
                                                "likely")))
    summary = (f"{len(hosts)} probed · {dangerous} with takeover "
               f"signs · 0 performed")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
