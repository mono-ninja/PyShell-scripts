#!/usr/bin/env python3
"""mail-probe/main.py — thin entry point; the wire lives in src/.

The SMTP layer of a mail domain, probed politely:

- **MX hosts** (DNS, passive) — most-preferred first, capped.
- **Port 25 per host**: the banner, the EHLO capability set (STARTTLS,
  AUTH mechanisms, SIZE…), and — when STARTTLS is offered — the TLS
  handshake with its **certificate chain** (subject, issuer, days to
  expiry, verification verdict).
- **PTR records** of each host's address, forward-confirmed.
- **The relay probe, opt-in and off by default**: MAIL FROM with a
  local sender, RCPT TO an external reserved-domain recipient, quit
  before DATA — **no mail is ever sent**. An accepted third-party RCPT
  is the open-relay red flag; a 550/554 rejection is the healthy
  answer.

The DNS half of a mail domain (SPF/DMARC/DKIM/MX records as records)
belongs to [Email DNS Audit](../email-dns-audit); the reputation half
to [DNSBL Check](../dnsbl-check). This script is the wire: what the
server actually says when you connect.

Point it at domains you own or operate. Some steps look like what a
scanner does — that's the point of checking them on yourself first.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

import dns.resolver
import dns.reversename
import dns.exception

from src.events import emit, log, status
from src.report import build_markdown, build_table_event, write_artifacts
from src.smtp_probe import (
    HostResult, RelayVerdict, TlsInfo, probe_host,
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# DNS (the only dnspython use)
# ---------------------------------------------------------------------------

def resolve_mx(domain: str, timeout: int) -> tuple[list[tuple[int, str]], str]:
    """([(preference, host)], note). Falls back to the A record (the
    implicit MX of RFC 5321) when no MX exists — reported honestly."""
    try:
        answers = dns.resolver.resolve(domain, "MX",
                                       lifetime=timeout)
        mx = sorted((a.preference, str(a.exchange).rstrip("."))
                    for a in answers)
        if mx and all(host == "" for _pref, host in mx):
            # RFC 7505 null MX — the domain explicitly accepts no mail.
            return [], "null MX (RFC 7505) — the domain accepts no mail"
        if mx:
            return mx, f"{len(mx)} MX record(s)"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        return [], f"MX lookup failed ({type(exc).__name__})"
    # No MX: the implicit MX is the A record (RFC 5321 §5.1).
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=timeout)
        if answers:
            return [(0, domain)], \
                "no MX records — using the A record (implicit MX)"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    return [], "no MX and no A records"


def resolve_ips(host: str, timeout: int) -> list[str]:
    """A (then AAAA) addresses of an MX host."""
    ips: list[str] = []
    for rdtype in ("A",):
        try:
            answers = dns.resolver.resolve(host, rdtype, lifetime=timeout)
            ips += [rdata.address for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    return ips


def ptr_record(ip: str, timeout: int) -> tuple[str, bool]:
    """(ptr_hostname, forward_confirmed). The forward check resolves the
    PTR name back and looks for the original IP — the anti-spoofing
    pairing every mail admin cares about."""
    try:
        answers = dns.resolver.resolve(dns.reversename.from_address(ip),
                                       "PTR", lifetime=timeout)
        name = str(answers[0].target).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.SyntaxError):
        return "", False
    confirmed = ip in resolve_ips(name, timeout)
    return name, confirmed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mail Probe — the SMTP wire layer of a mail domain: "
                    "MX hosts, banners, STARTTLS, certs, AUTH, PTR, "
                    "opt-in relay probe")
    parser.add_argument("--domain", required=True,
                        help="the mail domain to probe (yours)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-step timeout (default 15)")
    parser.add_argument("--max-hosts", type=int, default=3,
                        help="how many MX hosts to probe (default 3)")
    parser.add_argument("--check-relay", action="store_true",
                        help="opt-in relay probe: MAIL FROM/RCPT TO with "
                             "an external recipient, quit before DATA — "
                             "no mail is sent")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no DNS, no connections",
              flush=True)
        return 0

    domain = (args.domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        print(f"✗ {args.domain!r} is not a bare domain "
              f"(example.com — no scheme, no path)",
              file=sys.stderr, flush=True)
        return 2

    status(f"Resolving MX for {domain}")
    emit({"type": "progress", "pct": 5, "message": "MX lookup"})
    mx, mx_note = resolve_mx(domain, args.timeout)
    log(f"  {mx_note}" + (f": {', '.join(h for _p, h in mx)}"
                          if mx else ""))
    if not mx:
        print(f"✗ {domain} has no mail exchangers to probe ({mx_note})",
              file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Nothing to probe\n\n❌ **{domain}** — {mx_note}. "
              f"A domain without MX or A records has no SMTP wire to "
              f"test. Check the DNS side with "
              f"[Email DNS Audit](../email-dns-audit)."})
        return 1

    targets = mx[:args.max_hosts]
    results: list[HostResult] = []
    for i, (pref, host) in enumerate(targets, 1):
        status(f"Probing {host} ({i}/{len(targets)})")
        log(f"  ── {host} (preference {pref})")
        ips = resolve_ips(host, args.timeout)
        ptr_name, ptr_ok = ptr_record(ips[0], args.timeout) if ips \
            else ("", False)
        if ips:
            log(f"     {ips[0]} · PTR {'✓ ' + ptr_name if ptr_name else '—'}"
                + (" (forward-confirmed)" if ptr_ok
                   else " (NOT forward-confirmed)" if ptr_name else ""))
        else:
            log("     no A record — connecting by name")
        result = probe_host(host, ips, args.timeout, args.check_relay,
                            domain)
        result.preference = pref
        result.ptr = ptr_name
        result.ptr_confirmed = ptr_ok
        results.append(result)

        if result.connect_error:
            log(f"     ✗ connect: {result.connect_error}")
        else:
            bits = [f"banner “{result.banner[:60]}…”"
                    if len(result.banner) > 60 else f"banner “{result.banner}”"]
            if result.starttls_offered:
                if result.tls and result.tls.error:
                    bits.append(f"STARTTLS broken ({result.tls.error})")
                elif result.tls:
                    bits.append(f"TLS {result.tls.version} · cert "
                                f"{result.tls.days_left}d left")
                else:
                    bits.append("STARTTLS offered")
            else:
                bits.append("no STARTTLS")
            if result.auth_mechs:
                bits.append("AUTH " + " ".join(result.auth_mechs))
            log("     " + " · ".join(bits))
        if result.relay_verdict != RelayVerdict.NOT_TESTED:
            icon = {"accepted": "🔴", "rejected": "🟢",
                    "unclear": "🟡"}.get(result.relay_verdict.value, "")
            log(f"     relay probe: {icon} {result.relay_verdict.value}"
                + (f" ({result.relay_detail})" if result.relay_detail else ""))

        done = int(5 + 90 * i / len(targets))
        emit({"type": "progress", "pct": done, "message": f"{host} done"})

    if all(r.connect_error for r in results):
        print("✗ no MX host accepted a connection on port 25 — there "
              "was no wire to probe", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Nothing answered\n\n❌ None of {domain}'s MX hosts "
              f"accepted a connection on port 25 (firewall? wrong port? "
              f"block for residential IPs?). From many networks, port 25 "
              f"is blocked outbound — try from a server."})
        return 1

    report = build_markdown(domain, mx_note, results, args.check_relay)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(results))
    emit({"type": "markdown", "content": report})
    write_artifacts(domain, mx_note, results)

    relays = sum(1 for r in results
                 if r.relay_verdict == RelayVerdict.ACCEPTED)
    no_tls = sum(1 for r in results if not r.connect_error
                 and not r.starttls_offered)
    status(f"{len(results)} host(s) probed"
           + (f" · {relays} open-relay red flag(s)" if relays else "")
           + (f" · {no_tls} without STARTTLS" if no_tls else ""))
    log(f"← {len(results)} host(s) probed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
