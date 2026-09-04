#!/usr/bin/env python3
"""dnsbl-check/main.py — is this IP or domain on the public blocklists?

The deliverability sibling of ``email-dns-audit``: that one grades the
domain's DNS configuration (SPF/DMARC/DKIM), this one grades the
**reputation** of what actually sends the mail — the IP and the domain —
across the major public DNS blocklists. Pure DNS queries against the
blocklist zones; the target itself is never contacted beyond resolving
its A records.

**How a DNSBL query works:** for an IP list, the reversed IP is queried
under the zone (``25.100.51.198.zen.spamhaus.org``); for a domain list,
the domain itself (``example.com.dbl.spamhaus.org``). An answer in
``127.0.0.0/24`` (``127.0.1.x`` for the Spamhaus DBL) means **listed**,
with the last octet encoding the reason and a TXT record usually
carrying the human-readable one. NXDOMAIN means clean. ``127.255.255.x``
is not a listing — it is the zone refusing the query (most often:
Spamhaus's free tier does not serve big public resolvers), and it is
reported as ``blocked`` so a resolver artifact can never masquerade as
a reputation verdict.

Twelve curated, alive zones — ten IP lists and two domain lists. No
dead zones, no padding: a curated list where every row means something
beats a long one full of timeouts.

Exit codes: 0 = the checks ran (listings are results, not failures),
1 = the target is unusable or every query failed, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import concurrent.futures
from dataclasses import dataclass, field, asdict

import dns.exception
import dns.resolver

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

#: A domain with more A records than this gets its IP checks capped —
#: a CDN domain with 20 addresses would otherwise dominate the run (and
#: every address would answer identically anyway).
MAX_IPS_PER_DOMAIN = 8


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
# The zone catalogue
# ---------------------------------------------------------------------------

@dataclass
class Zone:
    """One blocklist: how to query it and how to read its answers."""
    zone: str                    # DNS zone
    kind: str                    # 'ip' | 'domain'
    about: str                   # what it lists
    url: str                     # lookup/delisting page
    codes: dict = field(default_factory=dict)   # last-octet -> meaning (IP lists)
    aggressive: bool = False     # listing quality worth flagging in the report


#: The 127.255.255.x answers — a refusal, never a listing.
BLOCKED_CODES = {
    "127.255.255.252": "query rate-limited — retry in a few minutes",
    "127.255.255.254": "public resolvers are not allowed on the free tier — "
                       "query via your own resolver or use the zone's web lookup",
    "127.255.255.255": "wrong zone for this kind of query",
}

#: Spamhaus DBL refusal (a different range: 127.0.1.102).
DBL_BLOCKED = "127.0.1.102"

IP_ZONES: list[Zone] = [
    Zone("zen.spamhaus.org", "ip",
         "Spamhaus ZEN — the composite list (SBL + XBL + CSS + DROP + PBL)",
         "https://check.spamhaus.org/results/",
         codes={
             2: "SBL — spam source", 3: "SBL — spam source",
             4: "XBL — exploited/hijacked system", 5: "XBL — exploited/hijacked system",
             6: "XBL — exploited/hijacked system", 7: "XBL — exploited/hijacked system",
             8: "CSS — spam-sending infrastructure",
             9: "DROP — stolen or hijacked netblock",
             10: "PBL — policy: this IP range should not send mail directly "
                 "(normal for residential/dynamic lines — not a spam listing)",
             11: "PBL — policy: this IP range should not send mail directly "
                 "(normal for residential/dynamic lines — not a spam listing)",
         }),
    Zone("bl.spamcop.net", "ip",
         "SpamCop — spam-trap and spam-report driven, listings auto-expire",
         "https://www.spamcop.net/w3m?action=checkblock"),
    Zone("b.barracudacentral.org", "ip",
         "Barracuda Reputation — spam and botnet activity",
         "https://www.barracudacentral.org/lookups"),
    Zone("dnsbl.sorbs.net", "ip",
         "SORBS aggregate — multiple sub-lists (spam, exploits, proxies)",
         "https://www.sorbs.net/lookup.shtml"),
    Zone("bl.blocklist.de", "ip",
         "blocklist.de — abuse reports from real servers (attacks, exploits)",
         "https://www.blocklist.de/en/remove.html"),
    Zone("psbl.surriel.com", "ip",
         "PSBL — the Public Squirrel List, spam-trap driven, easy delisting",
         "https://psbl.surriel.com/"),
    Zone("truncate.gbudb.net", "ip",
         "GBUDb — spam volume reputation",
         "https://www.gbudb.com/"),
    Zone("spam.spamrats.com", "ip",
         "SpamRats — dynamic/generic rDNS ranges and spam sources",
         "https://www.spamrats.com/"),
    Zone("bl.mailspike.net", "ip",
         "Mailspike — reputation-based, best-guess list",
         "https://mailspike.net/analyzer.html"),
    Zone("dnsbl-1.uceprotect.net", "ip",
         "UCEPROTECT level 1 — aggressive: single reports can list an IP, "
         "auto-expires; delisting is instant but their escalation (level 2/3) "
         "is not free",
         "https://www.uceprotect.net/en/",
         aggressive=True),
]

DOMAIN_ZONES: list[Zone] = [
    Zone("dbl.spamhaus.org", "domain",
         "Spamhaus Domain Block List — domains seen in spam",
         "https://check.spamhaus.org/results/",
         codes={2: "DBL — domain appears in spam"}),
    Zone("multi.surbl.org", "domain",
         "SURBL — domains appearing in spam message bodies "
         "(phishing/malware bit flags)",
         "https://surbl.org/surbl-analysis"),
]

ALL_ZONES = IP_ZONES + DOMAIN_ZONES


# ---------------------------------------------------------------------------
# Answer interpretation (pure — unit-tested)
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """One zone's verdict for one target."""
    zone: str
    target: str
    outcome: str                 # listed | clean | blocked | error
    answers: list[str] = field(default_factory=list)   # A records seen
    code_meaning: str = ""       # decoded last octet / bitmask
    reason: str = ""             # TXT record text, when the zone serves one
    note: str = ""               # error/blocked detail


def interpret_answers(answers: list[str], zone: Zone) -> CheckResult:
    """A records -> a verdict. The rules, in order:

    * ``127.255.255.x`` (or the DBL's ``127.0.1.102``) — the zone
      refused the query (public-resolver policy, rate limit). Not a
      listing; reported as ``blocked``.
    * any other ``127.x.y.z`` with a non-zero host part — **listed**;
      the trailing octet decodes against the zone's table (SURBL's is
      a bitmask, DBL's lives in the third octet).
    * anything else a resolver handed back (a real A record for the
      query name) means the zone is not behaving like a blocklist —
      ``error``, never "clean": a broken zone must not vouch for
      anyone.
    """
    result = CheckResult(zone=zone.zone, target="", outcome="clean",
                         answers=list(answers))
    for answer in answers:
        if answer in BLOCKED_CODES or answer == DBL_BLOCKED:
            result.outcome = "blocked"
            result.note = BLOCKED_CODES.get(answer, "zone refused the query "
                                             "(public-resolver policy)")
            return result
    listed = [a for a in answers if _is_listed_answer(a)]
    if listed:
        result.outcome = "listed"
        result.code_meaning = _decode(listed, zone)
    elif answers:
        # Answers, but none in a listing range — the zone answered
        # something a blocklist never should.
        result.outcome = "error"
        result.note = f"unexpected answers: {', '.join(answers)}"
    return result


def _is_listed_answer(answer: str) -> bool:
    """127.x.y.z with a non-zero host part and not a refusal code."""
    try:
        octets = [int(part) for part in answer.split(".")]
    except ValueError:
        return False
    if len(octets) != 4 or octets[0] != 127:
        return False
    if octets[1] == 255 and octets[2] == 255:
        return False                    # refusal range
    if answer == DBL_BLOCKED:
        return False
    return octets[2] != 0 or octets[3] != 0


def _decode(listed: list[str], zone: Zone) -> str:
    """Human text for the listing code(s), best effort per zone shape."""
    meanings = []
    for answer in listed:
        octets = [int(p) for p in answer.split(".")]
        if zone.zone == "multi.surbl.org":
            flags = []
            bits = {0x02: "phishing", 0x04: "malware", 0x08: "spam",
                    0x10: "abuse", 0x20: "abuse", 0x40: "spam",
                    0x80: "spam"}
            for bit, label in bits.items():
                if octets[3] & bit:
                    flags.append(label)
            meanings.append(f"SURBL: {', '.join(flags) or 'listed'} "
                            f"(bitmask {octets[3]})")
            continue        # Every zone encodes the listing type in the LAST octet — even
        # the DBL, whose answer range is 127.0.1.x rather than 127.0.0.x.
        code = octets[3]
        if code in zone.codes:
            meanings.append(zone.codes[code])
        else:
            meanings.append(f"listed (code {answer})")
    return "; ".join(dict.fromkeys(meanings))       # unique, ordered


def query_name(zone: Zone, target: str) -> str:
    """The name to look up: reversed IP under an IP zone, the domain
    itself under a domain zone."""
    if zone.kind == "ip":
        return ".".join(reversed(target.split("."))) + "." + zone.zone
    return f"{target}.{zone.zone}"


# ---------------------------------------------------------------------------
# DNS plumbing
# ---------------------------------------------------------------------------

def make_resolver(nameserver: str | None, timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    if nameserver:
        try:
            ipaddress.ip_address(nameserver)
        except ValueError:
            raise ValueError(f"--nameserver {nameserver!r} is not an IP address")
        resolver.nameservers = [nameserver]
    return resolver


def _resolve_safe(resolver, name: str, rdtype: str):
    """One query; NXDOMAIN/NoAnswer -> None, anything else raises."""
    try:
        return resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None


def check_zone(zone: Zone, target: str, resolver) -> CheckResult:
    """Query one zone for one target. A fresh resolver view per call keeps
    the thread pool free of shared-state questions."""
    name = query_name(zone, target)
    result = CheckResult(zone=zone.zone, target=target, outcome="clean")
    try:
        answer = _resolve_safe(resolver, name, "A")
        if answer is None:
            return result                              # NXDOMAIN = clean
        answers = [str(rdata) for rdata in answer.rrset]
        result = interpret_answers(answers, zone)
        result.target = target
        if result.outcome == "listed":
            txt = _resolve_safe(resolver, name, "TXT")
            if txt is not None:
                result.reason = " ".join(
                    str(rdata).strip('"') for rdata in txt.rrset)[:300]
        return result
    except dns.exception.Timeout:
        result.outcome, result.note = "error", "timeout"
        return result
    except dns.resolver.NoNameservers:
        result.outcome, result.note = "error", "SERVFAIL / no nameserver answered"
        return result
    except dns.exception.DNSException as exc:
        result.outcome, result.note = "error", type(exc).__name__
        return result


def resolve_domain_ips(resolver, domain: str) -> list[str] | None:
    """The domain's A records (capped); None when it doesn't resolve at all."""
    answer = _resolve_safe(resolver, domain, "A")
    if answer is None:
        return None
    ips = sorted({str(r) for r in answer.rrset})
    return ips[:MAX_IPS_PER_DOMAIN]


# ---------------------------------------------------------------------------
# Target parsing (pure)
# ---------------------------------------------------------------------------

def parse_target(raw: str) -> tuple[str, str | None]:
    """'(kind, value)' where kind is 'ip' or 'domain'.

    A bare IP is checked against the IP lists only; a domain brings its
    A records to the IP lists and itself to the domain lists.
    Raises ValueError for anything that is neither.
    """
    text = (raw or "").strip().lower().rstrip(".")
    if not text:
        raise ValueError("empty target")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        # Not an IP literal at all ("dbltest.com") — ValueError, the
        # base class; AddressValueError only covers malformed literals
        # like "999.1.1.1". Both mean "not an IP", so the domain path
        # is next.
        ip = None
    if ip is not None:
        if ip.version != 6:
            return "ip", str(ip)
        raise ValueError(f"{text} is IPv6 — the public DNSBLs query "
                         f"reversed IPv4 only")
    if DOMAIN_RE.match(text):
        return "domain", text
    raise ValueError(f"{text!r} is neither an IPv4 address nor a domain "
                     f"(no scheme, no path)")


#: Big public resolvers — Spamhaus will not serve them on the free tier.
#: Empirically: some answer 127.255.255.254 (detected as ``blocked``),
#: others silently return NXDOMAIN — a "clean" that is not a verdict.
#: Every Spamhaus row through these is worth a caveat.
PUBLIC_RESOLVERS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                    "9.9.9.9", "149.112.112.112",
                    "208.67.222.222", "208.67.220.220"}
SPAMHAUS_ZONES = {"zen.spamhaus.org", "dbl.spamhaus.org"}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

OUTCOME_ICON = {"listed": "❌", "clean": "✅", "blocked": "🚫", "error": "⚠️"}


def build_report(target_desc: str, results: list[CheckResult],
                 public_resolver: bool = False) -> str:
    listed = [r for r in results if r.outcome == "listed"]
    clean = [r for r in results if r.outcome == "clean"]
    blocked = [r for r in results if r.outcome == "blocked"]
    errors = [r for r in results if r.outcome == "error"]

    if listed:
        headline = f"## ❌ Listed on {len(listed)} of {len(results)} checks"
    else:
        headline = f"## ✅ Not listed — {len(clean)} of {len(results)} checks clean"

    lines = [headline, "", f"`{target_desc}`", ""]

    if listed:
        lines += ["### Listings", ""]
        for r in sorted(listed, key=lambda r: (r.zone, r.target)):
            zone = next(z for z in ALL_ZONES if z.zone == r.zone)
            lines.append(f"- **{r.zone}** — `{r.target}` — {r.code_meaning}")
            if r.reason:
                lines.append(f"  - “{r.reason}”")
            lines.append(f"  - Look up / request delisting: {zone.url}")
            if zone.aggressive:
                lines.append(f"  - ⚠ aggressive list — single reports can cause "
                             f"listings; weigh it accordingly")
        lines.append("")

    lines += ["### Zone summary", "",
              "| Zone | Target | Status | Detail |", "| --- | --- | --- | --- |"]
    for r in results:
        detail = r.code_meaning or r.note or ("answers: " + ", ".join(r.answers)
                                              if r.answers else "NXDOMAIN")
        lines.append(f"| {r.zone} | `{r.target}` | {OUTCOME_ICON[r.outcome]} "
                     f"{r.outcome} | {detail[:120]} |")

    if blocked:
        lines += ["", "### Blocked queries", "",
                  "A `blocked` row is the zone refusing *you* (most often "
                  "Spamhaus not serving public resolvers on the free tier), "
                  "not a verdict about the target. Re-run with the system "
                  "resolver or your own, or use the zone's web lookup page."]
    elif public_resolver and any(r.outcome == "clean" and r.zone in SPAMHAUS_ZONES
                                 for r in results):
        lines += ["", "### Note on Spamhaus", "",
                  "Queried via a big public resolver: Spamhaus serves some "
                  "of them a **silent not-listed** instead of an error, so "
                  "a `clean` from `zen.spamhaus.org` / `dbl.spamhaus.org` "
                  "is not a verdict here. Re-run with your own resolver, "
                  "or use check.spamhaus.org directly."]
    if errors:
        lines += ["", "### Zone errors", "",
                  f"{len(errors)} zone(s) could not be queried (timeouts, "
                  "SERVFAIL) — their rows say nothing about the target."]

    lines += ["", "_Pure DNS queries against the blocklist zones — the target "
              "itself was never contacted (beyond resolving its A records)._",
              ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DNSBL Check — is this IP or domain on the public "
                    "DNS blocklists?")
    parser.add_argument("--target", required=True,
                        help="IPv4 address or domain to check")
    parser.add_argument("--nameserver", default=None,
                        help="custom resolver (default: the system resolver; "
                             "note that Spamhaus refuses big public resolvers "
                             "on the free tier)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="per-query timeout in seconds (default 5)")
    parser.add_argument("--workers", type=int, default=10,
                        help="parallel blocklist queries (default 10)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no queries sent", flush=True)
        return 0

    try:
        kind, value = parse_target(args.target)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    try:
        resolver = make_resolver(args.nameserver, args.timeout)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    public_resolver = (args.nameserver or "") in PUBLIC_RESOLVERS
    if public_resolver:
        status("⚠ querying via a big public resolver — Spamhaus zones may "
               "answer a silent not-listed instead of a real verdict")

    log(f"Checking {value} against {len(ALL_ZONES)} blocklist zone(s)")
    emit({"type": "progress", "pct": 5, "message": "Resolving the target"})
    status(f"Target: {value}")

    # Build the (zone, target) plan.
    targets: list[str] = []          # every value that gets zone queries
    if kind == "ip":
        targets = [value]
        ip_zones, domain_zones = IP_ZONES, []
        target_desc = value
    else:
        ips = resolve_domain_ips(resolver, value)
        if ips is None:
            status(f"⚠ {value} has no A records — only the domain lists "
                   f"are checked; the IP lists have nothing to query")
            ips = []
        elif len(ips) == MAX_IPS_PER_DOMAIN:
            status(f"⚠ A-record set capped at {MAX_IPS_PER_DOMAIN} addresses")
        targets = ips + [value]
        ip_zones, domain_zones = IP_ZONES, DOMAIN_ZONES
        target_desc = value + (f" (IPs: {', '.join(ips)})" if ips else "")
        for ip in ips:
            log(f"  sending IP {ip}")

    plan = [(zone, t) for t in targets for zone in (ip_zones if _is_ip(t) else domain_zones)]
    if not plan:
        print("✗ nothing to check — a bare IP needs the IP lists, a domain "
              "needs A records or the domain lists", file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 10,
          "message": f"{len(plan)} queries across {len(targets)} target(s)"})

    results: list[CheckResult] = []
    done = 0
    last_pct = -1
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_zone, zone, t, resolver): (zone, t)
                   for zone, t in plan}
        for future in concurrent.futures.as_completed(futures):
            zone, t = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:                    # never expected — belt and braces
                results.append(CheckResult(zone=zone.zone, target=t,
                                           outcome="error",
                                           note=f"{type(exc).__name__}: {exc}"))
            done += 1
            pct = 10 + round(80 * done / len(plan))
            if pct != last_pct:
                last_pct = pct
                emit({"type": "progress", "pct": pct,
                      "message": f"Queried {done}/{len(plan)}"})

    if results and all(r.outcome == "error" for r in results):
        print("✗ every query failed — DNS is unusable from here (check the "
              "resolver and connectivity)", file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 95, "message": "Building the report"})

    # Stable, readable order: by target, then zone as catalogued.
    results.sort(key=lambda r: (r.target, [z.zone for z in ALL_ZONES].index(r.zone)))

    report = build_report(target_desc, results, public_resolver=public_resolver)
    emit({"type": "markdown", "content": report})
    emit({"type": "table",
          "columns": ["Zone", "Target", "Status", "Detail"],
          "rows": [[r.zone, r.target, f"{OUTCOME_ICON[r.outcome]} {r.outcome}",
                    (r.code_meaning or r.note)[:200]] for r in results]})

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "dnsbl_raw.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"target": target_desc, "results": [asdict(r) for r in results]},
                      fh, indent=2, ensure_ascii=False)
        with open(os.path.join(output_dir, "report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(report + "\n")

    counts = {o: sum(1 for r in results if r.outcome == o)
              for o in ("listed", "clean", "blocked", "error")}
    summary = (f"{counts['listed']} listed · {counts['clean']} clean"
               + (f" · {counts['blocked']} blocked" if counts["blocked"] else "")
               + (f" · {counts['error']} error" if counts["error"] else ""))
    emit({"type": "progress", "pct": 100, "message": "Done"})
    status(summary)
    log(f"← {summary}")
    # Listings are results, not failures — a fully blacklisted IP is a
    # successful check that found a bad reputation.
    return 0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    sys.exit(main())
