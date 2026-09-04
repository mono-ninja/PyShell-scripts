#!/usr/bin/env python3
"""dns-propagation/main.py — is the new DNS record live everywhere yet?

"I just changed the record — is it propagated?" One query to the system
resolver answers only for that one cache. This script asks **~20 public
resolvers from different operators** at once (Google, Cloudflare, Quad9,
OpenDNS, Yandex, DNS.Watch, …), plus your system resolver, and lays the
answers side by side: who serves the new value, who still the old one,
what TTLs they report, and whether the answers agree at all.

Give **Expected value** and every resolver is classified — serving the
new value, or something else (the old one); that's the propagation
progress bar. Leave it empty and the script answers the other question:
how many distinct answers are out there, and which resolver serves
which — the consistency view (a wrong DNS entry, a geo-split, a
round-robin, all show up here).

Record types are normalized before comparison: TXT strips its quotes,
MX compares the host part (priority aside), CNAME/NS fold case and the
trailing dot; A/AAAA compare exactly. A comma-separated expected list
covers round-robin sets — a resolver counts as updated when it serves
any of the expected values.

Pure DNS queries to the resolvers' addresses — the authoritative
nameservers are never contacted, nothing is changed anywhere. Exit
codes: 0 = the check ran (disagreement is a result, not a failure),
1 = every resolver failed to answer (nothing was checked), 2 = bad
arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import concurrent.futures
from dataclasses import dataclass, field, asdict

import dns.exception
import dns.resolver


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
# The resolver catalogue — different operators, different caches and views
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PublicResolver:
    ip: str
    operator: str
    where: str          # anycast is honest about being global


RESOLVERS: list[PublicResolver] = [
    PublicResolver("8.8.8.8", "Google Public DNS", "anycast (global)"),
    PublicResolver("8.8.4.4", "Google Public DNS", "anycast (global)"),
    PublicResolver("1.1.1.1", "Cloudflare", "anycast (global)"),
    PublicResolver("1.0.0.1", "Cloudflare", "anycast (global)"),
    PublicResolver("9.9.9.9", "Quad9", "anycast (Zurich HQ)"),
    PublicResolver("149.112.112.112", "Quad9", "anycast (Zurich HQ)"),
    PublicResolver("208.67.222.222", "OpenDNS (Cisco)", "anycast (global)"),
    PublicResolver("208.67.220.220", "OpenDNS (Cisco)", "anycast (global)"),
    PublicResolver("4.2.2.1", "Level3 / Lumen", "US"),
    PublicResolver("4.2.2.2", "Level3 / Lumen", "US"),
    PublicResolver("84.200.69.80", "DNS.Watch", "DE"),
    PublicResolver("84.200.70.40", "DNS.Watch", "DE"),
    PublicResolver("77.88.8.8", "Yandex DNS", "RU"),
    PublicResolver("77.88.8.1", "Yandex DNS", "RU"),
    PublicResolver("8.26.56.26", "Comodo Secure DNS", "US"),
    PublicResolver("8.20.247.20", "Comodo Secure DNS", "US"),
    PublicResolver("195.46.39.39", "SafeDNS", "RU"),
    PublicResolver("80.80.80.80", "Freenom World", "anycast (global)"),
    PublicResolver("156.154.70.1", "Neustar UltraDNS", "US"),
    PublicResolver("149.112.121.10", "CIRA Canadian Shield", "CA"),
]


# ---------------------------------------------------------------------------
# Answer normalization + classification (pure)
# ---------------------------------------------------------------------------

@dataclass
class ResolverResult:
    label: str            # "Google Public DNS (8.8.8.8)" / "System resolver"
    ip: str
    outcome: str          # ok | nxdomain | empty | error
    answers: list[str] = field(default_factory=list)
    ttl: int | None = None
    status: str = ""      # updated | differs | — (when expected given)
    error: str = ""


def normalize_answer(raw: str, record_type: str) -> str:
    """Comparable form per type: TXT loses its quotes, MX keeps only the
    host (priority is presentation), CNAME/NS fold case and the trailing
    dot; A/AAAA and the rest compare as-is."""
    value = str(raw).strip()
    if record_type == "TXT":
        return value.strip('"').strip('"')
    if record_type == "MX":
        parts = value.split()
        return parts[1].rstrip(".").lower() if len(parts) == 2 else value
    if record_type in ("CNAME", "NS", "SOA"):
        return value.rstrip(".").lower() if " " not in value else value
    return value


def classify(result: ResolverResult, expected: list[str],
             record_type: str) -> str:
    """updated / differs / — — against the expected values, normalized
    the same way as the answers. Empty expected means no classification:
    the answers themselves are the result."""
    if not expected:
        return ""
    if result.outcome != "ok":
        return ""
    wanted = {normalize_answer(e.strip(), record_type) for e in expected}
    served = {normalize_answer(a, record_type) for a in result.answers}
    return "updated" if served & wanted else "differs"


# ---------------------------------------------------------------------------
# Querying (the only I/O)
# ---------------------------------------------------------------------------

def query_resolver(name: str, record_type: str, ip: str, timeout: float,
                   label: str) -> ResolverResult:
    result = ResolverResult(label=label, ip=ip, outcome="error")
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.lifetime = timeout
        answer = resolver.resolve(name, record_type)
        result.outcome = "ok"
        result.answers = [str(rdata) for rdata in answer.rrset]
        result.ttl = answer.rrset.ttl
    except dns.resolver.NXDOMAIN:
        result.outcome = "nxdomain"
    except dns.resolver.NoAnswer:
        result.outcome = "empty"
    except dns.exception.Timeout:
        result.error = "timeout"
    except dns.resolver.NoNameservers:
        result.error = "SERVFAIL / refused"
    except dns.exception.DNSException as exc:
        result.error = type(exc).__name__
    return result


def query_system(name: str, record_type: str, timeout: float) -> ResolverResult:
    """The system resolver, as one more view — the one your own machine
    actually uses."""
    result = ResolverResult(label="System resolver", ip="", outcome="error")
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answer = resolver.resolve(name, record_type)
        result.outcome = "ok"
        result.answers = [str(rdata) for rdata in answer.rrset]
        result.ttl = answer.rrset.ttl
    except dns.resolver.NXDOMAIN:
        result.outcome = "nxdomain"
    except dns.resolver.NoAnswer:
        result.outcome = "empty"
    except (dns.exception.Timeout, dns.exception.DNSException) as exc:
        result.error = type(exc).__name__
    return result


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

STATUS_ICON = {"updated": "✅", "differs": "⚠️", "nxdomain": "❌",
               "empty": "⚪", "error": "⚠️", "ok": "✅"}


def agreement(results: list[ResolverResult], record_type: str) -> list[tuple[str, list[str]]]:
    """Distinct answer-sets among the resolvers that answered, each with
    its resolvers — the consistency view."""
    groups: dict[tuple[str, ...], list[str]] = {}
    for r in results:
        if r.outcome != "ok":
            continue
        key = tuple(sorted({normalize_answer(a, record_type) for a in r.answers}))
        groups.setdefault(key, []).append(r.label)
    return sorted((( " / ".join(k), v) for k, v in groups.items()),
                  key=lambda kv: -len(kv[1]))


def build_report(name: str, record_type: str, expected: list[str],
                 results: list[ResolverResult]) -> str:
    answered = [r for r in results if r.outcome == "ok"]
    lines = [f"## DNS propagation — {name} ({record_type})", ""]

    if expected:
        updated = [r for r in answered if r.status == "updated"]
        differs = [r for r in answered if r.status == "differs"]
        pct = round(100 * len(updated) / len(answered)) if answered else 0
        lines.append(f"**{len(updated)} of {len(answered)} answering resolver(s) "
                     f"serve the expected value ({pct}%).")
        if differs:
            lines.append(f"{len(differs)} still serve something else — old "
                         f"value or a different view.")
        lines.append("")
        if updated:
            lines.append("**Serving the expected value:**")
            lines.append(", ".join(r.label for r in updated))
            lines.append("")
        if differs:
            lines.append("**Serving something else:**")
            for r in differs:
                shown = ", ".join(r.answers[:3])
                more = f" (+{len(r.answers) - 3} more)" if len(r.answers) > 3 else ""
                lines.append(f"- {r.label}: {shown}{more}")
            lines.append("")
        lines.append("_A resolver still on the old value isn't broken — its "
                     "cache holds the record until the TTL runs out. The TTL "
                     "column shows how long each one might keep its answer._")
        lines.append("")
    else:
        groups = agreement(results, record_type)
        lines.append(f"**{len(groups)} distinct answer(s) across "
                     f"{len(answered)} answering resolver(s)**"
                     + (f" — the record is consistent" if len(groups) == 1
                        else " — resolvers disagree:"))
        lines.append("")
        for answer, who in groups:
            lines.append(f"- `{answer}` — {len(who)} resolver(s): "
                         + ", ".join(w.replace(" (", "·") for w in who[:6])
                         + (" …" if len(who) > 6 else ""))
        lines.append("")

    lines.append("### Per resolver")
    lines.append("")
    lines.append("| Resolver | Answer | TTL | Status |")
    lines.append("| --- | --- | --- | --- |")
    for r in results:
        answer = ", ".join(r.answers[:2]) if r.outcome == "ok" else (
            r.error or {"nxdomain": "NXDOMAIN", "empty": "no records"}[r.outcome])
        ttl = f"{r.ttl}s" if r.ttl is not None else "—"
        cell = r.status or r.outcome
        lines.append(f"| {r.label} | {answer} | {ttl} | "
                     f"{STATUS_ICON.get(cell, '')} {cell} |")
    lines.append("")
    return "\n".join(lines)


def build_table_event(results: list[ResolverResult]) -> dict:
    return {
        "type": "table",
        "columns": ["Resolver", "Answer", "TTL", "Status"],
        "rows": [[
            r.label,
            ", ".join(r.answers[:2]) if r.outcome == "ok" else
            (r.error or {"nxdomain": "NXDOMAIN", "empty": "no records"}[r.outcome]),
            f"{r.ttl}s" if r.ttl is not None else "—",
            f"{STATUS_ICON.get(r.status or r.outcome, '')} {r.status or r.outcome}",
        ] for r in results],
    }


def build_chart_event(expected: list[str],
                      results: list[ResolverResult]) -> dict | None:
    """A propagation bar when there's an expected value to track; skipped
    otherwise (the agreement section is the story there)."""
    if not expected:
        return None
    answered = [r for r in results if r.outcome == "ok"]
    updated = sum(1 for r in answered if r.status == "updated")
    differs = sum(1 for r in answered if r.status == "differs")
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": "Propagation across answering resolvers",
        "labels": ["Serving new value", "Serving other"],
        "series": [{"name": "resolvers", "values": [updated, differs]}],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DNS Propagation — one record, ~20 public resolvers, "
                    "side by side")
    parser.add_argument("--name", required=True,
                        help="the record name, e.g. example.com")
    parser.add_argument("--type", default="A", dest="record_type",
                        choices=["A", "AAAA", "CNAME", "MX", "TXT", "NS",
                                 "SOA", "CAA"],
                        help="record type (default A)")
    parser.add_argument("--expected", default=None,
                        help="the new value (comma-separated for round-robin); "
                             "classifies each resolver as serving it or not")
    parser.add_argument("--timeout", type=int, default=4,
                        help="per-resolver timeout in seconds (default 4)")
    parser.add_argument("--workers", type=int, default=8,
                        help="parallel queries (default 8)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no queries sent", flush=True)
        return 0

    name = args.name.strip().rstrip(".").lower()
    if not name or "." not in name:
        print(f"✗ {args.name!r} does not look like a DNS name",
              file=sys.stderr, flush=True)
        return 2
    expected = ([v.strip() for v in args.expected.split(",") if v.strip()]
                if args.expected else [])

    log(f"Checking {name} {args.record_type} on {len(RESOLVERS)} public "
        f"resolver(s) + the system resolver")
    emit({"type": "progress", "pct": 5, "message": "Querying resolvers"})

    jobs = [(f"{r.operator} ({r.ip})", r.ip) for r in RESOLVERS]
    results: list[ResolverResult] = []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(query_resolver, name, args.record_type, ip,
                               args.timeout, label): label
                   for label, ip in jobs}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:                    # belt and braces
                results.append(ResolverResult(
                    label=futures[future], ip="", outcome="error",
                    error=f"{type(exc).__name__}: {exc}"))
            done += 1
            emit({"type": "progress",
                  "pct": 5 + round(85 * done / len(jobs)),
                  "message": f"Queried {done}/{len(jobs)}"})

    # The system resolver joins last, as one more view.
    results.append(query_system(name, args.record_type, args.timeout))
    results.sort(key=lambda r: (r.status != "updated", r.status != "differs",
                                r.label))

    if all(r.outcome == "error" for r in results):
        print("✗ every resolver failed — DNS is unusable from here",
              file=sys.stderr, flush=True)
        return 1

    for r in results:
        r.status = classify(r, expected, args.record_type)
    # Re-sort now that statuses are known: updated, differs, then the rest.
    results.sort(key=lambda r: (r.status != "updated", r.status != "differs",
                                r.outcome == "error", r.label))

    emit({"type": "progress", "pct": 95, "message": "Building the report"})
    report = build_report(name, args.record_type, expected, results)
    emit(build_table_event(results))
    chart = build_chart_event(expected, results)
    if chart:
        emit(chart)
    emit({"type": "markdown", "content": report})

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "dns_propagation.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"name": name, "type": args.record_type,
                       "expected": expected,
                       "results": [asdict(r) for r in results]},
                      fh, indent=2, ensure_ascii=False)
        with open(os.path.join(output_dir, "report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(report + "\n")

    emit({"type": "progress", "pct": 100, "message": "Done"})
    answered = [r for r in results if r.outcome == "ok"]
    if expected:
        updated = sum(1 for r in answered if r.status == "updated")
        status(f"{updated}/{len(answered)} resolver(s) serve the expected value")
        log(f"← {updated}/{len(answered)} resolver(s) updated")
    else:
        groups = agreement(results, args.record_type)
        status(f"{len(groups)} distinct answer(s) across {len(answered)} "
               f"resolver(s)")
        log(f"← {len(groups)} distinct answer(s) across {len(answered)} "
            f"resolver(s)")
    # Disagreement is a result, not a failure.
    return 0


if __name__ == "__main__":
    sys.exit(main())
