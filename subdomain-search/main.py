#!/usr/bin/env python3
"""subdomain-search/main.py — enumerate a domain's subdomains for PyShell.

The inverse of ``ip-domains``: passive OSINT sources are asked for every
name that lives under one registrable domain — crt.sh (certificate
transparency), HackerTarget (host search), RapidDNS (passive DNS) and
Shodan (DNS domain lookup, API key) — and every candidate is then
confirmed by forward DNS resolution over a thread pool.

**Wildcard detection** separates this from a naive resolver fan-out: a
domain with a ``*.example.com`` record resolves *anything*, and a
source-fed candidate list would otherwise come back "alive" wholesale.
Two random probes are resolved first; when they answer, their IPs mark
the wildcard, and candidates that resolve *only* to those IPs are
reported as ``wildcard`` rather than ``alive`` — visible, not silent,
and never counted as finds.

Each subdomain carries the source(s) that named it — one API echoing
another's data is common, and "who saw this" is part of the result.

Structured events on stderr (progress 0–50 sources, 50–100
verification), human log on stdout. Exit codes: 0 = the search ran
(however many or few subdomains turned up), 1 = unusable input or every
source failed, 2 = bad arguments.
"""
import csv
import ipaddress
import json
import os
import random
import re
import socket
import string
import sys
import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

TIMEOUT = 10
CRTSH_TIMEOUT = 30
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; subdomain-search/1.0)"}

# RFC-1035-ish hostname filter: at least two dot-separated labels, each
# 1–63 chars, letters/digits/hyphen, no leading/trailing hyphen, total ≤ 253.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

#: How many result-table rows the final event carries; the CSV always
#: holds everything. Keeps one giant domain's table event sane.
MAX_TABLE_ROWS = 2000


# ── Structured event helpers ──────────────────────────────────────────────

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def log(msg: str) -> None:
    print(msg, flush=True)


def source_fail(label: str, e: Exception) -> None:
    msg = f"[{label}] error: {e}"
    log(f"  {msg}")
    emit({"type": "status", "message": msg})


# ── HTTP session ──────────────────────────────────────────────────────────

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


SESSION = make_session()


# ── Candidate hygiene ─────────────────────────────────────────────────────

def valid_domain(domain: str) -> bool:
    """A usable registrable-domain input: a DNS name that isn't an IP."""
    if not DOMAIN_RE.match(domain):
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        return True


def under_domain(name: str, domain: str) -> bool:
    """``name`` is the domain itself or a subdomain of it — never a
    sibling, never an unrelated name a loose source handed back."""
    return name == domain or name.endswith("." + domain)


def clean(raw_names, domain: str) -> set[str]:
    """Normalize and filter source output: lowercase, strip the root dot
    and ``*.`` wildcards, keep only DNS names under ``domain``."""
    out: set[str] = set()
    for x in raw_names:
        d = x.strip().rstrip(".").lower().removeprefix("*.")
        if not d or not DOMAIN_RE.match(d):
            continue
        try:
            ipaddress.IPv4Address(d)
            continue
        except ValueError:
            pass
        if under_domain(d, domain):
            out.add(d)
    return out


# ── Source parsers (pure — unit-tested without touching the network) ──────

def parse_crtsh(payload) -> set[str]:
    """Names from crt.sh's JSON: ``name_value`` (often multiline) and
    ``common_name``, wildcards stripped by clean()."""
    names: set[str] = set()
    if not isinstance(payload, list):
        return names
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for key in ("name_value", "common_name"):
            value = entry.get(key) or ""
            if isinstance(value, str):
                names.update(line.strip() for line in value.splitlines() if line.strip())
    return names


def parse_hackertarget(text: str) -> set[str]:
    """HackerTarget hostsearch answers ``host,ip`` per line — or an
    error string that must read as empty, not as a hostname."""
    names: set[str] = set()
    low = text.strip().lower()
    if not low or "error" in low or "no records" in low or "api count" in low:
        return names
    for line in text.strip().splitlines():
        host = line.split(",")[0].strip()
        if host:
            names.add(host)
    return names


def parse_rapiddns(html: str, domain: str) -> set[str]:
    """RapidDNS renders subdomains as link/table text; a hostname-shaped
    token ending in the domain is the signal, HTML noise is not."""
    pattern = re.compile(
        r"([a-zA-Z0-9._-]+\." + re.escape(domain) + r")(?![a-zA-Z0-9._-])"
    )
    return set(pattern.findall(html))


def parse_shodan(payload, domain: str) -> set[str]:
    """Shodan's DNS-domain endpoint: ``subdomains`` is a list of bare
    labels, ``data[].subdomain`` carries resolved ones — both become
    full hostnames under the domain."""
    names: set[str] = set()
    if not isinstance(payload, dict):
        return names
    for label in payload.get("subdomains", []) or []:
        if isinstance(label, str) and label.strip():
            names.add(f"{label.strip()}.{domain}")
    for entry in payload.get("data", []) or []:
        if isinstance(entry, dict):
            sub = entry.get("subdomain")
            if isinstance(sub, str) and sub.strip():
                names.add(f"{sub.strip()}.{domain}")
    return names


# ── Sources ───────────────────────────────────────────────────────────────
# Each fetch_*(domain) swallows its own exceptions and returns set() on
# failure so one dead API cannot kill the run. Output is normalised by
# clean() in main().

def fetch_crtsh(domain: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=CRTSH_TIMEOUT,
        )
        r.raise_for_status()
        # crt.sh occasionally answers an HTML error page with 200.
        try:
            payload = r.json()
        except ValueError:
            return set()
        return parse_crtsh(payload)
    except Exception as e:
        source_fail("crt.sh", e)
        return set()


def fetch_hackertarget(domain: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        return parse_hackertarget(r.text)
    except Exception as e:
        source_fail("hackertarget", e)
        return set()


def fetch_rapiddns(domain: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        return parse_rapiddns(r.text, domain)
    except Exception as e:
        source_fail("rapiddns", e)
        return set()


def fetch_shodan(domain: str, api_key: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return set()
        r.raise_for_status()
        return parse_shodan(r.json(), domain)
    except Exception as e:
        source_fail("shodan", e)
        return set()


# ── DNS resolution and wildcard detection ─────────────────────────────────

def resolve_domain(domain: str) -> Optional[list[str]]:
    """Every IPv4 the domain resolves to, sorted; None when it does not
    resolve. getaddrinfo returns the full A-record set, unlike
    gethostbyname which collapses round-robin / CDN names to one
    arbitrary address."""
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except socket.gaierror:
        return None


def _random_label() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=16))


def probe_wildcard(domain: str) -> tuple[bool, list[str]]:
    """Resolve two random labels under the domain.

    No answer → no wildcard record, every later resolution is real.
    An answer → the domain resolves anything; the union of the probe IPs
    becomes the wildcard fingerprint against which candidates are
    judged. Two probes because some CDNs answer one random name and not
    another (per-label geo shards) — either answer still proves the
    wildcard.
    """
    ips: set[str] = set()
    answered = False
    for _ in range(2):
        found = resolve_domain(f"{_random_label()}.{domain}")
        if found:
            answered = True
            ips.update(found)
    return answered, sorted(ips)


@dataclass
class VerifyResult:
    alive: list[tuple[str, list[str], str]] = field(default_factory=list)   # (subdomain, ips, sources)
    unresolved: list[tuple[str, str]] = field(default_factory=list)          # (subdomain, sources)
    wildcard: list[tuple[str, list[str], str]] = field(default_factory=list) # alive only via the wildcard record


def verify_subdomains(
    candidates: dict[str, set[str]],        # subdomain -> source labels
    wildcard_ips: list[str],
    workers: int,
    max_subdomains: int,
    csv_path: str,
) -> VerifyResult:
    """Resolve every candidate in parallel, bucketed by what DNS says.

    The CSV is written incrementally so a timeout-kill still leaves a
    complete-enough artifact. ``wildcard_ips`` empty means no wildcard
    record was detected and the wildcard bucket stays empty.
    """
    items = sorted(candidates.items())
    if max_subdomains and len(items) > max_subdomains:
        items = items[:max_subdomains]
        note = f"Truncated to {max_subdomains} subdomains for verification"
        log(f"  {note}")
        emit({"type": "status", "message": note})

    total = len(items)
    result = VerifyResult()
    wildcard_set = set(wildcard_ips)
    done = 0
    last_pct = -1

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["subdomain", "resolved_ips", "status", "sources"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_sub = {pool.submit(resolve_domain, sub): (sub, sources)
                             for sub, sources in items}
            for future in concurrent.futures.as_completed(future_to_sub):
                sub, sources = future_to_sub[future]
                addrs = future.result()
                source_list = " ".join(sorted(sources))
                if addrs is None:
                    result.unresolved.append((sub, source_list))
                    writer.writerow([sub, "", "unresolved", source_list])
                elif wildcard_set and wildcard_set.issuperset(addrs):
                    # Resolves, but only to IPs the random probes already
                    # answered on: the wildcard record, not the subdomain.
                    result.wildcard.append((sub, addrs, source_list))
                    writer.writerow([sub, ", ".join(addrs), "wildcard", source_list])
                else:
                    result.alive.append((sub, addrs, source_list))
                    writer.writerow([sub, ", ".join(addrs), "alive", source_list])
                f.flush()
                done += 1
                pct = 50 + (done / total) * 50 if total else 100
                if int(pct) != last_pct:
                    last_pct = int(pct)
                    emit({"type": "progress", "pct": pct,
                          "message": f"Resolving {done}/{total}"})

    result.alive.sort()
    result.unresolved.sort()
    result.wildcard.sort()
    return result


# ── Main ──────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Find a domain's subdomains via OSINT sources, "
                    "confirmed by forward-DNS resolution.")
    parser.add_argument("domain", help="registrable domain to enumerate, e.g. example.com")
    parser.add_argument("--sources", default="crtsh hackertarget rapiddns",
                        help="space-separated sources: crtsh hackertarget rapiddns shodan")
    parser.add_argument("--no-verify", action="store_true",
                        help="list raw candidates without DNS resolution")
    parser.add_argument("--workers", type=int, default=50,
                        help="DNS verification threads")
    parser.add_argument("--max-subdomains", type=int, default=5000,
                        help="cap on candidates sent to verification")
    args = parser.parse_args(argv)

    # Introspection builds the form from argparse; no queries are sent.
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no queries sent", flush=True)
        return 0

    domain = args.domain.strip().lower().rstrip(".")
    sources = args.sources.split() if isinstance(args.sources, str) else list(args.sources)
    shodan_key = os.environ.get("SHODAN_API_KEY", "")

    if not valid_domain(domain):
        emit({"type": "status", "message": f"Invalid domain: {args.domain}"})
        print(f"✗ {args.domain!r} is not a registrable domain (no scheme, "
              "no path, no IP literal)", file=sys.stderr, flush=True)
        return 1

    # The run must end at pct: 100 on every non-error return path.
    try:
        if "shodan" in sources and not shodan_key:
            sources = [s for s in sources if s != "shodan"]
            msg = "Shodan skipped: SHODAN_API_KEY not set"
            log(f"  {msg}")
            emit({"type": "status", "message": msg})

        log(f"Searching subdomains of: {domain}")
        emit({"type": "status", "message": f"Target: {domain}"})

        source_map = {
            "crtsh":        (lambda d: fetch_crtsh(d),        "crt.sh (certificate transparency)"),
            "hackertarget": (lambda d: fetch_hackertarget(d), "HackerTarget host search"),
            "rapiddns":     (lambda d: fetch_rapiddns(d),     "RapidDNS passive DNS"),
            "shodan":       (lambda d: fetch_shodan(d, shodan_key), "Shodan DNS domain lookup"),
        }

        valid_sources = [s for s in sources if s in source_map]
        total_sources = len(valid_sources)

        if total_sources == 0:
            emit({"type": "status", "message": "No sources to query"})
            log("No sources to query.")
            return 1

        # subdomain -> which source(s) named it
        candidates: dict[str, set[str]] = {}
        failures = 0
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {}
            for key in valid_sources:
                fn, label = source_map[key]
                log(f"  [{label}] querying...")
                futures[pool.submit(fn, domain)] = (label, key)
            for future in concurrent.futures.as_completed(futures):
                label, key = futures[future]
                try:
                    raw = future.result()
                except Exception as e:
                    source_fail(label, e)
                    raw = set()
                found = clean(raw, domain)
                if not found:
                    failures += 1
                log(f"  [{label}] {len(found)} unique name(s)")
                for name in found:
                    candidates.setdefault(name, set()).add(key)
                completed += 1
                emit({
                    "type": "progress",
                    "pct": round((completed / total_sources) * 45),
                    "message": f"Querying {label}",
                })

        if failures == total_sources:
            print("✗ every source failed — nothing to work with",
                  file=sys.stderr, flush=True)
            return 1

        emit({"type": "progress", "pct": 45,
              "message": f"Found {len(candidates)} unique subdomain candidate(s)"})
        log(f"\nTotal unique candidates: {len(candidates)}")

        output_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
        os.makedirs(output_dir, exist_ok=True)
        raw_path = os.path.join(output_dir, "subdomains_raw.json")
        with open(raw_path, "w") as f:
            json.dump({sub: sorted(srcs) for sub, srcs in sorted(candidates.items())},
                      f, indent=2)

        if not candidates:
            emit({"type": "table", "columns": ["Subdomain"], "rows": []})
            emit({"type": "status", "message": "No subdomain candidates found"})
            log("No subdomain candidates found.")
            return 0

        def sources_of(sub: str) -> str:
            return " ".join(sorted(candidates[sub]))

        if args.no_verify:
            csv_path = os.path.join(output_dir, "subdomains.csv")
            with open(csv_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["subdomain", "resolved_ips", "status", "sources"])
                for sub in sorted(candidates):
                    writer.writerow([sub, "", "unverified", sources_of(sub)])
            emit({
                "type": "table",
                "columns": ["Subdomain", "Sources"],
                "rows": [[sub, sources_of(sub)] for sub in sorted(candidates)],
            })
            emit({"type": "status",
                  "message": f"{len(candidates)} subdomain(s), unverified"})
            log("Done!")
            return 0

        # Wildcard probe — before verification, one phase of its own.
        emit({"type": "progress", "pct": 46, "message": "Probing for a wildcard record"})
        wildcard, wildcard_ips = probe_wildcard(domain)
        if wildcard:
            log(f"  ⚠ wildcard DNS detected: random names resolve to "
                f"{', '.join(wildcard_ips)} — candidates resolving only there "
                f"are reported as 'wildcard', not 'alive'")
            emit({"type": "status",
                  "message": f"⚠ Wildcard DNS detected ({', '.join(wildcard_ips)}) — "
                             f"'wildcard' rows resolve only via the * record"})

        log("Verifying via DNS resolution...")
        emit({"type": "status", "message": "Verifying via DNS..."})

        csv_path = os.path.join(output_dir, "subdomains.csv")
        result = verify_subdomains(candidates, wildcard_ips,
                                   args.workers, args.max_subdomains, csv_path)

        table_rows = [[sub, ", ".join(ips), "alive", srcs]
                      for sub, ips, srcs in result.alive]
        table_rows += [[sub, "", "unresolved", srcs]
                       for sub, srcs in result.unresolved]
        table_rows += [[sub, ", ".join(ips), "wildcard", srcs]
                       for sub, ips, srcs in result.wildcard]
        if len(table_rows) > MAX_TABLE_ROWS:
            table_rows = table_rows[:MAX_TABLE_ROWS]
            emit({"type": "status",
                  "message": f"Table truncated to {MAX_TABLE_ROWS} rows — "
                             f"the CSV holds every result"})

        log(f"\n  Alive: {len(result.alive)}")
        log(f"  Unresolved: {len(result.unresolved)}")
        if wildcard:
            log(f"  Wildcard-only: {len(result.wildcard)}")

        emit({
            "type": "table",
            "columns": ["Subdomain", "Resolved IPs", "Status", "Sources"],
            "rows": table_rows,
        })
        summary = (f"Alive: {len(result.alive)} | Unresolved: "
                   f"{len(result.unresolved)}"
                   + (f" | Wildcard: {len(result.wildcard)}" if wildcard else ""))
        emit({"type": "status", "message": summary})
        log("Done!")
        return 0
    finally:
        emit({"type": "progress", "pct": 100, "message": "Done"})


if __name__ == "__main__":
    sys.exit(main())
