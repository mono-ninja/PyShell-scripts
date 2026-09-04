#!/usr/bin/env python3
"""IP → Domains finder for PyShell.

Sources: crt.sh (certificate SAN), HackerTarget reverse IP, ViewDNS, Shodan.
Outputs structured events (progress, table, status) for PyShell's ResultView.
"""
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import concurrent.futures
from dataclasses import dataclass
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

TIMEOUT = 10
CRTSH_TIMEOUT = 30
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ip-domains-finder/1.0)"}

# RFC-1035-ish hostname filter: at least two dot-separated labels, each 1–63
# chars, letters/digits/hyphen, no leading/trailing hyphen, total ≤ 253.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


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


# ── Hostname hygiene ──────────────────────────────────────────────────────

def clean(domains: set[str]) -> set[str]:
    """Keep only strings that look like DNS names; drop emails, IP literals,
    quota prose and other junk a source may have handed us."""
    out: set[str] = set()
    for x in domains:
        d = x.strip().rstrip(".").lower()
        if not DOMAIN_RE.match(d):
            continue
        # Reject IPv4 literals (e.g. crt.sh name_value can carry the target IP);
        # IPv6 contains ":" and already fails DOMAIN_RE.
        try:
            ipaddress.IPv4Address(d)
            continue
        except ValueError:
            pass
        out.add(d)
    return out


# ── Sources ───────────────────────────────────────────────────────────────
# Each fetch_*(ip) swallows its own exceptions and returns set() on failure so
# one dead API cannot kill the run. Output is normalised by clean() in main().

def fetch_crtsh(ip: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://crt.sh/?q={ip}&output=json",
            timeout=CRTSH_TIMEOUT,
        )
        r.raise_for_status()
        domains = set()
        for entry in r.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().removeprefix("*.")
                if name:
                    domains.add(name.lower())
        return domains
    except Exception as e:
        source_fail("crt.sh", e)
        return set()


def fetch_hackertarget(ip: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        text = r.text.strip()
        if "error" in text.lower() or "no records" in text.lower():
            return set()
        return {line.strip().lower() for line in text.splitlines() if line.strip()}
    except Exception as e:
        source_fail("hackertarget", e)
        return set()


def fetch_viewdns(ip: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://viewdns.info/reverseip/?host={ip}&apiresponse=true",
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        domains = re.findall(r"<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>", r.text)
        return {d.lower() for d in domains}
    except Exception as e:
        source_fail("viewdns", e)
        return set()


def fetch_shodan(ip: str, api_key: str) -> set[str]:
    try:
        r = SESSION.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return set()
        r.raise_for_status()
        data = r.json()

        domains: set[str] = set()

        for h in data.get("hostnames", []):
            h = h.strip().lower()
            if h:
                domains.add(h)

        for port_data in data.get("data", []):
            ssl = port_data.get("ssl", {})
            cert = ssl.get("cert", {})
            cn = cert.get("subject", {}).get("CN", "")
            if cn:
                domains.add(cn.removeprefix("*.").lower())
            for ext in cert.get("extensions", []):
                if ext.get("name") == "subjectAltName":
                    for part in ext.get("data", "").split(","):
                        part = part.strip()
                        if part.startswith("DNS:"):
                            domains.add(part[4:].removeprefix("*.").lower())

        return {d for d in domains if d}
    except Exception as e:
        source_fail("shodan", e)
        return set()


# ── DNS verification ──────────────────────────────────────────────────────

def resolve_domain(domain: str) -> Optional[list[str]]:
    """Return every IPv4 the domain resolves to, sorted; None if it does not
    resolve. getaddrinfo returns the full A-record set, unlike gethostbyname
    which collapses round-robin / CDN domains to one arbitrary address."""
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except socket.gaierror:
        return None


@dataclass
class VerifyResult:
    confirmed: list[str]
    different: list[tuple[str, list[str]]]
    unresolved: list[str]


def verify_domains(
    domains: set[str],
    target_ip: str,
    workers: int,
    max_domains: int,
    csv_path: str,
) -> VerifyResult:
    if max_domains and len(domains) > max_domains:
        domains = set(sorted(domains)[:max_domains])
        note = f"Truncated to {max_domains} domains for verification"
        log(f"  {note}")
        emit({"type": "status", "message": note})

    total = len(domains)
    confirmed: list[str] = []
    different: list[tuple[str, list[str]]] = []
    unresolved: list[str] = []
    done = 0
    last_pct = -1

    # CSV is written incrementally so a timeout-kill still leaves an artifact.
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "resolved_ip", "status"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_domain = {pool.submit(resolve_domain, d): d for d in domains}
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                addrs = future.result()
                if addrs is None:
                    unresolved.append(domain)
                    writer.writerow([domain, "", "unresolved"])
                elif target_ip in addrs:
                    confirmed.append(domain)
                    writer.writerow([domain, target_ip, "confirmed"])
                else:
                    different.append((domain, addrs))
                    writer.writerow([domain, ", ".join(addrs), "different"])
                f.flush()
                done += 1
                pct = 50 + (done / total) * 50 if total else 100
                if int(pct) != last_pct:
                    last_pct = int(pct)
                    emit({"type": "progress", "pct": pct, "message": f"Resolving {done}/{total}"})

    confirmed.sort()
    different.sort(key=lambda x: x[0])
    unresolved.sort()
    return VerifyResult(confirmed, different, unresolved)


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Find all domains hosted on the same IP.")
    parser.add_argument("ip", help="Target IPv4 address")
    parser.add_argument("--sources", default="crtsh hackertarget viewdns")
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--workers", type=int, default=50, help="DNS verification threads")
    parser.add_argument("--max-domains", type=int, default=5000, help="Cap on domains to verify")
    args = parser.parse_args()

    # Introspection builds the form from argparse; no queries are sent.
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no queries sent", flush=True)
        return 0

    ip = args.ip
    sources = args.sources.split() if isinstance(args.sources, str) else args.sources
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    no_verify = args.no_verify

    # Strict IPv4 validation — inet_aton silently accepts short forms like
    # "1.2.3" and "127.1"; ipaddress.IPv4Address rejects them, matching the
    # manifest regex on the CLI path too.
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        emit({"type": "status", "message": f"Invalid IP: {ip}"})
        sys.exit(1)

    # The run must end at pct: 100 on every non-error return path.
    try:
        if "shodan" in sources and not shodan_key:
            sources = [s for s in sources if s != "shodan"]
            msg = "Shodan skipped: SHODAN_API_KEY not set"
            log(f"  {msg}")
            emit({"type": "status", "message": msg})

        log(f"Searching domains for IP: {ip}")
        emit({"type": "status", "message": f"Target: {ip}"})

        source_map = {
            "crtsh":        (fetch_crtsh,                     "crt.sh (certificate SAN)"),
            "hackertarget": (fetch_hackertarget,              "HackerTarget reverse IP"),
            "viewdns":      (fetch_viewdns,                   "ViewDNS reverse IP"),
            "shodan":       (lambda i: fetch_shodan(i, shodan_key), "Shodan host lookup"),
        }

        valid_sources = [s for s in sources if s in source_map]
        total_sources = len(valid_sources)

        if total_sources == 0:
            emit({"type": "status", "message": "No sources to query"})
            log("No sources to query.")
            return

        all_domains: set[str] = set()
        completed = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {}
            for key in valid_sources:
                fn, label = source_map[key]
                log(f"  [{label}] querying...")
                futures[pool.submit(fn, ip)] = label
            for future in concurrent.futures.as_completed(futures):
                label = futures[future]
                try:
                    raw = future.result()
                except Exception as e:
                    source_fail(label, e)
                    raw = set()
                found = clean(raw)
                log(f"  [{label}] {len(found)} domain(s)")
                all_domains |= found
                completed += 1
                emit({
                    "type": "progress",
                    "pct": (completed / total_sources) * 50,
                    "message": f"Querying {label}",
                })

        emit({"type": "progress", "pct": 50, "message": f"Found {len(all_domains)} unique domains"})
        log(f"\nTotal unique domains found: {len(all_domains)}")

        if not all_domains:
            emit({"type": "status", "message": "No domains found"})
            log("No domains found.")
            return

        output_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
        os.makedirs(output_dir, exist_ok=True)
        raw_path = os.path.join(output_dir, "domains_raw.json")
        with open(raw_path, "w") as f:
            json.dump(sorted(all_domains), f, indent=2)

        if no_verify:
            csv_path = os.path.join(output_dir, "domains_unverified.csv")
            with open(csv_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["domain"])
                for d in sorted(all_domains):
                    writer.writerow([d])
            emit({
                "type": "table",
                "columns": ["Domain"],
                "rows": [[d] for d in sorted(all_domains)],
            })
            emit({"type": "status", "message": f"{len(all_domains)} domains (unverified)"})
            return

        log("Verifying via DNS resolution...")
        emit({"type": "status", "message": "Verifying via DNS..."})

        csv_path = os.path.join(output_dir, "domains_verified.csv")
        result = verify_domains(all_domains, ip, args.workers, args.max_domains, csv_path)

        table_rows = []
        for d in result.confirmed:
            table_rows.append([d, ip, "confirmed"])
        for d, addrs in result.different:
            table_rows.append([d, ", ".join(addrs), "different"])
        for d in result.unresolved:
            table_rows.append([d, "", "unresolved"])

        log(f"\n  Confirmed on {ip}: {len(result.confirmed)}")
        log(f"  Different IP: {len(result.different)}")
        log(f"  Unresolved: {len(result.unresolved)}")

        emit({
            "type": "table",
            "columns": ["Domain", "Resolved IP", "Status"],
            "rows": table_rows,
        })
        emit({
            "type": "status",
            "message": f"Confirmed: {len(result.confirmed)} | Different: {len(result.different)} | Unresolved: {len(result.unresolved)}",
        })
        log("Done!")
    finally:
        emit({"type": "progress", "pct": 100, "message": "Done"})


if __name__ == "__main__":
    main()
