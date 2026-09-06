#!/usr/bin/env python3
"""port-check/main.py — which ports answer on a host you own.

A **TCP connect scan** — the second deliberate exception to the
collection's passive philosophy (after [Load Test](../load-test)) and
therefore under the same contract: **without the "I own this target"
confirmation the run refuses to start.** A port scan of a host you
don't control is reconnaissance for an attack, whatever the intent.
Even on your own servers, tell your host/ISP what you're doing: a
scan looks exactly like the first minutes of a real intrusion.

What it does, honestly:

- resolves the target to its IPv4 addresses (up to 4) and scans each;
- **Common set** (default): ~110 well-known service ports — web, mail,
  databases, remote access, admin panels, the dev-tooling classics;
  **Custom**: your `80,443,8000-8100` spec; **Full**: all 65535
  (minutes, not seconds);
- on every open port: **banner grab** — read the greeting, and send an
  HTTP HEAD where nothing greets — then a best-effort service guess
  (SSH, HTTP, SMTP, FTP, MySQL, RDP, VNC…);
- the report groups the findings by exposure: remote access, databases
  (must not face the internet), admin/dev panels, mail, web.

**TCP only, and connect-only.** No UDP (unreliable to scan honestly),
no exploit payloads, no guesses past the banner. TLS ports (443,
8443…) show "no banner (TLS?)" — the certificate is
[TLS Audit](../tls-audit)'s job, not duplicated here.

Stdlib only: sockets, threads, and patience.

Exit codes: 0 = the scan ran (open ports are findings), 1 = the
target doesn't resolve (nothing to scan), 2 = bad arguments —
including a missing ownership confirmation.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urlsplit

USER_AGENT_PROBE = "HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: pyshell-port-check\r\n\r\n"

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
# The curated common set (pure data)
# ---------------------------------------------------------------------------

COMMON_PORTS: dict[int, str] = {
    # web + hosting panels
    80: "HTTP", 443: "HTTPS", 81: "HTTP alt", 591: "HTTP alt",
    3000: "dev server (Grafana/Node)", 5000: "dev server (Flask)",
    8000: "HTTP alt", 8008: "HTTP alt", 8009: "HTTP alt",
    8080: "HTTP proxy/alt", 8081: "HTTP alt", 8088: "HTTP alt",
    8443: "HTTPS alt", 8888: "HTTP alt (Jupyter?)", 9000: "HTTP alt",
    9090: "Prometheus", 5601: "Kibana", 9200: "Elasticsearch",
    2082: "cPanel", 2083: "cPanel (SSL)", 2086: "WHM",
    2087: "WHM (SSL)", 2095: "webmail", 2096: "webmail (SSL)",
    10000: "Webmin/Virtualmin", 7080: "HTTP alt",
    2222: "SSH alt", 9080: "HTTP alt", 4443: "HTTP alt",
    # mail
    25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS",
    587: "SMTP submission", 993: "IMAPS", 995: "POP3S",
    # remote access
    22: "SSH", 23: "Telnet", 512: "rexec", 513: "rlogin",
    514: "rsh/syslog", 3389: "RDP", 5900: "VNC", 5901: "VNC",
    5902: "VNC", 5985: "WinRM", 5986: "WinRM (SSL)",
    5555: "ADB (Android debug!)",
    # file sharing / transfer
    20: "FTP data", 21: "FTP", 2121: "FTP alt", 69: "TFTP (UDP)",
    139: "NetBIOS", 445: "SMB", 873: "rsync", 2049: "NFS", 548: "AFP",
    3260: "iSCSI",
    # databases & caches
    1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL/MariaDB",
    5432: "PostgreSQL", 6379: "Redis", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 5984: "CouchDB",
    7000: "Cassandra", 7001: "Cassandra", 9200: "Elasticsearch",
    9300: "Elasticsearch transport", 7474: "Neo4j HTTP",
    7687: "Neo4j Bolt", 50000: "SAP/DB2",
    # admin / orchestration / dev tooling
    2181: "ZooKeeper", 2375: "Docker API (open!)",
    2376: "Docker API TLS", 2379: "etcd", 2380: "etcd (peer)",
    4848: "GlassFish admin", 6443: "Kubernetes API",
    10250: "Kubernetes kubelet", 10255: "kubelet (read-only)",
    7077: "Portainer?", 9418: "git daemon",
    3128: "Squid proxy", 1080: "SOCKS proxy",
    8500: "Consul", 8140: "Puppet", 8089: "Splunk",
    9001: "Supervisor/Tor control", 15672: "RabbitMQ management",
    4369: "RabbitMQ epmd", 5672: "RabbitMQ AMQP",
    1099: "Java RMI", 10050: "Zabbix agent", 10051: "Zabbix server",
    9100: "JetDirect printer / node_exporter",
    # directory & misc services
    53: "DNS", 389: "LDAP", 636: "LDAPS", 111: "rpcbind",
    113: "ident", 123: "NTP (UDP)", 161: "SNMP (UDP)", 554: "RTSP",
    1883: "MQTT", 631: "IPP/CUPS", 1723: "PPTP VPN",
    502: "Modbus", 6667: "IRC", 5222: "XMPP", 5269: "XMPP server",
}

# Ports where a plain-TCP banner grab usually yields nothing because
# the first bytes are TLS — said so instead of guessed at.
TLS_PORTS = {443, 465, 587, 636, 993, 995, 2087, 2096, 2376, 8443,
             7001, 6443}

# Report groupings: what an open port of this family means.
RISK_GROUPS = {
    "remote access": [22, 23, 512, 513, 514, 3389, 5900, 5901, 5902,
                      5985, 5986, 5555, 2222],
    "databases & caches": [1433, 1521, 3306, 5432, 6379, 11211,
                           27017, 27018, 5984, 7000, 7001, 9200,
                           9300, 7474, 7687, 50000],
    "admin / dev tooling": [2375, 2376, 2379, 2380, 4848, 6443, 10250,
                            10255, 2181, 7077, 9000, 9090, 5601, 10000,
                            3000, 5000, 8888, 9418, 8500, 8140, 8089,
                            9001, 15672, 4369, 5672, 1099, 10050,
                            10051, 9100],
    "file sharing & transfer": [20, 21, 69, 139, 445, 873, 2049, 548,
                                2121, 3260],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "web & panels": [80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095,
                     2096, 7080, 8000, 8008, 8009, 8080, 8081, 8088,
                     8443, 9080, 4443, 3128, 1080],
}

GROUP_BY_PORT = {port: group
                 for group, ports in RISK_GROUPS.items()
                 for port in ports}


def group_for_port(port: int) -> str:
    return GROUP_BY_PORT.get(port, "other")


# ---------------------------------------------------------------------------
# Port-spec parsing (pure)
# ---------------------------------------------------------------------------

def parse_port_spec(spec: str, port_set: str) -> tuple[list[int] | None, str]:
    """The port list for the chosen set. (ports, error) — the error is
    human, for exit 2."""
    if port_set == "full":
        return list(range(1, 65536)), ""
    if port_set == "common":
        return sorted(COMMON_PORTS), ""
    # custom
    spec = (spec or "").strip()
    if not spec:
        return None, "the custom set needs --custom-ports (e.g. 80,443,8000-8100)"
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            return None, f"empty part in {spec!r}"
        if chunk.isdigit():
            start = end = int(chunk)
        elif "-" in chunk:
            left, _, right = chunk.partition("-")
            if not left.isdigit() or not right.isdigit():
                return None, f"bad range {chunk!r}"
            start, end = int(left), int(right)
        else:
            return None, f"bad port {chunk!r}"
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            return None, f"{chunk!r}: ports are 1–65535"
        if start > end:
            return None, f"inverted range {chunk!r}"
        if end - start >= 65534:
            return None, "that range is the whole range — use --port-set full"
        out.update(range(start, end + 1))
    if not out:
        return None, f"no ports selected by {spec!r}"
    return sorted(out), ""


# ---------------------------------------------------------------------------
# Banner grabbing & classification (the guess is honest: best-effort)
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    state: str                 # open | closed | filtered
    service: str = ""          # curated name for the port
    banner: str = ""           # first bytes, printable-trimmed
    service_guess: str = ""    # from the banner
    group: str = ""


def classify_banner(banner: str) -> str:
    """Best-effort service name from the greeting bytes. Empty when
    nothing recognizable — never a confident invention."""
    low = banner.lower()
    if banner.startswith("SSH-"):
        return "SSH"
    if banner.startswith("HTTP/1"):
        return "HTTP"
    if "esmtp" in low or banner.startswith("220 ") and "smtp" in low:
        return "SMTP"
    if banner.startswith("+OK") or "pop3" in low:
        return "POP3"
    if banner.startswith("* OK") or "imap" in low:
        return "IMAP"
    if "mysql" in low or "mariadb" in low:
        return "MySQL/MariaDB"
    if banner.startswith("RFB "):
        return "VNC"
    if banner.startswith("220") and ("ftp" in low or "filezilla" in low
                                     or "vsftpd" in low or "proftpd" in low):
        return "FTP"
    if banner.startswith("\x03\x00\x00"):
        return "RDP"
    if "redis" in low:
        return "Redis"
    if "nginx" in low or "apache" in low:
        return "HTTP"
    if "mongodb" in low:
        return "MongoDB"
    if "postgres" in low:
        return "PostgreSQL"
    if "refused" in low or "denied" in low:
        return ""
    return ""


def grab_banner(sock: socket.socket, host: str, port: int,
                timeout: float) -> str:
    """Read the greeting; if nothing comes (HTTP servers wait for a
    request), send a minimal HEAD and read again. Returns printable
    bytes or ''."""
    sock.settimeout(timeout)
    banner = b""
    try:
        banner = sock.recv(128)
    except (socket.timeout, OSError):
        pass
    if not banner:
        try:
            sock.sendall(USER_AGENT_PROBE.format(host=host).encode())
            banner = sock.recv(128)
        except (socket.timeout, OSError):
            pass
    text = banner.decode("utf-8", "replace")
    # Keep it printable and single-line for the table/JSON.
    text = "".join(c if c.isprintable() or c in "\t" else "·"
                   for c in text).strip()
    return text.splitlines()[0][:100] if text else ""


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------

def scan_port(ip: str, port: int, timeout: float, banners: bool,
              host: str) -> PortResult:
    """One TCP connect probe. Never raises; filtered vs closed is
    distinguished where the OS allows it (refused = closed, drop/
    timeout = filtered)."""
    result = PortResult(port=port, state="closed",
                        service=COMMON_PORTS.get(port, ""),
                        group=group_for_port(port))
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return result                      # closed — an honest RST
    except (socket.timeout, TimeoutError):
        result.state = "filtered"          # dropped — a firewall ate it
        return result
    except OSError:
        result.state = "filtered"          # unreachable/network error
        return result
    with sock:
        result.state = "open"
        if banners:
            result.banner = grab_banner(sock, host, port, timeout)
            result.service_guess = classify_banner(result.banner)
            if not result.banner and not result.service_guess \
                    and port in TLS_PORTS:
                result.service_guess = "TLS? (no plain banner)"
    return result


def scan_ports(ip: str, host: str, ports: list[int], timeout: float,
               workers: int, banners: bool,
               progress) -> list[PortResult]:
    """The whole list against one IP, results sorted by port."""
    results: list[PortResult] = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_port, ip, port, timeout, banners,
                               host): port for port in ports}
        for future in as_completed(futures):
            done += 1
            if done % max(1, len(ports) // 100) == 0 or done == len(ports):
                open_n = sum(1 for r in results if r.state == "open")
                progress(int(100 * done / len(ports)),
                         f"{done}/{len(ports)} · {open_n} open")
            try:
                results.append(future.result())
            except Exception:  # a worker crash is a fact, not a death
                results.append(PortResult(port=futures[future],
                                          state="filtered"))
    results.sort(key=lambda r: r.port)
    return results


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def resolve_target(raw: str) -> tuple[list[str], str | None]:
    """(ipv4s, error). A URL, a bare host, or a bare IPv4 all work; up
    to 4 IPv4 addresses (round-robin hosts). The error string decides
    the exit code: a host that *cannot* be a hostname is a bad
    argument, a host that merely doesn't resolve is exit 1."""
    text = (raw or "").strip()
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return [], f"{raw!r} is not a parsable URL"
    if not text:
        return [], "the target is empty"
    if not HOSTNAME_RE.match(text):
        return [], f"{text!r} is not a valid hostname or IP"
    try:
        infos = socket.getaddrinfo(text, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
    except socket.gaierror:
        return [], f"{text!r} does not resolve (or no IPv4 record)"
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        return [], f"{text!r} has no IPv4 address"
    return ips[:4], None


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_table_event(per_ip: dict[str, list[PortResult]]) -> dict:
    rows = []
    for ip, results in per_ip.items():
        for r in results:
            if r.state != "open":
                continue
            name = r.service_guess or r.service or "?"
            rows.append([ip, r.port, name, r.banner or "—",
                         r.group or "—"])
    return {
        "type": "table",
        "columns": ["IP", "Port", "Service", "Banner", "Exposure group"],
        "rows": rows,
    }


def build_markdown(target: str, per_ip: dict[str, list[PortResult]],
                   scanned: int) -> str:
    all_open = [r for results in per_ip.values()
                for r in results if r.state == "open"]
    risky = [r for r in all_open
             if r.group in ("remote access", "databases & caches",
                            "admin / dev tooling", "file sharing & transfer")]
    head = f"## {'🔴' if risky else '🟢'} {len(all_open)} open port(s) " \
           f"over {scanned:,} scanned"
    lines = [head, "", f"`{target}` · "
             + ", ".join(f"{ip} ({sum(1 for r in rs if r.state == 'open')}"
                         f" open)" for ip, rs in per_ip.items()), ""]

    if all_open:
        lines += ["| Port | Service | Banner | Exposure group |",
                  "| --- | --- | --- | --- |"]
        for r in sorted(all_open, key=lambda r: (r.group != "remote access",
                                                 r.group, r.port)):
            name = r.service_guess or r.service or "?"
            lines.append(f"| {r.port} | {name} | "
                         f"{(r.banner or '—')[:60]} | {r.group or '—'} |")
        lines.append("")

    if risky:
        lines.append("**The attack surface worth a second look**")
        lines.append("")
        by_group: dict[str, list[PortResult]] = {}
        for r in risky:
            by_group.setdefault(r.group, []).append(r)
        for group, rows in by_group.items():
            ports = ", ".join(str(r.port) for r in rows)
            lines.append(f"- **{group}**: {ports}")
        lines += ["",
                  "_Databases, caches, remote access and admin panels have "
                  "no business facing the public internet — bind them to "
                  "localhost or the private network, and let the firewall "
                  "say no to the rest. [SSH Log Check](../ssh-log-check) "
                  "tells you what port 22 is already absorbing; "
                  "[Mail Probe](../mail-probe) grades the mail ports; "
                  "[TLS Audit](../tls-audit) and [Security Headers]"
                  "(../security-headers) grade the web ones._", ""]
    else:
        if all_open:
            lines.append("_Nothing in the risky families is listening "
                         "publicly — the open ports are the ordinary web/"
                         "mail set._")
            lines.append("")

    filtered = sum(1 for results in per_ip.values()
                   for r in results if r.state == "filtered")
    if filtered:
        lines.append(f"_{filtered:,} port(s) filtered (no answer at all — "
                     "a firewall dropping, the normal good case)._")
        lines.append("")

    lines.append("_TCP connect scan of a host you own; banners read, "
                 "an HTTP HEAD sent where nothing greeted. No UDP, no "
                 "exploit payloads, nothing beyond the banner._")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(target: str, per_ip: dict[str, list[PortResult]],
                    scanned: int, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "target": target,
        "scanned_ports": scanned,
        "ips": {
            ip: [{"port": r.port, "state": r.state,
                  "service": r.service, "banner": r.banner,
                  "service_guess": r.service_guess, "group": r.group}
                 for r in results if r.state == "open"]
            for ip, results in per_ip.items()
        },
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Port Check — TCP port scan of a host you own: "
                    "common services, your spec, or the full range")
    parser.add_argument("--target", required=True,
                        help="host or URL (yours)")
    parser.add_argument("--i-own-this-target", action="store_true",
                        help="the ownership contract — without it the "
                             "run refuses to start")
    parser.add_argument("--port-set", choices=["common", "custom", "full"],
                        default="common",
                        help="which ports to scan (default common)")
    parser.add_argument("--custom-ports", default="",
                        help="ports/ranges for the custom set: "
                             "80,443,8000-8100")
    parser.add_argument("--banners", action=argparse.BooleanOptionalAction,
                        default=True,
                        help="grab banners on open ports (default on)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="per-port timeout in seconds (default 2)")
    parser.add_argument("--workers", type=int, default=300,
                        help="ports probed in parallel (default 300)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no ports are probed", flush=True)
        return 0

    if not args.i_own_this_target:
        print("✗ this script only scans hosts you own. Re-run with "
              "--i-own-this-target (the form checkbox) to confirm — a "
              "port scan of a host you don't control is reconnaissance "
              "for an attack, whatever the intent.",
              file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Refused\n\n⛔ This script probes a host's ports. It "
              "only runs against a target you own or are explicitly "
              "permitted to scan — confirm with **I own this target** "
              "and re-run."})
        return 2

    ips, problem = resolve_target(args.target)
    if problem:
        print(f"✗ {problem}", file=sys.stderr, flush=True)
        return 1 if "does not resolve" in problem else 2

    ports, problem = parse_port_spec(args.custom_ports, args.port_set)
    if problem:
        print(f"✗ {problem}", file=sys.stderr, flush=True)
        return 2

    host = (args.target if "://" not in args.target
            else urlsplit(args.target).hostname or args.target)
    log(f"Scanning {len(ports):,} port(s) on {', '.join(ips)}"
        f" ({args.port_set} set, {args.workers} workers, "
        f"{args.timeout}s per port)")
    status(f"{len(ports):,} ports on {len(ips)} IP(s)")

    per_ip: dict[str, list[PortResult]] = {}
    for i, ip in enumerate(ips, 1):
        status(f"Scanning {ip} ({i}/{len(ips)})")
        results = scan_ports(
            ip, host, ports, args.timeout, args.workers, args.banners,
            progress=lambda pct, msg, _i=i, _n=len(ips): emit(
                {"type": "progress",
                 "pct": int((( _i - 1) + pct / 100) * 100 / _n),
                 "message": f"{ip}: {msg}"}))
        per_ip[ip] = results
        open_n = sum(1 for r in results if r.state == "open")
        log(f"  {ip}: {open_n} open, "
            f"{sum(1 for r in results if r.state == 'filtered'):,} filtered")

    report = build_markdown(args.target, per_ip, len(ports))
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(per_ip))
    emit({"type": "markdown", "content": report})
    write_artifacts(args.target, per_ip, len(ports), report)

    total_open = sum(1 for rs in per_ip.values()
                     for r in rs if r.state == "open")
    summary = f"{total_open} open over {len(ports):,} scanned on " \
              f"{len(ips)} IP(s)"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
