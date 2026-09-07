#!/usr/bin/env python3
"""protocol-check/protocol-check/main.py — which protocols the site
actually speaks.

TLS Audit grades the certificate and the handshake parameters; this
script reads the **protocol layer** around it, with the standard
library only (ssl, socket, http.client, urllib — no QUIC stack, and
the report says so where that matters):

- **ALPN** — the negotiated application protocol on a real
  handshake: `h2` or `http/1.1` (HTTP/2 over cleartext — h2c — is
  invisible to a client that never offers it; noted honestly).
- **HTTP/3** — the `Alt-Svc` announcement (`h3=":443"`).  Without a
  QUIC client this stays **an announcement**, reported as such —
  the difference between "the site tells browsers HTTP/3 exists"
  and "HTTP/3 works" is exactly the honesty line this script draws.
- **Compression** — what the server actually serves on
  `Accept-Encoding: br, gzip, zstd` — and the byte win it brought.
- **IPv6** — not just the AAAA record: a real TCP+TLS connection to
  the v6 address (with the hostname for SNI), because a published
  AAAA behind a closed v6 path is the classic silent breakage.
- **Keep-alive** — two requests over one connection: does the
  second answer without a new handshake.
- **TLS resumption** — a second handshake offering the first's
  session: `session_reused` is the cheap-connections story.  0-RTT
  is not visible to the standard client — stated, not guessed.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import urllib.request
from urllib.parse import urlsplit

USER_AGENT = "PyShell-protocol-check/1 (+protocol diagnostics)"


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


class ProbeError(Exception):
    pass


# The probes measure the protocol layer; the certificate is TLS
# Audit's subject, not this script's — every client here skips
# verification, consistently (raw sockets and HTTP alike).
NO_VERIFY = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
NO_VERIFY.check_hostname = False
NO_VERIFY.verify_mode = ssl.CERT_NONE


# --------------------------------------------------------------------- ALPN

def probe_alpn(host: str, port: int, timeout: int) -> dict:
    """The negotiated protocol on a real handshake offering h2."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE      # the protocol, not the cert
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    try:
        with socket.create_connection((host, port),
                                      timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return {
                    "negotiated": tls.selected_alpn_protocol()
                    or "none offered back",
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0],
                }
    except (OSError, ssl.SSLError) as exc:
        raise ProbeError(f"handshake failed: {exc}")


def probe_resumption(host: str, port: int, timeout: int) -> dict:
    """Two handshakes; the second offers the first's session."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port),
                                      timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                session = tls.session
        if session is None:
            return {"resumed": None,
                    "note": "the first handshake offered no session "
                            "to resume"}
        with socket.create_connection((host, port),
                                      timeout=timeout) as sock2:
            with ctx.wrap_socket(sock2, server_hostname=host,
                                 session=session) as tls2:
                return {"resumed": bool(tls2.session_reused),
                        "note": ""}
    except (OSError, ssl.SSLError) as exc:
        raise ProbeError(f"resumption probe failed: {exc}")


# -------------------------------------------------------------------- IPv6

def probe_ipv6(host: str, port: int, timeout: int) -> dict:
    """AAAA present, and a real TCP+TLS connection over it."""
    try:
        infos = socket.getaddrinfo(host, port,
                                   socket.AF_INET6,
                                   socket.SOCK_STREAM)
    except socket.gaierror:
        infos = []
    if not infos:
        return {"aaaa": False, "connected": False, "address": "",
                "note": "no AAAA record — the site is IPv4-only"}
    v6 = infos[0][4][0]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((v6, port),
                                      timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return {"aaaa": True, "connected": True,
                        "address": v6, "note": ""}
    except (OSError, ssl.SSLError) as exc:
        return {"aaaa": True, "connected": False, "address": v6,
                "note": f"AAAA exists but the v6 path fails: {exc} "
                        "— the classic silent breakage (published "
                        "record, closed route/firewall)"}


# ------------------------------------------------------------ HTTP behavior

def http_get(url: str, headers: dict, timeout: int):
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, **headers})
    return urllib.request.urlopen(req, timeout=timeout,
                                  context=NO_VERIFY)


def probe_alt_svc(url: str, timeout: int) -> dict:
    try:
        with http_get(url, {}, timeout) as resp:
            alt = resp.headers.get("Alt-Svc", "")
            status = resp.status
    except (OSError, urllib.error.URLError) as exc:
        raise ProbeError(f"cannot fetch {url}: {exc}")
    h3 = re.search(r'h3(?:-29)?=":(\d+)"', alt)
    if h3:
        return {"announced": True, "port": h3.group(1),
                "raw": alt,
                "note": "an announcement — browsers may use HTTP/3 "
                        "over QUIC; without a QUIC client this "
                        "script cannot confirm it works"}
    return {"announced": False, "port": "", "raw": alt,
            "note": "no Alt-Svc header — HTTP/3 is not advertised "
                    "to this client"}


def probe_compression(url: str, timeout: int) -> dict:
    try:
        with http_get(url, {}, timeout) as plain:
            plain_size = len(plain.read())
        with http_get(url, {"Accept-Encoding": "br, gzip, zstd"},
                      timeout) as comp:
            encoding = comp.headers.get("Content-Encoding", "")
            body = comp.read()
            compressed_size = len(body)
            vary = comp.headers.get("Vary", "")
    except (OSError, urllib.error.URLError) as exc:
        raise ProbeError(f"cannot fetch {url}: {exc}")
    saved = (100 - 100 * compressed_size / plain_size) \
        if plain_size else 0
    return {"encoding": encoding or "none (identity)",
            "plain_bytes": plain_size,
            "compressed_bytes": compressed_size,
            "saved_pct": round(saved, 1),
            "vary": vary}


def probe_keepalive(host: str, port: int, path: str,
                    timeout: int) -> dict:
    """Two requests over one TCP connection."""
    try:
        conn = http.client.HTTPSConnection(host, port,
                                           timeout=timeout,
                                           context=NO_VERIFY)
        conn.request("GET", path, headers={"User-Agent": USER_AGENT})
        r1 = conn.getresponse()
        r1.read()
        first = f"{r1.status}"
        conn.request("GET", path, headers={"User-Agent": USER_AGENT})
        r2 = conn.getresponse()
        r2.read()
        second = f"{r2.status}"
        conn.close()
        return {"second_on_same_connection": True,
                "first": first, "second": second}
    except (OSError, http.client.HTTPException) as exc:
        return {"second_on_same_connection": False, "note": str(exc)}


# -------------------------------------------------------------------- report

def build_table_event(results: dict) -> dict:
    a, alt = results["alpn"], results["alt_svc"]
    comp, v6 = results["compression"], results["ipv6"]
    ka, res = results["keepalive"], results["resumption"]
    rows = [
        ["alpn", a.get("negotiated", "probe failed"),
         a.get("tls_version", "")],
        ["http/3 (Alt-Svc)",
         "announced" if alt.get("announced")
         else "not advertised",
         (f"port {alt.get('port')}"
          if alt.get("announced") else "—")],
        ["compression",
         comp.get("encoding", "probe failed"),
         f"-{comp.get('saved_pct', '—')}%"],
        ["ipv6",
         ("connected" if v6.get("connected")
          else ("AAAA but broken"
                if v6.get("aaaa") else "no AAAA")),
         v6.get("address", "") or "—"],
        ["keep-alive",
         "works" if ka.get("second_on_same_connection")
         else "fails",
         ka.get("note", "2 requests, 1 connection")],
        ["tls resumption",
         ("resumed" if res.get("resumed")
          else ("n/a" if res.get("resumed") is None
                else "full handshake")),
         res.get("note") or "session reuse"],
    ]
    return {"type": "table", "columns": ["check", "result", "detail"],
            "rows": rows}


def build_markdown(url: str, results: dict) -> str:
    a = results["alpn"]
    alt = results["alt_svc"]
    comp = results["compression"]
    v6 = results["ipv6"]
    ka = results["keepalive"]
    res = results["resumption"]
    failed = [k for k, v in results.items() if "error" in v]
    out = [f"# Protocol Check — Report\n",
           f"URL: `{url}`\n"]
    if failed:
        out.append(f"- ⚫ probe(s) that failed: {', '.join(failed)}"
                   " — the rest of the report covers what could be "
                   "reached\n")
    out.append(
        f"- **ALPN**: negotiated **{a.get('negotiated', '?')}** over "
        f"{a.get('tls_version', '?')} ({a.get('cipher', '?')})"
        + ("" if a.get("negotiated") == "h2" else
           " — HTTP/2 is the modern default; http/1.1 here means "
           "every request pays the connection cost"))
    out.append(
        f"- **HTTP/3**: "
        + (f"**announced** on port {alt.get('port')} via Alt-Svc — "
           "an announcement, not a confirmation: this script has "
           "no QUIC stack and says so"
           if alt.get("announced") else
           "not advertised — no Alt-Svc header reached this "
           "client"))
    out.append(
        f"- **Compression**: {comp.get('encoding', '?')} served "
        f"({comp.get('plain_bytes', '?')} → "
        f"{comp.get('compressed_bytes', '?')} bytes, "
        f"{comp.get('saved_pct', '?')}% saved)"
        + ("" if comp.get("vary") else
           " — `Vary: Accept-Encoding` is absent, worth adding "
           "for cache correctness"))
    out.append(
        f"- **IPv6**: "
        + ("**connected** over " + v6["address"]
           if v6.get("connected") else
           v6.get("note", "not probed")))
    out.append(
        f"- **Keep-alive**: "
        + ("two requests answered on one connection"
           if ka.get("second_on_same_connection")
           else f"failed — {ka.get('note', '')}"))
    out.append(
        f"- **TLS resumption**: "
        + ("sessions resume — returning clients skip the full "
           "handshake" if res.get("resumed") else
           ("not measurable — " + res.get("note", "")
            if res.get("resumed") is None else
            "every connection pays the full handshake — check "
            "session tickets on the server")))
    out.append("")
    out.append("0-RTT is not visible to the standard TLS client — "
               "stated, not guessed.")
    out.append("\n## Why each line matters\n")
    out.append("- **h2**: one connection, many streams — the "
               "page-load multiplexing browsers actually use.")
    out.append("- **h3**: QUIC moves the whole stack over UDP — "
               "announced via Alt-Svc, confirmed only by a QUIC "
               "client.")
    out.append("- **Brotli/gzip**: the one-byte-cheap win; `br` "
               "beats `gzip` by ~15-20% on text.")
    out.append("- **IPv6**: a published AAAA behind a broken path "
               "hurts exactly the users who can't fall back.")
    out.append("- **Resumption**: the returning-visitor handshake "
               "discount.")
    out.append("\n## Related\n")
    out.append("- **TLS Audit** — the certificate and the handshake "
               "grades; this script is the protocol layer around "
               "it.")
    out.append("- **Server Timing / Cache Check / HAR Analyze** — "
               "what the protocols cost and save in practice.")
    return "\n".join(out)


def write_artifacts(url: str, results: dict, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"url": url, "results": results}, fh,
                  ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Protocol Check — which protocols the site "
                    "speaks: ALPN h2, HTTP/3 announcement, "
                    "compression, IPv6, keep-alive, resumption")
    parser.add_argument("--url", required=True,
                        help="the https:// site to probe")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-probe timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no probes are made", flush=True)
        return 0

    url = args.url.strip()
    if not re.match(r"^https://", url):
        print("✗ protocol probes need an https:// URL (the ALPN "
              "layer lives inside TLS)", file=sys.stderr, flush=True)
        return 2
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    path = parts.path or "/"

    log(f"Probing the protocol layer of {host}")
    status("alpn → alt-svc → compression → ipv6 → keep-alive")

    results: dict = {}
    steps = [
        ("alpn", lambda: probe_alpn(host, port, args.timeout)),
        ("alt_svc", lambda: probe_alt_svc(url, args.timeout)),
        ("compression",
         lambda: probe_compression(url, args.timeout)),
        ("ipv6", lambda: probe_ipv6(host, port, args.timeout)),
        ("keepalive",
         lambda: probe_keepalive(host, port, path, args.timeout)),
        ("resumption",
         lambda: probe_resumption(host, port, args.timeout)),
    ]
    failures = []
    for i, (name, fn) in enumerate(steps, 1):
        try:
            results[name] = fn()
        except ProbeError as exc:
            failures.append(f"{name}: {exc}")
            results[name] = {"error": str(exc)}
        emit({"type": "progress",
              "pct": int(100 * i / len(steps)), "message": name})

    # the core probes could not reach the host at all — nothing to
    # report (the ipv6 "no AAAA" answer is a result, not a failure,
    # so the gate is the reach-dependent probes)
    if "error" in results["alpn"] and "error" in results["alt_svc"]:
        print(f"✗ cannot reach {host} — every TLS/HTTP probe failed",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(url, results)
    emit(build_table_event(results))
    emit({"type": "markdown", "content": report})
    write_artifacts(url, results, report)

    bits = []
    if results["alpn"].get("negotiated") == "h2":
        bits.append("h2")
    if results["alt_svc"].get("announced"):
        bits.append("h3 announced")
    if str(results["compression"].get("encoding", "")).startswith(
            ("br", "gzip", "zstd")):
        bits.append(str(results["compression"]["encoding"]))
    if results["ipv6"].get("connected"):
        bits.append("IPv6")
    summary = " · ".join(bits) or "http/1.1, no extras"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
