#!/usr/bin/env python3
"""tls-audit/main.py — grade a host's TLS layer with the ssl module.

Seven TLS connections, no HTTP requests: certificate collection, chain
validation against the system trust store, one pinned handshake per
protocol version (1.0–1.3), and a weak-cipher offer. Everything a
connection learns becomes a Finding with a status, a weight and a
config-change recommendation; the weighted result is a 0–100 score and
a letter grade, identical in shape to ``security-headers`` — the two
scripts audit the two layers of the same endpoint (transport here,
HTTP headers there).

Exit codes follow the collection philosophy — findings aren't failures:

* ``0`` — the endpoint was reached and audited. Grade F is a successful
  audit that found a broken TLS setup, not a script failure;
* ``1`` — the endpoint could not be reached at all (DNS, refused,
  timeout — the very first handshake failed), or artifacts can't be
  written;
* ``2`` — the target can't be parsed as host[:port].
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys

from src.checks import Facts, audit
from src.connect import (
    ProbeUnavailable,
    VERSION_PROBES,
    handshake,
    probe_trust,
    probe_supported_versions,
    probe_version,
    probe_weak_ciphers,
)
from src.report import STATUS_ICON, build_report, grade_for, score_findings
from src.target import TargetError, parse_target

DEFAULT_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TLS Audit — grade a host's certificate, protocols "
                    "and ciphers from a handful of TLS handshakes")
    parser.add_argument("--target", required=True,
                        help="host to audit: example.com, example.com:8443 "
                             "or https://example.com (port defaults to 443)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Per-connection timeout in seconds "
                             f"(default {DEFAULT_TIMEOUT})")
    parser.add_argument("--cert-only", action="store_true",
                        help="Certificate checks only — 2 connections "
                             "instead of 7; the grade covers the "
                             "certificate alone")
    return parser


# ---------------------------------------------------------------------------
# The seven connections, with progress
# ---------------------------------------------------------------------------

def run_probes(host: str, port: int, timeout: int, cert_only: bool):
    """Every connection the audit makes. Returns (facts, connections).

    ``connections`` counts what was actually attempted — probes the
    local OpenSSL cannot make don't count, and the report footer must
    not claim traffic that never happened.
    """
    total = 2 if cert_only else 7
    step = 40 / total
    done = 0

    def tick(message: str) -> None:
        nonlocal done
        print(f"→ {message}", flush=True)
        emit({"type": "progress", "pct": round(done * step),
              "message": message})
        done += 1

    tick(f"Connecting to {host}:{port}")
    collect = probe_supported_versions(host, port, timeout)
    tick("Validating the chain of trust")
    trust = probe_trust(host, port, timeout)

    probes: dict[str, object | None] = {}
    weak = None
    if not cert_only:
        for name, version, legacy in VERSION_PROBES:
            tick(f"Probing {name}")
            try:
                probes[name] = probe_version(host, port, version, legacy, timeout)
            except ProbeUnavailable:
                probes[name] = None

        # The weak-cipher offer rides on TLS 1.2 (set_ciphers can't
        # restrict TLS 1.3 suites from Python). A server without TLS 1.2
        # can't be probed this way — report that instead of a bogus
        # "refused".
        tls12 = probes.get("TLS 1.2")
        if tls12 is not None and not tls12.ok:
            tick("Weak-cipher probe (skipped — no TLS 1.2)")
            weak = None
        else:
            tick("Offering weak ciphers")
            try:
                weak = probe_weak_ciphers(host, port, timeout)
            except ProbeUnavailable:
                weak = None

    facts = Facts(host=host, port=port, collect=collect, trust=trust,
                  probes=probes, weak=weak, cert_only=cert_only)
    facts.derive()
    return facts, done


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii") if data else ""


def write_artifacts(facts: Facts, findings: list, score: int | None,
                    grade: str, report: str, connections: int) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return

    parsed = facts.parsed
    raw = {
        "target": {"host": facts.host, "port": facts.port},
        "connections": connections,
        "negotiated": {"version": facts.collect.version,
                       "cipher": facts.collect.cipher},
        "certificate": {
            "not_before": parsed.not_before.isoformat() if parsed and parsed.not_before else None,
            "not_after": parsed.not_after.isoformat() if parsed and parsed.not_after else None,
            "subject_cn": parsed.subject_cn if parsed else None,
            "issuer_cn": parsed.issuer_cn if parsed else None,
            "dns_sans": parsed.dns_sans if parsed else [],
            "ip_sans": parsed.ip_sans if parsed else [],
            "parse_notes": parsed.parse_notes if parsed else [],
        },
        "certificate_der": _b64(facts.collect.cert_der),
        "chain": [_b64(c) for c in facts.collect.chain],
        "public_key": {"key_type": facts.pub_key.key_type,
                       "key_bits": facts.pub_key.key_bits,
                       "curve": facts.pub_key.curve,
                       "note": facts.pub_key.note} if facts.pub_key else None,
        "signature": {"oid": facts.signature.oid,
                      "label": facts.signature.label} if facts.signature else None,
        "trust": {"ok": facts.trust.ok, "error": facts.trust.error},
        "protocol_probes": {name: {"ok": h.ok, "error": h.error,
                                   "version": h.version, "cipher": h.cipher}
                            for name, h in facts.probes.items()},
        "weak_cipher_probe": ({"ok": facts.weak.ok, "cipher": facts.weak.cipher,
                               "error": facts.weak.error}
                              if facts.weak is not None else None),
    }
    with open(os.path.join(out_dir, "tls_raw.json"), "w", encoding="utf-8") as fh:
        json.dump(raw, fh, indent=2, ensure_ascii=False)

    from dataclasses import asdict
    payload = {"score": score, "grade": grade,
               "findings": [asdict(f) for f in findings]}
    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no connection made", flush=True)
        return 0

    try:
        host, port = parse_target(args.target)
    except TargetError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    try:
        facts, connections = run_probes(host, port, args.timeout, args.cert_only)
    except OSError as exc:
        print(f"✗ {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1

    if not facts.collect.ok:
        # The endpoint answered nothing TLS-shaped — there is no audit
        # to grade, only the failure to report.
        message = facts.collect.error or "TLS handshake failed"
        print(f"✗ {message}", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Audit failed\n\n❌ **{message}** · _`{host}:{port}` did not "
              f"complete a TLS handshake_"})
        status(f"Failed: {message}")
        return 1

    emit({"type": "progress", "pct": 60, "message": "Analyzing the certificate"})
    findings = audit(facts)
    score = score_findings(findings)
    grade = grade_for(score)
    emit({"type": "progress", "pct": 80, "message": "Scoring"})

    emit({
        "type": "table",
        "columns": ["Check", "Status", "Detail", "Fix"],
        "rows": [[f.check, f"{STATUS_ICON[f.status]} {f.status}",
                  f.detail[:200], f.recommendation[:200]] for f in findings],
    })

    report = build_report(facts, findings, score, grade, connections)
    emit({"type": "markdown", "content": report})

    try:
        write_artifacts(facts, findings, score, grade, report, connections)
    except OSError as exc:
        print(f"✗ cannot write artifacts: {exc}", file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 100, "message": f"Grade {grade}"})
    status(f"Grade {grade} · score {score if score is not None else 'n/a'}")
    print(f"← Grade {grade} · score {score if score is not None else 'n/a'} "
          f"({connections} connection(s))", flush=True)

    # The handshake happened, so the audit succeeded — an F is a
    # successful audit that found a broken endpoint, not a failure.
    return 0


if __name__ == "__main__":
    sys.exit(main())
