"""The checks — pure functions over collected facts, no I/O.

Mirrors ``security-headers``' model exactly, so the two reports read the
same way: one :class:`Finding` per aspect, a ``status`` (pass / warn /
fail), a ``severity`` weight toward the 0–100 score (0 = informational,
unscored), and a ``recommendation`` that is a config change, not a
lecture. The grade buckets and the pass=1.0 / warn=0.5 / fail=0 credit
live in :mod:`src.report`, identical to the sibling.

Fatal things weigh the most: an unverifiable chain or a hostname
mismatch (10) outranks an expiring certificate (8), which outranks a
deprecated protocol (8/6) or an accepted weak cipher (8); lifetime
length (2) is a nudge. "Cannot probe" is **never** scored — the local
OpenSSL sometimes refuses to offer TLS 1.0 client-side, and a verdict
the client couldn't test is a note, not a guess.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from src.certinfo import (
    ParsedCert,
    PublicKeyInfo,
    SignatureInfo,
    hostname_matches,
    parse_cert_fields,
    parse_public_key,
    parse_signature_alg,
)
from src.connect import Handshake

# Days-to-expiry thresholds: inside EXPIRY_FAIL_DAYS it is as good as
# expired (there is no sane renewal window left), inside EXPIRY_WARN_DAYS
# it needs scheduling now.
EXPIRY_FAIL_DAYS = 7
EXPIRY_WARN_DAYS = 30

# The public-trust validity cap, by issue date. Ballot 193 (March
# 2018) set 398 days; SC-081 shortens it further: 200 days for
# certificates issued from 2026-03-15, 100 from 2027-03-15, 47 from
# 2029-03-15. The cap applies to the *issue* date, so a 398-day
# certificate issued in early 2026 stays legal — the schedule, not
# a flat number, is the check.
LIFETIME_SCHEDULE = (
    (datetime(2029, 3, 15, tzinfo=timezone.utc), 47),
    (datetime(2027, 3, 15, tzinfo=timezone.utc), 100),
    (datetime(2026, 3, 15, tzinfo=timezone.utc), 200),
)
LEGACY_LIFETIME_DAYS = 398


def lifetime_limit(issued_on: datetime) -> int:
    """Maximum public-trust validity for a certificate issued on
    that date (the SC-081 schedule; 398 days before 2026-03-15)."""
    for since, limit in LIFETIME_SCHEDULE:
        if issued_on >= since:
            return limit
    return LEGACY_LIFETIME_DAYS


@dataclass
class Finding:
    """One check result: what was seen, how it scores, what to change."""
    check: str
    status: Literal["pass", "warn", "fail"]
    severity: float      # weight toward the score; 0 = informational, unscored
    detail: str          # what was actually observed, verbatim where possible
    recommendation: str  # the config change, ready to paste


@dataclass
class Facts:
    """Everything the connections learned, before any judgment."""
    host: str
    port: int
    collect: Handshake                 # connection 1: cert + negotiation
    trust: Handshake                   # connection 2: chain validation
    probes: dict[str, Handshake | None]   # 'TLS 1.0' … -> result, None = cannot probe
    weak: Handshake | None             # weak-cipher probe; None = skipped/unavailable
    cert_only: bool = False
    pq: dict | None = None             # post-quantum probe (src.postquantum)

    # Derived once, shared by several checks:
    parsed: ParsedCert | None = None
    pub_key: PublicKeyInfo | None = None
    signature: SignatureInfo | None = None
    hostname: tuple[bool, str, list[str]] | None = None   # (matched, how, sans)

    def derive(self) -> None:
        self.parsed = parse_cert_fields(self.collect.cert_der)
        self.pub_key = parse_public_key(self.collect.cert_der)
        self.signature = parse_signature_alg(self.collect.cert_der)
        self.hostname = hostname_matches(self.host, self.parsed)


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Certificate checks
# ---------------------------------------------------------------------------

def check_trust(facts: Facts) -> list[Finding]:
    """Does the chain validate against the local trust store?"""
    if facts.trust.ok:
        return [Finding("Chain of trust", "pass", 10,
                        "validates against the system trust store", "")]
    return [Finding(
        "Chain of trust", "fail", 10,
        facts.trust.error or "verification failed",
        "Install the full chain on the server (leaf + intermediates) — "
        "a missing intermediate breaks exactly the older clients that "
        "don't fetch it themselves; a self-signed cert must be issued "
        "by a CA your visitors already trust")]


def check_hostname(facts: Facts) -> list[Finding]:
    matched, how, _sans = facts.hostname or (False, "no certificate", [])
    if matched:
        return [Finding("Hostname match", "pass", 10, how, "")]
    return [Finding(
        "Hostname match", "fail", 10,
        how,
        "Reissue the certificate for the exact hostnames served — SANs "
        "must list every name the endpoint answers on")]


def check_validity(facts: Facts) -> list[Finding]:
    cert = facts.parsed
    if cert is None or cert.not_before is None or cert.not_after is None:
        return [Finding("Certificate validity", "warn", 8,
                        "validity dates unreadable from the certificate",
                        "Check the certificate with the issuer — its dates "
                        "could not be parsed")]
    now = _now()
    not_before, not_after = cert.not_before, cert.not_after
    if now < not_before:
        return [Finding("Certificate validity", "fail", 8,
                        f"not valid yet (starts {not_before:%Y-%m-%d %H:%M UTC})",
                        "The endpoint serves a certificate from the future — "
                        "check server time and which certificate was deployed")]
    days = (not_after - now).days
    if days < 0:
        return [Finding("Certificate validity", "fail", 8,
                        f"expired {-days} day(s) ago ({not_after:%Y-%m-%d})",
                        "Renew now — every visitor sees a certificate error")]
    if days <= EXPIRY_FAIL_DAYS:
        return [Finding("Certificate validity", "fail", 8,
                        f"expires in {days} day(s) ({not_after:%Y-%m-%d})",
                        "Renew immediately — inside a week, renewal races "
                        "propagation")]
    if days <= EXPIRY_WARN_DAYS:
        return [Finding("Certificate validity", "warn", 8,
                        f"expires in {days} day(s) ({not_after:%Y-%m-%d})",
                        "Schedule the renewal this week")]
    return [Finding("Certificate validity", "pass", 8,
                    f"expires in {days} day(s), on {not_after:%Y-%m-%d}", "")]


def check_lifetime(facts: Facts) -> list[Finding]:
    """The SC-081 schedule: the validity cap depends on the issue
    date, and short certificates carry a renewal-cadence verdict —
    the "will you manage this by hand" question the 47-day era
    makes unavoidable."""
    cert = facts.parsed
    if cert is None or cert.not_before is None or cert.not_after is None:
        return [Finding("Certificate lifetime", "pass", 0,
                        "validity dates unreadable", "")]
    days = (cert.not_after - cert.not_before).days
    limit = lifetime_limit(cert.not_before)
    findings: list[Finding] = []
    if days > limit:
        findings.append(Finding(
            "Certificate lifetime", "warn", 2,
            f"{days} days — over the {limit}-day limit for "
            f"certificates issued {cert.not_before:%Y-%m-%d} "
            f"(SC-081 schedule)",
            "A public CA cannot issue over the schedule — this is "
            "a private CA or a misissued certificate; check the "
            "issuer, and plan the shorter renewals the schedule "
            "forces"))
    else:
        findings.append(Finding("Certificate lifetime", "pass", 2,
                                f"{days} days (limit {limit} for "
                                f"issue date "
                                f"{cert.not_before:%Y-%m-%d})", ""))
    # The cadence verdict — informational, the honest answer to
    # "can a human keep this up".
    if days <= 47:
        findings.append(Finding(
            "Renewal cadence", "warn", 0,
            f"{days}-day certificate — a manual renewal every "
            "few weeks is not a process, it is an outage waiting "
            "to happen",
            "Automate: ACME (certbot/acme.sh), the load balancer's "
            "managed certificates, or the CDN's edge certificates "
            "— by the 2029 47-day norm, manual renewal is untenable"))
    elif days <= 100:
        findings.append(Finding(
            "Renewal cadence", "warn", 0,
            f"{days}-day certificate — roughly three manual "
            "renewals a year per name",
            "Automation recommended before the schedule tightens "
            "to 47 days in 2029 — ACME or managed certificates"))
    elif days <= 200:
        findings.append(Finding(
            "Renewal cadence", "pass", 0,
            f"{days}-day certificate — about two manual renewals "
            "a year; manageable by hand, automation still better",
            ""))
    return findings


def check_public_key(facts: Facts) -> list[Finding]:
    key = facts.pub_key
    if key is None or key.key_bits is None:
        return [Finding("Public key", "warn", 0,
                        f"{key.key_type if key else 'key'} — {key.note if key else 'unreadable'}"
                        " (not scored)",
                        "Parse the certificate with openssl x509 -text to "
                        "check the key by hand")]
    detail = f"{key.key_type} {key.key_bits}-bit" + (f", {key.curve}" if key.curve else "")
    if key.key_type == "RSA":
        if key.key_bits < 2048:
            return [Finding("Public key", "fail", 6, detail,
                            "Reissue with RSA-2048 minimum (3072 recommended) "
                            "or ECDSA P-256")]
        return [Finding("Public key", "pass", 6, detail, "")]
    if key.key_type == "EC":
        if key.key_bits < 256:
            return [Finding("Public key", "fail", 6, detail,
                            "Reissue with ECDSA P-256 minimum")]
        return [Finding("Public key", "pass", 6, detail, "")]
    if key.key_type == "Ed25519":
        return [Finding("Public key", "pass", 6, "Ed25519", "")]
    return [Finding("Public key", "warn", 0, f"{detail} (not scored)", "")]


def check_signature(facts: Facts) -> list[Finding]:
    sig = facts.signature
    if sig is None:
        return []
    if sig.hash_name in ("md5", "sha1"):
        return [Finding("Signature algorithm", "fail", 4,
                        f"{sig.label} — {sig.hash_name.upper()} is broken",
                        "Reissue the certificate (the signature is made by the "
                        "CA — a SHA-1/MD5 certificate is old or misissued)")]
    if sig.hash_name is None:
        return [Finding("Signature algorithm", "warn", 0,
                        f"{sig.label} (unrecognized — not scored)",
                        "Verify with openssl x509 -text | grep 'Signature "
                        "Algorithm'")]
    return [Finding("Signature algorithm", "pass", 4, sig.label, "")]


def check_no_sans(facts: Facts) -> list[Finding]:
    """No SANs at all is the legacy shape — informational, the hostname
    check carries the verdict."""
    cert = facts.parsed
    if cert is not None and not cert.has_sans:
        return [Finding("Certificate SANs", "warn", 0,
                        "certificate has no subjectAltName extension — "
                        "matching fell back to the CN",
                        "Reissue with explicit SANs; CN-only certificates are "
                        "ignored by modern clients")]
    return []


# ---------------------------------------------------------------------------
# Protocol and cipher checks (skipped whole in --cert-only mode)
# ---------------------------------------------------------------------------

def check_protocols(facts: Facts) -> list[Finding]:
    if facts.cert_only:
        return [Finding("Protocol probes", "pass", 0,
                        "skipped (--cert-only) — the grade covers the "
                        "certificate alone", "")]

    rows: list[tuple[str, int, bool, str, str]] = [
        ("TLS 1.0", 8, False, "offered — deprecated since 2021 (RFC 8996)", "refused"),
        ("TLS 1.1", 6, False, "offered — deprecated since 2021 (RFC 8996)", "refused"),
        ("TLS 1.2", 4, True, "offered", "not offered"),
        ("TLS 1.3", 4, True, "offered", "not offered"),
    ]
    findings: list[Finding] = []
    unprobeable: list[str] = []
    for name, weight, supported_good, note_supported, note_refused in rows:
        result = facts.probes.get(name)
        if result is None:
            unprobeable.append(name)
            continue
        if result.ok:
            status = "pass" if supported_good else "fail"
            finding = Finding(name, status, weight, note_supported, "")
        else:
            status = "warn" if supported_good else "pass"
            finding = Finding(name, status, weight, note_refused, "")
        if name == "TLS 1.2" and finding.status == "warn":
            finding.recommendation = (
                "TLS 1.3-only is the modern posture, but older clients "
                "(pre-2018 Android, older tooling) cannot connect — enable "
                "1.2 unless the client base is fully modern")
        findings.append(finding)

    if unprobeable:
        findings.append(Finding(
            "Protocol probes", "warn", 0,
            f"cannot probe {', '.join(unprobeable)} from this client (not "
            f"scored)",
            "The local OpenSSL refuses these versions client-side; verify "
            "with nmap --script ssl-enum-ciphers"))
    return findings


def check_weak_ciphers(facts: Facts) -> list[Finding]:
    if facts.cert_only:
        return []
    if facts.weak is None:
        return [Finding("Weak ciphers", "warn", 0,
                        "cannot probe from this client (not scored)",
                        "The local OpenSSL has no weak suites compiled in to "
                        "offer; verify with nmap --script ssl-enum-ciphers")]
    if facts.weak.ok:
        return [Finding("Weak ciphers", "fail", 8,
                        f"accepted {facts.weak.cipher}",
                        "Remove NULL/EXPORT/DES/RC4/IDEA and anonymous suites "
                        "from the server's cipher list (nginx: "
                        "ssl_ciphers …:!eNULL:!aNULL:!DES:!RC4:!3DES)")]
    return [Finding("Weak ciphers", "pass", 8, "refused", "")]


def check_postquantum(facts: Facts) -> list[Finding]:
    """The X25519MLKEM768 hybrid — informational by design: it is
    2026-forward readiness, not a vulnerability being graded today.
    "Not checked" (a client that cannot offer the group) is never
    allowed to read as "not supported"."""
    if facts.cert_only or not facts.pq:
        return []
    state, note = facts.pq.get("state", "not checked"), \
        facts.pq.get("note", "")
    if state == "supported":
        return [Finding("Post-quantum (X25519MLKEM768)", "pass", 0,
                        "negotiated — " + note, "")]
    if state == "not offered":
        return [Finding("Post-quantum (X25519MLKEM768)", "warn", 0,
                        note,
                        "Enable the hybrid key exchange on the "
                        "frontend when it supports it (nginx 1.28+ "
                        "with OpenSSL 3.5+, or the CDN's PQ toggle) "
                        "— informational today, table stakes in a "
                        "few years")]
    return [Finding("Post-quantum (X25519MLKEM768)", "warn", 0,
                    "not checked — " + note,
                    "Install OpenSSL ≥ 3.5 locally to probe the "
                    "hybrid group; the verdict stays empty rather "
                    "than guessed")]


def check_negotiated(facts: Facts) -> list[Finding]:
    """What a modern client actually gets — informational context."""
    c = facts.collect
    if c.ok and c.version and c.cipher:
        chain_note = ""
        if c.chain:
            chain_note = f", presented chain of {len(c.chain)} certificate(s)"
        return [Finding("Negotiated session", "pass", 0,
                        f"{c.version} · {c.cipher}{chain_note}", "")]
    return []


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

ALL_CHECKS = (
    check_trust,
    check_hostname,
    check_validity,
    check_lifetime,
    check_public_key,
    check_signature,
    check_no_sans,
    check_negotiated,
    check_protocols,
    check_weak_ciphers,
    check_postquantum,
)


def audit(facts: Facts) -> list[Finding]:
    """Every check, in report order. Pure — used by tests too."""
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(facts))
    return findings
