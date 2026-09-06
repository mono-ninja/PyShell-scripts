"""src/smtp_probe.py — one MX host, port 25, politely.

The sequence per host (one connection when everything works):

    connect → banner → EHLO → capabilities
           → STARTTLS (if offered) → TLS facts + certificate
           → EHLO again → [relay probe if opted in] → QUIT

**No mail is ever sent.** The relay probe stops before DATA — the
verdict is the RCPT answer for an external recipient, nothing more.

smtplib verifies nothing by default; this probe does it in two steps:
STARTTLS with a verifying context first (a bad certificate is a
finding, not a crash — reported and retried unverified so the rest of
the handshake's facts still come back), the way an operator would.
"""
from __future__ import annotations

import smtplib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

PROBE_EHLO_NAME = "probe.pyshell.local"
# The external recipient for the relay probe: a reserved documentation
# domain (IANA) — mail to it goes nowhere even if a broken relay accepted.
RELAY_RECIPIENT = "postmaster@example.com"


class RelayVerdict(str, Enum):
    NOT_TESTED = "not tested"
    ACCEPTED = "accepted"     # third-party RCPT accepted — the red flag
    REJECTED = "rejected"     # 5xx — the healthy answer
    UNCLEAR = "unclear"       # 4xx / weird — tempfail or greylisting


@dataclass
class TlsInfo:
    version: str = ""            # TLSv1.3
    cipher: str = ""
    subject_cn: str = ""
    issuer_cn: str = ""
    days_left: int | None = None
    verified: bool = False       # chain + hostname verification passed
    verify_error: str = ""       # the reason when it didn't
    error: str = ""              # handshake failed outright


@dataclass
class HostResult:
    host: str
    ips: list[str] = field(default_factory=list)
    preference: int = 0
    banner: str = ""
    connect_error: str = ""
    starttls_offered: bool = False
    auth_mechs: list[str] = field(default_factory=list)
    features: dict[str, str] = field(default_factory=dict)  # EHLO caps
    tls: TlsInfo | None = None
    ptr: str = ""
    ptr_confirmed: bool = False
    relay_verdict: RelayVerdict = RelayVerdict.NOT_TESTED
    relay_detail: str = ""


# ---------------------------------------------------------------------------
# Helpers (pure — tests live on these)
# ---------------------------------------------------------------------------

def parse_auth_mechs(features: dict) -> list[str]:
    """smtplib puts AUTH mechanisms into features['auth'] as one
    space-separated string — split and sort for the report."""
    raw = features.get("auth") or ""
    if isinstance(raw, list):
        raw = " ".join(str(x) for x in raw)
    return sorted(m for m in str(raw).replace("\n", " ").split() if m)


def cert_days_left(not_after: str | None) -> int | None:
    """OpenSSL `notAfter` ('Sep  4 12:00:00 2026 GMT') → days left."""
    if not not_after:
        return None
    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return (expires.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days


def relay_verdict_for(code: int | None) -> RelayVerdict:
    """The RCPT answer → the verdict. 2xx for an external recipient is
    the open-relay flag; 5xx is the healthy rejection; 4xx is a
    tempfail (greylisting) — unclear, honestly."""
    if code is None:
        return RelayVerdict.UNCLEAR
    if 200 <= code < 300:
        return RelayVerdict.ACCEPTED
    if 400 <= code < 500:
        return RelayVerdict.UNCLEAR
    return RelayVerdict.REJECTED


def tls_facts(sock: ssl.SSLSocket, verified: bool,
              verify_error: str = "") -> TlsInfo:
    """Version/cipher/certificate from a live SSL socket. Note: Python
    only populates getpeercert()'s fields on a *verified* connection —
    with an unverified context the subject/issuer/expiry stay empty and
    the verify_error carries the story. That's the honest split."""
    info = TlsInfo(verified=verified, verify_error=verify_error)
    try:
        info.version = sock.version() or ""
        cipher = sock.cipher()
        if cipher:
            info.cipher = cipher[0]
    except (ssl.SSLError, ValueError, OSError):
        pass
    try:
        cert = sock.getpeercert()
        if cert:
            info.subject_cn = ", ".join(
                v for k, v in (cert.get("subject") or [[]])[0]
                if k == "commonName") or ", ".join(
                str(x) for x in (cert.get("subject") or [[]])[0][:1])
            info.issuer_cn = ", ".join(
                v for k, v in (cert.get("issuer") or [[]])[0]
                if k == "commonName")
            info.days_left = cert_days_left(cert.get("notAfter"))
    except (ssl.SSLError, ValueError, OSError):
        pass
    return info


# ---------------------------------------------------------------------------
# The probe
# ---------------------------------------------------------------------------

def _as_text(value) -> str:
    """smtplib messages are str on 3.13+, bytes before — normalize."""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def _connect(host: str, timeout: int):
    """(smtp, banner_or_error). `SMTP.banner` was removed in Python
    3.13 — connect()'s return value is the portable shape."""
    try:
        smtp = smtplib.SMTP(timeout=timeout)
        code, banner = smtp.connect(host, 25)
        return smtp, f"{code} {_as_text(banner).strip()}".strip()
    except (smtplib.SMTPConnectError, ConnectionRefusedError,
            socket.timeout, socket.gaierror, OSError) as exc:
        return None, type(exc).__name__


def _safe_close(smtp: smtplib.SMTP | None) -> None:
    if smtp is None:
        return
    try:
        smtp.quit()
    except (smtplib.SMTPException, OSError):
        try:
            smtp.close()
        except OSError:
            pass


def _ehlo(smtp: smtplib.SMTP, result: HostResult) -> None:
    """EHLO (HELO fallback) + capabilities into the result. The
    post-STARTTLS refresh may legitimately not list STARTTLS again —
    an offered capability must never be un-offered by a refresh."""
    code, _ = smtp.ehlo(PROBE_EHLO_NAME)
    if code >= 400:
        # Some servers want HELO — fall back once.
        smtp.helo(PROBE_EHLO_NAME)
    result.features = dict(smtp.esmtp_features or {})
    offered = "starttls" in result.features
    if offered or not result.starttls_offered:
        result.starttls_offered = offered
    result.auth_mechs = parse_auth_mechs(result.features)


def probe_host(host: str, ips: list[str], timeout: int,
               check_relay: bool, domain: str) -> HostResult:
    """One MX host through the full sequence. Never raises: every
    failure lands in the result as a fact.

    A failing certificate verification aborts the TLS handshake — and
    a broken handshake kills the connection. So the facts come in two
    passes when needed: pass one with a verifying context (the
    verdict), and — only when verification failed — a fresh pass with
    an unverified context, so version/cipher/expiry still return for
    the report."""
    result = HostResult(host=host, ips=ips)
    smtp, banner_or_error = _connect(host, timeout)
    if smtp is None:
        result.connect_error = banner_or_error
        return result
    result.banner = banner_or_error

    try:
        _ehlo(smtp, result)
        verify_error = ""
        if result.starttls_offered:
            try:
                smtp.starttls(context=ssl.create_default_context())
                result.tls = tls_facts(smtp.sock, verified=True)
                # Capabilities may change inside TLS — refresh once.
                try:
                    _ehlo(smtp, result)
                except smtplib.SMTPException:
                    pass
            except ssl.SSLCertVerificationError as exc:
                verify_error = str(exc)[:120]
                result.tls = TlsInfo(verified=False,
                                     verify_error=verify_error)
                _safe_close(smtp)
                smtp = None
            except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
                result.tls = TlsInfo(verified=False,
                                     error=type(exc).__name__)
                _safe_close(smtp)
                smtp = None

        # Pass two — only when verification failed: a fresh connection,
        # unverified, so the handshake's facts still come back.
        if smtp is None and result.tls and result.tls.verify_error:
            smtp2, _banner2 = _connect(host, timeout)
            if smtp2 is not None:
                try:
                    smtp2.ehlo(PROBE_EHLO_NAME)
                    smtp2.starttls(
                        context=ssl._create_unverified_context())
                    result.tls = tls_facts(smtp2.sock, verified=False,
                                           verify_error=verify_error)
                    smtp = smtp2  # the relay probe continues here
                except (smtplib.SMTPException, ssl.SSLError, OSError):
                    _safe_close(smtp2)

        if check_relay and smtp is not None:
            _relay_probe(smtp, result, domain)
    finally:
        _safe_close(smtp)
    return result


def _relay_probe(smtp: smtplib.SMTP, result: HostResult,
                 domain: str) -> None:
    """MAIL FROM a local sender, RCPT TO an external reserved-domain
    recipient, read the answer, RSET+quit. **No DATA — no mail is
    sent, ever.**"""
    try:
        code, _msg = smtp.docmd(f"MAIL FROM:<postmaster@{domain}>")
        if code >= 400:
            result.relay_verdict = RelayVerdict.REJECTED
            result.relay_detail = f"MAIL FROM refused ({code})"
            smtp.docmd("RSET")
            return
        code, msg = smtp.docmd(f"RCPT TO:<{RELAY_RECIPIENT}>")
        result.relay_verdict = relay_verdict_for(code)
        result.relay_detail = f"{code} {_as_text(msg).strip()[:120]}"
        smtp.docmd("RSET")
    except (smtplib.SMTPException, OSError) as exc:
        result.relay_verdict = RelayVerdict.UNCLEAR
        result.relay_detail = type(exc).__name__
