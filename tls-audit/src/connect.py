"""Connection layer — every TLS handshake the audit makes.

The script speaks TLS directly (``ssl`` + ``socket``) and never sends
an HTTP request: the handshake itself is the evidence. A full run makes
**seven connections** to the same host:port, each answering one question
—

1. **collect** — a modern default handshake, verification off, to read
   the certificate (and, on Python 3.13+, the whole presented chain)
   plus the negotiated protocol and cipher;
2. **verify** — the same handshake with ``CERT_REQUIRED`` against the
   system trust store: does the chain actually validate?
3–6. **protocol probes** — TLS 1.0 / 1.1 / 1.2 / 1.3, one connection
   each, by pinning the context to exactly that version;
7. **weak-cipher probe** — a TLS 1.2 handshake offering *only* weak
   suites (NULL, EXPORT, DES, RC4, IDEA, aNULL): if it succeeds, the
   server accepted one of them.

Probing old protocol versions needs the OpenSSL security level dropped
(``@SECLEVEL=0``) — modern OpenSSL refuses TLS 1.0/1.1 client-side
otherwise. Where the *client* cannot offer a version or cipher list at
all, the probe reports ``None`` ("cannot probe") rather than inventing
a verdict; the report then says so plainly instead of guessing.
"""
from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import dataclass, field

# Cipher list offered *only* in the weak-cipher probe — every entry is a
# suite no modern server should accept. A successful handshake with one
# of these negotiated is the fail condition.
WEAK_CIPHERS = "NULL:EXPORT:DES:RC4:IDEA:aNULL:@SECLEVEL=0"

# The legacy-compatible list for old-protocol probes — SECLEVEL 0 alone
# is not enough, the default list also has to still contain SHA-1 MAC
# suites for a TLS 1.0 handshake to have anything to offer.
LEGACY_CIPHERS = "DEFAULT:@SECLEVEL=0"


@dataclass
class Handshake:
    """One connection attempt, everything it learned."""
    ok: bool = False
    error: str | None = None          # short human-readable failure
    version: str | None = None        # negotiated, e.g. 'TLSv1.3'
    cipher: str | None = None         # negotiated suite name
    cert_der: bytes = b""             # leaf certificate, DER
    chain: list[bytes] = field(default_factory=list)   # DERs, leaf first (3.13+)


def _context(*, min_version, max_version, ciphers: str | None,
             verify: bool, legacy: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Order matters: PROTOCOL_TLS_CLIENT ships with check_hostname=True,
    # and OpenSSL refuses verify_mode=CERT_NONE while it is on.
    ctx.check_hostname = False
    # The TLSv1/TLSv1_1 constants are deprecated precisely because those
    # versions are — but deprecating the probe for them would defeat the
    # audit, so the warning is silenced at the source.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=r"ssl\.TLSVersion\.TLSv1.*")
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
    if legacy:
        ciphers = ciphers or LEGACY_CIPHERS
    if ciphers:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError as exc:
            # The client OpenSSL has nothing in this list to offer —
            # e.g. RC4 compiled out entirely. Surface as "cannot probe".
            raise ProbeUnavailable(str(exc)) from exc
    if verify:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class ProbeUnavailable(Exception):
    """The local OpenSSL cannot offer this version/cipher list at all."""


def handshake(host: str, port: int, ctx: ssl.SSLContext,
              timeout: float) -> Handshake:
    """One TLS connection. Failures come back as data, not exceptions —
    a refused handshake is a *finding*, and the caller decides which."""
    result = Handshake()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=None if _is_ip(host) else host) as tls:
                result.ok = True
                result.version = tls.version()
                cipher = tls.cipher()
                result.cipher = cipher[0] if cipher else None
                # getpeercert() comes back empty on an unverified
                # handshake — the DER always comes through, and
                # certinfo parses every field the audit needs from it.
                result.cert_der = tls.getpeercert(binary_form=True) or b""
                if hasattr(tls, "get_unverified_chain"):
                    # Python 3.13+: the full presented chain, leaf first,
                    # as DER bytes (older alphas handed out certificate
                    # objects — accept both).
                    result.chain = [
                        c if isinstance(c, bytes)
                        else c.public_bytes(ssl.ENCODING_DER)
                        for c in tls.get_unverified_chain()
                    ]
    except ssl.SSLCertVerificationError as exc:
        result.error = str(exc.verify_message or exc)
    except ssl.SSLError as exc:
        result.error = _short_ssl_error(exc)
    except socket.timeout:
        result.error = "connection timed out"
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def _short_ssl_error(exc: ssl.SSLError) -> str:
    """'SSL: SSLV3_ALERT_HANDSHAKE_FAILURE' style — reason first, library noise last."""
    reason = getattr(exc, "reason", None)
    lib = getattr(exc, "library", None)
    if reason:
        return f"{lib} {reason}".strip() if lib and lib != reason else reason
    return str(exc)


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# The seven connections
# ---------------------------------------------------------------------------

def probe_supported_versions(host: str, port: int, timeout: float) -> Handshake:
    """Connection 1: a modern default handshake — certificate + negotiation."""
    ctx = _context(min_version=ssl.TLSVersion.MINIMUM_SUPPORTED,
                   max_version=ssl.TLSVersion.MAXIMUM_SUPPORTED,
                   ciphers=None, verify=False, legacy=False)
    return handshake(host, port, ctx, timeout)


def probe_trust(host: str, port: int, timeout: float) -> Handshake:
    """Connection 2: chain-of-trust validation against the system store."""
    ctx = _context(min_version=ssl.TLSVersion.MINIMUM_SUPPORTED,
                   max_version=ssl.TLSVersion.MAXIMUM_SUPPORTED,
                   ciphers=None, verify=True, legacy=False)
    return handshake(host, port, ctx, timeout)


#: version -> (needs the legacy security level?)
VERSION_PROBES: list[tuple[str, ssl.TLSVersion, bool]] = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1, True),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1, True),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2, False),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3, False),
]


def probe_version(host: str, port: int, version: ssl.TLSVersion,
                  legacy: bool, timeout: float) -> Handshake:
    """Connections 3–6: pin the context to exactly one protocol version."""
    ctx = _context(min_version=version, max_version=version,
                   ciphers=None, verify=False, legacy=legacy)
    return handshake(host, port, ctx, timeout)


def probe_weak_ciphers(host: str, port: int, timeout: float) -> Handshake:
    """Connection 7: offer only weak suites on a TLS 1.2 handshake."""
    ctx = _context(min_version=ssl.TLSVersion.MINIMUM_SUPPORTED,
                   max_version=ssl.TLSVersion.TLSv1_2,
                   ciphers=WEAK_CIPHERS, verify=False, legacy=True)
    return handshake(host, port, ctx, timeout)
