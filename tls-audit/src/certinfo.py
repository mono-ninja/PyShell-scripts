"""Certificate internals the ``ssl`` module does not surface.

``getpeercert()`` only returns a parsed dict on a *verified* handshake —
under ``CERT_NONE`` (the only way to read the certificate of a host
whose chain is broken, which is exactly the host an audit must still
describe) it comes back empty. So this module walks the DER by hand and
reads everything the audit needs straight from the bytes:

* validity dates (``notBefore`` / ``notAfter``),
* subject and issuer common names,
* SANs (``dNSName`` / ``iPAddress``),
* the **public key** (type / size / curve) from ``subjectPublicKeyInfo``,
* the **signature algorithm**.

No ``cryptography`` dependency — the collection is standard-library
only — and every walk is tolerant: a field that won't parse degrades to
an informational finding, never a crash.

Also here: **hostname matching (RFC 6125)**. ``ssl.match_hostname`` was
removed in Python 3.12, so the rules live as code again: SANs
``dNSName`` first (exact, case-insensitive; ``*`` wildcard matches
exactly one leftmost label), IP ``iPAddress`` for IP targets, and the
legacy single-CN fallback only when the certificate has no SANs at all.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone

# --- OID table (dotted) — only what the audit has an opinion about ------

RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
EC_PUBLIC_KEY = "1.2.840.10045.2.1"
ED25519 = "1.3.101.112"

CURVE_BITS = {
    "1.2.840.10045.3.1.7": ("P-256 (secp256r1)", 256),   # NIST curves
    "1.3.132.0.34": ("P-384 (secp384r1)", 384),
    "1.3.132.0.35": ("P-521 (secp521r1)", 521),
    "1.3.132.0.33": ("P-224 (secp224r1)", 224),
    "1.2.840.10045.3.1.1": ("P-192 (secp192r1)", 192),
}

COMMON_NAME = "2.5.4.3"                 # id-at-commonName
SUBJECT_ALT_NAME = "2.5.29.17"          # subjectAltName extension

# signature-algorithm OIDs -> (label, hash). Anything unknown reads as
# "unrecognized" and stays informational rather than guessed at.
SIGNATURE_ALGS = {
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "md5"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "sha1"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "sha256"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "sha384"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "sha512"),
    "1.2.840.113549.1.1.10": ("rsassaPss", "sha256"),   # hash lives in params; PSS is modern — treat as sha256-class
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "sha1"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "sha512"),
    "1.3.101.112": ("Ed25519", "sha512"),
}


@dataclass
class PublicKeyInfo:
    key_type: str          # 'RSA' | 'EC' | 'Ed25519' | 'unknown'
    key_bits: int | None   # None when the walk failed or curve unknown
    curve: str | None      # EC curve label
    note: str | None       # why key_bits is None, when it is


@dataclass
class SignatureInfo:
    oid: str | None
    label: str             # 'unrecognized' when the OID isn't in the table
    hash_name: str | None  # 'sha1'/'md5' are the audited ones


@dataclass
class ParsedCert:
    """The audit-relevant fields of one certificate, read from DER."""
    not_before: datetime | None = None
    not_after: datetime | None = None
    subject_cn: str | None = None
    issuer_cn: str | None = None
    dns_sans: list[str] = field(default_factory=list)
    ip_sans: list[str] = field(default_factory=list)
    parse_notes: list[str] = field(default_factory=list)   # what didn't parse

    @property
    def has_sans(self) -> bool:
        return bool(self.dns_sans or self.ip_sans)


# ---------------------------------------------------------------------------
# DER — a minimal TLV reader
# ---------------------------------------------------------------------------

def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """(tag, value, next_offset) for one TLV at ``offset``.

    Supports the tag and length forms certificates actually use: single-
    byte tags and short/long (up to 4 length bytes) lengths. Raises
    ``ValueError`` on truncation — callers treat that as "unparseable".
    """
    if offset >= len(data):
        raise ValueError("DER truncated (no tag)")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tags not supported")
    pos = offset + 1
    if pos >= len(data):
        raise ValueError("DER truncated (no length)")
    first = data[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise ValueError("unsupported DER length form")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise ValueError("DER truncated (value)")
    return tag, data[pos:pos + length], pos + length


def _children(value: bytes) -> list[tuple[int, bytes]]:
    """All TLVs packed inside one constructed value."""
    out, pos = [], 0
    while pos < len(value):
        tag, inner, pos = _read_tlv(value, pos)
        out.append((tag, inner))
    return out


def _read_oid(value: bytes) -> str:
    """Dotted string from an OBJECT IDENTIFIER content (no tag/length)."""
    if not value:
        raise ValueError("empty OID")
    first = value[0]
    arcs = [first // 40, first % 40] if first < 80 else [2, first - 80]
    num, continuing = 0, False
    for byte in value[1:]:
        num = (num << 7) | (byte & 0x7F)
        if byte & 0x80:
            continuing = True
            continue
        arcs.append(num)
        num, continuing = 0, False
    if continuing:
        raise ValueError("OID truncated")
    return ".".join(str(a) for a in arcs)


# ---------------------------------------------------------------------------
# Certificate structure
# ---------------------------------------------------------------------------

def _cert_parts(cert_der: bytes) -> tuple[list[tuple[int, bytes]], list[tuple[int, bytes]]] | None:
    """(tbs children, top-level children) — None when not a certificate."""
    try:
        tag, cert_value, _ = _read_tlv(cert_der, 0)
        if tag != 0x30:
            return None
        top = _children(cert_value)
        if len(top) < 3 or top[0][0] != 0x30:
            return None
        tbs = _children(top[0][1])
        return tbs, top
    except ValueError:
        return None


def _cert_tbs(cert_der: bytes) -> list[tuple[int, bytes]] | None:
    parts = _cert_parts(cert_der)
    return parts[0] if parts else None


def _skip_optional_version(tbs: list[tuple[int, bytes]]) -> int:
    """Index of the serialNumber: tbs[0] is [0]-tagged version when present."""
    return 1 if tbs and tbs[0][0] == 0xA0 else 0


def parse_public_key(cert_der: bytes) -> PublicKeyInfo:
    """The leaf's SPKI: key type, size, curve.

    X.509 tbs layout after the optional [0] version: serial, signature,
    issuer, validity, subject, **subjectPublicKeyInfo** — index 5 (or 6
    with the version element).
    """
    tbs = _cert_tbs(cert_der)
    if tbs is None:
        return PublicKeyInfo("unknown", None, None, "certificate DER unparseable")
    base = _skip_optional_version(tbs)
    try:
        spki = tbs[base + 5]
    except IndexError:
        return PublicKeyInfo("unknown", None, None, "no subjectPublicKeyInfo")
    try:
        spki_children = _children(spki[1])
        alg_children = _children(spki_children[0][1])
        oid = _read_oid(alg_children[0][1])
    except (ValueError, IndexError):
        return PublicKeyInfo("unknown", None, None, "SPKI unparseable")

    if oid == RSA_ENCRYPTION:
        bits = _rsa_modulus_bits(spki_children)
        return PublicKeyInfo("RSA", bits, None,
                             None if bits else "RSA modulus unreadable")
    if oid == EC_PUBLIC_KEY:
        curve_oid = _algorithm_param_oid(alg_children)
        if curve_oid in CURVE_BITS:
            label, bits = CURVE_BITS[curve_oid]
            return PublicKeyInfo("EC", bits, label, None)
        return PublicKeyInfo("EC", None, None,
                             f"unrecognized curve {curve_oid or '(none)'}")
    if oid == ED25519:
        return PublicKeyInfo("Ed25519", 256, "Ed25519", None)
    return PublicKeyInfo("unknown", None, None, f"unrecognized key OID {oid}")


def _algorithm_param_oid(alg_children: list[tuple[int, bytes]]) -> str:
    """The EC curve: AlgorithmIdentifier parameters are the curve OID
    *directly* (a primitive TLV), unlike RSA's NULL — unwrap only when
    the tag says OID."""
    if len(alg_children) < 2:
        return ""
    tag, value = alg_children[1]
    if tag != 0x06:
        return ""
    try:
        return _read_oid(value)
    except ValueError:
        return ""


def _rsa_modulus_bits(spki_children: list[tuple[int, bytes]]) -> int | None:
    """Modulus bit length: SPKI BIT STRING -> RSAPublicKey SEQUENCE ->
    INTEGER modulus. ``bit_length()`` of the integer is the key size."""
    try:
        bitstring = spki_children[1][1]
        if not bitstring or bitstring[0] != 0:
            return None                       # unused-bits byte must be 0
        key_tag, key_value, _ = _read_tlv(bitstring[1:], 0)
        if key_tag != 0x30:
            return None
        modulus_tag, modulus, _ = _read_tlv(key_value, 0)
        if modulus_tag != 0x02:
            return None
        return int.from_bytes(modulus, "big").bit_length()
    except (ValueError, IndexError):
        return None


def parse_signature_alg(cert_der: bytes) -> SignatureInfo:
    """The certificate's signatureAlgorithm (top-level element #2)."""
    parts = _cert_parts(cert_der)
    if parts is None:
        return SignatureInfo(None, "unparseable", None)
    _, top = parts
    try:
        alg = _children(top[1][1])
        oid = _read_oid(alg[0][1])
    except (ValueError, IndexError):
        return SignatureInfo(None, "unparseable", None)
    label, hash_name = SIGNATURE_ALGS.get(oid, (f"OID {oid}", None))
    return SignatureInfo(oid, label, hash_name)


# ---------------------------------------------------------------------------
# The audit-relevant fields, read from DER
# ---------------------------------------------------------------------------

def parse_cert_fields(cert_der: bytes) -> ParsedCert:
    """Validity dates, CNs and SANs — everything ``getpeercert()`` would
    give, except it works on the unverified handshake too (the case an
    audit cannot avoid: describing the certificate of a broken host).

    Each section is independent: a missing extension or unparseable
    name costs that field and a note, not the whole parse.
    """
    parsed = ParsedCert()
    tbs = _cert_tbs(cert_der)
    if tbs is None:
        parsed.parse_notes.append("certificate DER unparseable")
        return parsed
    base = _skip_optional_version(tbs)

    # validity: tbs[base+3] = SEQUENCE { notBefore, notAfter }
    try:
        validity = _children(tbs[base + 3][1])
        parsed.not_before = _parse_asn1_time(validity[0])
        parsed.not_after = _parse_asn1_time(validity[1])
    except (ValueError, IndexError):
        parsed.parse_notes.append("validity unreadable")
    if parsed.not_before is None or parsed.not_after is None:
        if "validity unreadable" not in parsed.parse_notes:
            parsed.parse_notes.append("validity dates unparsable")

    # subject / issuer CNs: Name = SEQUENCE OF SET OF SEQUENCE {OID, value}
    try:
        parsed.subject_cn = _name_cn(tbs[base + 4][1])
    except (ValueError, IndexError):
        parsed.parse_notes.append("subject unreadable")
    try:
        parsed.issuer_cn = _name_cn(tbs[base + 2][1])
    except (ValueError, IndexError):
        parsed.parse_notes.append("issuer unreadable")

    # extensions: tbs[base+6] = [3] EXPLICIT SEQUENCE OF Extension
    try:
        ext_tag, ext_value = tbs[base + 6]
        if ext_tag != 0xA3:
            raise ValueError("no [3] extensions element")
        dns, ips = _parse_sans(ext_value)
        parsed.dns_sans, parsed.ip_sans = dns, ips
    except (ValueError, IndexError):
        # No SANs at all is legitimate (if dated) — the checks module
        # flags it; here it is a fact, not a parse failure.
        pass
    return parsed


def _parse_asn1_time(tlv: tuple[int, bytes]) -> datetime | None:
    """UTCTime (YY…) or GeneralizedTime (YYYY…), both ending in Z."""
    tag, value = tlv
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    if tag == 0x17:                                   # UTCTime YYMMDDHHMMSSZ
        if len(text) < 12 or not text.endswith("Z"):
            return None
        yy = int(text[:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        rest = text[2:]
    elif tag == 0x18:                                 # GeneralizedTime
        if len(text) < 14 or not text.endswith("Z"):
            return None
        year = int(text[:4])
        rest = text[4:]
    else:
        return None
    try:
        month, day, hour, minute, second = (int(rest[i:i + 2])
                                            for i in range(0, 10, 2))
        return datetime(year, month, day, hour, minute, second,
                        tzinfo=timezone.utc)
    except ValueError:
        return None


def _name_cn(name_value: bytes) -> str | None:
    """First commonName in an RDNSequence."""
    for rdn_tag, rdn in _children(name_value):
        if rdn_tag != 0x31:                           # SET
            continue
        for atv_tag, atv in _children(rdn):
            if atv_tag != 0x30:                       # SEQUENCE {OID, value}
                continue
            try:
                parts = _children(atv)
                if _read_oid(parts[0][1]) == COMMON_NAME and len(parts) > 1:
                    return parts[1][1].decode("utf-8", "replace")
            except (ValueError, IndexError):
                continue
    return None


def _parse_sans(extensions_value: bytes) -> tuple[list[str], list[str]]:
    """(dns_names, ip_strings) from the subjectAltName extension.

    GeneralNames entries this audit doesn't use (rfc822Name, URI, …)
    are skipped silently — they are not errors, just not our business.
    """
    dns_names: list[str] = []
    ip_strings: list[str] = []
    for ext_tag, ext in _children(_children(extensions_value)[0][1]):
        if ext_tag != 0x30:                           # Extension ::= SEQUENCE
            continue
        fields = _children(ext)
        try:
            if _read_oid(fields[0][1]) != SUBJECT_ALT_NAME:
                continue
            # extnValue is the last field (OCTET STRING), critical is
            # an optional middle BOOLEAN.
            value = next(f for f in reversed(fields) if f[0] == 0x04)
        except (ValueError, IndexError, StopIteration):
            continue
        try:
            general_names = _children(_children(value[1])[0][1])
        except (ValueError, IndexError):
            continue
        for tag, raw in general_names:
            if tag == 0x82:                           # [2] dNSName (IA5String)
                dns_names.append(raw.decode("ascii", "replace"))
            elif tag == 0x87 and len(raw) in (4, 16):  # [7] iPAddress
                try:
                    ip_strings.append(str(ipaddress.ip_address(raw)))
                except ValueError:
                    continue
    return dns_names, ip_strings


# ---------------------------------------------------------------------------
# Hostname matching (RFC 6125) — ssl.match_hostname is gone in 3.12
# ---------------------------------------------------------------------------

def hostname_matches(host: str, cert: ParsedCert | None) -> tuple[bool, str, list[str]]:
    """(matched, how, dns_names) for ``host`` against the certificate.

    ``how`` explains the path taken — 'SAN (exact)', 'SAN (wildcard)',
    'iPAddress SAN', 'CN fallback' — because "why this matches" is as
    worth auditing as whether it does. No SANs at all falls back to the
    single-CN rule of RFC 6125 §6.4.4; a wildcard must sit alone in the
    leftmost label and matches exactly one label.
    """
    if cert is None:
        return False, "no certificate", []

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        for candidate in cert.ip_sans:
            try:
                if ipaddress.ip_address(candidate) == ip:
                    return True, "iPAddress SAN", cert.dns_sans
            except ValueError:
                continue
        # A dNSName can never match an IP literal (RFC 6125 §1.7).
        if cert.dns_sans or cert.ip_sans:
            return False, "IP host, no matching iPAddress SAN", cert.dns_sans

    if cert.dns_sans:
        for candidate in cert.dns_sans:
            if _dns_label_match(candidate.lower(), host.lower()):
                how = "SAN (exact)" if "*" not in candidate else "SAN (wildcard)"
                return True, how, cert.dns_sans
        return False, "no SAN matches", cert.dns_sans

    # Legacy: no SANs -> CN. Modern certificates always carry SANs, so
    # this path is itself a finding elsewhere (the checks module notes it).
    cn = cert.subject_cn
    if cn and _dns_label_match(cn.lower(), host.lower()):
        return True, "CN fallback (no SANs)", []
    return False, "no SANs, CN does not match" if cn else "no SANs and no CN", []


def _dns_label_match(pattern: str, host: str) -> bool:
    """RFC 6125 name match: case-insensitive; ``*`` only as the entire
    leftmost label of the *pattern*, matching exactly one host label."""
    if not pattern or not host:
        return False
    p_parts, h_parts = pattern.split("."), host.split(".")
    if len(p_parts) != len(h_parts):
        return False
    if "*" in pattern:
        if len(p_parts[0]) != 1:             # '*' must stand alone
            return False
        if len(p_parts) < 3:                 # wildcard needs 2 real labels
            return False
    return all(p == h or (p == "*" and i == 0)
               for i, (p, h) in enumerate(zip(p_parts, h_parts)))
