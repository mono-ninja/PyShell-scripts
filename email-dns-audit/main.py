#!/usr/bin/env python3
"""email-dns-audit/main.py — Email DNS Audit.

Given a domain, checks every DNS record that governs whether mail claiming
to be from it is trusted or blocked: MX, SPF, DMARC, DKIM (by selector), and
— behind opt-in toggles — MTA-STS / TLS-RPT / BIMI. The result is a
pass/warn/fail finding per pillar plus one plain-language readiness
sentence; that sentence is the actual deliverable, the per-record table is
supporting evidence.

Passive by design, same philosophy as ip-search/ip-domains: DNS lookups
only (the one exception is the opt-in MTA-STS policy fetch, gated behind
its own toggle). The domain's mail infrastructure is never contacted.

Structured events are emitted on stderr so PyShell renders them natively.
Artifacts are written to PYSHELL_OUTPUT_DIR: ``dns_records_raw.json``
(every record actually fetched, verbatim — the evidence), ``findings.json``
(structured, for CI), and ``report.md``.

Run from a terminal too — the events degrade to plain JSON log lines.
"""
import argparse
import base64
import json
import os
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Literal

try:
    import dns.resolver
except ImportError:  # optional at import time, required at run time
    dns = None

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ

# DKIM selectors aren't discoverable via DNS — this wordlist covers the
# common providers; the user can extend it with their own.
DEFAULT_DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "dkim", "k1",
    "mail", "smtp", "s1", "s2", "amazonses", "mx",
]

# RFC 7208 §4.6.4: more than 10 DNS-consuming mechanisms is a permerror.
SPF_LOOKUP_LIMIT = 10
# Recurse into include: targets this deep when counting lookups (depth 0 =
# the domain's own record, 1 = its includes, 2 = includes of includes); past
# it, flag the count as possibly incomplete instead of chasing the chain.
SPF_MAX_DEPTH = 2

# Mechanisms that cost a DNS lookup each (ptr is deprecated and ignored).
SPF_DNS_MECHANISMS = {"a", "mx", "include", "exists", "redirect"}


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
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One check result within a pillar (MX / SPF / DMARC / DKIM / Advanced)."""
    pillar: str
    record: str
    status: Literal["pass", "warn", "fail", "missing"]
    detail: str
    recommendation: str


@dataclass
class RawRecords:
    """Every DNS record actually fetched, verbatim — the evidence artifact."""
    entries: list[dict] = field(default_factory=list)

    def add(self, name: str, rtype: str, records: list[str]) -> None:
        if records:
            self.entries.append({"name": name, "type": rtype, "records": records})


# ---------------------------------------------------------------------------
# DNS access — the only layer that touches the network
# ---------------------------------------------------------------------------

class Dns:
    """Thin dnspython wrapper. Every lookup returns a plain list/bool, so the
    audit logic above never sees a dnspython exception — "no answer",
    "NXDOMAIN" and "timeout" all collapse to an empty result, which is all
    the audit ever needs to know (tests stub this class)."""

    def __init__(self, nameserver: str | None = None, timeout: float = 10.0):
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        if nameserver:
            self._resolver.nameservers = [nameserver]
        self.raw = RawRecords()

    def _resolve(self, name: str, rtype: str):
        return self._resolver.resolve(name, rtype)

    def txt(self, name: str) -> list[str]:
        """TXT records at `name`, one string per record.

        A single TXT record split into multiple character-strings on the
        wire (the 255-byte chunking some providers do) is re-joined per
        RFC 7208 §3.3 / RFC 6376 §3.6.2.2 — parsing a chunked SPF or DKIM
        record without joining would misread every long record.
        """
        try:
            answer = self._resolve(name, "TXT")
        except Exception:
            return []
        out = []
        for rr in answer:
            try:
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            except (AttributeError, TypeError):
                out.append(str(rr))
        self.raw.add(name, "TXT", out)
        return out

    def mx(self, name: str) -> list[tuple[int, str]]:
        try:
            answer = self._resolve(name, "MX")
        except Exception:
            return []
        out = []
        for rr in answer:
            out.append((int(getattr(rr, "preference", 0)),
                        str(getattr(rr, "exchange", rr)).rstrip(".")))
        out.sort()
        self.raw.add(name, "MX", [f"{pref} {host}" for pref, host in out])
        return out

    def addresses(self, name: str) -> list[str]:
        """A + AAAA records for `name` — used to check MX hosts resolve."""
        out: list[str] = []
        for rtype in ("A", "AAAA"):
            try:
                answer = self._resolve(name, rtype)
            except Exception:
                continue
            out.extend(str(rr) for rr in answer)
        self.raw.add(name, "A/AAAA", out)
        return out

    def domain_exists(self, name: str) -> bool:
        """A domain 'exists' for mail purposes if any of NS / A / AAAA / MX
        resolves — a domain with no A record but valid NS still exists."""
        for rtype in ("NS", "A", "AAAA", "MX"):
            try:
                self._resolve(name, rtype)
                return True
            except dns.resolver.NXDOMAIN:
                return False
            except Exception:
                continue
        return True  # no answer anywhere, but no NXDOMAIN either — it exists


# ---------------------------------------------------------------------------
# A2. SPF — parsing and grading
# ---------------------------------------------------------------------------

def spf_records(txts: list[str]) -> list[str]:
    """The v=spf1 records among a domain's TXT strings.

    The version check is case-sensitive per RFC 7208 §4.5 — ``v=SPF1`` is
    not an SPF record.
    """
    return [t for t in txts if t.startswith("v=spf1 ")]


def parse_spf(record: str) -> dict:
    """Parse one SPF record into its mechanisms.

    Returns {"mechanisms": [(qualifier, name, value), …],
             "all": qualifier-or-None, "lookups": top-level DNS-consuming
             mechanism count, "unknown": [offending tokens]}.
    """
    mechanisms: list[tuple[str, str, str]] = []
    unknown: list[str] = []
    all_qualifier: str | None = None
    lookups = 0
    terms = record.split()[1:]  # drop the leading v=spf1
    for term in terms:
        qualifier = "+"
        body = term
        if term[0] in "+-~?":
            qualifier, body = term[0], term[1:]
        if ":" in body:
            name, _, value = body.partition(":")
        elif "=" in body and body.split("=", 1)[0] in ("redirect", "exp"):
            name, _, value = body.partition("=")
        else:
            name, value = body, ""
        name = name.lower()
        if name == "all":
            all_qualifier = qualifier
        elif name in ("ip4", "ip6", "a", "mx", "include", "exists", "ptr"):
            mechanisms.append((qualifier, name, value))
            if name in SPF_DNS_MECHANISMS:
                lookups += 1
        elif name == "redirect":
            mechanisms.append((qualifier, "redirect", value))
            lookups += 1
        elif name == "exp":
            mechanisms.append((qualifier, "exp", value))
        else:
            unknown.append(term)
    return {"mechanisms": mechanisms, "all": all_qualifier,
            "lookups": lookups, "unknown": unknown}


def spf_total_lookups(domain: str, record: str, dns: Dns,
                      depth: int = 0, seen: frozenset = frozenset()
                      ) -> tuple[int, bool]:
    """Count DNS lookups an SPF evaluation would really consume.

    Recurses into include: *and* redirect= targets up to SPF_MAX_DEPTH so
    the count is realistic rather than just counting top-level directives.
    redirect= is not optional to follow: when present (and unmatched by an
    earlier mechanism), evaluation continues entirely at the target record,
    so the target's own DNS-consuming mechanisms are exactly as "real" a
    cost as an include:'s — a domain redirecting to a target that alone
    blows the 10-lookup ceiling must not come back as a clean pass just
    because the top-level record only spent one lookup on the redirect
    itself.

    Returns (count, capped) — capped=True means the recursion hit its depth
    limit and the real count may be higher.
    """
    if domain in seen or depth > SPF_MAX_DEPTH:
        return 0, depth > SPF_MAX_DEPTH
    parsed = parse_spf(record)
    count = parsed["lookups"]
    capped = False
    for _qual, name, value in parsed["mechanisms"]:
        if name in ("include", "redirect") and value:
            # A domain with no SPF record at the target is a hard permerror
            # at evaluation time, but it still consumed its lookup — which
            # the top-level count already charged for.
            nested = spf_records(dns.txt(value))
            if len(nested) == 1:
                sub, sub_capped = spf_total_lookups(
                    value, nested[0], dns, depth + 1, seen | {domain})
                count += sub
                capped = capped or sub_capped
    return count, capped


def audit_spf(domain: str, dns: Dns) -> list[Finding]:
    txts = dns.txt(domain)
    records = spf_records(txts)
    findings: list[Finding] = []

    if not records:
        return [Finding("SPF", "TXT @ domain", "missing",
                        "no v=spf1 record published",
                        "v=spf1 include:_spf.google.com ~all (adjust to your "
                        "provider; finish with -all once verified)")]

    if len(records) > 1:
        # The single highest-value check here: RFC 7208 requires exactly one
        # SPF record, and multiple make receivers treat the whole thing as a
        # permanent failure — silently, on every message.
        findings.append(Finding(
            "SPF", "TXT @ domain", "fail",
            f"{len(records)} v=spf1 records published — receivers treat this "
            "as a permanent SPF failure for ALL mail from the domain",
            "Publish exactly one v=spf1 record; merge the others' mechanisms "
            "into it and delete the extras"))

    record = records[0]
    parsed = parse_spf(record)

    total, capped = spf_total_lookups(domain, record, dns)
    if capped:
        # Surface the cap on its own: it matters even when the visible
        # count is under the limit, because the real count may not be.
        findings.append(Finding(
            "SPF", f"TXT @ {domain}", "warn",
            f"lookup count ({total} visible) may be incomplete — include: "
            f"recursion capped at depth {SPF_MAX_DEPTH}",
            ""))
    if total > SPF_LOOKUP_LIMIT:
        findings.append(Finding(
            "SPF", f"TXT @ {domain}", "fail",
            f"{total} DNS-consuming mechanisms/redirects (limit {SPF_LOOKUP_LIMIT}) "
            "— a permerror per RFC 7208 §4.6.4"
            + ("; count may be incomplete, recursion capped" if capped else ""),
            "Flatten nested include: chains or drop unused mechanisms to get "
            "under the 10-lookup limit"))

    if parsed["unknown"]:
        findings.append(Finding(
            "SPF", f"TXT @ {domain}", "warn",
            f"unknown terms: {', '.join(parsed['unknown'])}",
            "Remove or fix the unknown mechanisms — strict evaluators treat "
            "them as syntax errors"))

    all_q = parsed["all"]
    # RFC 7208 §6.1: with redirect= and no matching mechanism, evaluation
    # continues at the target record — its terminal qualifier is the one
    # that matters (gmail.com's own SPF is exactly this shape: no `all`
    # locally, `redirect=_spf.google.com`).
    redirect_to = next((v for _q, n, v in parsed["mechanisms"]
                        if n == "redirect" and v), None)
    if all_q is None and redirect_to:
        target_records = spf_records(dns.txt(redirect_to))
        if len(target_records) == 1:
            target_all = parse_spf(target_records[0])["all"]
            if target_all:
                findings.append(Finding(
                    "SPF", f"TXT @ {domain}", "pass" if target_all == "-" else "warn",
                    f"`{record}` — redirects to `{redirect_to}`, which ends "
                    f"in {target_all}all",
                    "" if target_all == "-" else
                    f"The redirect target {redirect_to} should end in -all"))
                return findings
        findings.append(Finding(
            "SPF", f"TXT @ {domain}", "fail",
            f"`{record}` — redirect target {redirect_to} has no usable SPF "
            "record: a permerror at evaluation time",
            "Point redirect= at a domain with a valid v=spf1 record"))
        return findings

    if all_q == "-":
        findings.append(Finding("SPF", f"TXT @ {domain}", "pass",
                                f"`{record}` — ends in -all (fail/strict)", ""))
    elif all_q == "~":
        findings.append(Finding(
            "SPF", f"TXT @ {domain}", "warn",
            f"`{record}` — ends in ~all (softfail): a common deliberate "
            "intermediate state, but nothing is hard-rejected",
            "Once legitimate mail sources are all covered, switch ~all to -all"))
    elif all_q == "?":
        findings.append(Finding(
            "SPF", f"TXT @ {domain}", "fail",
            f"`{record}` — ends in ?all (neutral): SPF is present but "
            "toothless, every sender matches",
            "Replace ?all with -all (or at minimum ~all)"))
    else:
        findings.append(Finding(
            "SPF", f"TXT @ {domain}", "fail",
            f"`{record}` — no `all` mechanism: nothing is excluded, the most "
            "permissive posture possible",
            "Finish the record with -all (or ~all while testing)"))

    return findings


# ---------------------------------------------------------------------------
# A3. DMARC
# ---------------------------------------------------------------------------

def parse_dmarc(record: str) -> dict:
    """Parse a DMARC TXT record into tags, preserving order.

    Returns {"tags": {name: value}, "valid_version": bool} — v=DMARC1 must
    be the first tag or the record is invalid (RFC 7489 §6.4).
    """
    parts = record.split(";")
    tags: dict[str, str] = {}
    ordered: list[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition("=")
        name = name.strip().lower()
        tags[name] = value.strip()
        ordered.append(name)
    return {"tags": tags, "first_tag": ordered[0] if ordered else "",
            "valid_version": ordered[:1] == ["v"] and
            tags.get("v", "").upper() == "DMARC1"}


def audit_dmarc(domain: str, dns: Dns) -> tuple[list[Finding], str | None]:
    """Returns (findings, policy) — policy feeds the summary sentence."""
    txts = dns.txt(f"_dmarc.{domain}")
    dmarc = [t for t in txts if "dmarc" in t.lower()]
    if not dmarc:
        return [Finding("DMARC", "TXT @ _dmarc." + domain, "missing",
                        "no DMARC record — the domain is fully spoofable, "
                        "with no reporting either",
                        "v=DMARC1; p=none; rua=mailto:dmarc@" + domain)], None

    record = dmarc[0]
    parsed = parse_dmarc(record)
    tags = parsed["tags"]
    findings: list[Finding] = []

    if not parsed["valid_version"]:
        findings.append(Finding(
            "DMARC", f"TXT @ _dmarc.{domain}", "fail",
            f"`{record}` — v=DMARC1 must be the first tag; this record is "
            "invalid and will be ignored",
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain))
        return findings, tags.get("p")

    policy = tags.get("p", "").lower()
    policy_note = ""
    if "pct" in tags and tags["pct"] != "100":
        policy_note = f" (pct={tags['pct']}: only {tags['pct']}% of mail gets the policy)"
    if policy in ("quarantine", "reject"):
        findings.append(Finding(
            "DMARC", f"TXT @ _dmarc.{domain}", "pass",
            f"`{record}` — p={policy}{policy_note}", ""))
    elif policy == "none":
        findings.append(Finding(
            "DMARC", f"TXT @ _dmarc.{domain}", "warn",
            f"`{record}` — p=none (monitor-only): spoofed mail is being "
            f"reported on, not blocked{policy_note}",
            "Move to p=quarantine, then p=reject, once reports show only "
            "legitimate sources"))
    else:
        findings.append(Finding(
            "DMARC", f"TXT @ _dmarc.{domain}", "fail",
            f"`{record}` — no usable p= tag",
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain))

    # sp= weaker than p= — subdomains get the softer policy on purpose or by
    # accident; either way it's worth seeing stated.
    sp = tags.get("sp", "").lower()
    strength = {"none": 0, "quarantine": 1, "reject": 2}
    if sp and sp in strength and policy in strength and strength[sp] < strength[policy]:
        findings.append(Finding(
            "DMARC", f"TXT @ _dmarc.{domain}", "warn",
            f"sp={sp} is weaker than p={policy} — subdomains keep the softer "
            "policy",
            "Set sp= to match p=, or remove sp= (it defaults to p=)"))

    if "rua" not in tags:
        findings.append(Finding(
            "DMARC", f"TXT @ _dmarc.{domain}", "warn",
            "no rua= — no aggregate reports, no visibility into who is "
            "spoofing the domain",
            "Add rua=mailto:dmarc-reports@" + domain))
    else:
        findings.append(Finding(
            "DMARC", f"TXT @ _dmarc.{domain}", "pass",
            f"rua={tags['rua']} (aggregate reports)", ""))

    alignment = []
    for tag, label in (("adkim", "DKIM"), ("aspf", "SPF")):
        mode = tags.get(tag, "r").lower()
        alignment.append(
            f"{label} alignment: {'relaxed (default)' if mode == 'r' else 'strict' if mode == 's' else mode}")
    findings.append(Finding(
        "DMARC", f"TXT @ _dmarc.{domain}", "pass",
        " · ".join(alignment), ""))

    return findings, (policy or None)


# ---------------------------------------------------------------------------
# A4. DKIM
# ---------------------------------------------------------------------------

def parse_dkim(txt: str) -> dict:
    """DKIM TXT record → tag dict (v, k, p, …). p= may be explicitly empty —
    an empty p= means a revoked key per RFC 8463, which is a different
    finding from 'no record found'."""
    tags: dict[str, str] = {}
    for part in txt.split(";"):
        part = part.strip()
        if part:
            name, _, value = part.partition("=")
            tags[name.strip()] = value.strip()
    return tags


def _der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """One DER TLV → (tag, content, offset-after). Raises ValueError on
    truncated input."""
    if offset + 2 > len(data):
        raise ValueError("truncated")
    tag = data[offset]
    length = data[offset + 1]
    if length & 0x80:  # long form
        nbytes = length & 0x7F
        if nbytes == 0 or offset + 2 + nbytes > len(data):
            raise ValueError("bad length")
        length = int.from_bytes(data[offset + 2:offset + 2 + nbytes], "big")
        start = offset + 2 + nbytes
    else:
        start = offset + 2
    if start + length > len(data):
        raise ValueError("truncated content")
    return tag, data[start:start + length], start + length


def dkim_key_bits(p_value: str) -> int | None:
    """Key length from the base64 public-key blob — nice-to-have, not load-
    bearing: anything unexpected returns None rather than failing anything.

    Walks the DER SubjectPublicKeyInfo far enough to reach the RSA modulus
    (the first INTEGER inside the BIT STRING). Ed25519 keys (no inner
    sequence) report their fixed 256 bits.
    """
    try:
        blob = base64.b64decode("".join(p_value.split()))
        tag, spki, _ = _der_tlv(blob)          # SubjectPublicKeyInfo SEQUENCE
        if tag != 0x30:
            return None
        _, _alg, off = _der_tlv(spki)          # AlgorithmIdentifier SEQUENCE
        tag, bits, _ = _der_tlv(spki, off)     # subjectPublicKey BIT STRING
        if tag != 0x03 or not bits:
            return None
        inner = bits[1:]                       # skip the unused-bits count
        tag, seq, _ = _der_tlv(inner)          # RSAPublicKey SEQUENCE
        if tag != 0x30:
            return 256                         # Ed25519: OID-only inside
        tag, modulus, _ = _der_tlv(seq)        # modulus INTEGER
        if tag != 0x02 or not modulus:
            return None
        # A leading 0x00 keeps the INTEGER positive — it is not a key bit.
        stripped = modulus.lstrip(b"\x00")
        return len(stripped) * 8
    except (ValueError, TypeError, IndexError):
        return None


def audit_dkim(domain: str, selectors: list[str], dns: Dns) -> list[Finding]:
    findings: list[Finding] = []
    found = 0
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        txts = dns.txt(name)
        for txt in txts:
            tags = parse_dkim(txt)
            # A DKIM record either declares v=DKIM1 or carries a public key
            # (p=); anything else at the selector name is just a stray TXT.
            if tags.get("v", "").upper() != "DKIM1" and "p" not in tags:
                continue
            found += 1
            if "p" not in tags:
                findings.append(Finding(
                    "DKIM", f"TXT @ {name}", "warn",
                    f"`{txt}` — no p= public key: the record is unusable",
                    "Publish the public key your mail provider generated"))
                continue
            if tags["p"] == "":
                findings.append(Finding(
                    "DKIM", f"TXT @ {name}", "warn",
                    f"`{txt}` — p= is empty: a REVOKED key (RFC 8463), "
                    "distinct from no key at all",
                    "Publish a real public key, or remove the record entirely"))
                continue
            bits = dkim_key_bits(tags["p"])
            detail = f"`{txt}`"
            if bits:
                detail += f" — {tags.get('k', 'rsa')} key ≈{bits} bits"
            findings.append(Finding("DKIM", f"TXT @ {name}", "pass", detail, ""))

    if not found:
        # This is the one place where "no findings" might just mean "wrong
        # selector" — the docs panel says so explicitly, and so does this
        # finding, rather than letting a blank read as "no DKIM."
        findings.append(Finding(
            "DKIM", "<selector>._domainkey." + domain, "missing",
            f"no DKIM record found for any of the {len(selectors)} tried "
            f"selectors ({', '.join(selectors)}) — DKIM selectors are NOT "
            "discoverable via DNS; this may simply mean the right selector "
            "isn't in the list",
            "Find your provider's selector (e.g. Google's is in the admin "
            "console) and add it to the selector list, or set up DKIM signing"))
    return findings


# ---------------------------------------------------------------------------
# A1. MX
# ---------------------------------------------------------------------------

def audit_mx(domain: str, dns: Dns) -> list[Finding]:
    records = dns.mx(domain)
    if not records:
        return [Finding(
            "MX", "MX @ " + domain, "fail",
            "no MX records — modern MTAs mostly no longer fall back to the "
            "domain's A record (that implicit-MX behaviour is legacy, not "
            "something to rely on), so mail to this domain is undeliverable",
            "Publish MX records pointing at your mail provider "
            "(e.g. `10 aspmx.l.google.com.`)")]

    findings: list[Finding] = []
    for pref, host in records:
        addrs = dns.addresses(host)
        if addrs:
            findings.append(Finding(
                "MX", f"MX {pref} {host}", "pass",
                f"resolves ({len(addrs)} address{'es' if len(addrs) != 1 else ''})", ""))
        else:
            # An MX pointing at a dead hostname is common, easy to miss, and
            # silently eats mail — the record exists, the host doesn't.
            findings.append(Finding(
                "MX", f"MX {pref} {host}", "fail",
                "hostname does not resolve (no A/AAAA) — mail routed here "
                "bounces or vanishes",
                "Fix or remove the MX entry; verify the hostname in your "
                "provider's setup instructions"))
    return findings


# ---------------------------------------------------------------------------
# A5. Advanced / opt-in checks
# ---------------------------------------------------------------------------

def fetch_url(url: str, timeout: float = 10.0) -> str | None:
    """The one non-DNS step in the script (opt-in MTA-STS policy fetch)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PyShell-EmailDnsAudit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(65536).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None


def audit_advanced(domain: str, dns: Dns, check_mta_sts: bool,
                   check_tlsrpt: bool, check_bimi: bool) -> list[Finding]:
    findings: list[Finding] = []
    if check_mta_sts:
        findings.extend(audit_mta_sts(domain, dns))
    if check_tlsrpt:
        findings.extend(audit_tlsrpt(domain, dns))
    if check_bimi:
        findings.extend(audit_bimi(domain, dns))
    return findings


def audit_mta_sts(domain: str, dns: Dns) -> list[Finding]:
    name = f"_mta-sts.{domain}"
    txts = dns.txt(name)
    record = next((t for t in txts if "STSv1" in t), None)
    if record is None:
        return [Finding("Advanced", f"TXT @ {name}", "missing",
                        "no MTA-STS record",
                        "v=STSv1; id=20250101T000000")]
    findings = [Finding("Advanced", f"TXT @ {name}", "pass", f"`{record}`", "")]
    # The DNS record only *advertises* the policy; fetch the policy itself
    # (the one non-DNS step, gated behind this toggle).
    policy = fetch_url(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
    if policy is None:
        findings.append(Finding(
            "Advanced", f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
            "fail",
            "policy URL unreachable — receivers in enforce mode will not "
            "treat the domain as MTA-STS-protected",
            "Serve the policy at that exact path over HTTPS"))
    else:
        mode = next((line.split(":", 1)[1].strip()
                     for line in policy.splitlines()
                     if line.strip().lower().startswith("mode:")), "?")
        if mode == "enforce":
            findings.append(Finding("Advanced", "mta-sts.txt", "pass",
                                    "policy fetched, mode: enforce", ""))
        elif mode == "testing":
            findings.append(Finding("Advanced", "mta-sts.txt", "warn",
                                    "policy fetched, mode: testing — no mail "
                                    "is actually refused yet",
                                    "Move to mode: enforce once TLS failures "
                                    "in reports look benign"))
        else:
            findings.append(Finding("Advanced", "mta-sts.txt", "warn",
                                    f"policy fetched, mode: {mode!r}", ""))
    return findings


def audit_tlsrpt(domain: str, dns: Dns) -> list[Finding]:
    name = f"_smtp._tls.{domain}"
    txts = dns.txt(name)
    record = next((t for t in txts if t.lower().startswith("v=tlsrpt1")), None)
    if record is None:
        return [Finding("Advanced", f"TXT @ {name}", "missing",
                        "no TLS-RPT record — no reports about TLS delivery "
                        "failures",
                        "v=TLSRPT1; rua=mailto:tls-reports@" + domain)]
    has_rua = "rua=" in record
    return [Finding(
        "Advanced", f"TXT @ {name}",
        "pass" if has_rua else "warn",
        f"`{record}`" + ("" if has_rua else " — no rua= destination"),
        "" if has_rua else "Add rua=mailto:… so reports go somewhere")]


def audit_bimi(domain: str, dns: Dns) -> list[Finding]:
    name = f"default._bimi.{domain}"
    txts = dns.txt(name)
    record = next((t for t in txts if "BIMI1" in t), None)
    if record is None:
        return [Finding(
            "Advanced", f"TXT @ {name}", "missing",
            "no BIMI record — only checked at the default selector (same "
            "discoverability problem as DKIM, but only one common selector "
            "in practice)",
            "v=BIMI1; l=https://" + domain + "/logo.svg")]
    has_logo = "l=" in record
    return [Finding(
        "Advanced", f"TXT @ {name}", "pass" if has_logo else "warn",
        f"`{record}`" + ("" if has_logo else " — no l= logo URL"),
        "" if has_logo else "Add l=https://…/logo.svg (SVG, and BIMI needs "
        "a VMC certificate for most mailbox providers)")]


# ---------------------------------------------------------------------------
# A6. Summary — the plain-language readiness sentence
# ---------------------------------------------------------------------------

def build_summary(findings: list[Finding]) -> str:
    """One readiness sentence (plus caveats) — the actual deliverable."""
    def worst(pillar: str) -> str | None:
        order = {"fail": 0, "missing": 0, "warn": 1, "pass": 2}
        states = [f.status for f in findings if f.pillar == pillar]
        return min(states, key=lambda s: order[s]) if states else None

    mx, spf, dmarc, dkim = worst("MX"), worst("SPF"), worst("DMARC"), worst("DKIM")

    if spf in (None, "missing") and dmarc in (None, "missing"):
        sentence = ("Neither SPF nor DMARC is published — anyone can send "
                    "mail claiming to be from this domain, and nothing will "
                    "even report it.")
    elif dmarc in (None, "missing"):
        sentence = ("SPF is published, but there is no DMARC record — "
                    "receiving servers get no spoofing policy and send no "
                    "reports.")
    elif dmarc == "warn" and spf in ("pass", "warn"):
        sentence = ("SPF and DMARC are both present, but DMARC is monitor-only "
                    "(p=none) — spoofed mail is being reported on, not "
                    "blocked yet.")
    elif dmarc == "pass" and spf == "pass":
        sentence = ("SPF and DMARC are both enforced — spoofed mail is being "
                    "blocked or quarantined.")
    else:
        sentence = ("Email authentication is partially in place — see the "
                    "per-pillar findings for what's missing.")

    caveats: list[str] = []
    if spf == "warn":
        caveats.append("SPF ends in ~all (softfail) rather than -all — "
                       "nothing is hard-rejected by SPF alone.")
    if mx == "fail":
        caveats.append("MX is broken: no records, or a host that doesn't "
                       "resolve.")
    if dkim in (None, "missing"):
        caveats.append("No DKIM key found for the tried selectors — DKIM "
                       "selectors aren't discoverable, so add your "
                       "provider's selector before concluding DKIM is absent.")
    elif dkim == "warn":
        caveats.append("A DKIM key was found, but something needs attention "
                       "(e.g. a revoked key).")

    return " ".join([sentence] + caveats).strip()


# ---------------------------------------------------------------------------
# Report & artifacts
# ---------------------------------------------------------------------------

STATUS_ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌", "missing": "❌"}


def esc_cell(val: str, max_len: int = 200) -> str:
    s = str(val).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def pillar_status(findings: list[Finding], pillar: str) -> str:
    """Collapse a pillar's findings to one status for the summary table."""
    order = {"fail": 0, "missing": 0, "warn": 1, "pass": 2}
    states = [f.status for f in findings if f.pillar == pillar]
    return min(states, key=lambda s: order[s]) if states else "—"


def build_report(domain: str, findings: list[Finding]) -> str:
    lines = [f"## Email DNS audit — {domain}", "", build_summary(findings), ""]
    lines += ["| Pillar | Status |", "| --- | --- |"]
    for pillar in ("MX", "SPF", "DMARC", "DKIM"):
        st = pillar_status(findings, pillar)
        lines.append(f"| {pillar} | {STATUS_ICON.get(st, '—')} {st} |")
    lines += ["", "### Findings", "",
              "| Pillar | Record | Status | Detail | Fix |",
              "| --- | --- | --- | --- | --- |"]
    for f in findings:
        lines.append(f"| {f.pillar} | {esc_cell(f.record)} | "
                     f"{STATUS_ICON[f.status]} {f.status} | "
                     f"{esc_cell(f.detail) or '—'} | "
                     f"{esc_cell(f.recommendation) or '—'} |")
    return "\n".join(lines)


def write_artifacts(domain: str, findings: list[Finding], raw: RawRecords,
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return

    with open(os.path.join(out_dir, "dns_records_raw.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"domain": domain, "records": raw.entries}, fh,
                  indent=2, ensure_ascii=False)

    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump({"domain": domain, "findings": [asdict(f) for f in findings],
                   "summary": build_summary(findings)},
                  fh, indent=2, ensure_ascii=False)

    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(report + "\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_audit(domain: str, dns: Dns, selectors: list[str],
              check_mta_sts: bool, check_tlsrpt: bool, check_bimi: bool
              ) -> list[Finding]:
    """The full audit, phase by phase, with progress events. Pure aside from
    the Dns object (tests inject a stub)."""
    phases = [
        ("MX", 0, 15, lambda: audit_mx(domain, dns)),
        ("SPF", 15, 45, lambda: audit_spf(domain, dns)),
        ("DMARC", 45, 60, lambda: audit_dmarc(domain, dns)[0]),
        ("DKIM", 60, 90, lambda: audit_dkim(domain, selectors, dns)),
    ]
    findings: list[Finding] = []
    for name, lo, hi, fn in phases:
        emit({"type": "progress", "pct": lo, "message": f"Checking {name}"})
        result = fn()
        findings.extend(result)
        emit({"type": "progress", "pct": hi, "message": f"{name} done"})
    emit({"type": "progress", "pct": 90, "message": "Advanced checks"})
    findings.extend(audit_advanced(domain, dns, check_mta_sts,
                                   check_tlsrpt, check_bimi))
    emit({"type": "progress", "pct": 100, "message": "Done"})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Email DNS Audit — SPF, DMARC, DKIM and MX for a domain")
    parser.add_argument("--domain", required=True,
                        help="Bare domain, no scheme — e.g. example.com")
    parser.add_argument("--dkim-selectors", default=None,
                        help="DKIM selectors to try, one per line "
                             "(default: common provider list)")
    parser.add_argument("--nameserver", default=None,
                        help="Custom resolver, e.g. 1.1.1.1 "
                             "(default: system resolver)")
    parser.add_argument("--check-mta-sts", action="store_true",
                        help="Check MTA-STS (fetches a policy URL — not "
                             "DNS-only)")
    parser.add_argument("--check-tlsrpt", action="store_true",
                        help="Check TLS-RPT (_smtp._tls TXT)")
    parser.add_argument("--check-bimi", action="store_true",
                        help="Check BIMI (default._bimi TXT)")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="DNS timeout per lookup, seconds")
    args = parser.parse_args()

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no lookups performed", flush=True)
        return 0

    if dns is None:
        print("✗ dnspython is not installed — run Prepare Env",
              file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Environment not ready\n\n❌ `dnspython` is not installed. "
              "Press **Prepare Env** and run again."})
        return 2

    domain = args.domain.strip().rstrip(".").lower()
    # A full URL pasted into a domain field is the classic input mistake —
    # peel scheme and path instead of failing three phases later.
    if "://" in domain or "/" in domain:
        domain = domain.split("://", 1)[-1].split("/", 1)[0]

    selectors = (args.dkim_selectors.strip().splitlines()
                 if args.dkim_selectors and args.dkim_selectors.strip()
                 else list(DEFAULT_DKIM_SELECTORS))
    selectors = [s.strip() for s in selectors if s.strip()]

    print(f"Auditing mail DNS for {domain}", flush=True)
    status(f"Resolving {domain}…")

    ns_desc = f" via {args.nameserver}" if args.nameserver else ""
    dns_ = Dns(args.nameserver, args.timeout)
    if not dns_.domain_exists(domain):
        message = f"{domain} does not resolve (NXDOMAIN)"
        print(f"✗ {message}", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Audit failed\n\n❌ **{esc_cell(message)}**"})
        status("Domain not found")
        return 1

    print(f"Domain exists; using resolver{ns_desc}", flush=True)
    findings = run_audit(domain, dns_, selectors,
                         args.check_mta_sts, args.check_tlsrpt, args.check_bimi)

    emit({
        "type": "table",
        "columns": ["Pillar", "Record", "Status", "Detail"],
        "rows": [[f.pillar, f.record, f"{STATUS_ICON[f.status]} {f.status}",
                  f.detail[:200]] for f in findings],
    })

    report = build_report(domain, findings)
    emit({"type": "markdown", "content": report})

    write_artifacts(domain, findings, dns_.raw, report)
    status(build_summary(findings)[:120])
    print("\n" + build_summary(findings), flush=True)

    # A fully spoofable domain is a successful audit that found a bad
    # result — not a script failure.
    return 0


if __name__ == "__main__":
    sys.exit(main())
