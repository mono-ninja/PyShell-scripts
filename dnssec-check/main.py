#!/usr/bin/env python3
"""dnssec-check/main.py — can the DNS answer be trusted?

This script asks whether a DNS answer is cryptographically
trustworthy.  The DS/DNSKEY chain is validated
from the IANA root trust anchor (KSK-2017, key tag 20326 — the same
anchor every validating resolver ships) down through every parent
zone to the target: each delegation's DS is verified against the
parent's keys, each zone's DNSKEY set is matched to its DS and its
self-signature validated.

The verdict vocabulary is the RFC 4033 one, in plain words:

- **secure** — the full chain validates; a validating resolver
  (which is most of them now) will answer for this zone with the
  `AD` bit, knowing the data wasn't tampered with on the way;
- **insecure (unsigned)** — no DS at a delegation: the zone opted
  out of DNSSEC; nothing is wrong, but nothing is provable either;
- **signed but no DS at the parent** — the zone HAS keys but the
  parent doesn't publish the DS: resolvers treat it as unsigned and
  all the signing work is wasted (the classic half-finished setup);
- **bogus** — the chain breaks: a signature that doesn't validate, a
  DNSKEY that doesn't match the DS. A validating resolver will
  SERVFAIL here — that's what "DNSSEC broke my site" looks like;
- **indeterminate** — the chain couldn't be built (resolver issues);
  reported honestly, never guessed at.

On top of the verdict: key inventory (algorithms, RSA key sizes —
1024-bit keys are flagged weak, KSK/ZSK split), signature expiry
(roots roll ~ every two weeks; zones that let signatures lapse go
bogus), and an NSEC/NSEC3 peek from a random-name probe.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import re
import string
import sys
import time

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset

# IANA root trust anchor — KSK-2017 (tag 20326, RSA/SHA-256, SHA-256
# digest). Every validating resolver ships exactly this trust.
ANCHOR = (20326, 8, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC"
                    "683457104237C7F8EC8D")

ALGORITHM_NAMES = {1: "RSA/MD5", 3: "DSA/SHA-1", 5: "RSA/SHA-1",
                   6: "DSA-NSEC3/SHA-1", 7: "RSA/SHA-1-NSEC3",
                   8: "RSA/SHA-256", 10: "RSA/SHA-512", 13: "ECDSA/P-256",
                   14: "ECDSA/P-384", 15: "Ed25519", 16: "Ed448"}

# Algorithms nobody should still be signing with (RFC 8624).
WEAK_ALGORITHMS = (1, 3, 5, 6, 7)

# DS digest types, by the number the DS record itself carries. SHA-256
# is the norm; SHA-384 and SHA-1 are both legal and appear in the wild,
# and a SHA-256-only comparison would call such a zone bogus.
DIGEST_NAMES = {1: "SHA1", 2: "SHA256", 4: "SHA384"}

FLAG_KSK = 0x0001  # bit 15 of DNSKEY flags (257 = KSK, 256 = ZSK)

# One wall-clock budget for the whole walk, so that no combination of
# --timeout and retries can outlive the manifest's run timeout (180 s).
RUN_BUDGET = 150


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------- probe

class QueryError(Exception):
    """A DNS query that cannot be answered at all."""


class Probe:
    """DNS queries with DNSSEC records requested: one retry per query,
    TCP fallback when the UDP answer is truncated. Every query draws on
    one shared deadline — a resolver that black-holes traffic cannot
    stretch the walk past RUN_BUDGET."""

    def __init__(self, resolver: str, timeout: int,
                 budget: float = RUN_BUDGET):
        self.resolver = resolver
        self.timeout = timeout
        self.deadline = time.monotonic() + budget

    def _left(self) -> float:
        return self.deadline - time.monotonic()

    def query(self, qname: str, rdtype: str) -> dns.message.Message:
        msg = dns.message.make_query(qname, rdtype, want_dnssec=True)
        last_exc: Exception | None = None
        for attempt in (1, 2):
            left = self._left()
            if left <= 0:
                raise QueryError(f"{qname}/{rdtype}: the {RUN_BUDGET}s run "
                                 f"budget is spent")
            try:
                resp = dns.query.udp(msg, self.resolver,
                                     timeout=min(self.timeout, left))
                if resp.flags & dns.flags.TC:
                    resp = dns.query.tcp(
                        msg, self.resolver,
                        timeout=max(0.1, min(self.timeout, self._left())))
                return resp
            except Exception as exc:  # timeout / network / ServFail wire
                last_exc = exc
                if attempt == 1:
                    time.sleep(0.3)
        raise QueryError(f"{qname}/{rdtype}: {last_exc}")


def rrset_of(resp: dns.message.Message, rdtype: str,
             covers: str = "") -> dns.rrset.RRset | None:
    want = dns.rdatatype.from_text(rdtype)
    want_covers = dns.rdatatype.from_text(covers) if covers else None
    for section in (resp.answer, resp.authority):
        for rr in section:
            if rr.rdtype == want:
                if want == dns.rdatatype.RRSIG and want_covers is not None:
                    if rr.covers == want_covers:
                        return rr
                else:
                    return rr
    return None


def has_own_ns(resp: dns.message.Message) -> bool:
    """NS records in the ANSWER section — the name is a zone cut of its
    own. The authority section carries the parent's NS on a referral and
    the SOA on NODATA; neither proves a cut, so only the answer counts."""
    return any(rr.rdtype == dns.rdatatype.NS for rr in resp.answer)


# ----------------------------------------------------------------- analysis

def verify_anchor(root_keys: dns.rrset.RRset) -> tuple[object | None, str]:
    """Does any root key hash to the IANA anchor? (The real crypto —
    DS digest over the DNSKEY, offline.)"""
    tag, algo, digest_hex = ANCHOR
    for key in root_keys:
        try:
            ds = dns.dnssec.make_ds(".", key, "SHA256")
        except (ValueError, dns.dnssec.AlgorithmKeyMismatch,
                dns.dnssec.DeniedByPolicy):
            continue
        if ds.key_tag == tag and ds.digest.hex().upper() == digest_hex:
            return key, f"root KSK-2017 (tag {tag}) matches the IANA anchor"
    return None, "no root key matches the IANA anchor — the trust base " \
                 "cannot be established"


def ds_match(ds_rrset: dns.rrset.RRset,
             dnskey_rrset: dns.rrset.RRset) -> object | None:
    """The DNSKEY whose DS hash is in the parent's DS set. Each DS is
    re-hashed with the digest type that record declares — comparing
    everything as SHA-256 would report a SHA-384 or SHA-1 delegation as
    bogus. (SHA-1 needs the permissive policy: dnspython's default one
    refuses to compute it at all.)"""
    for ds in ds_rrset:
        digest = DIGEST_NAMES.get(ds.digest_type)
        if digest is None:                       # GOST and other exotica
            continue
        for key in dnskey_rrset:
            try:
                computed = dns.dnssec.make_ds(
                    dnskey_rrset.name, key, digest,
                    policy=dns.dnssec.allow_all_policy)
            except (ValueError, dns.dnssec.AlgorithmKeyMismatch,
                    dns.dnssec.DeniedByPolicy):
                continue
            if (computed.key_tag == ds.key_tag
                    and computed.algorithm == ds.algorithm
                    and computed.digest == ds.digest):
                return key
    return None


def key_size(key) -> int | None:
    """Bits of the public key: RSA from the modulus blob, ECDSA/Ed25519
    fixed sizes. (Public knowledge printed on the wire — no crypto.)"""
    raw = key.key
    if key.algorithm in (5, 7, 8, 10):          # RSA family
        if not raw:
            return None
        if raw[0] == 0:                          # 16/24-bit exponent len
            exp_len = int.from_bytes(raw[:3], "big")
            offset = 3
        else:
            exp_len = raw[0]
            offset = 1
        modulus = raw[offset + exp_len:]
        return len(modulus) * 8 if modulus else None
    if key.algorithm in (13, 14):                # ECDSA P-256 / P-384
        return {13: 256, 14: 384}[key.algorithm]
    if key.algorithm == 15:
        return 253                               # Ed25519 effective
    if key.algorithm == 16:
        return 456                               # Ed448 effective
    return None


def key_inventory(dnskey_rrset: dns.rrset.RRset) -> list[dict]:
    inv = []
    for key in dnskey_rrset:
        inv.append({
            "tag": dns.dnssec.key_id(key),
            "role": "KSK" if key.flags & FLAG_KSK else "ZSK",
            "algorithm": key.algorithm,
            "algorithm_name": ALGORITHM_NAMES.get(key.algorithm,
                                                  f"algo {key.algorithm}"),
            "bits": key_size(key),
            "weak": key.algorithm in WEAK_ALGORITHMS or (
                key.algorithm in (8, 10)
                and (key_size(key) or 0) < 2048),
        })
    return sorted(inv, key=lambda k: (-k["bits"] if k["bits"] else 0,
                                      k["tag"]))


def sig_days_left(rrsig_rrset: dns.rrset.RRset) -> float | None:
    expiries = [r.expiration for r in rrsig_rrset]
    if not expiries:
        return None
    return (min(expiries) - time.time()) / 86400


def validate_rrset(rrset: dns.rrset.RRset,
                   rrsig: dns.rrset.RRset,
                   keys: dict) -> tuple[bool, str]:
    """dns.dnssec.validate wrapped into (ok, note)."""
    try:
        dns.dnssec.validate(rrset, rrsig, keys)
        return True, "signature valid"
    except dns.dnssec.ValidationFailure as exc:
        return False, f"signature INVALID: {exc}"
    except KeyError as exc:
        return False, f"no key for the signer {exc}"
    except Exception as exc:  # malformed rdata etc.
        return False, f"cannot validate: {exc}"


# --------------------------------------------------------------------- chain

VERDICT_SECURE = "secure"
VERDICT_INSECURE = "insecure (unsigned)"
VERDICT_NO_DS = "signed but no DS at the parent"
VERDICT_BOGUS = "bogus (validation failed)"
VERDICT_INDETERMINATE = "indeterminate"


class Step:
    def __init__(self, zone: str, action: str, ok: bool, note: str):
        self.zone, self.action, self.ok, self.note = zone, action, ok, note

    def as_dict(self) -> dict:
        return {"zone": self.zone, "action": self.action,
                "ok": self.ok, "note": self.note}


class ChainResult:
    def __init__(self, zone: str):
        self.zone = zone
        self.verdict = VERDICT_INDETERMINATE
        self.steps: list[Step] = []
        self.inventory: list[dict] = []
        # Which zone the inventory and the signature expiry describe. The
        # walk stops wherever the chain ends, so that is often a zone
        # ABOVE the target — saying so is the difference between a report
        # and a misleading one.
        self.inventory_zone: str | None = None
        self.sig_days: float | None = None
        self.nsec3: bool | None = None
        # The closest enclosing signed zone, when the target itself is
        # not a zone cut (www.example.com inside example.com).
        self.signed_zone: str | None = None
        # The very first query failed: the run never started (exit 1),
        # as opposed to a chain that merely could not be finished.
        self.unreachable = False
        self.notes: list[str] = []


def chain_zones(zone: dns.name.Name) -> list[dns.name.Name]:
    """From the TLD down to the zone: com → example.com → a.example.com."""
    zones = []
    walker = zone
    while walker != dns.name.root:
        zones.append(walker)
        walker = walker.parent()
    return list(reversed(zones))


def probe_nsec3(probe: Probe, zone: str) -> bool | None:
    """One random-name query: NSEC3 vs NSEC in the negative proof.
    Both NXDOMAIN and empty-answer NOERROR (NODATA) count — each
    carries the zone's negative-proof records in the authority."""
    label = "".join(random.choices(string.ascii_lowercase, k=12))
    try:
        resp = probe.query(f"{label}.{zone}", "A")
    except QueryError:
        return None
    negative = resp.rcode() == dns.rcode.NXDOMAIN \
        or (resp.rcode() == dns.rcode.NOERROR and not resp.answer)
    if not negative:
        return None
    for rr in resp.authority:
        if rr.rdtype == dns.rdatatype.NSEC3:
            return True
        if rr.rdtype == dns.rdatatype.NSEC:
            return False
    return None


def zone_label(zone_text: str) -> str:
    """The root reads as a phrase, every other zone as its own name."""
    return "the root zone" if zone_text == "." else zone_text


def finish_secure(result: ChainResult, probe: Probe,
                  signed_zone: str) -> ChainResult:
    """The chain held all the way down to `signed_zone`."""
    result.verdict = VERDICT_SECURE
    result.signed_zone = signed_zone
    if signed_zone != ".":       # a random name under the root proves nothing
        result.nsec3 = probe_nsec3(probe, signed_zone)
    return result


def walk_chain(probe: Probe, zone_text: str) -> ChainResult:
    """The heart: root anchor → every delegation → the zone."""
    result = ChainResult(zone_text)
    try:
        zone = dns.name.from_text(zone_text if zone_text.endswith(".")
                                  else zone_text + ".")
    except dns.exception.DNSException:
        result.notes.append(f"{zone_text!r} is not a valid DNS name")
        return result
    if zone == dns.name.root:
        result.notes.append("the root zone itself — nothing to delegate")
        return result

    # ── level 0: the root, anchored to IANA's KSK-2017 ────────────
    try:
        root_resp = probe.query(".", "DNSKEY")
    except QueryError as exc:
        result.unreachable = True
        result.steps.append(Step(".", "fetch root DNSKEY", False, str(exc)))
        result.notes.append("cannot reach the resolver for the root keys")
        return result
    root_keys = rrset_of(root_resp, "DNSKEY")
    if root_keys is None:
        result.steps.append(Step(".", "fetch root DNSKEY", False,
                                 "no DNSKEY in the answer"))
        return result
    anchor_key, anchor_note = verify_anchor(root_keys)
    result.steps.append(Step(".", "anchor verification",
                             anchor_key is not None, anchor_note))
    if anchor_key is None:
        return result

    parent_keys: dns.rrset.RRset | None = root_keys
    parent_name = dns.name.root
    parent_text = "."            # query-safe; rendered by zone_label()

    # ── every delegation from the TLD down ────────────────────────
    for z in chain_zones(zone):
        z_text = str(z).rstrip(".")
        # DS of z, signed by the parent
        try:
            ds_resp = probe.query(z_text, "DS")
        except QueryError as exc:
            result.steps.append(Step(z_text, "fetch DS", False, str(exc)))
            result.notes.append("the chain cannot be walked further — "
                                "resolver trouble")
            return result
        if ds_resp.rcode() == dns.rcode.NXDOMAIN:
            result.verdict = VERDICT_INDETERMINATE
            result.steps.append(Step(z_text, "fetch DS", False,
                                     "NXDOMAIN — the zone does not exist"))
            return result
        ds_rrset = rrset_of(ds_resp, "DS")
        if ds_rrset is None:
            # No DS here, which is three different worlds: the zone is
            # signed but the parent never published the DS; the
            # delegation exists and is genuinely unsigned; or this label
            # is no zone cut at all and simply lives inside the parent.
            has_keys = False
            try:
                key_resp = probe.query(z_text, "DNSKEY")
                has_keys = rrset_of(key_resp, "DNSKEY") is not None
            except QueryError:
                pass
            if has_keys:
                result.verdict = VERDICT_NO_DS
                result.steps.append(Step(
                    z_text, "delegation DS", False,
                    "no DS at the parent — the delegation is unsigned "
                    "(but the zone HAS keys: publish the DS or the "
                    "signing is wasted)"))
                return result
            is_cut = True
            try:
                is_cut = has_own_ns(probe.query(z_text, "NS"))
            except QueryError:
                pass
            if is_cut:
                result.verdict = VERDICT_INSECURE
                result.steps.append(Step(
                    z_text, "delegation DS", False,
                    "no DS at the parent — the delegation is unsigned"))
                return result
            # Not a zone cut: an ordinary name inside the last validated
            # zone, and it inherits that zone's security. Calling this
            # "unsigned" would be plain wrong — the answers for it are
            # signed by the parent.
            result.steps.append(Step(
                z_text, "zone cut", True,
                f"not a delegation — the name lives inside "
                f"{zone_label(parent_text)}, whose chain validates above, "
                f"and is signed by it"))
            return finish_secure(result, probe, parent_text)
        ds_rrsig = rrset_of(ds_resp, "RRSIG", covers="DS")
        if ds_rrsig is None or parent_keys is None:
            result.verdict = VERDICT_INDETERMINATE
            result.steps.append(Step(z_text, "DS signature", False,
                                     "the DS answer carries no RRSIG — "
                                     "cannot validate (resolver issue?)"))
            return result
        ok, note = validate_rrset(ds_rrset, ds_rrsig,
                                  {parent_name: parent_keys})
        result.steps.append(Step(z_text, "validate DS", ok, note))
        if not ok:
            result.verdict = VERDICT_BOGUS
            return result

        # the zone's own keys, matched against the DS
        try:
            key_resp = probe.query(z_text, "DNSKEY")
        except QueryError as exc:
            result.steps.append(Step(z_text, "fetch DNSKEY", False,
                                     str(exc)))
            result.notes.append("resolver trouble mid-chain")
            return result
        z_keys = rrset_of(key_resp, "DNSKEY")
        if z_keys is None:
            result.verdict = VERDICT_BOGUS
            result.steps.append(Step(z_text, "DNSKEY", False,
                                     "the parent has a DS but the zone "
                                     "serves no DNSKEY — broken chain"))
            return result
        matched = ds_match(ds_rrset, z_keys)
        result.steps.append(Step(
            z_text, "DS ↔ DNSKEY match", matched is not None,
            f"key tag {dns.dnssec.key_id(matched)} matches the DS"
            if matched is not None else
            "no key in the zone hashes to the parent's DS — the zone "
            "was re-keyed without updating the parent"))
        if matched is None:
            result.verdict = VERDICT_BOGUS
            return result
        z_rrsig = rrset_of(key_resp, "RRSIG", covers="DNSKEY")
        if z_rrsig is None:
            result.verdict = VERDICT_INDETERMINATE
            result.steps.append(Step(z_text, "DNSKEY signature", False,
                                     "no RRSIG over the DNSKEY set"))
            return result
        ok, note = validate_rrset(z_keys, z_rrsig, {z: z_keys})
        result.steps.append(Step(z_text, "validate DNSKEY", ok, note))
        if not ok:
            result.verdict = VERDICT_BOGUS
            return result

        parent_keys, parent_name, parent_text = z_keys, z, z_text
        result.inventory = key_inventory(z_keys)
        result.inventory_zone = z_text
        result.sig_days = sig_days_left(z_rrsig)

    return finish_secure(result, probe, zone_text)


# -------------------------------------------------------------------- report

VERDICT_ICON = {VERDICT_SECURE: "🟢", VERDICT_INSECURE: "⚪",
                VERDICT_NO_DS: "🟠", VERDICT_BOGUS: "🔴",
                VERDICT_INDETERMINATE: "⚫"}


def build_table_event(result: ChainResult) -> dict:
    rows = [[step.zone, step.action,
             "✓" if step.ok else "✗", step.note]
            for step in result.steps]
    return {"type": "table",
            "columns": ["zone", "step", "result", "note"],
            "rows": rows}


def build_markdown(result: ChainResult) -> str:
    icon = VERDICT_ICON.get(result.verdict, "")
    out = ["# DNSSEC Check — Report\n",
           f"Zone: `{result.zone}` · Verdict: **{icon} "
           f"{result.verdict}**\n"]
    out.append("The chain was validated here — from the IANA root "
               "anchor (KSK-2017, tag 20326) through every delegation "
               "— not taken from a resolver's word.\n")

    if result.steps:
        out.append("### Chain\n")
        for step in result.steps:
            out.append(f"- {'✓' if step.ok else '✗'} **{step.zone}** · "
                       f"{step.action} — {step.note}")
        out.append("")

    if result.signed_zone and result.signed_zone != result.zone:
        out.append(f"`{result.zone}` is not a zone cut of its own — it is "
                   f"ordinary data inside "
                   f"`{zone_label(result.signed_zone)}`, so the answers "
                   f"for it carry that zone's signatures.\n")

    if result.inventory:
        out.append(f"### Key inventory (the DNSKEY set of "
                   f"`{result.inventory_zone}`)\n")
        for k in result.inventory:
            weak = " · ⚠️ **weak**" if k["weak"] else ""
            out.append(f"- tag {k['tag']} · {k['role']} · "
                       f"{k['algorithm_name']}"
                       + (f" · {k['bits']} bits" if k["bits"] else "")
                       + weak)
        ksk = sum(1 for k in result.inventory if k["role"] == "KSK")
        zsk = len(result.inventory) - ksk
        out.append(f"\nLayout: {ksk} KSK + {zsk} ZSK"
                   + (" (combined-signing style)" if ksk and zsk == 0
                      else "") + ".")
        if any(k["weak"] for k in result.inventory):
            out.append("\n⚠️ Weak keys flagged: RSA/SHA-1 is deprecated; "
                       "RSA under 2048 bits is considered breakable "
                       "in scope of a determined attacker.")
        out.append("")
    if result.sig_days is not None:
        out.append(f"Signatures of `{result.inventory_zone}`: the nearest "
                   f"expiry is **{result.sig_days:.1f} days** away."
                   + (" ⚠️ That is close — zones that let signatures "
                      "lapse go bogus." if result.sig_days < 3 else ""))
        out.append("")
    if result.nsec3 is not None and result.verdict == VERDICT_SECURE:
        out.append("Negative answers proven with "
                   + ("NSEC3 (hashed — zone content names are not "
                      "enumerable)" if result.nsec3 else
                      "NSEC (plain — the zone can be walked name by "
                      "name)").rstrip(".") + ".\n")

    verdict_notes = {
        VERDICT_SECURE: "A validating resolver answers for this zone "
            "with the AD bit — tampering on the way would be caught. "
            "This is what DNSSEC done right looks like.",
        VERDICT_INSECURE: "The zone (or a delegation above it) is not "
            "signed. Nothing is broken — but nothing is provable: a "
            "lying resolver or a hijacked path would go unnoticed.",
        VERDICT_NO_DS: "The zone has DNSKEY records but the parent "
            "doesn't publish a DS — resolvers treat it as unsigned and "
            "the signing is wasted. Publishing the DS in the parent "
            "zone completes the setup (registrar / parent DNS panel).",
        VERDICT_BOGUS: "The chain breaks somewhere above — a signature "
            "that doesn't validate or a re-keyed zone whose parent "
            "still points at the old key. **Validating resolvers will "
            "SERVFAIL for this zone**: that is the 'DNSSEC broke my "
            "site' outage shape. Fix the DS at the parent or re-sign.",
        VERDICT_INDETERMINATE: "The chain couldn't be walked to the "
            "end (resolver trouble) — try a different resolver to "
            "separate a local problem from a zone problem.",
    }
    out.append("### What the verdict means\n")
    out.append(verdict_notes.get(result.verdict, "") + "\n")
    if result.notes:
        for n in result.notes:
            out.append(f"- {n}")
        out.append("")
    out.append("\n### Related\n")
    out.append("- **Email DNS Audit** — SPF/DKIM/DMARC: the mail "
               "records of the same zone.")
    out.append("- **Subdomain Search** — the passive name inventory of "
               "the same zone.")
    return "\n".join(out)


def write_artifacts(result: ChainResult, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "zone": result.zone,
        "verdict": result.verdict,
        "anchor": {"tag": ANCHOR[0], "algorithm": "RSA/SHA-256",
                   "digest": "SHA-256:" + ANCHOR[2]},
        "steps": [s.as_dict() for s in result.steps],
        "inventory": result.inventory,
        "inventory_zone": result.inventory_zone,
        "signed_zone": result.signed_zone,
        "signature_days_left": result.sig_days,
        "nsec3": result.nsec3,
        "notes": result.notes,
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def default_resolver() -> str:
    """The system's first nameserver, IPv4 for choice: a link-local IPv6
    resolver (fe80::…%en0 — what macOS often lists first) is unusable as
    a plain query target, so it must not become the default."""
    try:
        ns = [str(n) for n in dns.resolver.get_default_resolver().nameservers]
    except Exception:
        ns = []
    for candidate in ns:
        if parse_resolver(candidate) and "." in candidate:
            return candidate
    for candidate in ns:
        if parse_resolver(candidate):
            return candidate
    return "8.8.8.8"


def parse_resolver(text: str) -> str:
    """The resolver address if it is a usable IPv4/IPv6 literal, else ""."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if addr.is_link_local or addr.is_unspecified:
        return ""
    return text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DNSSEC Check — the DS/DNSKEY chain validated from "
                    "the root anchor, with key quality and honest "
                    "verdicts")
    parser.add_argument("--domain", required=True,
                        help="the zone to validate")
    parser.add_argument("--resolver", default="",
                        help="resolver IP (v4 or v6) to query through "
                             "(default: the system resolver)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-query timeout in seconds, 3–60 "
                             "(default 10)")
    return parser


def run(probe: Probe, domain: str) -> int:
    result = walk_chain(probe, domain)
    report = build_markdown(result)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(result))
    emit({"type": "markdown", "content": report})
    write_artifacts(result, report)
    summary = f"{result.zone}: {result.verdict}"
    status(summary)
    log(f"← {summary}")
    if result.unreachable:
        # Not a verdict about the zone: nothing could be asked at all.
        print("✗ the resolver answered nothing — the run could not start",
              file=sys.stderr, flush=True)
        return 1
    return 0


def main(argv: list[str] | None = None, probe: Probe | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no queries are made", flush=True)
        return 0

    domain = args.domain.strip().strip(".").lower()
    if any(ord(ch) > 127 for ch in domain):      # IDN → punycode
        try:
            domain = dns.name.from_unicode(domain).to_text().strip(".")
        except (dns.exception.DNSException, UnicodeError):
            domain = ""
    if not domain or not re.match(r"^[a-z0-9._-]+$", domain):
        print(f"✗ {args.domain!r} is not a domain name",
              file=sys.stderr, flush=True)
        return 2

    if not 3 <= args.timeout <= 60:
        print(f"✗ --timeout must be between 3 and 60 seconds, got "
              f"{args.timeout}", file=sys.stderr, flush=True)
        return 2

    resolver = args.resolver.strip() or default_resolver()
    if not parse_resolver(resolver):
        print(f"✗ --resolver must be an IPv4 or IPv6 address, got "
              f"{resolver!r}", file=sys.stderr, flush=True)
        return 2

    log(f"Validating the DNSSEC chain of {domain} (via {resolver})")
    status(f"{domain} · root anchor → zone")
    emit({"type": "progress", "pct": 10, "message": "fetching root keys"})
    real_probe = probe or Probe(resolver, args.timeout)
    return run(real_probe, domain)


if __name__ == "__main__":
    sys.exit(main())
