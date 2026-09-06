# DNSSEC Check

**Can the DNS answer be trusted?** The DS/DNSKEY chain is validated
from the IANA root trust anchor (KSK-2017, tag 20326) through every
parent zone down to the target — each delegation's DS against the
parent's keys, each DNSKEY set matched to its DS, every signature
cryptographically validated **here**, not taken from the resolver's
word. Verdicts in plain words: 🟢 secure · ⚪ insecure (unsigned) ·
🟠 signed but no DS at the parent · 🔴 bogus · ⚫ indeterminate.

---

## Before running

1. Enter the **Domain** to validate. Optionally a **Resolver IP**
   (8.8.8.8, 1.1.1.1, your local one) — the validation is done by
   this script either way; the resolver is just the transport.
2. **Prepare Env** — installs `dnspython`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **Domain** — the zone to validate; the chain is walked from the
  root through the TLD and every intermediate zone down to it.
- **Resolver IP (optional)** — default: the system resolver. Point
  it at a different one to separate "my resolver lies/breaks" from
  "the zone is broken".
- **Per-query timeout (s)** — each query gets one retry and a TCP
  fallback when the UDP answer is truncated (DNSKEY sets are big).

---

## Result

- **Results tab** — the chain table (zone · step · ✓/✗ · note) and
  the report:
  - **Chain** — anchor verification, then per zone: DS fetch,
    DS signature validation, DS↔DNSKEY match, DNSKEY validation.
  - **Key inventory** — every DNSKEY with tag, role (KSK/ZSK),
    algorithm, bits; RSA under 2048 bits and RSA/SHA-1 flagged weak.
  - **Signature expiry** — nearest RRSIG expiry in days; under 3
    days gets a warning (zones that let signatures lapse go bogus).
  - **NSEC/NSEC3** — from a random-name probe: whether the zone's
    negative answers reveal its name list.
  - **What the verdict means** — a paragraph per verdict, including
    the SERVFAIL story for bogus and the "publish the DS" fix for
    signed-but-no-DS.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the verdict (any of the five) is the result |
| 1 | the resolver is unreachable |
| 2 | bad arguments: not a domain, resolver not an IPv4 |

## Related

- **DNS Propagation** — the other half of DNS trust: is the answer
  the same at every resolver?
- **Email DNS Audit** — SPF/DKIM/DMARC, the mail records of the
  same zone.
- **Subdomain Search** — the passive inventory of the zone.
