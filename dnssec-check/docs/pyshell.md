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

- **Domain** — the name to validate; the chain is walked from the
  root through the TLD and every intermediate zone down to it. A name
  that is not a zone cut of its own — `www.example.com` inside
  `example.com` — is ordinary data in its parent zone: it inherits
  that zone's verdict rather than being reported as unsigned. Unicode
  names are accepted and converted to punycode (`мон.укр` →
  `xn--l1acc.xn--j1amh`).
- **Resolver IP (optional)** — IPv4 or IPv6; default is the system
  resolver (the first usable non-link-local address it lists). Point
  it at a different one to separate "my resolver lies/breaks" from
  "the zone is broken".
- **Per-query timeout (s)** — 3 to 60. Each query gets one retry and
  a TCP fallback when the UDP answer is truncated (DNSKEY sets are
  big). The whole walk additionally shares a 150-second budget, so a
  resolver that swallows packets cannot stall the run past the
  script's 180-second manifest timeout.

---

## Result

- **Results tab** — the chain table (zone · step · ✓/✗ · note) and
  the report:
  - **Chain** — anchor verification, then per zone: DS fetch,
    DS signature validation, DS↔DNSKEY match, DNSKEY validation. The
    DS is re-hashed with the digest type the DS record itself
    declares (SHA-256, SHA-384 or SHA-1), so a zone that does not use
    SHA-256 is not mistaken for a broken one.
  - **Key inventory** — every DNSKEY with tag, role (KSK/ZSK),
    algorithm, bits; RSA under 2048 bits, RSA/SHA-1 and DSA flagged
    weak. The heading names the zone these keys belong to: when the
    chain stops above the target (an unsigned delegation, a broken
    link), the inventory describes the last zone that validated, not
    the target.
  - **Signature expiry** — nearest RRSIG expiry in days, for that
    same zone; under 3 days gets a warning (zones that let signatures
    lapse go bogus).
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
| 1 | the resolver answered nothing at all — the run could not start |
| 2 | bad arguments: not a domain, resolver not an IP, timeout outside 3–60 |

Only a resolver that fails on the very first query (the root DNSKEY)
gives exit 1. A chain that breaks lower down is a **result**: the run
exits 0 with 🔴 bogus or ⚫ indeterminate, and the report says where
it stopped.

## Related

- **Email DNS Audit** — SPF/DKIM/DMARC, the mail records of the
  same zone.
- **Subdomain Search** — the passive inventory of the zone.
