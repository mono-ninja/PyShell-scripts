# DNSSEC Check

**Can the DNS answer be trusted?** The DS/DNSKEY chain is validated
from the IANA root trust anchor (KSK-2017, key tag 20326 — the same
anchor every validating resolver ships) down through every parent
zone to the target: each delegation's DS is verified against the
parent's keys, each zone's DNSKEY set is matched to its DS, every
signature is cryptographically validated. The validation happens
**here**, not in the resolver's word.

The verdict vocabulary is the RFC 4033 one, in plain words —
🟢 **secure** · ⚪ **insecure (unsigned)** · 🟠 **signed but no DS at
the parent** (the classic half-finished setup) · 🔴 **bogus** (the
"DNSSEC broke my site" SERVFAIL shape) · ⚫ **indeterminate** (honest:
the chain couldn't be walked).

On top: key inventory (algorithms, RSA key sizes — 1024-bit flagged
weak, KSK/ZSK layout), signature expiry, and an NSEC/NSEC3 peek.

The DNS line of the collection: **DNS Propagation** asks *is the
answer the same everywhere?* — this asks *is it provably authentic?*

## Using with PyShell

1. Enter the **Domain** to validate (optionally a resolver IP to
   query through — default: the system resolver).
2. Press **Prepare Env** (installs `dnspython`), then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --domain cloudflare.com
python3 main.py --domain example.com --resolver 1.1.1.1
```

## Result

- **Results tab** — the chain table (zone · step · ✓/✗ · note) and
  the report: what the verdict means, the key inventory, signature
  expiry, NSEC/NSEC3, what to do about it.
- **Artifacts** — `report.md`, `findings.json` (steps, inventory,
  anchor info).

### What gets checked

- **Anchor** — a root key must hash to the IANA trust anchor.
- **Every delegation** — DS present? DS signature valid against the
  parent's keys? DNSKEY that hashes to the DS? DNSKEY set
  self-signed?
- **Key quality** — algorithm (RSA/SHA-256, ECDSA P-256, Ed25519…),
  RSA key size < 2048 flagged, KSK/ZSK split.
- **Signature freshness** — nearest expiry in days; zones that let
  signatures lapse go bogus.
- **NSEC/NSEC3** — whether the zone's negative answers can be walked
  name-by-name.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the verdict (any of the five) is the result |
| 1 | the resolver is unreachable — nothing could be queried |
| 2 | bad arguments (not a domain, resolver not an IPv4) |

## Layout

```
dnssec-check/
├── pyshell.yaml      # manifest
├── main.py           # probe · anchor · chain · key quality · report
├── requirements.txt  # dnspython
├── docs/             # EN + UA docs
└── tests/            # 20 tests: real root-anchor crypto offline + fake-probe chains
```

## License

MIT — see the root [LICENSE](../LICENSE).
