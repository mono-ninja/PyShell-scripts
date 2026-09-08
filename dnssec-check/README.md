# DNSSEC Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that answers
one question: **can this DNS answer be trusted?** The DS/DNSKEY chain
is validated from the IANA root trust anchor (KSK-2017, key tag 20326
— the same anchor every validating resolver ships) down through every
parent zone to the target: each delegation's DS is verified against
the parent's keys, each zone's DNSKEY set is matched to its DS, every
signature is cryptographically validated. The validation happens
**here** — nothing is taken on the resolver's word. Read-only: the
script asks questions, it never changes a zone.

The verdict vocabulary is the RFC 4033 one, in plain words —
🟢 **secure** · ⚪ **insecure (unsigned)** · 🟠 **signed but no DS at
the parent** (the classic half-finished setup) · 🔴 **bogus** (the
"DNSSEC broke my site" SERVFAIL shape) · ⚫ **indeterminate** (honest:
the chain couldn't be walked).

## What gets checked

- **Anchor** — a root key must hash to the IANA trust anchor.
- **Every delegation** — DS present? DS signature valid against the
  parent's keys? A DNSKEY that hashes to the DS (in whichever digest
  type the DS declares — SHA-256, SHA-384 or SHA-1)? DNSKEY set
  self-signed?
- **Zone cuts** — a name that is not a delegation of its own
  (`www.example.com`) is ordinary data inside its parent zone and
  inherits that zone's security instead of being called unsigned.
- **Key quality** — algorithm (RSA/SHA-256, ECDSA P-256, Ed25519…),
  RSA key size under 2048 flagged, RSA/SHA-1 and DSA flagged, KSK/ZSK
  split. The report always names the zone the keys belong to — the
  walk stops where the chain ends, which is often above the target.
- **Signature freshness** — nearest RRSIG expiry in days; zones that
  let signatures lapse go bogus.
- **NSEC/NSEC3** — whether the zone's negative answers can be walked
  name by name.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `dnspython`.
3. **Domain** — a bare name, no scheme (`example.com`); optionally a
   **Resolver IP** to query through. Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --domain cloudflare.com
python3 main.py --domain www.isc.org --resolver 1.1.1.1
python3 main.py --domain example.com --resolver 8.8.8.8 --timeout 20
```

## Result

- **Results tab** — the chain table (zone · step · ✓/✗ · note) and
  the report: what the verdict means, the key inventory, signature
  expiry, NSEC/NSEC3, what to do about it.
- **Artifacts** — `report.md`, `findings.json` (steps, key inventory
  with the zone it belongs to, anchor info).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the verdict (any of the five) is the result |
| 1 | the resolver answered nothing at all — the run could not start |
| 2 | bad arguments (not a domain, resolver not an IP, timeout outside 3–60) |

A chain that breaks *below* the root is a verdict, not a failure: the
run still exits 0 with 🔴 bogus or ⚫ indeterminate.

## Layout

```
dnssec-check/
├── pyshell.yaml      # manifest: form fields, bindings, artifacts
├── main.py           # probe · anchor · chain · key quality · report
├── requirements.txt  # dnspython
└── docs/
    ├── pyshell.md    # operator docs (Docs panel)
    └── pyshell_ua.md # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
