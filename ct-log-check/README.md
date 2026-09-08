# CT Log Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that reads
**every certificate ever issued for a domain** out of the certificate
transparency logs (the crt.sh feed — the same source Subdomain Search
reads for *names*; this one reads *issuances*). TLS Audit inspects the
**live** certificate; this reads the **history**. Passive: one feed
fetch plus a couple of DNS-over-HTTPS lookups — nothing is probed.

## What it does

- **The timeline** — issuances per month (a bar chart): the renewal
  rhythm, accelerations and silences at a glance.
- **The issuers, grouped by CA** — your main CA and *everyone else who
  ever issued for the domain*, the headline. Grouping is by CA, never
  by the intermediate that signed: `CN=R3`, `CN=E5` and `CN=X3` are one
  Let's Encrypt, and a CN-keyed census lists one CA a dozen times and
  buries the real stranger (isc.org: 48 intermediates, 10 CAs). An
  unfamiliar CA in that list is either history (a rotation) or a
  question — who ordered that cert?
- **One issuance, counted once** — a precertificate and its final
  certificate are two crt.sh rows with different ids and the same
  serial. They are folded on `(issuer_ca_id, serial_number)`; without
  that every count roughly doubles.
- **Wildcards** — the `*.domain` certificates, each covering
  everything below it.
- **Names** — every name the certs cover, the ones still covered by a
  valid certificate separated from the expired history. Which names
  still *exist* is a DNS question — the report says so and points at
  Subdomain Search instead of guessing.
- **The burst flag** — the recent pace against the last year's monthly
  average.
- **CAA vs the actual issuers** — the policy half nobody reads: the
  domain's CAA records (who is *allowed* to issue, via DNS-over-HTTPS,
  parents climbed the way a CA does — RFC 8659, stopping at the
  registrable domain) compared with the CAs holding **live**
  certificates: allowed ✅ · outside the list 🔴 (issued before the
  policy, or a gap in it) · unrecognized ⚪ (the curated issuer→CAA
  mapping doesn't know every CA — never guessed into a verdict). When
  the domain publishes **no** CAA record, no CA is called "outside" —
  there is no list to be outside of; they are reported as
  unconstrained, under the plain statement that any CA in the world may
  issue. The nuance is said aloud: CAA governs from publication, so a
  live certificate may legitimately predate your own policy.
- **An old feed, read honestly** — when the newest issuance is months
  old, that is the crt.sh cap (very large domains: only the oldest
  ~5000 rows come back) **or** a dormant domain, and only the feed size
  tells them apart. A large feed gets the cap named and every
  "valid now" count withheld; a small one is reported as dormant with
  its counts intact. Neither is guessed.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **Domain** — a registrable domain, no scheme (`example.com`).
   Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md)
— the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --domain example.com
python3 main.py --domain example.com --timeout 90 --skip-caa
```

## Result

- **Results tab** — the CA table (CA · certificates · intermediates),
  the issuance-per-month chart, and the report.
- **Artifacts** — `report.md`, `findings.json` (every record: cert id,
  the certificate's identity key, name, issuer, validity; the per-CA
  and per-intermediate censuses; the CAA policy and verdicts).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the history |
| 1 | crt.sh unreachable / non-JSON, or no records for the domain |
| 2 | bad arguments (not a domain) |

## Layout

```
ct-log-check/
├── pyshell.yaml      # manifest: form fields, bindings, artifacts
├── main.py           # feed · parse · analyze · report
├── requirements.txt  # requests
└── docs/
    ├── pyshell.md    # operator docs (Docs panel)
    └── pyshell_ua.md # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
