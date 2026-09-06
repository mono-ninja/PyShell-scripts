# TLS Audit

A [PyShell](https://github.com/mono-ninja/PyShell) script that grades a
host's TLS layer — certificate chain, expiry, hostname match, key
strength, signature algorithm, protocol support, weak ciphers, the
SC-081 lifetime schedule and the post-quantum hybrid — from **seven
TLS handshakes, zero HTTP requests** (an eighth, optional probe
rides on the system `openssl`). The transport-side
sibling of [Security Headers](../security-headers): identical scoring
model (0–100, letter grade, findings with config-change fixes), the
two reports read as one system.

Active by necessity but benign: every connection is a handshake a
browser would make, nothing is sent after it, and the report footer
counts exactly what was attempted.

## What it does

- **Certificate** — chain of trust against the system store, hostname
  match (RFC 6125: SANs first, wildcard rules, legacy CN fallback),
  expiry with a 7-day/30-day escalation, the **SC-081 lifetime
  schedule** (398 days before 2026-03-15, 200 from 2026-03-15, 100
  from 2027-03-15, 47 from 2029-03-15 — the cap follows the issue
  date, not a flat number), the **renewal-cadence verdict** (at 47
  days, manual renewal is an outage waiting to happen — automate),
  public key strength (RSA/EC/Ed25519), signature
  algorithm (SHA-1/MD5 flagged). The certificate is parsed from its
  DER bytes, so a **self-signed or expired cert still gets fully
  described** — an audit of a broken host must not come back empty.
- **Protocols** — one pinned handshake per version: TLS 1.0/1.1
  offered → fail (deprecated, RFC 8996); TLS 1.2 missing → warn
  (modern but drops older clients); TLS 1.3 missing → warn.
- **Weak ciphers** — a TLS 1.2 handshake offering only
  NULL/EXPORT/DES/RC4/IDEA/anon suites: accepted → fail with the
  negotiated suite named.
- **Post-quantum (informational)** — the X25519MLKEM768 hybrid
  (group `0x11EC`) probed via the system `openssl s_client`
  offering it as the only group: negotiated / refused / no TLS 1.3
  (a TLS 1.2 server ignores key-share groups — never read as
  "refused"). Needs a local OpenSSL ≥ 3.5; otherwise **not
  checked**, never "not supported". Severity 0 on every branch —
  the grade never moves for PQ.
- **Honest "cannot probe"** — when the local OpenSSL refuses to offer
  a version or cipher client-side, the row says so and is **not
  scored**; the fix section points at `nmap --script ssl-enum-ciphers`.
- **Graded like Security Headers** — pass earns full credit, warn
  half, fail none; informational rows stay out of the denominator.
  Grade F is a successful audit that found a broken endpoint.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — nothing to install (standard library only).
3. **Host** — `example.com`, `example.com:8443` or `https://example.com`
   (scheme and path ignored, port defaults to 443). Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 main.py --target example.com
python3 main.py --target example.com:8443
python3 main.py --target https://example.com --timeout 15
python3 main.py --target example.com --cert-only
```

## Result

- **Results tab** — the grade headline, the findings table (check /
  status / detail / fix), and a certificate summary: dates, key,
  signature, SANs.
- **Artifacts** — `tls_raw.json` (negotiated session, parsed
  certificate fields, leaf+chain DER, every probe's outcome),
  `findings.json` (score/grade/findings, for CI), `report.md`.

## Exit codes

- `0` — the endpoint was reached and audited; the grade is a result,
  not a failure.
- `1` — the endpoint could not be reached at all (DNS, refused,
  timeout — the first handshake failed), or artifacts can't be
  written.
- `2` — the target can't be parsed as `host[:port]`.

## Layout

```
tls-audit/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: argparse, seven connections, events
├── docs/
│   ├── pyshell.md       # operator docs (Docs panel)
│   └── pyshell_ua.md    # Ukrainian translation
└── src/
    ├── target.py        # host[:port] / URL parsing
    ├── connect.py       # handshake machinery, protocol & weak-cipher probes
    ├── certinfo.py      # DER walker: dates, CNs, SANs, key, signature; RFC 6125 matching
    ├── checks.py        # the findings — pure functions over collected facts
    └── report.py        # score → grade, markdown report
```

## License

[MIT](../LICENSE), same as the repository.
