# TLS Audit

Grades a host's TLS layer the way [**Security
Headers**](../../security-headers) grades its HTTP layer — the two
scripts audit the two halves of the same endpoint, and their reports
are deliberately identical in shape (a 0–100 score, a letter grade, a
findings table with concrete fixes).

The audit makes **seven TLS connections** and sends no HTTP requests:

1. a modern handshake to collect the certificate and what gets
   negotiated;
2. a validating handshake against the system trust store;
3–6. one pinned handshake per protocol version — TLS 1.0, 1.1, 1.2, 1.3;
7. a TLS 1.2 handshake offering *only* weak cipher suites
   (NULL, EXPORT, DES, RC4, IDEA, anonymous).

Everything a connection learns becomes a finding: chain of trust,
hostname match, expiry, key strength, signature algorithm, protocol
support, weak ciphers — each with a status, a weight in the score, and
a recommendation that is a config change, not a lecture.

---

## Before running

1. **Host** — anything that names the endpoint: `example.com`,
   `example.com:8443`, `https://example.com`. Scheme and path are
   ignored; the port defaults to 443.
2. Click **Prepare Env** — nothing to install, standard library only.
3. Press **Run** (⌘↩). A full run takes seconds; *Certificate checks
   only* takes two connections instead of seven.

The certificate is read **even when the chain is broken** — a
self-signed, expired or mismatched certificate is exactly the one an
audit must still describe, so the fields are parsed from the
certificate bytes directly rather than from the validating handshake.

---

## Fields

### Target

- **Host** — the TLS endpoint. Bare IPs work too (SNI is skipped for
  them, as a browser would).
- **Per-connection timeout (s)** — each of the connections gets this
  long. The default 10 s handles slow handshakes; the whole run is
  bounded by roughly seven times this.
- **Certificate checks only** — skip the protocol and weak-cipher
  probes. Two connections instead of seven, and the grade then covers
  the certificate alone (chain, hostname, expiry, key, signature).

---

## Result

- **Results tab** — the grade headline, a findings table (check /
  status / detail / fix), and a certificate summary with the dates,
  key, signature and SANs — the facts you quote in a ticket.
- **Artifacts** — `tls_raw.json` (everything collected: negotiated
  session, parsed certificate fields, DER of the leaf and chain,
  every probe's outcome), `findings.json` (score, grade, findings —
  machine-readable for CI), `report.md`.

### What the checks mean

| Check | Pass | Fail |
|---|---|---|
| Chain of trust | validates against the system store | self-signed, missing intermediate, untrusted root — the verify error is the detail |
| Hostname match | a SAN (or legacy CN) matches the host | no name in the certificate covers the host |
| Certificate validity | more than 30 days left | expired, not yet valid, or ≤ 7 days left; ≤ 30 days is a warn |
| Certificate lifetime | ≤ 398 days | over 398 days — outside the public-trust limit (warn) |
| Public key | RSA ≥ 2048, EC ≥ P-256, Ed25519 | RSA < 2048 or EC < P-256 |
| Signature algorithm | SHA-256+ | SHA-1 or MD5 |
| TLS 1.0 / 1.1 | refused | offered — deprecated since 2021 (RFC 8996) |
| TLS 1.2 | offered | not offered (warn — TLS 1.3-only is modern but drops older clients) |
| TLS 1.3 | offered | not offered (warn) |
| Weak ciphers | refused | the server completed a handshake on a NULL/EXPORT/DES/RC4/IDEA/anon suite |

"Cannot probe" rows (the local OpenSSL refusing to offer, say, TLS 1.0
client-side) are **not scored** — the report says so and points at
`nmap --script ssl-enum-ciphers` for an independent verdict.

### What this tool deliberately does not check

HTTP headers (HSTS and friends) are [Security
Headers](../../security-headers)' job. OCSP stapling and TLS
renegotiation aren't exposed by Python's `ssl` module — when a check
can't be tested honestly, it's left out rather than guessed.

---

## Exit codes

- `0` — the endpoint was reached and audited. Grade F is a successful
  audit that found a broken TLS setup, not a script failure.
- `1` — the endpoint could not be reached at all (DNS failure,
  connection refused, timeout — the very first handshake failed).
- `2` — the target can't be parsed as `host[:port]`.
