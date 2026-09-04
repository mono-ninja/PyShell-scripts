# Email DNS Audit

Checks every DNS record that governs whether mail claiming to be from a
domain is trusted or blocked: **MX**, **SPF**, **DMARC**, **DKIM** (by
selector), and — behind opt-in toggles — MTA-STS / TLS-RPT / BIMI. The
result is a pass/warn/fail finding per pillar plus one plain-language
readiness sentence; that sentence is the deliverable, the per-record table
is supporting evidence.

Passive by design: **DNS lookups only** — the domain's mail infrastructure
is never contacted. The single exception is the opt-in MTA-STS check, which
additionally fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` and
is labelled accordingly.

---

## Before running

1. Click **Prepare Env** — installs `dnspython`.
2. **Domain** — bare domain, no scheme (`example.com`).

---

## Fields

### Target

- **Domain** — the domain mail claims to come from.
- **DKIM selectors to try** — DKIM selectors are **not discoverable via
  DNS**: the script probes `<selector>._domainkey.<domain>` for each name
  in this list. The default covers the common providers (Google
  `google`, Microsoft 365 `selector1`/`selector2`, Mailchimp `k1`, Amazon
  SES `amazonses`, …). An empty DKIM result may just mean the right
  selector isn't in the list — the finding says so explicitly rather than
  reading as "no DKIM".
- **Custom resolver** — e.g. `1.1.1.1`; blank = system resolver.

### Advanced (off by default)

- **MTA-STS** — `_mta-sts` TXT, plus a fetch of the policy URL (the one
  non-DNS step in the script; that's why it's opt-in). Checks the policy's
  `mode:` (enforce / testing).
- **TLS-RPT** — `_smtp._tls` TXT, reporting of TLS delivery failures.
- **BIMI** — `default._bimi` TXT (the one common selector in practice).

---

## What gets checked

- **MX** — records exist; every MX host actually resolves (an MX pointing
  at a dead hostname silently eats mail).
- **SPF** — exactly one `v=spf1` record (more than one is a hard fail:
  receivers treat all mail as SPF-permerror — a common, silent
  misconfiguration); the 10-lookup ceiling of RFC 7208, counted
  **recursively into `include:` targets**; the terminal qualifier
  (`-all` pass / `~all` warn / `?all` or nothing → fail).
- **DMARC** — record exists at `_dmarc.<domain>`; `v=DMARC1` first;
  `p=` strength (none → warn, quarantine/reject → pass); `sp=` weaker than
  `p=`; `pct=` partial enforcement; `rua=` reporting; alignment modes.
- **DKIM** — per selector: `v=DKIM1`, key type, and `p=` non-empty (an
  **empty `p=` is a revoked key** per RFC 8463 — reported distinctly from
  "no record found"). Key length from the public-key blob is included.

## Result

- **Results tab** — markdown report: the readiness sentence, the
  per-pillar status table, and every finding with a concrete fix.
- **Artifacts** — `dns_records_raw.json` (every record actually fetched,
  verbatim), `findings.json` (machine-readable, for CI), `report.md`.

## Exit code

- `0` — the domain resolved and checks ran, however many pillars failed. A
  fully spoofable domain is a successful audit that found a bad result.
- `1` — the domain itself doesn't resolve (NXDOMAIN).
- `2` — environment not ready (dnspython missing).
