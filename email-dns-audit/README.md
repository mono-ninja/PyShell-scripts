# Email DNS Audit

A [PyShell](https://github.com/mono-ninja/PyShell) script that checks every
DNS record governing whether mail claiming to be from a domain is trusted
or blocked: **MX**, **SPF**, **DMARC**, **DKIM** (by selector), and —
behind opt-in toggles — MTA-STS / TLS-RPT / BIMI. The result is a
pass/warn/fail finding per pillar plus one plain-language readiness
sentence; that sentence is the deliverable, the per-record table is
supporting evidence.

Passive by design: **DNS lookups only** — the domain's mail infrastructure
is never contacted. The single exception is the opt-in MTA-STS check,
which additionally fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

## What gets checked

- **MX** — records exist; every MX host actually resolves (an MX pointing
  at a dead hostname silently eats mail).
- **SPF** — exactly one `v=spf1` record (more than one is a hard fail:
  receivers treat all mail as SPF-permerror); the 10-lookup ceiling of
  RFC 7208, counted recursively into `include:` targets; the terminal
  qualifier (`-all` pass / `~all` warn / `?all` or nothing → fail).
- **DMARC** — record exists at `_dmarc.<domain>`; `v=DMARC1` first; `p=`
  strength (none → warn, quarantine/reject → pass); `sp=` weaker than
  `p=`; `pct=` partial enforcement; `rua=` reporting; alignment modes.
- **DKIM** — per selector: `v=DKIM1`, key type, and `p=` non-empty (an
  **empty `p=` is a revoked key** per RFC 8463 — reported distinctly from
  "no record found"). Key length from the public-key blob is included.
- **Advanced (off by default)** — MTA-STS (policy fetch + `mode:` check),
  TLS-RPT (`_smtp._tls`), BIMI (`default._bimi`).

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `dnspython`.
3. **Domain** — a bare domain, no scheme (`example.com`). Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --domain example.com
python3 main.py --domain example.com --nameserver 1.1.1.1
python3 main.py --domain example.com --dkim-selectors google,selector1,selector2
python3 main.py --domain example.com --check-mta-sts --check-tlsrpt --check-bimi
```

DKIM selectors are **not discoverable via DNS**: the script probes
`<selector>._domainkey.<domain>` for each name in the list. The default
covers the common providers (Google, Microsoft 365, Mailchimp, Amazon
SES, …); an empty DKIM result may just mean the right selector isn't in
the list — the finding says so explicitly rather than reading as "no
DKIM".

## Result

- **Results tab** — a markdown report: the readiness sentence, the
  per-pillar status table, and every finding with a concrete fix.
- **Artifacts** — `dns_records_raw.json` (every record actually fetched,
  verbatim), `findings.json` (machine-readable, for CI), `report.md`.

## Exit codes

- `0` — the domain resolved and the checks ran, however many pillars
  failed. A fully spoofable domain is a successful audit that found a bad
  result.
- `1` — the domain itself doesn't resolve (NXDOMAIN).
- `2` — environment not ready (dnspython missing).

## Layout

```
email-dns-audit/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point
├── requirements.txt     # dnspython
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
