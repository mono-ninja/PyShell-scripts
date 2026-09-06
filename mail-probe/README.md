# Mail Probe

A [PyShell](https://github.com/mono-ninja/PyShell) script that probes
the **SMTP wire layer** of a mail domain — what the server actually
says when you connect on port 25:

- **MX hosts** (DNS, passive), most-preferred first;
- per host: the **banner**, the **EHLO capability set** (STARTTLS,
  AUTH mechanisms, SIZE…);
- **STARTTLS with the certificate** — TLS version, cipher, subject,
  issuer, days to expiry, and the verification verdict (a failing
  chain is a finding, reported with its reason, not a crash);
- **PTR records**, forward-confirmed;
- **the relay probe — opt-in, off by default**: MAIL FROM a local
  sender, RCPT TO an external reserved-domain recipient, quit before
  DATA. **No mail is ever sent.** An accepted third-party RCPT is the
  open-relay red flag.

The wire-side sibling of [Email DNS Audit](../email-dns-audit) (the
records: SPF/DMARC/DKIM) and [DNSBL Check](../dnsbl-check) (the
reputation) — together the collection's full email stack.

**Point it at domains you own or operate.** Some steps look exactly
like what a scanner does — that's the point of running them on
yourself first. From many residential networks, port 25 is blocked
outbound; run it from a server if every connection fails.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `dnspython`.
3. **Mail domain** — press **Run** (⌘↩). Turn on the relay probe only
   when you mean it.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --domain example.com
python3 main.py --domain example.com --max-hosts 5 --timeout 20
python3 main.py --domain example.com --check-relay
```

## Result

- **Results tab** — the per-host table (MX host · connect · STARTTLS ·
  TLS · AUTH · PTR · relay) and the report: per-host details, then the
  red flags spelled out (open relay, missing/broken STARTTLS,
  unverified certificates, expiring certificates, missing PTR).
- **Artifacts** — `findings.json` (every host, machine-readable),
  `report.md`.

## Exit codes

- `0` — the probe ran. Findings — even an open relay — are results,
  not failures.
- `1` — no MX records to probe, or every MX host refused the
  connection (nothing could be tested).
- `2` — bad arguments (not a bare domain).

## Layout

```
mail-probe/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # thin entry point: MX/PTR resolution, phases
├── requirements.txt     # dnspython
├── src/
│   ├── smtp_probe.py    # the port-25 sequence, TLS facts, relay probe
│   └── report.py        # table, markdown, artifacts
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
