# TLS RPT Report

**Which receivers could not raise TLS to your MX.** The sixth act of
the mail story and DMARC Report's twin: Email DNS Audit publishes
the MTA-STS policy and the TLS-RPT address (`_smtp._tls`), Mail
Probe walks your own TLS wire — and this script reads the
**feedback loop**: the RFC 8460 reports receivers mail to that
address when they could not deliver to you over TLS. Nobody is
probed; the internet already reported.

Fewer than 1% of the top-million domains publish MTA-STS — but
those who did are exactly the ones left blind without reading these
reports, and the collection itself leads users there (Email DNS
Audit sets up `_smtp._tls`).

Inputs are what the mailbox already holds: `.json`, `.json.gz`, and
`.zip` (several reports inside one archive — all unpacked). Several
files merge into one picture:

- **Failure types** — `starttls-not-supported` (the receiver's MX
  never offered TLS), `certificate-expired`,
  `certificate-not-trusted`, `validation-failure`,
  `sts-policy-invalid` (**your own policy is broken**),
  `tls-version-insufficient` — each with its counts and its meaning
  spelled out.
- **Your MX hosts the failures hit** — which of your MX names the
  failing sessions aimed at.
- **The sending MTAs** — the IPs behind the failures.
- **The mode read** — in `testing` mode failures are observations;
  in `enforce` mode every failure is **mail that did not land**.
  The report says which world you are in.

Offline, stdlib only, zero network.

## Using with PyShell

1. Save the report attachments from the mailbox (the messages your
   `_smtp._tls` address receives).
2. Pick a **Source** — one file, several, or a folder.
3. Press **Run** (⌘↩).

## Running standalone

```bash
python3 main.py --single-file google.com!example.com!1727.json
python3 main.py --mode multiple --input-file a.json --input-file b.json.gz
python3 main.py --mode folder --input-folder ./reports --recursive
```

## Result

- **Results tab** — the failure-types table (type · count · what it
  means) and the report: successes vs failures, failure types with
  meanings, your MX hosts, the sending MTAs, and what the mode
  means for each failure.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | no report parsed |
| 2 | bad arguments (wrong extension, missing file, empty folder) |

## Layout

```
tls-rpt-report/
├── pyshell.yaml      # manifest
├── main.py           # json/gz/zip in · merge · failure types · mode read
├── docs/             # EN + UA docs
└── tests/            # 17 tests: fixtures in all three container formats
```

## License

MIT — see the root [LICENSE](../LICENSE).
