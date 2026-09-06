# SSH Log Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that answers
the questions an sshd log holds: **who is hammering the server, what
usernames they're trying, and — the critical one — whether any of them
got in.** The third sibling of the log-analyzer family
([Bot Hunter](../bot-hunter) for bots, [Log Attack Checker](../log-attack-checker)
for web attacks — this one for SSH).

Four log shapes, detected per file:

- Linux `auth.log` / `secure` (Debian, Ubuntu, RHEL, Amazon Linux) —
  plain or `.gz`;
- `journalctl -u ssh` text output (same message format);
- `journalctl -u ssh -o json` exports;
- macOS `log show` text.

OpenSSH ≥ 9.8's `sshd-session` program name is understood too.

The report: brute-force IPs with failed-attempt counts, users tried and
last-seen times; **success-after-failure chains** (an IP that failed
and then logged in — treat as compromised until proven otherwise);
accepted logins with methods; the attacker username wordlist; optional
country enrichment via the free ip-api.com batch endpoint. Artifacts:
`findings.json` (everything, machine-readable) and a ready-to-paste
**fail2ban jail**.

Reads logs only. Nothing is sent anywhere except the optional GeoIP
lookup of attacker IPs — and `--skip-geoip` makes the run fully
offline.

## Using with PyShell

1. Copy the logs (or a folder of them) off the server.
2. Import this folder via **+ Folder** (⇧⌘O), press **Prepare Env** —
   installs `requests`.
3. Point **Logs directory** at the folder, press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --logs-dir /var/log/auth-logs/
python3 main.py --logs-dir ~/logs/ssh --bruteforce-threshold 3 --top-n 30
python3 main.py --logs-dir ~/logs/ssh --whitelist 203.0.113.7,198.51.100.2
python3 main.py --logs-dir ~/logs/ssh --skip-geoip
```

## Result

- **Results tab** — the brute-force table (IP · failed attempts · users
  tried · got in? · last seen · country) and the report with the
  success-after-failure chains spelled out.
- **Artifacts** — `report.md`, `findings.json` (every flagged IP with
  its users and acceptances), `fail2ban_jail.conf` (a ready
  `/etc/fail2ban/jail.local` sshd jail + ufw deny lines; IPs that also
  logged in are commented as such and never suggested for a raw block).

## Exit codes

- `0` — the analysis ran. Brute force and compromised accounts are
  findings, not failures — a riddled log is what you came to see.
- `1` — no sshd events in any file (wrong folder, unsupported format —
  the log tells you which files were skipped and why).
- `2` — bad arguments (not a folder).

## Layout

```
ssh-log-check/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # thin entry point
├── requirements.txt     # requests (GeoIP only)
├── src/
│   ├── formats.py       # format sniffing + line parsers (the sshd core)
│   ├── analysis.py      # aggregation, brute-force flags, chains
│   ├── geoip.py         # optional ip-api.com batch enrichment
│   └── report.py        # markdown, table, fail2ban jail, artifacts
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
