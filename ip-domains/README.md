# IP → Domains

A [PyShell](https://github.com/mono-ninja/PyShell) script for passive reverse-IP OSINT: finds
domains pointing at a single IPv4 address by querying open sources (crt.sh,
HackerTarget, ViewDNS, Shodan), then confirms them with forward DNS resolution.
The target itself is never contacted — only third-party APIs.

## What it does

| Source | Method | Notes |
|---|---|---|
| crt.sh | Certificate SAN fields | Weak reverse-IP: finds certs issued for the IP literal, not hosted domains |
| HackerTarget | Reverse IP | No key required |
| ViewDNS | Reverse IP | No key required |
| Shodan | Host database lookup | Requires `SHODAN_API_KEY` |

The three keyless sources are enabled by default. A failing source is skipped —
one dead API never kills the run. Every candidate is then confirmed by forward
DNS resolution and bucketed as `confirmed` (points at the target IP),
`different` (resolves elsewhere) or `unresolved`.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. Enter the target IPv4 address and press **Run** (⌘↩).

`SHODAN_API_KEY` is a Keychain secret in PyShell: it travels in the
environment, never in `argv`, so `ps aux` never sees it. Field-by-field
documentation lives in [`docs/pyshell.md`](docs/pyshell.md) — the same text is
shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
pip install -r requirements.txt

python3 main.py 93.184.216.34
python3 main.py 93.184.216.34 --sources "crtsh hackertarget viewdns shodan" --no-verify
```

| Flag | Meaning | Default |
|---|---|---|
| `--sources` | Space-separated list of sources | `crtsh hackertarget viewdns` |
| `--no-verify` | Skip forward DNS verification, emit raw results | off |
| `--workers` | Parallel DNS resolution threads | 50 |
| `--max-domains` | Cap on domains sent to verification (excess truncated) | 5000 |

## Result

- **stdout** — human-readable log lines.
- **stderr** — one JSON object per line (marked `"pyshell": true`): `progress`,
  `status` and the final `table` event that PyShell renders as native UI.

Artifacts (written to `PYSHELL_OUTPUT_DIR`, not next to the script):

- `domains_raw.json` — all found domains, cleaned but unverified.
- `domains_verified.csv` — verification results (domain, IP, status), written
  incrementally so an interrupted run still leaves a partial file.
- `domains_unverified.csv` — single-column raw output when `--no-verify` is set.

## Exit codes

- `0` — the lookups ran, whatever they found. An IP with no domains is a
  successful (if uninteresting) result.
- `1` — the input is not a valid IPv4 address.
- `2` — invalid command line (missing target, unknown flag).

## Legal note

Querying third-party APIs about an IP you don't own can look like pre-attack
reconnaissance. Only look up addresses you own or have written permission to
investigate.

## Layout

```
ip-domains/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point — source queries + DNS verification
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
