# DNSBL Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that checks an
IP address — or a domain and the IPs behind it — against the major
public DNS blocklists: Spamhaus ZEN and DBL, SpamCop, Barracuda, SORBS,
blocklist.de, PSBL, GBUDb, SpamRats, Mailspike, SURBL and UCEPROTECT.
Pure DNS queries; the target is never contacted beyond resolving its A
records.

The reputation half of the email story — the sibling of [Email DNS
Audit](../email-dns-audit): that one grades what your DNS says
(SPF/DMARC/DKIM), this one grades what the world thinks of what you
send from.

## What it does

- **Twelve curated, alive zones** — ten IP lists and two domain lists,
  each with what-it-lists metadata, decoded return codes (Spamhaus ZEN
  SBL/XBL/CSS/DROP/PBL meanings, the DBL's `127.0.1.x` range, SURBL's
  bitmask) and a delisting link per listing.
- **Domain mode** — a domain's A records (up to 8) go to the IP lists
  and the domain itself to the domain lists; a bare IP checks the IP
  lists only.
- **TXT reasons** — a listed zone usually serves a human-readable TXT
  record; it's fetched and quoted in the report.
- **Honest statuses** — `listed`, `clean` (NXDOMAIN), `blocked` (the
  zone refused *you*: public-resolver policy, rate limit) and `error`
  (timeout/SERVFAIL). A zone that can't answer never vouches for
  anyone, and a refusal never masquerades as a listing.
- **The public-resolver trap, handled** — Spamhaus's free tier doesn't
  serve big public resolvers: some get a `blocked` refusal, others a
  **silent not-listed**. The report explicitly calls out Spamhaus rows
  queried through a known public resolver, so a false "clean" can't
  read as a verdict.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `dnspython`.
3. **IP or domain** — `198.51.100.25` or `example.com`. Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --target 198.51.100.25
python3 main.py --target example.com
python3 main.py --target 198.51.100.25 --workers 20
# Spamhaus's official always-listed test vectors:
python3 main.py --target 127.0.0.2
python3 main.py --target dbltest.com
# The public-resolver trap, made visible (blocked row / silent-clean caveat):
python3 main.py --target 127.0.0.2 --nameserver 1.1.1.1
```

## Result

- **Results tab** — listings with decoded codes, TXT reasons and
  delisting links, then the full zone table, then blocked/error notes.
- **Artifacts** — `dnsbl_raw.json` (every query's outcome),
  `report.md`.

## Exit codes

- `0` — the checks ran; listings are results, not failures.
- `1` — nothing could be checked (no A records, or every query failed).
- `2` — bad arguments (not an IP or domain, bad nameserver).

## Layout

```
dnsbl-check/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: zone catalogue, queries, report
├── requirements.txt     # dnspython
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
