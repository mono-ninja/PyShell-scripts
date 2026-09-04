# Subdomain Search

A [PyShell](https://github.com/mono-ninja/PyShell) script that
enumerates a domain's subdomains from passive OSINT sources — crt.sh
(certificate transparency), HackerTarget, RapidDNS and Shodan (API
key) — then confirms every candidate with parallel forward-DNS
resolution. The inverse of [IP → Domains](../ip-domains).

The OSINT queries ask the sources, never the target; the verification
phase makes the same DNS lookups any visitor's resolver would.

## What it does

- **Four sources, one table** — every subdomain carries the source(s)
  that named it (`crtsh hackertarget` …), because one API echoing
  another's data is common and *who saw this* is part of the result.
- **Wildcard-aware verification** — before resolving, two random probes
  test for a `*.domain` catch-all record. Candidates that resolve only
  to the probe IPs are reported as `wildcard`, not `alive`: a domain
  with a wildcard resolves *anything*, and a naive fan-out would report
  every stale certificate-transparency entry as live. Without this
  check the result would lie wholesale.
- **Full A-record capture** — `getaddrinfo` per candidate over a
  thread pool (default 50), so round-robin and CDN names show every
  address, not one arbitrary pick.
- **Honest statuses** — `alive` (resolves), `unresolved` (no DNS answer
  today — usually a stale CT entry), `wildcard` (only the catch-all
  answers).

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **Domain** — the registrable domain (`example.com`, no scheme, no
   `www.`). Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py example.com
python3 main.py example.com --sources "crtsh rapiddns"
python3 main.py example.com --sources "crtsh hackertarget rapiddns shodan" --workers 100
python3 main.py example.com --no-verify --max-subdomains 500
```

Shodan needs `SHODAN_API_KEY` in the environment (PyShell keeps it in
the Keychain); without it Shodan is skipped with a status note.

## Result

- **Results tab** — table: subdomain, resolved IPs, status, sources.
  Alive first; truncated past 2000 rows (the CSV holds everything).
- **Artifacts** — `subdomains.csv` (every candidate, status, sources),
  `subdomains_raw.json` (candidate → sources map, pre-verification).

## Exit codes

- `0` — the search ran; zero subdomains is a result, not a failure.
- `1` — the input isn't a registrable domain, or every selected source
  failed.
- `2` — bad arguments.

## Layout

```
subdomain-search/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: sources, wildcard probe, verification
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
