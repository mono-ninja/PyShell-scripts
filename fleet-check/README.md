# Fleet Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that gives
**one overview of a whole portfolio of sites** — the composite the
collection was building toward. For every site in the list:

- **HTTP status** — is it up at all;
- **TLS grade + certificate days** — from [TLS Audit](../tls-audit)
  when installed, else a compact ssl-stdlib check (expiry +
  verification, labeled compact);
- **Security-headers grade** — from [Security Headers](../security-headers)
  when installed, else a compact five-key presence grade (labeled);
- **WordPress version** — from [Tech Stack](../tech-stack) when
  installed, else the generator-tag fallback (labeled);
- **sitemap.xml presence** — always an inline GET.

Plus the fleet-level view: a grade-distribution chart, expired /
expiring certificates called out, and a **baseline diff** — point
`--baseline` at a previous run's `fleet.json` and the report shows
what improved (↑), what slipped (↓), site by site.

This is the script that exercises PyShell's **needs** mechanic the
invocation way: it declares the three siblings and runs their
`main.py` as child processes per site, parsing their artifacts — the
full grades, the real detection logic, zero duplication. Missing
siblings degrade to the labeled compact checks, never silently.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O) — PyShell pulls the
   three needed siblings automatically (the **Needs** chain).
2. Press **Prepare Env** — installs `requests` + `pyyaml`.
3. Paste the site list (one URL per line), press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --urls "example.com
example.org
blog.example.net"
python3 main.py --urls "$(printf 'example.com\nexample.org')" --workers 4
python3 main.py --urls "example.com" --baseline fleet.json
```

Standalone, the sibling scripts aren't in `PYSHELL_DEPS` — the run
uses the compact checks (labeled). For full grades standalone, set
`PYSHELL_DEPS` manually:

```bash
PYSHELL_DEPS='{"com.pyshell.tlsaudit": "../tls-audit", "com.pyshell.securityheaders": "../security-headers", "com.pyshell.techstack": "../tech-stack"}' \
  python3 main.py --urls "example.com"
```

## Result

- **Results tab** — the fleet table (site · HTTP · TLS · cert ·
  headers · WP · sitemap · Δ vs baseline) and the grade-distribution
  chart.
- **Artifacts** — `fleet.json` (everything, machine-readable — the
  next run's baseline), `fleet.csv` (the flat table), `report.md`.

## Exit codes

- `0` — the fleet ran. Bad grades and down sites are findings.
- `1` — every site was unreachable (there was no fleet to check).
- `2` — bad arguments (no usable URLs, over the 50-site cap, an
  unreadable baseline).

## Layout

```
fleet-check/
├── pyshell.yaml         # manifest: fields, bindings, needs, artifacts
├── main.py              # thin entry point: fleet loop, baseline, report
├── requirements.txt     # requests, pyyaml (for the tech-stack child)
├── src/
│   ├── checks.py        # full (sibling invocation) + compact checks
│   ├── baseline.py      # the fleet.json diff
│   └── report.py        # chart, table, markdown, artifacts
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
