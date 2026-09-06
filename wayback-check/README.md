# Wayback Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that reads a
site's history through the free, keyless [archive.org CDX
API](https://archive.org) and turns it into:

- **The timeline** — first and last capture, years and months with
  captures, and a per-year bar chart in the Results tab.
- **The vanished pages** (opt-in) — URLs the archive recorded as 200
  that answer 404 on the live site today: redirect-map candidates for
  an SEO migration, with the full list in `wayback_vanished.csv`.
- **The raw history** — `wayback_history.json`, machine-readable.

Archive-only by default: the CDX queries are read-only lookups. The
vanished-pages check makes real GET requests to the target site (your
site — the pages it tests are its own archived URLs), which is why it's
a separate opt-in switch.

The CDX server is routinely busy — every query gets a generous timeout
and up to three attempts with backoff. Scope defaults to **one host**
(subdomains excluded: the SEO-sensible unit); the whole-domain scope is
opt-in because wildcard-heavy domains can flood the answer.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **Domain or URL** — press **Run** (⌘↩). Turn on **Check for vanished
   pages** when you want the redirect-map candidates.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --target example.org
python3 main.py --target https://example.org/deep/page --scope site
python3 main.py --target example.org --check-vanished --vanished-limit 30
python3 main.py --target example.org --scope domain
```

## Result

- **Results tab** — the per-year capture chart, then the report: first
  and last capture, year span, the vanished-pages table (archived URL ·
  first seen · live status · verdict) when the check ran.
- **Artifacts** — `wayback_history.json` (timeline, machine-readable),
  `wayback_vanished.csv` (the redirect-map candidates:
  url · first_seen · live_status · verdict), `report.md`.

A domain with **no captures at all** is reported honestly as a finding
(too new, never archived, or archived under a different host) — the run
succeeds.

## Exit codes

- `0` — the check ran. Vanished pages are findings; an empty archive is
  a finding too.
- `1` — the CDX server couldn't be reached after three attempts (their
  load, not your input) — re-run later.
- `2` — bad arguments (empty target, no dot in the domain,
  out-of-range limit).

## Layout

```
wayback-check/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: CDX queries, live checks, report
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
