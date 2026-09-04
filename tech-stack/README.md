# Tech Stack

A [PyShell](https://github.com/mono-ninja/PyShell) script that fingerprints
what a website is built on — and reports **versions, evidence and a
confidence score**, not just technology names. It also builds a third-party
network-request inventory, flags EOL/vulnerable components against an offline
advisory table, and can diff a run against a previous `stack.json`.

It is entirely passive: Tech Stack fetches the same pages, scripts and
stylesheets a browser would, and nothing more. No brute-forcing, no port
scanning, no exploit attempts — the only opt-in "active" step is a probe of
a handful of public files (`/composer.json`, `/CHANGELOG.txt`,
`/readme.html`) for a version string, off by default.

## Features

- **Versions with evidence** — 9 of 10 technologies never announce a
  version, and `unknown` is shown as a visible state rather than an empty
  cell. When a version *is* found, the table shows the source (header, meta
  generator, filename, JS global, …) and the exact string that matched.
- **Confidence scoring** — signals accumulate as `1 - Π(1 - cᵢ)`; a single
  weak signal (30%) stays under the default 50% threshold, two weak ones
  (~51%) cross it. Every row keeps its evidence for a manual sanity check.
- **~165 curated technologies across 18 categories** (server, language, CMS,
  e-commerce, JS framework/library, UI kit, build tool, SSR, analytics,
  advertising, CDN, hosting, monitoring, auth, payment, fonts, database) —
  plus an optional, much larger GPL-3.0 signature base downloaded separately
  (see [Signature database](#signature-database)).
- **Third-party inventory** — every external host the sampled pages pull
  from, grouped by registrable domain (eTLD+1) and purpose. This is a
  network-request inventory, not a cookie/consent audit.
- **EOL / vulnerability advisories** — offline table of EOL branches and
  vulnerable JS-library ranges, with an optional online refresh from
  endoflife.date.
- **Diff mode** — compare today's scan against a previous `stack.json`,
  scope-aware: a dimension neither run measured is reported as "not
  compared", never as a false "disappeared".
- **Optional JS rendering** — headless Chromium via Playwright adds
  `js_globals` (the most reliable version source, e.g. `Vue.version`) and
  real network requests, worth roughly +20% more detectable technologies on
  SPAs. Off by default; degrades to a warning (never a crash) if the
  package or the browser isn't installed.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests` and `pyyaml` (`playwright` is
   commented out in `requirements.txt`; uncomment it if you want `--render`).
3. Fill in the form and press **Run** (⌘↩).

The **Results** tab shows a markdown report, the full stack as a table, and a
chart of third-party requests by purpose. Field-by-field documentation lives
in [`docs/pyshell.md`](docs/pyshell.md) — the same text is shown in PyShell's
**Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt   # requests + pyyaml; playwright optional, see above

python main.py --url https://example.com
python main.py --url https://example.com --versions --third-party --advisories
python main.py --url https://example.com --pages 5 --render
python main.py --url https://example.com --category cms --category server
python main.py --url https://example.com --third-party --baseline stack.json
```

Flags map 1:1 to the form (see `main.py` / `pyshell.yaml`):

```
--url URL                required target, https:// or http://
--pages N                 pages to sample: main + internal (1–10, default 3)
--extra-urls FILE         extra URLs to sample, one per line
--user-agent STRING       custom User-Agent (default: rotates common browser UAs)
--category NAME           repeatable category filter (server, cms, js-framework, …)
--min-confidence N        0–100 threshold to show a technology (default 50)
--versions                detect versions from 9 ranked sources
--probe-known-paths       also probe /composer.json, /CHANGELOG.txt, /readme.html
--render                  render JS via headless Chromium (Playwright)
--third-party             build the third-party domain inventory
--advisories              flag EOL / vulnerable versions
--online-eol              refresh EOL dates from endoflife.date (external request)
--baseline FILE           previous stack.json — writes diff.md when given
--timeout N               HTTP timeout in seconds (default 15)
--delay SEC               polite delay between requests (default 0.5, 0 = none)
--verbose                 step-by-step log
```

Artifacts are written to `PYSHELL_OUTPUT_DIR` (fallback: current directory):
`techstack-report.md`, `stack.json`, `technologies.csv`, `third-party.csv`,
and `diff.md` when `--baseline` is given.

## Signature database

`techstack/tech.yaml` is the curated base shipped in this repo — data, not
code, so adding a technology is a YAML edit. `scripts/update_db.py`
optionally downloads the much larger `enthec/webappanalyzer` base (the
active Wappalyzer-fingerprint successor, GPL-3.0) into `~/.cache/techstack/`,
**outside the repository** — every live fork of that fingerprint base is
GPL-3.0 regardless of the license badge on the surrounding code, so the
generated file must never be committed. The curated `tech.yaml` always wins
on a slug collision.

```bash
python scripts/update_db.py
```

## Exit codes

`0` on every completed scan — an EOL PHP or a vulnerable jQuery is a report
row, not a script failure. `1` — invalid URL or target unreachable. `2` — the
scan itself crashed.

## Layout

```
Tech Stack/
├── pyshell.yaml          # manifest: 16 form inputs, bindings, artifacts
├── main.py                # entry point: argparse, 4 progress phases, report assembly
├── requirements.txt       # requests, pyyaml; playwright commented out (opt-in)
├── scripts/
│   └── update_db.py       # optional GPL-3.0 signature base → ~/.cache/techstack/
├── techstack/
│   ├── pyshell_io.py       # structured progress/status/table/chart events
│   ├── fetch.py             # SiteFetcher: session, UA rotation, polite delay
│   ├── pages.py              # page-sampling heuristic + --extra-urls
│   ├── evidence.py            # per-page parsed HTML/headers/cookies/scripts
│   ├── signatures.py           # loads + compiles tech.yaml (curated wins)
│   ├── detect.py                # signal matching, confidence accumulation
│   ├── graph.py                  # implies/excludes closure, CDN-hidden-origin note
│   ├── versions.py                # version candidate ranking, ?ver= trap handling
│   ├── thirdparty.py               # external-domain inventory
│   ├── advisories.py                # EOL / vulnerable-range lookups
│   ├── render.py                     # optional Playwright rendering
│   ├── report.py                      # table/chart/markdown events, CSVs, diff
│   ├── tech.yaml                       # curated signature base
│   └── advisories.yaml                  # EOL dates + vulnerable JS ranges
└── docs/
    ├── pyshell.md          # operator docs (Docs panel), English
    └── pyshell_ua.md       # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
