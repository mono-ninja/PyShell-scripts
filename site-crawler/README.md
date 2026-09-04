# Site Crawler

A [PyShell](https://github.com/mono-ninja/PyShell) script that crawls a
site from a seed URL and writes **one structured snapshot** —
`site_snapshot.json` — containing pages, status codes, redirect chains,
titles, meta descriptions, canonical URLs, `meta robots`, response
headers, page-structure facts (H1s, word count, Open Graph, hreflang,
pagination), and the internal/external link graph. **Facts only, no
judgment calls**: deciding whether any of this is a problem is the job of
the separate [SEO Checks](../seo-checks) script, which reads the snapshot
without re-crawling. Crawl once (minutes), then check as many times as
you like (seconds each).

Alongside the JSON it writes `crawl_summary.csv` — one row per page, a
quick spreadsheet view without parsing the JSON.

**This script generates real, repeated traffic against the target site** —
potentially hundreds or thousands of requests, unlike the one-request
audit scripts in this collection. Only crawl sites you own or have
permission to crawl, and keep the politeness defaults unless you know why
you're changing them.

## Highlights

- **robots.txt respected on every request** — redirect hops included. A
  disallowed URL is recorded with `blocked_by_robots: true` (a fact
  SEO Checks reports) but never fetched. A redirect can neither smuggle
  the crawler past robots.txt nor walk it off the site.
- **Politeness** — bounded concurrency plus a per-worker delay, optional
  `Crawl-delay` honoring, an honest `site-crawler/1.0 (+PyShell)`
  User-Agent, retries that honor `Retry-After`.
- **Scope control** — subdomains, path prefix, exclude regex (the defence
  against crawler traps: infinite calendars, faceted navigation), max
  depth/pages, tracking-param stripping for dedup, optional sitemap
  seeding (the only way to discover true orphans).
- **Interrupt-safe** — a capped or interrupted run is marked `partial`
  and the snapshot is still written; **Resume** continues an earlier
  crawl from the existing snapshot.
- **Every fact always collected** — there is no "collect less" toggle; a
  fact left out at crawl time cannot be recovered without re-crawling.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests` and `lxml`.
3. **Seed URL** — where the crawl starts (`https://…`). Pick a **real
   output folder**: the snapshot needs to survive past this one run so
   SEO Checks can read it later. Press **Run** (⌘↩).

Basic-auth credentials for password-gated staging sites are stored in the
macOS Keychain and passed via the `BASIC_AUTH` environment variable —
never on the command line.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --seed-url https://example.com/ --out-dir ./snapshot
python3 main.py --seed-url https://example.com/ --out-dir ./snapshot \
  --max-pages 200 --use-sitemap
python3 main.py --seed-url https://example.com/ --out-dir ./snapshot --resume
```

## Result

- **Results tab** — a table with the status-code breakdown
  (2xx/3xx/4xx/5xx, no-response errors, robots-blocked) plus pages
  discovered/crawled/capped, and — with sitemap seeding on — how many
  pages the sitemap listed.
- **Artifacts** — `site_snapshot.json` (the snapshot, schema version 6)
  and `crawl_summary.csv`.

## Exit codes

- `0` — the crawl ran, whatever it found. A capped run and a site full
  of 404s are both *successful crawls*; the conclusions are SEO Checks'
  job, not this script's.
- `1` — the seed URL itself was unreachable or robots.txt-blocked —
  nothing to crawl.
- `2` — bad arguments (a seed URL without a scheme, an invalid
  `--exclude-pattern`, a seed that falls outside its own scope).
- `130` — interrupted with Ctrl+C. The partial snapshot is still written.

## Layout

```
site-crawler/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point
├── src/                 # crawler engine
├── requirements.txt     # requests, lxml
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
