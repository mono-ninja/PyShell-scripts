# Sitemap Generator

A [PyShell](https://github.com/mono-ninja/PyShell) script that builds a
search-engine `sitemap.xml` from a Site Crawler snapshot — listing only
URLs that clear the bar a sitemap promises (fetched, alive, indexable,
canonical, on this host) and reporting **every exclusion with its
reason**.

The third leg of the pipeline: [Site Crawler](../site-crawler) collects
the facts, [SEO Checks](../seo-checks) judges them, this script acts on
the verdict. Reads the snapshot only — no network, no writes to the
crawled site.

## What it does

- **Filters by the sitemap's own contract** — every URL in the output
  was actually fetched, answered 2xx, is an HTML page, isn't `noindex`
  (meta robots *or* `X-Robots-Tag`), isn't robots.txt-blocked, doesn't
  redirect (redirect sources resolve to their final URL), canonicalizes
  to itself, and belongs to the site's host.
- **Excludes visibly** — 13 reason codes (`noindex`, `non-canonical`,
  `duplicate`, `off-host`, …), each exclusion in
  `sitemap_excluded.csv` with the target named, each reason explained
  in the report. Nothing leaves the sitemap silently.
- **`lastmod` done honestly** — *preserve* mode keeps the previous
  sitemap's date per URL (so a regenerated file doesn't claim the whole
  site changed today), falling back to crawl time; or crawl time
  always; or none.
- **hreflang alternates** — each entry carries the page's hreflang map
  as `<xhtml:link rel="alternate">` rows, the correct form for
  multi-language sites (schema 2+ snapshot).
- **Scales by the protocol's rules** — past 50,000 URLs (or the 50 MB
  cap) the file splits automatically: `sitemap.xml` becomes a
  `<sitemapindex>` pointing at `sitemap-1.xml` … parts. `changefreq`
  and `priority` are deliberately omitted — search engines ignore them.
- **Refuses to build on bad evidence** — a capped/partial crawl exits 1
  (the sitemap would silently drop unreached URLs; `--allow-partial`
  overrides when the gap is understood), and so does a run where
  nothing qualifies (an empty sitemap deployed over a working one drops
  the whole site).

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — nothing to install (standard library only).
3. **Site snapshot** — pick the `site_snapshot.json` from a Site Crawler
   run. Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 main.py --snapshot-file site_snapshot.json
python3 main.py --snapshot-file site_snapshot.json --exclude-path '/tag/*' --exclude-path '/author/*'
python3 main.py --snapshot-file site_snapshot.json --lastmod-mode crawl --no-hreflang
python3 main.py --snapshot-file site_snapshot.json --include-path /blog/* --out-dir ./dist
python3 main.py --snapshot-file site_snapshot.json --allow-partial
```

Artifacts are written next to the snapshot (or to `--out-dir`), and to
`PYSHELL_OUTPUT_DIR` when it is set.

## Result

- **Results tab** — a disposition table and bar chart (URLs included vs
  excluded per reason) plus the full report: warnings, exclusions
  grouped by reason, deployment instructions with the ready-to-paste
  robots.txt `Sitemap:` line.
- **Artifacts** — `sitemap.xml` (index + `sitemap-*.xml` parts when the
  URL count passes 50,000), `sitemap_excluded.csv` (every excluded URL
  with its reason and target), `report.md`.

## Exit codes

- `0` — the sitemap was generated. Exclusions are results, not
  failures: a third of the site in `noindex` is a successful run with a
  finding.
- `1` — the snapshot doesn't parse or its schema is unknown; the crawl
  was capped/partial without `--allow-partial`; nothing qualified (no
  `sitemap.xml` is written — the report and CSV still are); or the
  artifacts can't be written.
- `2` — bad arguments.

## Layout

```
sitemap-generator/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: argparse, phases, exit codes
├── docs/
│   ├── pyshell.md       # operator docs (Docs panel)
│   └── pyshell_ua.md    # Ukrainian translation
└── src/
    ├── snapshot.py      # snapshot loading, schema guard, URL normalization
    ├── eligibility.py   # the per-URL decision: included or excluded+reason
    ├── sitemap.py       # XML writing: urlset, hreflang, 50k split, index
    └── report.py        # events, report.md, excluded.csv, artifacts
```

## License

[MIT](../LICENSE), same as the repository.
