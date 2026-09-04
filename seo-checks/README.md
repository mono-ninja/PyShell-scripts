# SEO Checks

A [PyShell](https://github.com/mono-ninja/PyShell) script that runs
rule-based SEO checks over a `site_snapshot.json` produced by the
separate [Site Crawler](../site-crawler) script: redirect chains and
loops, broken links, canonical issues, a sitemap cross-check, duplicate
titles/descriptions, orphan pages, URL variants, internal `nofollow`
links, meta quality, and indexability.

The split is deliberate: **crawl once, check as many times as you like.**
The crawler (minutes, real traffic against the site) only collects facts;
this script (seconds, zero requests to the crawled site) is where "is
this actually a problem" gets decided. Re-run it with a different check
selection after every fix — no re-crawl needed. Point **Compare against
previous findings.json** at last run's output and the report tells you
what got fixed (✅) and what's new (🆕).

## Checks

- **Redirect chains, loops & internal links to redirecting URLs** —
  multi-hop chains, and pages linking straight to a URL that redirects
  (update the links, don't rely on the redirect).
- **Broken internal links** — dead URLs with every referring page listed;
  the only always-`fail` severity.
- **Canonical issues** — canonicals pointing at broken, redirecting,
  `noindex`, robots-blocked or chained URLs; contradictory
  noindex+canonical signals.
- **Sitemap cross-check** — dead/`noindex`/robots-blocked sitemap URLs,
  redirecting or off-host ones, and crawled pages missing from the
  sitemap.
- **Duplicate titles / meta descriptions** — exact or normalized
  matching; byte-identical visible text on newer snapshots.
- **Linked pages excluded from indexing** — `noindex` (meta tag or
  `X-Robots-Tag`) or robots-blocked pages that internal links point at.
- **Orphan pages & excessive click depth** — pages with zero or one
  incoming internal links.
- **URL variants** — http/https, trailing-slash, path-case, and campaign
  parameters in internal links.
- **Internal rel=nofollow links** — grouped by target, almost always a
  CMS default rather than a choice.
- **Missing or oversized title & meta description** — with tunable
  length guidelines.
- **Richer-snapshot checks** (each says so plainly when the snapshot
  predates the field it needs) — heading structure, conflicting
  `<title>` tags, meta-refresh redirects, missing viewport, Open
  Graph/Twitter completeness, off-site `<base href>`, broken structured
  data, images without `alt`, sitemap freshness, third-party embeds.

**External link verification** is off by default — the one check that
needs the network (one `HEAD` per unique external URL, spaced out per
host).

## Using with PyShell

1. Crawl the site with [Site Crawler](../site-crawler) first — this
   script reads the `site_snapshot.json` that run wrote.
2. Import this folder via **+ Folder** (⇧⌘O) and press **Prepare Env** —
   installs `requests` (used only by the external-link check).
3. Pick the snapshot, choose the checks, press **Run** (⌘↩).

**Snapshot age matters**: past 7 days (configurable) the note becomes a
warning — findings against a stale snapshot can already be fixed or plain
wrong, so re-crawl instead of re-checking.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --snapshot-file site_snapshot.json
python3 main.py --snapshot-file site_snapshot.json --check-external-links
python3 main.py --snapshot-file site_snapshot.json --baseline findings.json
python3 main.py --snapshot-file site_snapshot.json --fail-on fail   # CI gate
```

## Result

- **Results tab** — a markdown report: counts by severity, the 🆕/✅/➖
  baseline summary when set, and the highest-value findings first (broken
  links and failed canonicals before info-level meta-length notes).
- **Artifacts** — `findings.json` (machine-readable, with the snapshot
  and run settings recorded — enough to stand on its own for CI or as a
  future baseline), `findings.csv`, `report.md`, plus a self-contained
  `report.html` when that format is selected.

## Exit codes

- `0` — checks ran, however many findings turned up. **Findings aren't
  failures** — a run that found 40 problems is a successful run.
- `1` — the snapshot doesn't parse, its `schema` version isn't
  understood, or the baseline/output files couldn't be read or written.
- `2` — bad arguments.
- `3` — findings at or above the *Fail the run on* threshold were found
  (opt-in only, for a CI gate).

## Layout

```
seo-checks/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point
├── src/                 # check implementations
├── requirements.txt     # requests (external-link check only)
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
