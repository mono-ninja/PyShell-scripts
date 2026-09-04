# Sitemap Generator

Builds a search-engine `sitemap.xml` from the `site_snapshot.json` written
by the separate [**Site Crawler**](../../site-crawler) script — the last
leg of the *crawl → check → fix* pipeline that [**SEO
Checks**](../../seo-checks) is the middle of.

The sitemap lists only URLs that clear the bar a sitemap promises: really
fetched, alive, indexable, canonical, on this site's host. Everything
else is excluded **with a reason** — noindex pages, redirect sources,
non-canonical duplicates, robots-blocked URLs, off-host pages, broken
links — and every exclusion lands in `sitemap_excluded.csv`. A sitemap
you can audit is a sitemap you can trust; one you can't is a file you
hope is right.

No network: the snapshot is the only input, nothing is fetched, nothing
on the crawled site is touched.

---

## Dependencies

Requires [**Site Crawler**](../../site-crawler) (`com.pyshell.sitecrawler`):

1. Run Site Crawler on the site — it writes `site_snapshot.json` (pick
   an output folder so the file survives the run)
2. Point this script's **Site snapshot** field at that file

Without Site Crawler there is nothing to generate from — the snapshot
is the sole input, carrying every page's status, canonical and robots
signals.

---

## Before running

1. Crawl the site with [Site Crawler](../../site-crawler) first. The
   snapshot's `schema` version is checked; an unknown version is refused
   with a clear message. Older schemas load but say what they're missing:
   schema 2+ carries response headers (the `X-Robots-Tag` half of noindex
   detection) and hreflang; schema 5+ carries the previous sitemap's
   `lastmod` per page (used by the *preserve* lastmod mode).
2. Click **Prepare Env** — nothing to install, the script is
   standard-library only.
3. **Site snapshot** — pick the `site_snapshot.json` file.

**A capped or partial crawl is refused** (exit 1). A sitemap built from
an interrupted crawl silently drops every URL the crawl never reached,
and deploying that file over a working sitemap would remove them from
it. Re-crawl without the cap, or — when you understand the gap — turn on
*Generate even from a capped/partial crawl*. The same refusal, for the
same reason, fires when **nothing qualifies**: an empty sitemap deployed
over a working one drops the whole site.

---

## Fields

### Input

- **Site snapshot** — the `site_snapshot.json` written by Site Crawler.
- **Generate even from a capped/partial crawl** — off by default. When
  the snapshot is marked `capped` (hit the page/depth limit) or
  `partial` (stopped early), the run refuses rather than build a
  sitemap that would silently omit pages. Turn this on only when the
  omission is acceptable; the report still carries a prominent warning.

### Filters

- **Only include URLs matching this path glob** — e.g. `/blog/*`, to
  build a sitemap for one section. One pattern in the form; a terminal
  run accepts several `--include-path` flags.
- **Skip URLs matching this path glob** — e.g. `/tag/`, to leave a
  section out. Same single-pattern note.

### Content

- **lastmod source** — what goes into each `<lastmod>`:
  - *Preserve* (default) — keep the `lastmod` the site's *previous*
    sitemap carried for that URL (needs a schema 5+ snapshot crawled
    with `--use-sitemap`), falling back to the crawl time. Preserving
    keeps dates honest: a regenerated sitemap doesn't claim every page
    changed today.
  - *Crawl time* — when Site Crawler fetched the page.
  - *None* — omit `<lastmod>` entirely.
- **Skip hreflang alternates** — off by default. Each entry normally
  carries the page's hreflang map as `<xhtml:link rel="alternate">`
  rows — the form multi-language sites are supposed to use. Skip them
  only if you serve hreflang some other way (HTTP headers, for
  instance).

### Output

- **Write artifacts here too** — a real project folder, so
  `sitemap.xml` survives after the run. Without it, artifacts land next
  to the snapshot and in PyShell's run folder.

---

## Result

- **Results tab** — a disposition table (how many URLs included, how
  many excluded per reason), a bar chart of the same, and the full
  report: warnings, every exclusion grouped by reason with the target
  named, and deployment instructions.
- **Artifacts**:
  - `sitemap.xml` — the sitemap. Over 50,000 URLs it becomes a
    `<sitemapindex>` plus `sitemap-1.xml` … parts (the robots.txt line
    and every submission bookmark keep pointing at `sitemap.xml`).
  - `sitemap_excluded.csv` — one row per excluded URL: the URL, the
    reason code, the target where one exists. The audit trail.
  - `report.md` — the same report the Results tab shows.

`changefreq` and `priority` are deliberately not written — search
engines ignore them, and leaving them out keeps the file honest.

---

## Exit codes

- `0` — the sitemap was generated. Exclusions are results, not
  failures: 30% of the site being `noindex` is a successful run with a
  finding.
- `1` — the snapshot doesn't parse or its schema is unknown; the crawl
  was capped/partial without the override; nothing qualified (no
  `sitemap.xml` is written in that case — the report and CSV still
  are); or the artifacts can't be written.
- `2` — bad arguments.
