# SEO Checks

Runs rule-based SEO checks over a `site_snapshot.json` produced by the
separate [**Site Crawler**](../../site-crawler) script: redirect chains and
loops, internal links that rely on redirects, broken links, canonical
issues, a sitemap cross-check, duplicate titles/descriptions, orphan pages,
URL variants, internal `nofollow` links, meta quality, and indexability.

The split is deliberate: **crawl once, check as many times as you like.**
The crawler (minutes, real traffic against the site) only collects facts;
this script (seconds, zero requests to the crawled site) is where
"is this actually a problem" gets decided. Re-run it with a different
check selection after every fix — no re-crawl needed. Point **Compare
against previous findings.json** at last run's output and the report
tells you what got fixed and what's new.

---

## Dependencies

Requires [**Site Crawler**](../../site-crawler) (`com.pyshell.sitecrawler`):

1. Run Site Crawler on the site — it writes `site_snapshot.json` (pick
   an output folder so the file survives the run)
2. Point this script's **Site snapshot** field at that file

Without Site Crawler there is nothing to check — the snapshot is the
sole input, carrying every fact the checks read.

---

## Before running

1. Crawl the site with [Site Crawler](../../site-crawler) first — this script
   reads the `site_snapshot.json` that run wrote. A newer Site Crawler
   (schema 2) also records sitemap URLs and response headers, which two
   checks below use — with an older (schema 1) snapshot they just say so
   and skip what they can't see. Schema 3 additionally records the
   resource and image srcs each page references; schema 4 adds parsed
   JSON-LD, the heading outline, anchor texts and charset/viewport;
   schema 5 adds the full Open Graph/Twitter property sets,
   meta-refresh, every `<title>`, a text hash for duplicate detection,
   base href, iframes, microdata and sitemap `lastmod`. All load the
   same way — no current check depends on the newer fields.
2. Click **Prepare Env** — installs `requests` (used only if external-link
   verification is on; every other check runs with zero dependencies).
3. **Site snapshot** — pick the `site_snapshot.json` file.

**Snapshot age matters.** The run starts by reporting how old the snapshot
is ("Snapshot crawled 2h ago"); past 7 days (configurable) the note turns
into a warning — findings against a stale snapshot can already be fixed or
plain wrong, so re-crawl instead of re-checking. A capped or partial crawl
(Site Crawler hit its page/depth limit, or stopped early) is also called
out: findings only cover the crawled part of the site.

---

## Fields

### Input

- **Site snapshot** — the `site_snapshot.json` written by Site Crawler.
  Its `schema` version is checked; an incompatible version is refused with
  a clear message instead of being misread.
- **Compare against previous findings.json** — optional. Point it at the
  `findings.json` this script wrote on an earlier run of the same site,
  and the report adds a 🆕 new / ✅ fixed / ➖ unchanged summary, plus a
  "Fixed since the baseline" section. Comparison ignores the numbers inside
  a finding's detail (a referring-page count going from 5 to 4 reads as
  "still open," not "old one fixed, new one appeared").

### Checks

- **Checks to run** — pick any subset, re-run as often as you like:
  - *Redirect chains, loops & internal links to redirecting URLs* —
    multi-hop chains (`warn`), a chain that never resolves after 10 hops
    (`fail`), and the valuable one: pages that link straight to a URL that
    redirects, grouped into one finding per redirecting URL with every
    referring page listed — update the links, don't rely on the redirect.
  - *Broken internal links (4xx/5xx)* — dead URLs with every referring
    page listed; the only always-`fail` severity. When the dead URL sits
    behind a redirect, the finding names both ends, since the status
    belongs to the final response.
  - *Canonical tag issues* — canonicals pointing at a broken, redirecting,
    `noindex`, robots-blocked, or chained URL (`fail` — none of those
    consolidate); outside the crawl scope (`info` — often a legitimate
    cross-domain canonical) or absent from the crawl (`warn`); a page
    that's both `noindex` and canonicalized elsewhere (`warn`,
    contradictory signals); duplicate-content pages missing a canonical
    (only when *duplicates* is also selected). Comparisons are
    normalized, so `#fragment`s, port numbers and host casing don't hide
    a self-referencing canonical.
  - *Sitemap cross-check* — needs a **schema-2** snapshot (Site Crawler
    records `Sitemap:` URLs from robots.txt); with a schema-1 snapshot
    this check reports that plainly instead of finding nothing silently.
    Flags sitemap URLs that are dead/`noindex`/robots-blocked (`fail`),
    redirecting or off-host (`warn`), or never reached by the crawl
    (`warn`, skipped on a capped/partial crawl) — and, separately,
    crawled indexable pages missing from the sitemap (`info`).
  - *Duplicate titles / meta descriptions* — exact matches by default;
    *Duplicate matching* below can switch to a normalized mode that also
    folds case, whitespace and a trailing brand suffix. A group whose
    pages all already canonicalize to the same URL drops to `info` — the
    canonical has already resolved it. On a **schema-5+** snapshot a
    third key runs too: pages with byte-identical visible text
    (`text_hash`), which is what catches printer-friendly twins and
    leaked staging copies that titles cannot.
  - *Linked pages excluded from indexing* — `noindex` (from the meta tag
    **or** the `X-Robots-Tag` response header — schema 2 only) or
    robots.txt-blocked pages that internal links point at: reachable by
    users, invisible to search engines — very often unintentional.
  - *Orphan pages & excessive click depth* — pages with zero incoming
    internal links (`warn` — reachable only via sitemap or an external
    link), pages with exactly one (`info`), and pages deeper than the
    click-depth guideline (`info`).
  - *http/https, trailing-slash & case URL variants* — internal links
    still using `http://` on an https site, both `/page` and `/page/`
    serving real content instead of one redirecting to the other, URLs
    differing only in path case, and internal links carrying campaign
    tracking parameters.
  - *Internal rel=nofollow links* — an internal link nofollowed almost
    always by CMS default, not by choice (`warn`, grouped by target);
    plus a one-line `info` tally of `sponsored`/`ugc` disclosures on
    external links, so those can be confirmed present.
  - *Missing or oversized title & meta description* — missing title is a
    `fail`, missing description a `warn`, off-guideline lengths (defaults
    ~30–60 / ~70–158 chars, all four tunable below) an `info` framed as
    "may be truncated", not an error. Redirect sources are skipped: the
    crawler attributes their content to the destination page, so judging
    the redirect's own record used to report a phantom "no title" for
    every legacy redirect on the site.

  The checks below read the facts Site Crawler recorded in snapshot
  schemas 3–6; each says so plainly (one `info` note) when the snapshot
  predates the field it needs, instead of silently finding nothing.

  - *Heading structure* (**schema 4+**) — no headings at all or a first
    heading that isn't an h1 (`warn`), skipped levels like h1→h3 and
    multiple h1s (`info`), empty headings (`warn` — a rung with no label
    on the only ladder screen readers have).
  - *Conflicting or empty `<title>` tags* (**schema 5+**) — two title
    tags means a template and a plugin both wrote one (`warn`); a
    present-but-empty tag is an `info` complement to meta_quality's
    "no title" fail.
  - *meta-refresh redirects* (**schema 5+**) — an immediate `0; url=`
    refresh is a redirect wearing the wrong mechanism (`warn` — return a
    301 instead); delayed refreshes and periodic reloads are `info`.
  - *Missing mobile viewport* (**schema 4+**) — no
    `<meta name=viewport>` means the page renders at desktop width on
    every phone; the fix is one line of HTML (`warn`).
  - *Open Graph / Twitter completeness* (**schema 5+**) — missing
    `og:title`/`og:image` (`warn`: a shared link shows a bare URL / no
    preview); pages without `twitter:card` get one grouped `info`.
  - *Off-site `<base href>`* (**schema 5+**) — a base pointing at
    another host silently turns every relative link external (`warn`):
    the explanation behind "missing" internal links.
  - *Structured data* (**schema 4+**) — JSON-LD blocks that fail to
    parse are a `fail` (worse than none: they turn rich results into
    Search Console errors); pages shipping neither JSON-LD nor
    microdata get one grouped `info` — the unclaimed rich-result
    opportunity (full judgment needs schema 5, where microdata becomes
    visible).
  - *Images without alt* (**schema 3+**) — per page, with the actual
    image srcs named (`warn`): a statistic turns into a to-do list.
    `alt=""` is deliberately not counted — an explicit "decorative"
    marker is correct markup.
  - *Sitemap freshness* (**schema 5+**) — a sitemap `<lastmod>` newer
    than the page's own `Last-Modified` (`warn`): search engines stop
    trusting lastmod dates they catch being wrong. Only the misleading
    direction is flagged; unparsable dates are skipped, not guessed.
  - *Third-party embeds* (**schema 5+**) — one grouped `info` listing
    the iframe hosts running on the site's pages: a privacy and
    performance fact, not a verdict.
- **Show findings down to** — hide `info`, or `info`+`warn`, without
  turning the check off entirely. The report says how many were hidden.
- **Group the report by** — *Page* lists every finding under the page it
  belongs to, useful when one person is working through one page at a
  time instead of one check at a time.

### External links

- **Also verify external links** — **off by default.** This is the one
  check that needs the network: the crawler only visited in-scope pages,
  so verifying external links means requests to third-party hosts. When
  on, each *unique* external URL gets one `HEAD` request (`GET` fallback
  where HEAD isn't allowed), spaced out per host so this script doesn't
  hammer someone else's server. A host that answers `401`/`403`/`429` —
  bot protection reacting to anything without a browser — is reported as
  `warn`, not `fail`; a person should click it to confirm.
- **External check concurrency / timeout** — separate knobs from the
  crawler's politeness settings: this is usually a much smaller set of
  URLs, and the two scripts share nothing by design.
- **Stop after this many unique external URLs** — a site with thousands
  of external links can otherwise outlast this script's own timeout; the
  report says how many were skipped so you know the count is partial.
- **Skip links marked rel=nofollow** / **Never probe this host** — narrow
  what gets probed.

### Thresholds

- **Duplicate matching** — *Normalized* also groups titles differing only
  in case, spacing, or a trailing " | Brand" suffix.
- **Also flag pages with no canonical tag at all** — off by default (a
  missing canonical is only a problem when it's ambiguous which URL is
  correct); turn on for a stricter, "every page should say so" report.
- **Title / meta description too short/long** — the four length
  guidelines the meta-quality check uses, in characters. The default
  "too short" title bound (30) sits well below the familiar ~50–60
  advice on purpose — a 45-character title is fine, and a stricter bound
  turns nearly every page on the site into a low-value `info` finding.
- **Flag pages deeper than this many clicks from the seed** — feeds the
  orphan check's depth note.
- **Warn when the snapshot is older than (days)** — the staleness
  threshold from *Before running* above.

### Scope

- **Only check URLs matching this path glob** / **Skip URLs matching this
  path glob** — narrow the report to part of the site (e.g. `/blog/*`).
  Links and redirects still resolve against the *whole* crawled site, so
  scoping to one section doesn't make the rest of the site's links look
  broken. One pattern each here; run from a terminal with repeated
  `--include-path`/`--exclude-path` flags for several.

### CI

- **Fail the run (exit code 3) on** — off by default, because **findings
  aren't failures** (see *Exit code* below). Turn this on only to gate a
  pipeline: exit 3 when a finding at or above the chosen severity exists.

### Output

- **Write artifacts here too** — artifacts always land in the PyShell run
  folder; pick a real project folder here (the same idea as Site
  Crawler's own output folder) so `findings.json`/`.csv`/`report.md`
  survive after the run folder is cleaned up, and so a later run can use
  this run's `findings.json` as its baseline.
- **Report format** — add a self-contained `report.html` alongside the
  markdown: sortable columns, a click-to-toggle severity filter, no
  external dependencies.

---

## Result

- **Results tab** — a markdown report: counts by severity, a 🆕/✅/➖
  summary when a baseline is set, and the highest-value findings first
  (broken links and failed canonicals before info-level meta-length
  notes), then the full findings table (capped at 300 rows in the
  markdown/table view — `findings.csv`/`.json` always carry every one).
- **Artifacts** — `findings.json` (machine-readable, with the snapshot and
  run settings recorded alongside the findings — enough to stand on its
  own for CI or as a future `--baseline`), `findings.csv` (spreadsheet
  view), `report.md`, and `report.html` when that format is selected.
  Written to the Run's artifacts under PyShell, and additionally to
  **Write artifacts here too** / next to the snapshot file when set.

## Exit code

- `0` — checks ran, however many findings turned up. **Findings aren't
  failures** — a run that found 40 problems is a successful run (same
  philosophy as `security-headers`), unless *Fail the run on* is set.
- `1` — the snapshot doesn't parse, its `schema` version isn't one this
  script understands, the baseline file exists but isn't readable, or the
  output folder couldn't be written to.
- `2` — bad arguments.
- `3` — findings at or above the *Fail the run on* threshold were found
  (opt-in only, for a CI gate).

A red row in History means "the snapshot (or baseline) couldn't be read",
not "the site has problems" — except when you've deliberately turned on
*Fail the run on*.
