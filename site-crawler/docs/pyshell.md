# Site Crawler

Crawls a site from a seed URL and writes **one structured snapshot** —
`site_snapshot.json` — containing pages, status codes, redirect chains,
titles, meta descriptions, canonical URLs, `meta robots`, response
headers, page-structure facts (H1s, word count, Open Graph, hreflang,
pagination), and the internal/external link graph. **Facts only, no
judgment calls**: deciding whether any of this is a problem is the job of
the separate [`seo-checks`](../../seo-checks) script, which reads the
snapshot without re-crawling. Crawl once (minutes), then check as many
times as you like with different check selections (seconds each).

Alongside the JSON it writes `crawl_summary.csv` — one row per page with
the flat columns (url, status, depth, redirect count, canonical present,
blocked, title, content type, word count, response time, in-sitemap,
error), a quick spreadsheet view without parsing the JSON.

---

## Before running

1. Click **Prepare Env** — installs `requests` and `lxml`.
2. **Seed URL** — where the crawl starts, with scheme (`https://…`). If
   you set **Limit to path prefix** or **Exclude URLs matching**, the
   seed itself must not fall outside that scope — the run stops with an
   error instead of quietly crawling zero pages.
3. **Snapshot output folder** — pick a *real project folder*, not a
   scratch dir: the snapshot needs to survive past this one Run so
   `seo-checks` can read it later. Re-running with **Resume** picks up
   from whatever's already in that folder instead of starting over.

**This script generates real, repeated traffic against the target site** —
potentially hundreds or thousands of requests, unlike the one-request
audit scripts in this collection. Only crawl sites you own or have
permission to crawl, and keep the politeness defaults unless you know why
you're changing them.

---

## Fields

> Every fact worth checking is extracted from every fetched page, always
> — there is no "collect less" toggle. The inputs below control request
> volume, politeness, and what counts as one URL; a fact left out at
> crawl time cannot be recovered without re-crawling the whole site.

### Scope

- **Seed URL** — the starting page. The crawl scope is its exact host by
  default.
- **Include subdomains** — widens scope to a host-suffix match
  (`blog.example.com` matches `example.com`). Not registrable-domain
  aware: on a `co.uk`-style domain this can pull in unrelated sites that
  happen to share the suffix — use carefully.
- **Limit to path prefix** — e.g. `/blog/` to audit only one section of a
  large site. Blank crawls the whole scope. The seed URL must itself sit
  under this prefix.
- **Exclude URLs matching (regex)** — skip URLs matching a pattern, e.g.
  `/cart/` or `\?filter=`. The defence against crawler traps: an infinite
  calendar, faceted navigation, or a checkout flow that would otherwise
  eat the whole page budget without adding any content worth auditing.
  Applies to every URL the crawler considers, redirect targets included.
- **Max depth** — how many link hops from the seed to follow (default 5).
- **Max pages** — hard cap on pages crawled (default 500). URLs are
  deduplicated first: `?utm_source=…` variants of the same page count as
  one page.
- **Keep tracking params** — off by default, meaning `utm_*`, `gclid` and
  `fbclid` params are stripped before dedup. Turn on only if those
  variants really are distinct pages on your site.
- **Ignore all query strings** — the blunt instrument for faceted
  navigation: dedupes `?color=red&size=m` variants down to the bare path
  entirely, rather than naming individual params to drop.
- **Drop query param before dedup (optional)** — the middle ground
  between the two above: name one param (e.g. `color`) whose value is
  decoration, and URLs differing only in it count as one page. One
  param can be named here; the command-line flag `--drop-query-param`
  is repeatable for several.
- **Also seed from sitemap.xml** — reads `Sitemap:` entries from
  robots.txt plus the conventional `/sitemap.xml` (following one level of
  sitemap index), adds every URL they list as a crawl candidate, and
  records `in_sitemap` on every page. A link-following crawl can only
  ever find pages something links to; orphan pages — present in the
  sitemap but linked from nowhere — are invisible without this.
- **Also fetch non-HTML resources (img/css/js)** — off by default; the
  primary use case is page structure and `<a href>` links, and fetching
  resources roughly doubles request volume. When on, resource URLs are
  fetched and recorded as status-only leaves — never parsed, never
  expanded further. `<link rel=alternate|next|prev>` targets (language
  and pagination variants) are always crawled as ordinary pages, on or
  off — they're documents, not assets, whatever this setting says.
- **Do not follow rel=nofollow links** — off by default (facts, not
  judgment calls — the crawl records nofollow status and lets
  `seo-checks` decide what it means). A target linked *anywhere* on the
  page without `rel=nofollow` still counts as followed, even if the same
  page also links it with `rel=nofollow` elsewhere.

### Politeness

- **Concurrent requests** — simultaneous in-flight requests (default 5).
- **Delay between requests per worker (ms)** — each worker waits this
  long between its own requests (default 200ms). High concurrency with a
  delay still throttles load; it's the combination that controls it.
- **Honor robots.txt Crawl-delay** — when the site's robots.txt asks for
  a longer gap than the setting above, use the site's number instead.
  Off by default because most sites don't set one and it would otherwise
  silently override an explicit choice.
- **Ignore robots.txt (only for sites you own)** — off by default, i.e.
  robots.txt **is respected**, on every request the crawler makes —
  including a redirect's target, not only the URL that was requested. A
  URL robots.txt disallows is never fetched, but it is recorded in the
  snapshot with `blocked_by_robots: true` — a fact `seo-checks` reports
  (a linked page invisible to search engines). If robots.txt itself
  returns a 5xx, the crawl treats the whole host as disallowed — the
  conservative reading. If robots.txt is simply unreachable (a dropped
  connection, a timeout), that is treated as no robots.txt at all — a
  transient network hiccup on one request shouldn't empty out a crawl.
  Disable robots.txt only on a site you own or have explicit permission
  to crawl at will.
- **User-Agent** — identifies the tool honestly by default
  (`site-crawler/1.0 (+PyShell)`) rather than spoofing a browser. A
  crawler that hides what it is has no business getting polite defaults.
- **Extra request header (optional)** — `Name: value`, e.g.
  `X-Forwarded-User: qa`, sent with every request. One header can be
  set here; the command-line flag `--header` is repeatable for several.
- **HTTP basic auth (optional)** — `user:password`, for password-gated
  staging sites. Stored in the macOS Keychain and passed to the script via
  the `BASIC_AUTH` environment variable — never on the command line, so the
  password doesn't show up in `ps aux`.
- **Per-request timeout (s)** — network timeout per request (default 15).
- **Retries per request** — retried on connection errors and on
  429/502/503/504, honoring the server's `Retry-After` header when it
  sends one (default 1).
- **Max HTML bytes per page** — bodies are read only up to this cap
  (default 5 MB); past it the page is recorded as `truncated`. Only HTML
  is ever read — recording the status of a huge video never means
  downloading it.
- **Stop after (s, optional)** — ends the crawl gracefully once it's run
  this long, and still writes whatever it collected, instead of being
  killed by the run's overall timeout with nothing to show for it.

### Output

- **Snapshot output folder** — where `site_snapshot.json` and
  `crawl_summary.csv` are written. Under PyShell the files are also
  mirrored into the run's artifacts.
- **Resume from the snapshot already in that folder** — continues an
  interrupted or capped crawl by reading the existing
  `site_snapshot.json`, skipping every URL that already produced a
  response (pages that errored — a timeout, a dropped connection — are
  retried, not carried forward as fetched), and picking up the frontier
  from the links it found. Off by default: a fresh run always starts
  clean.

---

## What the crawl does

Breadth-first from the seed, following `<a href>` links within scope
(plus `<link rel=alternate|next|prev>` targets, and sitemap URLs when
that option is on). Every fetched page records: status code, the full
redirect chain (if any), content type, title, meta description, every
`rel=canonical` found (not just the first), meta robots, the `H1`s, page
language, Open Graph title/description, visible word count, image alt
coverage (the counts *and* the srcs, so a check can name which images
lack `alt`), the resource URLs the page references (img/script/stylesheet),
parsed JSON-LD structured data (with a count of blocks that won't parse —
"ships it, broken" is a finding), the full heading outline (h1–h6, empty
headings included), the visible anchor text of every link, the document's
declared charset and viewport, every Open Graph and Twitter-card property
(not just title/description), `meta refresh` tags (an HTML-level redirect
the redirect chain can't see — recorded, never followed), every `<title>`
tag (two conflicting ones is a finding, the way two canonicals are), a
whitespace-insensitive hash of the visible text (exact-duplicate
detection), the effective `<base href>`, iframe embeds, microdata
itemtypes, and — with sitemap seeding on — the sitemap's own `lastmod`
for the page, plus how many retries the page cost the run, the page's
text direction (ltr/rtl), and the whole `Content-Type` response header
(server charset included — the other half of a charset-conflict
finding), hreflang and pagination links, response headers worth
keeping
(`X-Robots-Tag` — a server-level `noindex` a `<meta>`-only reader can't
see — plus content-length, last-modified, etag, and similar), response
time, and internal + external links (with `rel` attributes where
present). Non-HTML link targets (PDFs, images) are recorded as
status-only "leaves." A page that fails to parse still gets a snapshot
entry with the failure recorded in `error` — one broken page doesn't lose
the rest of the crawl's data.

**Every request the crawl makes — including redirect hops — passes
through the same robots.txt and scope checks as the URLs it chose
itself.** A redirect can neither smuggle the crawler past a
robots.txt-disallowed area nor walk it off the site it was pointed at; a
refused hop is recorded as a fact on the page that redirected, not
followed. And a redirect's target is fetched at most once, however many
different pages link to it or redirect to it.

A **capped** run (page or depth limit reached) is marked in the
snapshot: how many URLs were found but never crawled, so "500 pages"
reads as "capped at 500," not "that's the whole site." Interrupting the
run (Ctrl+C) or hitting `--max-duration` does the same — the snapshot is
marked `partial` and written with whatever was collected, rather than
losing the run entirely.

---

## Result

- **Results tab** — a table with the status-code breakdown
  (2xx/3xx/4xx/5xx, no-response errors, robots.txt-blocked) plus pages
  discovered/crawled/capped, and — when sitemap seeding is on — how many
  pages the sitemap listed.
- **Artifacts** — `site_snapshot.json` (the snapshot, schema version 6)
  and `crawl_summary.csv`.

While the crawl is still finding new URLs, the run reports status lines
(the total is unknown yet); once the set of URLs it actually plans to
crawl stabilizes, it switches to a percentage — bounded by the page cap,
so a capped run's progress bar reflects the work it will actually do,
not every URL ever discovered.

## Exit code

- `0` — the crawl ran, whatever it found. A capped run and a site full of
  404s are both *successful crawls*; the conclusions are `seo-checks`'
  job, not this script's.
- `1` — the seed URL itself was unreachable (no response at all) or
  robots.txt-blocked — nothing to crawl.
- `2` — bad arguments (a seed URL without a scheme, an invalid
  `--exclude-pattern`, a seed URL that falls outside its own
  `--path-prefix` or `--exclude-pattern`, and similar).
- `130` — interrupted with Ctrl+C. The partial snapshot is still written.

## Handing the snapshot to seo-checks

Import the [`seo-checks`](../../seo-checks) script, pick the
`site_snapshot.json` this run wrote, and choose your checks. The snapshot
carries a `schema` version; if a future crawler version changes the
format incompatibly, the version bumps and older copies of `seo-checks`
say so instead of misreading the file.
