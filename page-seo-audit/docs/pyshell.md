# Page SEO Audit

Full on-page SEO audit of **one URL**: response status, meta tags and
indexability, heading structure, image `alt` text, Open Graph / Twitter
Card tags, hreflang, structured data (JSON-LD, microdata, RDFa), word
count, and mixed content — one fetch, one parse pass, a report in
seconds. No crawling.

This is the one-shot counterpart to the [Site Crawler](../../site-crawler) +
[SEO Checks](../../seo-checks) pair: those two need a whole crawl to say
anything useful (duplicates, redirect reliance and indexability all
compare *across* pages); this one answers "is this single page any
good?" from a bare URL. HTTP security headers have their own script
([Security Headers](../../security-headers)) and are deliberately **not**
re-checked here.

---

## Before running

1. Click **Prepare Env** — installs `requests` and `lxml`.
2. **URL** — the page to audit, with scheme (`https://…`).

---

## Fields

### Request

- **URL** — the page to audit. A scheme-less input gets `https://`
  prepended automatically.
- **Follow redirects** (on by default) — audit the page the URL finally
  lands on. The redirect chain is shown either way, so you always know
  whether the audited page is the URL you gave.
- **Timeout (s)** — per request; each redirect hop gets its own budget.
- **User-Agent** — defaults to a PyShell audit identity. Some WAFs
  silently drop bare `python-requests`, which would look like a timeout.
  A field left all-blank falls back to the same default rather than
  sending an empty header.
- **Skip TLS verification** — for internal/staging hosts with
  self-signed certificates. Also applies to the optional link check and
  robots.txt fetch below, so a staging link doesn't fail on the same
  certificate the page itself was allowed to skip.

### Checks

- **Thin-content threshold (words)** — Content gets an info finding
  below this count. 300 is a general heuristic; lower it for a site
  built mostly of short reference pages, raise it for long-form content.
- **Check robots.txt** — one extra request, to the page's own host, that
  folds crawl-level allow/disallow into the same indexability verdict as
  `<meta name=robots>` and `X-Robots-Tag`. A page can carry no `noindex`
  at all and still be unreachable to crawlers because robots.txt blocks
  the path.
- **Verify links on the page** — **off by default.** This is the one
  option that sends requests beyond the page itself: every unique link
  on the page gets one `HEAD` request, with a `GET` fallback where HEAD
  isn't allowed (or is refused with a 4xx other than 404/410). A footer
  link repeated 50 times is still one request. The **canonical target**
  is verified in the same pass — a canonical pointing at a dead or
  redirecting URL consolidates the page into nothing, which the
  presence checks could never see.
  - **Which links to verify** — all, internal only, or external only.
  - **Max links to verify** — caps the request count outright (0 = no
    cap); a broken CDN behind hundreds of links no longer means hundreds
    of findings either — past 20 broken links the rest are summarized in
    one line.
  - **Link check concurrency / timeout** — separate knobs for that pass
    only.
- **Categories to drop from the report** — hide a category outright,
  e.g. Social on an internal admin tool that will never generate a share
  preview.

### Output

- **Fail the run on** — `none` (default) always exits successfully,
  whatever the audit found; `warn` or `fail` makes the run itself fail
  (exit code 2) once a finding at that severity or worse shows up. Wire
  this into a pipeline gate instead of parsing prose out of the report.

---

## What gets checked

| Category | Checks |
|---|---|
| Response | the audited status itself: 2xx = pass, an unfollowed redirect body = warn, 4xx/5xx = fail (every finding below describes an error page, not real content); the final URL's scheme — https = pass, a page that answers over plain http without redirecting to https = warn (an unfollowed 3xx over http stays silent: it might still redirect there); redirect chain length, a redirect with no `Location`, and a truncated body are reported here too |
| Meta | `<title>` (missing = fail, duplicate = warn, off-guideline length ~50–60 = info), meta description (missing = warn, duplicate = warn, ~120–158 = info), **canonical** — duplicate tags = warn, unresolvable = warn, self-referencing = pass, pointing at another domain = warn ("asking to be dropped from the index"), pointing elsewhere on the same host = info, **indexability** — `noindex` (or its `none` alias, including bot-specific meta like `googlebot`) from meta robots, `X-Robots-Tag`, or robots.txt, naming every source that said so (warn), viewport (missing = warn), charset (undeclared = warn — the fix for the mojibake this script's own fetch layer used to be vulnerable to), favicon (missing = info), `<html lang>` (missing = info), stray `<meta name=keywords>` (info) |
| Headings | zero `h1` = fail; multiple `h1` = warn; empty heading text = warn; a heading before the first `h1` = info; a level skipped going down (`h1` → `h3`) = info; an `h1` over ~70 characters or identical to `<title>` = info |
| Images | missing `alt` **attribute** — one aggregate warn ("N of M"). `alt=""` (decorative) is the correct, spec-sanctioned marking and is never flagged. Beyond presence: whitespace-only alt (warn — not the same as `alt=""`), alt over 125 characters (info), alt that says nothing the filename didn't (info, e.g. `alt="photo.jpg"`), missing `width`/`height` (info — the cheapest fix for layout shift), a lazy-loaded first image (info — likely delaying the page's own LCP) |
| Social | Open Graph: all absent = warn; `og:image` missing = warn; a *relative* `og:image` **or `twitter:image`** = warn (most crawlers require an absolute URL); `og:url` disagreeing with the canonical = info; an empty `og:title`/`og:description` = warn. Twitter: `twitter:card` absent is only an info when Open Graph exists (platforms fall back to OG), a warn when both are missing, a warn when the value isn't one of the defined card types, and a warn when `summary_large_image` has no `twitter:image` |
| Hreflang | silent on a page with no `hreflang` alternates at all. When present: an invalid language code = warn, the same code declared twice = warn, a non-absolute target = warn, no entry pointing back at this page = warn ("a set without a self-reference is ignored wholesale"), no `x-default` = info, a self-referencing entry declaring a different language than `<html lang>` = warn (region variants of the same language — `en` vs `en-GB` — are agreement, and `x-default` never conflicts) |
| Structured Data | every `<script type="application/ld+json">` parsed; malformed JSON = fail; parses but has no `@context` = fail (ignored just as silently as broken JSON); has `@context` but no `@type` = warn; valid blocks report their `@type`s (object, `@graph` and array shapes all supported). Microdata (`itemtype`) and RDFa (`typeof`) are read too, so a page using only those isn't reported as having no structured data. Zero of any kind = info — an enhancement, not a baseline requirement |
| Content | word count under the threshold above = info; word count computed from `<body>` text only, correctly spacing text split across block elements; text-to-markup ratio under 5% = info (usually a client-rendered shell); no `<main>`/`<article>` landmark = info; a count of `rel=nofollow`/`sponsored`/`ugc` links = info; anchors a crawler cannot follow (`href="#"`, `#fragment`, `javascript:…`) = warn — and they are never counted as internal links, which `urljoin()`'s fragment resolution used to do |
| Mixed Content | on an https page: any subresource — `img`, `script`, `iframe`, `video`, `audio`, `source`, `embed`, `track`, a stylesheet/icon/manifest `<link>`, a `srcset` entry, a form action — loaded over bare `http://` = warn. `rel=alternate` (an RSS feed) and `rel=preconnect` are never subresources and are never flagged |
| Links | off unless **Verify links** is on: non-2xx = one fail per broken URL (capped, then summarized), reachable only through a redirect = info; the canonical target is verified in the same pass — an unreachable/erroring target = fail, a redirecting one = info, a live one = pass |

**No single score.** Independent check families make a defensible
weighted score hard to calibrate on paper, so the deliverable is a
per-category status table (pass/warn/fail/info per row) plus the
findings, worst first — "Images: warn, Structured Data: pass" is more
actionable than a single 74/100.

## Result

- **Results tab** — a markdown report: response status and redirect
  summary, the per-category status table, then all findings (Category /
  Status / Detail / Fix), highest severity first.
- **Artifacts** — `page_facts.json` (every raw extracted fact — the
  evidence), `findings.json` (machine-readable: every finding carries a
  stable `code` in addition to its prose `detail`, plus a top-level
  `counts` and `category_status` summary — key CI rules off `code`, not
  off wording that can be reworded later), `report.md`.

## Exit code

- `0` — the page was fetched and audited, and nothing crossed **Fail the
  run on**. A page failing every check is still a successful audit by
  default.
- `1` — no usable response: timeout, connection refused, DNS failure, a
  redirect chain that never resolves, a non-HTML response (JSON, an
  image, a PDF — there is no on-page SEO to audit there), or a body that
  isn't parseable HTML.
- `2` — the audit ran to completion, but a finding at or above the **Fail
  the run on** severity was present.

A red row in History from exit `1` means "the request never landed", not
"the page scored poorly" — that distinction is what exit `2` is for.
