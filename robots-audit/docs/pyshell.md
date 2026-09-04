# Robots Audit

Validates a robots.txt — live or a local draft — against **RFC 9309**
and against the classic mistakes that cost indexing: a `Disallow: /`
that blocks the whole site, a **duplicate user-agent group** whose
second half crawlers silently ignore, orphan rules, silent 500 KiB
truncation, non-absolute Sitemap lines. And the most direct check of
all: paste your key URLs and see each one's verdict — allowed or
disallowed — with the exact rule that decided it.

The third member of the crawl pipeline: [Site Crawler](../../site-crawler)
respects robots.txt, [Bot Hunter](../../bot-hunter) drafts one from
your access logs, and this script tells you whether the file actually
says what you think it says — audit the draft *before* deploying it,
or the live file after.

One robots.txt is read (fetched, or loaded from disk); with *Verify
Sitemap URLs* on, one request per `Sitemap:` line follows. Nothing
else — no crawling, no writes.

---

## Before running

1. Pick a source: **Site URL** (its `/robots.txt` is fetched, redirects
   followed) or **a local file** (a draft — e.g. Bot Hunter's output —
   before it goes live). Exactly one of the two.
2. Click **Prepare Env** — installs `requests` (unused in file mode).
3. Press **Run** (⌘↩).

A **404** is not an error: per RFC 9309 the crawl is then unrestricted,
and the audit says exactly that. 401/403 and server errors get their
own nuance — crawlers disagree there, and the report explains how.

---

## Fields

### Source

- **Site URL** — `https://example.com`; the file is fetched from
  `{origin}/robots.txt`. A redirect to another host is followed but
  flagged — robots.txt is only authoritative at its own origin.
- **…or a local robots.txt** — audit a draft before deploying it.
- **Per-request timeout (s)** — for the fetch (and sitemap checks).

### Rules

- **URLs to test against the rules** — one URL per line, `#` comments
  allowed. Each is evaluated and reported with the deciding rule.
- **User-agent for the URL tests** — which group's rules apply: a bot
  token like `Googlebot`, or `*` (default) for the catch-all group.
- **Verify Sitemap URLs** — fetch each `Sitemap:` line and check it
  answers 200. Off by default: one extra request per sitemap.

---

## What gets checked

- **Syntax (RFC 9309)** — invalid lines (no `:`), unknown fields,
  non-numeric `Crawl-delay`, orphan rules before any `User-agent`, a
  UTF-8 BOM. Ignored lines are findings, not noise: an ignored line is
  a rule you think you have but don't.
- **Grouping** — consecutive `User-agent` lines share one group (per
  the RFC); the same token in **two groups** is the classic trap —
  crawlers use only the first, so the second block never runs.
- **The big one** — is `/` itself disallowed for `*`? That's the whole
  site gone from every compliant crawler; `fail`, with the exact rule
  that did it.
- **Rule semantics** — evaluation follows Google's implementation of
  RFC 9309 §2.2.2: longest matching rule wins, ties go to `Allow`,
  `*`/`$` wildcards supported; an empty `Disallow:` is the RFC's
  explicit allow-all.
- **Crawl-delay** — Google ignores it, Bing and Yandex honor it; values
  past 30 s are effectively "don't crawl me" for the bots that obey.
- **Sitemaps** — every line must be an absolute URL (RFC requirement);
  cross-host sitemaps are legal but noted; with verification on, each
  must answer 200.
- **Size** — past 500 KiB crawlers read only the first chunk; the rest
  of the file is ignored (warned).

---

## Result

- **Results tab** — the findings table (severity / check / detail /
  fix), the URL-test verdicts, the sitemap checks, and the groups as
  parsed — every rule, verbatim.
- **Artifacts** — `findings.json` (machine-readable, CI-friendly),
  `robots_parsed.json` (the parsed structure: groups, rules, notes),
  `report.md`.

## Exit codes

- `0` — the audit ran. Findings are results, not failures: a
  fully-blocked site is a successful audit that found a blocked site.
- `1` — the robots.txt could not be obtained (network error, missing
  file).
- `2` — bad arguments (neither or both sources given, unusable URL).
