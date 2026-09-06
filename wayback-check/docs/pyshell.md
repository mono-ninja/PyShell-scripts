# Wayback Check

Reads a site's history through the free, keyless archive.org CDX API:
first and last capture, a per-year activity chart, and — opt-in — the
**vanished pages**: URLs the archive recorded as 200 that answer 404 on
the live site today, the redirect-map candidates an SEO migration
needs.

---

## Before running

1. **Domain or URL** — a bare domain (`example.com`) or a full URL; the
   host is what's inspected. Subdomains are excluded by default (see
   **Scope**).
2. Click **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩). The CDX queries are read-only; the
   **vanished-pages check** is a separate switch because it makes real
   GET requests to the target site.

The CDX server is routinely busy: every query gets a long timeout and
up to three attempts with backoff. A busy archive.org is exit 1 —
re-run, don't debug.

## Fields

### Target

- **Domain or URL** — the site whose history you want. A deep URL is
  fine; only its host matters for scoping.
- **Scope** — *Site* (default): this one host. *Domain*: include
  subdomains — can flood the answer or hit the CDX rate limits on
  wildcard-heavy domains; the report says when the row cap truncated
  the scan.

### Vanished pages

- **Check for vanished pages** — off by default. When on: archived
  URLs of this host (oldest-first-seen first) are fetched against the
  live site; 404/410 answers become redirect-map candidates.
- **Vanished check limit** — how many archived URLs to live-test,
  1–50 (default 20). Real GETs to the target — keep it polite.

### Query

- **Per-request timeout (s)** — default 45; a big year-scan on the
  CDX server can genuinely take that long.

---

## Result

- **Results tab** — the bar chart of **capture months per year**, then
  the report:
  - first and last capture with the year span, years/months with
    captures;
  - the vanished-pages table (archived URL · first seen · live status ·
    verdict), each row 🔴 vanished / 🟢 still there / ⚫ unreachable /
    🟡 other;
  - the redirect advice pointing at [Site Crawler](../../site-crawler)
    and [SEO Checks](../../seo-checks) for the after-migration
    verification.
- **Artifacts** — `wayback_history.json` (timeline, machine-readable),
  `wayback_vanished.csv` (url · first_seen · live_status · verdict),
  `report.md`.

### Reading the data honestly

- **The chart counts months with captures** — a monthly collapse over
  the CDX data, an activity proxy that saturates at 12/year on heavily
  archived sites. It is not a raw snapshot count.
- **A domain with no captures** is a finding, not an error: too new,
  never archived, or archived under a different host. The run still
  exits 0.
- **Unreachable live URLs** are reported separately — a vanished count
  over a half-down site would be a lie.

## Exit codes

- `0` — the check ran. Vanished pages are findings; an empty archive is
  a finding too.
- `1` — the CDX server couldn't be reached after three attempts —
  their load, not your input. Re-run later.
- `2` — bad arguments (empty target, no dot in the domain, limit out
  of range).
