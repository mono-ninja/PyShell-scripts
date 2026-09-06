# Redirect Map

The missing link between Wayback Check's vanished URLs and SEO
Checks' chain audits: old URLs matched against a fresh Site Crawler
snapshot, with a **confidence tier per row** — the script proposes
the map, it never claims to know the right answer.

Inputs:

- **Old URLs** — Wayback Check's `wayback_vanished.csv`, an old
  Site Crawler snapshot (`.json` — its living pages that no longer
  exist become the candidates), or a plain one-URL-per-line list.
- **The fresh snapshot** — Site Crawler's `site_snapshot.json` of
  the site as it is now.

The matching ladder, per old URL:

1. **Exact** — the normalized path exists in the new snapshot
   (case, trailing slash, `.html`/`index` suffixes folded away):
   confident.
2. **Slug** — the last path segment matches exactly
   (`/blog/post/` → `/posts/post/`): confident, the classic
   migration move.
3. **Fuzzy** — slug or title similarity ≥ 0.80: **needs review**,
   with the score and what matched shown.
4. Nothing clears the bar: **not found** — the map cannot invent a
   target; 410 Gone is the honest option for truly gone pages.

Unless skipped, every proposed redirect is **verified live**: does
it land 301 → 200, without chains (redirect → redirect) or loops —
and 404s are named as *expected until the map is installed*, which
is exactly what the first run measures.

---

## Dependencies

Requires [**Site Crawler**](../../site-crawler)
(`com.pyshell.sitecrawler`):

1. Run Site Crawler on the site as it is now — it writes
   `site_snapshot.json` (pick an output folder so the file survives
   the run)
2. Point this script's **New snapshot** field at that file

**Old URLs** come from outside: Wayback Check's
`wayback_vanished.csv` (run it on the same domain), an old Site
Crawler snapshot kept from before the migration, or a plain list.
Without Site Crawler there is no fresh side to match against — the
script cannot run.

## Before running

1. Crawl the site now (Site Crawler), keep the snapshot.
2. Collect the old URLs (Wayback Check / old snapshot / a list).
3. Press **Run** (⌘↩). **Prepare Env** installs `requests` once.

## Fields

### Input

- **Old URLs** — the gone URLs' source: `wayback_vanished.csv`
  (its `url` column), an old `site_snapshot.json` (its living
  pages become candidates), or a `.txt` with one URL per line
  (`#` comments allowed).
- **New snapshot** — the fresh `site_snapshot.json`; its living
  pages are the redirect targets.

### Verification

- **Skip live verification** — off by default: each proposed
  redirect is requested live (one GET, redirects followed by hand:
  301 → 200, chains and loops named). Skip for a pure offline pass
  over the two files.
- **Per-request timeout (s)** — per-request deadline, 3–60
  (default 15).

---

## Result

- **Results tab** — the rows table (old → new · confidence · live
  check) and the report: confident matches with their reasons,
  review proposals with scores, not-found rows with the 410
  suggestion, still-existing rows excluded from the map.
- **Artifacts** —
  - `redirect_map.conf` — the nginx `map $uri` snippet
    (query-preserving `return`; review rows commented out),
  - `redirect_map_htaccess.txt` — the Apache `Redirect 301` twin,
  - `redirect_map.csv` — old, new, tier, score, live check — edit
    it, argue with it, re-run,
  - `findings.json`, `report.md`.

The honesty contract, verbatim: **matching is heuristic**. Confident
rows matched on an exact normalized path or an exact slug; review
rows cleared a similarity bar and are proposals. The script
proposes the map — you confirm it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the tiers are the result (a row "not found" is a finding, not a failure) |
| 2 | bad arguments: unreadable source, no `url` column, not a snapshot |

## Related

- **Wayback Check** — where the vanished URLs come from.
- **Site Crawler** — the fresh snapshot this map is matched
  against.
- **SEO Checks** — the chain/canonical audit for after the map is
  installed.
