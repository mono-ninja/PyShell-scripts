# Redirect Map

**The missing link of the migration story.** Wayback Check finds the
vanished URLs; SEO Checks grades the redirects that already exist —
nothing between them built the map. This script does: old URLs
matched against a fresh Site Crawler snapshot, every row with a
confidence tier, ready-to-paste server configs, and a live check
that each proposed redirect really lands.

The honesty contract up front: **matching is heuristic**. The script
*proposes* a map — it never claims to know the right answer.

- **Confident** — the old path exists in the new snapshot after
  normalization (case, trailing slash, `.html`/`index` folded), or
  the slug moved (`/blog/post/` → `/posts/post/`, the classic
  migration move).
- **Needs review** — slug or title similarity ≥ 0.80 (difflib),
  with the score and what matched shown; these rows ship
  **commented out** in the configs.
- **Not found** — nothing cleared the bar; the map cannot invent a
  target. 410 Gone is the honest option for truly gone pages.
- **Still exists** — the page is already there; excluded from the
  map.

**Live verification** (on by default): each proposed redirect is
requested once, redirects followed by hand — 301 → target 200
(✅), chains (redirect → redirect: point the map at the final URL),
loops, "redirected elsewhere", "still live (200) — no redirect
needed", and 404s named as *expected until the map is installed*.
Install, run again: every row should read ✅.

## Using with PyShell

1. Crawl the site now — **Site Crawler** writes
   `site_snapshot.json` (pick an output folder).
2. Collect the old URLs — Wayback Check's `wayback_vanished.csv`,
   an old snapshot, or a plain list.
3. Press **Run** (⌘↩).

## Running standalone

```bash
pip install -r requirements.txt
python3 main.py --old-source wayback_vanished.csv --snapshot-file site_snapshot.json
python3 main.py --old-source old_urls.txt --snapshot-file site_snapshot.json --skip-verify
```

## Result

- **Results tab** — the rows table (old → new · confidence · live
  check) and the tiered report.
- **Artifacts** — `redirect_map.conf` (nginx `map $uri`,
  query-preserving), `redirect_map_htaccess.txt` (Apache
  `Redirect 301`), `redirect_map.csv` (edit it, argue with it,
  re-run), `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the tiers are the result |
| 2 | bad arguments (unreadable source, no `url` column, not a snapshot) |

## Layout

```
redirect-map/
├── pyshell.yaml      # manifest (needs: site-crawler)
├── main.py           # three-source input · match ladder · live verify · configs
├── requirements.txt  # requests
├── docs/             # EN + UA docs
└── tests/            # 12 tests: matching matrix + redirect-flavored server
```

## License

MIT — see the root [LICENSE](../LICENSE).
