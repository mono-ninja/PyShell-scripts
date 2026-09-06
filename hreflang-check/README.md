# Hreflang Check

**The multilingual wiring under the microscope.** SEO Checks grades
one page at a time; hreflang is a **cluster** property — one page
cannot show the broken half of it. This script reads a Site Crawler
snapshot and checks the wiring across pages:

- **Reciprocity** — `A → B` must be answered by `B → A`; one-way
  alternates are the classic silent killer (Google drops the pair).
- **Clusters** — the connected components of alternate links; every
  cluster gets the x-default and duplicate-language audit, with the
  standard shape understood: *every page declaring the full set is
  normal* — the error is one code pointing at **different targets**
  across the cluster.
- **Self-reference** — each page declaring hreflang should name
  itself too (Google's recommendation).
- **Code validity** — `pt-br` (wrong case), `english` (a name, not
  a code), `xx`: each named with the right spelling.
- **Target sanity** — alternates at a page that canonicalizes
  elsewhere, at a 404, or outside the crawl (noted as such — the
  snapshot is the boundary of what is known).

Pure functions over the snapshot — no network. The one thing a
snapshot cannot carry — hreflang in the **sitemap** vs in **HTML** —
is said so in the report instead of guessed.

## Using with PyShell

1. Run **Site Crawler** on the site first — it writes
   `site_snapshot.json` (pick an output folder so the file survives
   the run).
2. Point this script's **Site snapshot** field at that file.
3. Press **Run** (⌘↩).

## Running standalone

```bash
python3 main.py --snapshot-file site_snapshot.json
```

## Result

- **Results tab** — a table (severity · check · page · detail) and
  the report grouped by check, with the not-checked note (sitemap
  hreflang) and the related scripts.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the wiring picture |
| 1 | snapshot unreadable / too old, or no hreflang in the crawl |
| 2 | bad arguments |

## Layout

```
hreflang-check/
├── pyshell.yaml      # manifest (needs: Site Crawler)
├── main.py           # loader · clusters · checks · report
├── docs/             # EN + UA docs
└── tests/            # 17 tests over synthetic snapshots
```

## License

MIT — see the root [LICENSE](../LICENSE).
