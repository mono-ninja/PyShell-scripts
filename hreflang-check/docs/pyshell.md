# Hreflang Check

The multilingual wiring under the microscope — over a **Site
Crawler snapshot**: reciprocity of alternate links (A → B but B ↛ A
— Google drops one-way pairs), cluster audits (the standard shape
understood: every page declaring the full set is normal; the error
is one language or x-default pointing at **different targets**),
missing x-default, self-references, code validity (`pt-br`,
`english`, `xx` — each with the right spelling), and target sanity
(alternates at non-canonical or 404 pages; outside-the-crawl marked
as unverifiable, not as broken).

Hreflang is a cluster property — one page cannot show the broken
half of it; that is why this reads the whole crawl, not one URL.

---

## Dependencies

Requires [**Site Crawler**](../../site-crawler)
(`com.pyshell.sitecrawler`):

1. Run Site Crawler on the site — it writes `site_snapshot.json`
   (pick an output folder so the file survives the run)
2. Point this script's **Site snapshot** field at that file

The snapshot needs schema 2 (the hreflang fields) — an older
snapshot is rejected with instructions to re-crawl.

## Before running

1. Crawl first (see above).
2. Pick the **Site snapshot** file.
3. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **Site snapshot** — the `site_snapshot.json` from Site Crawler.

---

## Result

- **Results tab** — the table (severity · check · page · detail)
  and the report grouped by check:
  - **reciprocity** — one-way alternates, named on both ends'
    context.
  - **x-default** — missing in a cluster, or pointing at several
    different pages.
  - **duplicate-language** — a language code with several different
    targets inside one cluster.
  - **invalid-code** — case, names-vs-codes, unknown codes.
  - **non-canonical-target / broken-target / outside-crawl** —
    where the alternates actually lead.
  - **self-reference** — the Google-recommended own-language entry,
    missing.
  - **Not checked** — hreflang in the sitemap vs in HTML: the
    snapshot records the HTML side only; said so, not guessed.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the wiring picture |
| 1 | snapshot unreadable/too old, or no hreflang declarations in the crawl |
| 2 | bad arguments |

## Related

- **SEO Checks** — the one-page pass over the same snapshot; its
  canonical findings explain some non-canonical targets here.
- **Sitemap Generator** — generates hreflang alternates into the
  sitemap; this script audits what exists.
- **Site Crawler** — produced the snapshot; re-crawl after fixes.
