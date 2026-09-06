# Font Subset

A font cut to what a page actually serves. Web fonts ship whole —
the visitor downloads every glyph of every alphabet the typeface
supports, to render one paragraph. Subsetting is the fix and woff2
is the container (97%+ support); the classic shape of the savings:
Montserrat 64.6 KB → 15 KB, −76%.

Three ways to say what to keep, in precedence order:

- **Pages actually served** — HTML/CSS files scanned for the
  glyphs really used (tags stripped from HTML, syntax lines
  dropped from CSS): the honest "what the site needs" cut, one
  woff2, no `unicode-range` (it *is* the range).
- **A text sample** — the copy the font must cover, exactly.
- **Language subsets** — Google's ranges (latin, latin-ext,
  cyrillic, cyrillic-ext, greek, greek-ext, vietnamese): one woff2
  per subset, each with its `unicode-range`, so the browser
  downloads only the ranges it renders — a Cyrillic page never
  fetches the Greek block.

Every subset ships with a ready `@font-face` (`font-display: swap`
included) and the **measured** savings table. The **Inventory**
mode answers the other half — what is actually in the font:
family, weight, style, per-language coverage, and (with files
given) what the pages use and what the font is missing.

Honesty lines: a subset with zero coverage is skipped and said so;
partial coverage is reported per subset; the swap flash is named
as the price of `font-display: swap`.

---

## Before running

1. Pick the **Font file** — TTF/OTF/WOFF/WOFF2. The original is
   never touched; the subsets land in the output folder.
2. Pick the **Mode** — Subset or Inventory.
3. **Prepare Env** — installs fontTools + brotli. Press **Run**
   (⌘↩).

## Fields

### Input

- **Mode** — *Subset*: cut and get woff2 + `@font-face`;
  *Inventory*: what the font contains.
- **Font file** — any of TTF, OTF, WOFF, WOFF2.

### Subset by (subset mode)

- **Language subsets** — one woff2 per selected subset with its
  `unicode-range` (used when no text or files are given).
- **Or by text sample** — paste the copy the font must cover; one
  woff2 with exactly those glyphs, no `unicode-range`. Takes
  precedence over the subsets.
- **Or by pages actually served** — HTML/CSS files scanned for the
  glyphs really used; takes precedence over everything else. In
  inventory mode the same field adds the what-the-pages-use
  column.

---

## Result

- **Results tab** — the savings table (subset · coverage · woff2 ·
  % of the original) and the report: the `@font-face` blocks, the
  coverage notes, the deploy steps. Inventory mode: the per-
  language coverage table and the pages-use analysis.
- **Artifacts** — `<family>-<subset>.woff2`, `fontface.css` (the
  ready blocks), `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the subsets (or the inventory) are the result |
| 1 | font unreadable, or no subset produced (see the report why) |
| 2 | bad arguments: missing file, nothing to subset by, unknown subset |

## Related

- **CWV Check / HAR Analyze** — the field and lab side of what the
  font does to loading; fonts are a classic LCP culprit.
- **Asset Minify** — the neighbor step for the CSS this snippet
  joins.
- **SVG Sprite — From Font** — the other fontTools user in the
  collection.
