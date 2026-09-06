# OG Image

Social cards at the 1200×630 standard — **produced, not checked**.
Page SEO Audit verifies the `og:image` tag exists; this makes the
file it points at. Every preview renderer (the Open Graph family,
X/Twitter's `summary_large_image`) reads this size.

The favicon-generator form, applied to the social side: one input
→ the set + the snippet to paste. Batch mode is the point — a real
site has hundreds of pages, and a CSV drives them all through the
same template in one run.

**Three fixed templates, not a constructor** (the pdf-toolkit
scope rule):

- **Gradient** — a diagonal blend of the two brand colors, title
  bottom-left;
- **Accent banner** — solid base, an accent bar on the left, title
  shifted right of it;
- **Background image** — your photo, cover-fit (never squashed)
  and darkened so text reads; legibility over the picture, said
  aloud.

Titles wrap and auto-shrink to fit (four lines max), the subtitle
sits under the title, an optional logo goes top-left, an optional
brand font replaces the system sans. Every card ships with the
complete meta snippet: `og:image`, `og:image:width/height`,
`og:image:alt`, `twitter:card`.

---

## Before running

1. Pick the **Mode** — one card, or a batch from CSV.
2. Pick the **Template** and the two brand colors (hex).
3. **Prepare Env** — installs Pillow. Press **Run** (⌘↩).

## Fields

### Input

- **Mode** — *Single card* (title + subtitle) or *Batch from CSV*.
- **Title** — the page title as it should read on the card
  (wrapped and auto-shrunk to fit).
- **Subtitle** — the smaller line (optional).
- **CSV of cards** (batch) — columns `title`, `subtitle`
  (optional), `out` (optional filename without extension); one
  card per row, empty titles skipped, cap 500 rows.

### Design

- **Template** — gradient / accent banner / background image.
- **Primary color** — hex: the gradient's start / the banner's
  background.
- **Accent color** — hex: the gradient's end / the accent bar /
  the overlay tint.
- **Logo (optional)** — PNG with transparency works best;
  top-left corner. A broken logo never kills the card.
- **Background image** — for the image template; cover-fit and
  darkened for legibility.
- **Font (optional)** — brand TTF/OTF; a system sans-serif
  otherwise.

### Snippet

- **Base URL** — when given, the snippets point at absolute URLs
  (`https://site.com/og/card.png`); otherwise relative filenames
  with a note.

---

## Result

- **Results tab** — the cards table (file · title · size) and the
  report: per card, the complete head block; the deploy steps.
- **Artifacts** — `<slug>.png` per card, `meta-snippets.html`
  (every card's block, commented), `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the cards rendered |
| 1 | a card failed to render (disk, unreadable image) |
| 2 | bad arguments: no title, no CSV, missing files, image template without a background |

## Related

- **Page SEO Audit** — checks the `og:image` tag on the live page;
  this makes the file it points at.
- **Color Palette** — extract the site's brand colors, paste the
  hexes here.
- **Responsive Images / Font Subset** — the other delivery steps
  of the design line.
