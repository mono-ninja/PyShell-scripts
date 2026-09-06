# Responsive Images

One source image in, a **delivery-ready ladder** out — the link the
chain was missing: Image Converter changes the format, Image
Optimizer makes one file light — this builds the **set** a real
page needs and the markup that ties it together. A proper `srcset`
cuts image weight 40–60% in pure HTML.

Every requested width (default 320/640/960/1280/1920) becomes
`<stem>-<width>.avif`, `.webp` and a fallback — JPEG for
photographic sources, PNG when the source carried alpha. Steps
wider than the source are **skipped, never upscaled** — and the
skip is reported. The fallback `<img>` is the largest produced
step, so the snippet works everywhere.

The **snippet** is ready to paste: AVIF source first, WebP source,
then the fallback `<img>` with `srcset`, `sizes`, `width`/`height`
(the browser reserves the box before loading), `loading="lazy"`,
`decoding="async"`, and your alt text.

Originals are never touched; EXIF orientation is baked in and the
rest of the metadata dropped (delivery copies — EXIF Inspect's
privacy point applies to shipped files too).

---

## Before running

1. Pick the **Source image** — the one image the page will serve.
2. **Prepare Env** — installs Pillow and the AVIF plugin.
3. Press **Run** (⌘↩).

## Fields

### Input

- **Source image** — PNG, JPEG, WebP, AVIF, TIFF, BMP. The
  original is never modified; the ladder lands in the output
  folder.

### Ladder

- **Width ladder** — comma-separated pixel widths, ascending
  (default `320,640,960,1280,1920`). Steps wider than the source
  are skipped (never upscaled) and listed in the report.
- **sizes attribute** — goes into the snippet verbatim, default
  `100vw`. **The honest warning:** `sizes` describes *your layout*,
  and no script can know it — with a wrong `sizes` the browser
  downloads the largest step anyway and the ladder saves nothing.
  Measure the rendered box, then write it (e.g.
  `(max-width: 768px) 100vw, 50vw`).
- **Quality** — encoder quality for AVIF/WebP/the fallback, 10–95
  (default 80).

### Snippet

- **Alt text** — placed into the snippet's `alt` attribute:
  describe the image for screen readers and SEO.

---

## Result

- **Results tab** — the weight table (width · AVIF · WebP ·
  fallback, each with its share of the original's bytes) and the
  report: skipped steps, the snippet, the `sizes` warning, the
  deploy steps.
- **Artifacts** — the ladder files (`<stem>-<width>.avif/.webp/
  .jpg|.png`), `snippet.html`, `findings.json` (the measured
  table), `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the ladder was built |
| 1 | unusable source: unreadable, or smaller than the smallest step; AVIF support missing |
| 2 | bad arguments: bad width ladder, quality out of range, missing file |

## Related

- **Image Converter / Image Optimizer** — the format and weight
  steps before this one.
- **Page SEO Audit** — checks that `srcset`/`sizes` survived your
  CMS on the live page.
- **OG Image** — the social-card sibling of this delivery step.
