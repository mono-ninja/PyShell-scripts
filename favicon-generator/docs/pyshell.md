# Favicon Generator

Turns one image into the **complete modern favicon set** — everything a
browser, iOS or a PWA linter will ever ask for, generated from a single
source file:

| File | What it's for |
|---|---|
| `favicon.ico` | legacy browsers — 16+32+48 packed in one multi-size ICO |
| `favicon-16x16.png`, `favicon-32x32.png` | the browser tab, classic and retina |
| `apple-touch-icon.png` | iOS home screen, 180×180, **opaque** |
| `icon-192.png`, `icon-512.png` | PWA / Android manifest icons |
| `site.webmanifest` | the manifest wiring the PWA icons (plus your app name) |
| `snippet.html` | the `<head>` tags, ready to paste |

The processing rules are deliberately conservative: the source is
**contained, never cropped** (a logo is not something to chop), non-square
sources letterbox onto a square canvas, transparency is preserved
everywhere it is legal — except `apple-touch-icon.png`, which iOS
composites onto black and is therefore always flattened (onto your
background color, or white when the background is transparent — the
report says so).

---

## Before running

1. **Source image** — one image, square and ≥512px recommended. PNG with
   transparency is the ideal input; JPEG/WebP/GIF/BMP/TIFF work too.
   Smaller sources are upscaled with a warning; strongly non-square
   ones letterbox (with a warning).
2. Click **Prepare Env** — installs `Pillow`.
3. Press **Run** (⌘↩).

## Fields

### Source

- **Source image** — the one image everything is generated from.

### Content

- **App name (optional)** — written into `site.webmanifest` as
  `name`/`short_name`. A manifest without a name fails PWA
  installability checks — fill it in before shipping.
- **Background** — `transparent` (default) or a `#rrggbb` color. Used
  for the letterbox of non-square sources and the apple-touch flatten.
  With the default, `apple-touch-icon.png` gets a white background
  (iOS composites transparent icons onto black; a black box is nobody's
  intent).
- **Padding (%)** — percent of the canvas kept empty around the icon
  (0–25). iOS home-screen and Android adaptive icons crop into the
  corners; 5–10% of padding keeps the logo clear of the cut.

### Output

- **Write the set here too** — a real project folder so the files
  survive the run. Default: next to the source image; the set always
  also lands in the PyShell run folder.

## Result

- **Results tab** — the file table (name, bytes, purpose) and the
  ready-to-paste `<head>` snippet.
- **Artifacts** — the eight files above.

## Exit codes

- `0` — the set was generated, however degraded the source (warnings
  are results, not failures).
- `1` — the source cannot be read as an image, or the files can't be
  written.
- `2` — bad arguments (an unknown background color, padding outside
  0–25).
