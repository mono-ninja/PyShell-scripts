# SVG Sprite — Build

Builds a folder of `.svg` icons into a single symbol-sprite (`sprite.svg`) — a
set of `<symbol>` definitions inside one hidden `<svg>`, later referenced from
markup via `<svg><use href="#icon-…"/></svg>`. It can additionally generate
`catalog.html` (a self-contained preview page of all icons) and `sprite.php`
(a WordPress include with the same defs).

---

## Before running

1. Click **Prepare Env** — PyShell will install `lxml`, `tinycss2`, `jinja2`.
2. **Icons folder** — the folder with `.svg` files. No recursion: subfolders are
   ignored, hidden files (starting with a dot) too.
3. **Output folder** — where to write the artifacts, usually somewhere inside
   the project (`assets/icons/`). The sprite is written here, and under PyShell
   also into the artifacts folder, so the **Show**/**Save** cards appear.

---

## Fields

### Source

- **Icons folder** — the single input folder. Paths are sorted deterministically
  (byte order), so the same folder yields a byte-for-byte identical sprite — a
  git diff shows the real change, not reshuffled lines.

### Naming

- **Symbol ID prefix** — prefix for the id of each symbol (default `icon-`).
  The filename is slugified: lowercase, separators → `-`, the `icon-` prefix is
  stripped from the name, then your prefix is added back. So both
  `Arrow_Left.svg` and `icon-arrow-left.svg` become `icon-arrow-left`.

### Normalize

- **Substitute currentColor** — off by default. When enabled, it scans all
  `fill`/`stroke` values of the icon; if there is exactly one non-`none` color —
  it is replaced with `currentColor` (the icon picks up the CSS `color`).
  Multiple colors (duotone) stay as-is; a "multicolour" notice appears in the
  warnings. Gradient references `url(#…)` are not treated as colors.
- **Add `<title>` from filename** — adds a `<title>` from the slugified name as
  the first child of `<symbol>` (accessibility). Editorial `<title>`/`<desc>`
  are always removed; this toggle only re-adds a new `<title>`.

Root attributes `fill`, `stroke`, `stroke-width`, `stroke-linecap`,
`stroke-linejoin`, `fill-rule` are carried over from the source `<svg>` onto the
`<symbol>` — this is what saves outline sets (Lucide/Feather with `fill="none"`)
from turning into black blobs. `width`/`height` are stripped — size is driven by
CSS.

### Optimize

- **Path precision** — number of decimals to which numbers in `d` (path) and
  `points` (polygon/polyline) are rounded. `3` by default; `0` — integers.
- **Run npx svgo pre-pass** — run the sources through SVGO before building.
  Requires Node/npx. This is the only way to get serious compression (merging
  paths, collapsing transforms) — the script does not duplicate this internally.
  On any failure (svgo not installed, timeout) the run simply falls back to the
  originals, without aborting.

Optimization inside is intentionally conservative: it strips comments and
`<metadata>`, empty `<g>`, unused children of `<defs>`, attributes equal to SVG
defaults (only when no ancestor sets the same property — so an explicit
`stroke="none"` overriding an inherited `stroke="red"` doesn't disappear).

### Output

- **Generate catalog.html** — on by default. A self-contained HTML page: the
  sprite is embedded inside (hidden), each icon is rendered via
  `<use href="#id">`. Works from `file://`.
- **Generate WordPress include (sprite.php)** — the sprite-defs as a PHP file.
  `<?php include 'sprite.php'; ?>` will output the hidden `<svg>` with all
  symbols; then in markup `<use href="#icon-…">`.

---

## id and class deduplication

Each `id` inside an icon gets a `{symbol-id}__` prefix, and every reference to
it is rewritten — `href="#a"`, `url(#a)` in `fill`/`stroke`/`clip-path`/`mask`/
`filter`/`marker-*`, in `style` attributes and in CSS inside `<style>`, as well
as `id.event` in animation `begin`/`end`. Classes are prefixed the same way,
and selectors in `<style>` are rewritten via `tinycss2`. That's why an
Illustrator `.st0 { fill:#000 }` won't override every other icon in the sprite.

---

## Exit code

- `0` — sprite built (even if some files were skipped: broken SVG, or an icon
  without a `viewBox` — they remain in the table with a warning).
- `1` — no `.svg` found at all.
- `2` — argument error, or a **name conflict** (A3): two files slugify to the
  same id (e.g. `arrow_left.svg` and `arrow-left.svg` in the same folder). The
  message names both paths — this is a hard error, because the sprite cannot
  contain two symbols with the same id. A single broken export does not trigger
  this — you'll see it in History as a green run with warnings, not a red one.
