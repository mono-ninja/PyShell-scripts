# SVG Sprite — From Font

Converts an existing icon font (FontAwesome 4, IcoMoon, custom IcoMoon sets)
into a modern SVG sprite in the `<symbol>` format. The practical scenario is an
inherited WordPress theme where the font is embedded and the original SVGs were
lost long ago: only the font files and CSS remain.

## ⚠️ Licence — read before running

Extracting outlines from a font is a matter of **redistribution**, not
technique. FontAwesome Pro, Linearicons and most commercial sets prohibit this
explicitly. The tool reads the font's `name` table (copyright and licence),
displays it as a status, and **halts without writing any files** if the licence
is restrictive and the **“I have redistribution rights”**
(`--i-have-the-rights`) flag is not set. The licence text is always printed —
so an operator who does have the rights sees exactly what they are overriding.

For permissive licences (OFL, Apache, MIT, BSD, Public Domain) writing
proceeds without the flag. If the licence could not be classified, the run
continues, but at your own risk: SVG fonts have no `name` table, so they always
fall into this category.

## Before running

- **Font file** — `.ttf`, `.otf`, `.woff`, `.woff2` or an SVG font (`.svg` with
  a `<font>` element). `.eot` is not supported (provide a TTF).
- **Accompanying CSS** — the most important optional field. This is where the
  human-readable names live: `.icon-user:before { content: "\e900" }`. Without
  CSS, names are taken from the `post` table (sometimes `glyph42`) or from
  ligatures, and failing that — the fallback `icon-uniE900`.
- **Existing names.json** — re-running. The previous run's output
  (`names.json`) can be edited by hand: if the file exists, it is re-read and
  takes priority over everything else.
- **Flatten transform** (enabled) — bakes the y-flip into the path data via
  `svgpathtools` instead of wrapping in a `<g>`. Smaller output and no
  conflicts with CSS applied to `<use>`.
- **Fit** — `advance` (faithful to the font's side bearings, the default) or
  `bbox` (visually normalized: the viewBox is cropped to the icon's real bbox
  + Padding). `bbox` helps when icons “float” inside wide side bearings and
  look offset next to a hand-built sprite.
- **Restrict to icons found in the theme** + **Theme folder to scan** — walks
  `.php`, `.html`, `.js`, `.css` in the theme, looks for legacy classes and
  keeps only the icons actually used. Works for class-based fonts
  (FontAwesome 4, IcoMoon). Both numbers are reported: found in the font /
  actually used.

## Results

The **Results** tab shows a table: codepoint, resulting symbol id, name source
(CSS / `post` / GSUB / fallback / names.json), warnings. Artifacts in the files
tab:

- `sprite.svg` — the `<symbol>` sprite.
- `catalog.html` — a two-column grid: the icon from the sprite via `<use>`
  next to the same icon rendered from the original font (as a base64
  `@font-face`). This is the only honest way to spot geometry defects (B5)
  immediately. For SVG fonts the original is not rendered (browsers dropped
  SVG fonts) — a note is shown instead.
- `names.json` — codepoint → name → source. Edit it and re-run.
- `sprite.php` — a WordPress include: the `wp_body_open` hook (with a
  `wp_footer` fallback) prints the sprite once; the helper
  `mn_icon( $name, $class, $label )` renders a `<use>` with `aria-hidden` or
  `role="img"` + `<title>`.
- `migration.css` — **the main migration artifact**. Every legacy class
  (`.fa-user`) is mapped to `mask-image: url("sprite.svg#icon-user")`, and the
  `::before` content is zeroed out. Markup like
  `<i class="fa fa-user"></i>` does not need to be touched — it keeps working
  after the font file is deleted. Load it **after** the theme's icon-font CSS.

## Exit codes

- `0` — success (unnamed icons do not make the code non-zero — that is a
  partial success; the data is in the table).
- `2` — input not recognized / extraction impossible (`.eot` support, a COLR
  font, a broken file). No files are written.
- `3` — licence gate: restrictive licence without `--i-have-the-rights`.
  No files are written.
