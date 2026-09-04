# SVG Sprite — From Font

Convert a legacy icon font (FontAwesome 4, IcoMoon, custom IcoMoon sets) into
a modern SVG sprite built from `<symbol>` elements — with human-readable icon
names, a side-by-side verification catalog, and optional WordPress /
migration-CSS shims.

Typical scenario: an inherited WordPress theme where the icon font is embedded
and the original SVG sources were lost long ago — only the font files and CSS
remain.

## ⚠️ Licence — read before running

Extracting outlines from a font is a matter of **redistribution**, not
technique. FontAwesome Pro, Linearicons and most commercial sets prohibit it
explicitly. The tool reads the font's `name` table (copyright and licence),
prints it, and **halts without writing any files** if the licence is
restrictive and the `--i-have-the-rights` flag is not set.

- Permissive licences (OFL, Apache, MIT, BSD, Public Domain) proceed without
  the flag.
- Unclassifiable licences proceed at your own risk. SVG fonts have no `name`
  table and always fall into this category.

## Running standalone

Requires Python 3.11–3.14; dependencies: `lxml`, `tinycss2`, `jinja2`,
`fontTools[woff]`, `svgpathtools`.

```bash
pip install -r requirements.txt

python main.py \
  --font icons.ttf \
  --css icons.css \
  --out ./sprite-out \
  --wordpress \
  --migration-css
```

### Options

| Flag | Description |
| --- | --- |
| `--font` | Font file: `.ttf`, `.otf`, `.woff`, `.woff2`, or SVG font (`.svg` with `<font>`). `.eot` is not supported — provide a TTF. **Required.** |
| `--css` | Accompanying CSS with icon class names. The source of human-readable names (`.icon-user:before { content: "\e900" }`). Without it, names come from the `post` table, ligatures, or the `icon-uniE900` fallback. |
| `--names` | Existing `names.json` from a previous run — re-read and takes priority over everything else. Edit it by hand and re-run. |
| `--prefix` | Sprite symbol id prefix (default `icon-`). |
| `--flatten` / `--no-flatten` | Bake the y-flip transform into path data (smaller output, no `<g>` wrapper conflicts with CSS on `<use>`) vs. keep a wrapper `<g>`. CLI default: no flattening. |
| `--fit advance\|bbox` | viewBox fit: `advance` (faithful to the font's side bearings, default) or `bbox` (visually normalized — useful when icons “float” in wide side bearings). |
| `--fit-padding` | Padding around the bbox fit, in font units. |
| `--scan-usage` + `--scan` | Restrict output to icons actually used in a theme: walks `.php`, `.html`, `.js`, `.css` looking for legacy classes. Works for class-based fonts (FontAwesome 4, IcoMoon). |
| `--out` | Output folder. **Required.** |
| `--wordpress` / `--no-wordpress` | Generate the `sprite.php` WordPress include. CLI default: off. |
| `--migration-css` / `--no-migration-css` | Generate `migration.css`. CLI default: off. |
| `--i-have-the-rights` | Confirm you hold redistribution rights for the font's outlines; required for restrictive licences. |

## Result

- `sprite.svg` — the `<symbol>` sprite.
- `catalog.html` — a two-column grid: each icon from the sprite via `<use>`
  next to the same icon from the original font (embedded as a base64
  `@font-face`). The honest way to spot geometry defects immediately. For SVG
  fonts the original is not rendered (browsers dropped SVG fonts) — a note is
  shown instead.
- `names.json` — codepoint → name → source mapping. Edit and re-run.
- `sprite.php` *(with `--wordpress`)* — WordPress include: the `wp_body_open`
  hook (with a `wp_footer` fallback) prints the sprite once; the helper
  `mn_icon( $name, $class, $label )` renders a `<use>` with `aria-hidden` or
  `role="img"` + `<title>`.
- `migration.css` *(with `--migration-css`)* — **the main migration
  artifact**. Every legacy class (`.fa-user`) is mapped to
  `mask-image: url("sprite.svg#icon-user")` and the `::before` content is
  zeroed out. Existing markup like `<i class="fa fa-user"></i>` keeps working
  after the font file is deleted. Load it **after** the theme's icon-font CSS.

## Exit codes

- `0` — success (unnamed icons are a partial success; see the results table).
- `2` — input not recognized / extraction impossible (`.eot`, COLR font,
  broken file). No files are written.
- `3` — licence gate: restrictive licence without `--i-have-the-rights`.
  No files are written.

## Using with PyShell

The tool is primarily designed to run under
[PyShell](https://github.com/mono-ninja/PyShell),
where it renders as a form-driven app
(`pyshell.yaml`) with structured progress, a results table, and artifact
cards. CLI flags map 1:1 to form fields; the PyShell UI additionally enables
`--flatten`, `--wordpress` and `--migration-css` by default.

See [docs/pyshell.md](docs/pyshell.md) for the PyShell-focused walkthrough
(the Ukrainian translation is [docs/pyshell_ua.md](docs/pyshell_ua.md)).

## Development

Pipeline stages live in `src/`: triage → extract (binary / SVG font) → name →
geometry → subset → assemble → emit.

## Layout

```
svg-sprite-from-font/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point — wraps the src/ pipeline
├── requirements.txt     # lxml, tinycss2, jinja2, fontTools, svgpathtools
├── src/                 # pipeline: triage → extract → name → geometry → subset → assemble
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository. The ⚠️ licence note above concerns
the fonts you feed the tool, not this script.
