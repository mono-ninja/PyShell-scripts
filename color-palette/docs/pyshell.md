# Color Palette

Extracts a site's color palette from its CSS: every color in the
background, text, border, shadow and SVG/icon declarations, similar
colors grouped, handed back as a chart, a table, a ready-to-paste
**`palette.css`** (`:root` variables) and `palette.json`.

A port of the standalone colorPallet tool, reshaped for the
collection's one-fetch philosophy (same as [Page SEO
Audit](../../page-seo-audit)): the page is fetched once, its inline
`<style>` blocks and `style="…"` attributes are read, and each linked
stylesheet is fetched once — politely capped.

---

## Before running

1. **Site URL** — the page whose palette you want.
2. Click **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩). Seconds for a typical site.

**Static CSS only, v1.** Colors painted by JavaScript at runtime are
not seen — a page whose styles arrive via JS shows an honestly empty
palette with that explanation, never a guess. `@import` chains inside
stylesheets aren't followed either.

## Fields

### Target

- **Site URL** — `https://…`. Only this page and the stylesheets it
  links are read (cross-origin CDN links included — that's where CSS
  usually lives).
- **Max stylesheets** — how many linked CSS files to read (default
  25). A single stylesheet over 2 MB is skipped and reported, not
  read.
- **Per-request timeout (s)** — each fetch gets this long.

### Report

- **Colors per category** — how many colors each report section shows;
  `palette.json` keeps every group.

---

## Result

- **Results tab** — the bar chart (color groups per category), the
  table (hex · category · uses · variants · tone · primary/secondary
  role) and the report.
- **Artifacts** — `palette.css` (the `:root` variables:
  `--color-bg-primary`, `--color-text-secondary`, …, six per category),
  `palette.json` (every group with its variants, machine-readable),
  `report.md`.

### How the reading works

- **Every CSS color syntax parses**: `#fff`, `#rrggbb`, `#rrggbbaa`
  (alpha dropped — the palette wants the color, not the transparency),
  `rgb()/rgba()` and `hsl()/hsla()` in both the legacy comma form and
  the modern space form (`rgb(0 0 0 / 50%)`, `hsl(210 100% 50%)`),
  `oklch()`/`oklab()`, hue units `deg`/`grad`/`rad`/`turn`, and all 148
  named colors (incl. `rebeccapurple`; `transparent`/`inherit`/
  `currentColor` are keywords, not colors, and drop out).
- **What is deliberately *not* read**: a `var(--brand)` or
  `color-mix()` reference resolves only against the whole cascade, so
  it is left out rather than guessed at — but a literal fallback still
  counts (`var(--brand, #FF0000)` → `#FF0000`), as do literals written
  inside a `color-mix()`. Custom-property *names*
  (`var(--brand-red-500)`), `url()` paths, CSS comments and at-rule
  preludes (`@supports (color: color-mix(in lab, red, red))`) are never
  mistaken for colors.
- **Syntax variants are normalized at parse time** (`#333`, `#333333`
  and `rgb(51,51,51)` are one color); **grouping folds NEAR colors**
  (a hand-tuned `#343434` next to `#333333`) by perceptual HSL
  distance — the group's representative is its most-used member.
- **Categories come from the property**: `background`/`background-color`
  → backgrounds, `color` → text, `border*`/`outline*` → borders,
  `*-shadow` → shadows, `fill`/`stroke`/`stop-color` → SVG & icons.
- **Tone** (dark/light) is Rec. 601 luma — a quick readability hint,
  not a WCAG contrast verdict.

## Exit codes

- `0` — the run completed (an empty palette is an honest finding, not
  a failure).
- `1` — the page never answered: there was nothing to read.
- `2` — bad arguments (no scheme/host).
