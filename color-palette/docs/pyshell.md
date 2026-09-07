# Color Palette

Extracts a site's color palette from its CSS: every color in the
background, text, border, shadow and SVG/icon declarations, similar
colors grouped, handed back as a chart, a table, a ready-to-paste
**`palette.css`** (`:root` variables) and `palette.json`.

A port of the standalone colorPallet tool, reshaped for the
collection's one-fetch philosophy (same as [Page SEO
Audit](../../page-seo-audit)): the page is fetched once, its inline
`<style>` blocks and `style="…"` attributes are read, and each linked
stylesheet is fetched once — politely capped. Relative links resolve
against the URL the page finally answered from (and its `<base href>`),
so a site that redirects keeps its stylesheets.

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
  read; a page over 5 MB is not read at all.
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
- **Custom properties are resolved where they are unambiguous**: the
  stylesheets are read twice, once for `--token: <literal color>`
  definitions and once for the colors. A token the page defines
  exactly once resolves every `var()` that references it, so a
  token-driven site reports the palette it paints rather than an empty
  one. A token redefined per theme (`:root` light, `.dark` dark) needs
  the whole cascade to settle, so it stays unresolved — as does
  `color-mix()`. A literal fallback still counts on its own
  (`var(--never-defined, #FF0000)` → `#FF0000`), as do literals
  written inside a `color-mix()`. Custom-property *names*
  (`var(--brand-red-500)`), `url()` paths, CSS comments and at-rule
  preludes (`@supports (color: color-mix(in lab, red, red))`) are never
  mistaken for colors.
- **Syntax variants are normalized at parse time** (`#333`, `#333333`
  and `rgb(51,51,51)` are one color); **grouping folds NEAR colors**
  (a hand-tuned `#343434` next to `#333333`) by perceptual distance —
  ΔE in OKLab, which holds at the ends of the lightness range as well
  as in the middle, where HSL filed `#FFFFFF` and `#FFFEFE` as
  opposites. The group's representative is its most-used member.
- **Categories come from the property**, shorthands included:
  `background*`/`accent-color`/`scrollbar-color` → backgrounds,
  `color`/`caret-color`/`text-decoration*`/`text-emphasis*` → text,
  `border*` (`border-bottom: 1px solid #ddd` too)/`outline*`/
  `column-rule*` → borders, `*-shadow`/`filter` → shadows,
  `fill`/`stroke`/`stop-color`/`flood-color`/`lighting-color` → SVG &
  icons.
- **Tone** (dark/light) is Rec. 601 luma — a quick readability hint,
  not a WCAG contrast verdict.

## Exit codes

- `0` — the run completed (an empty palette is an honest finding, not
  a failure).
- `1` — the page could not be read: it never answered, or it is over
  5 MB.
- `2` — bad arguments (no scheme/host).
