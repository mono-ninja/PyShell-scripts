# A11y Check

**The accessibility pass a page deserves** — statically and
honestly. One fetch (the Page SEO Audit principle), everything
computed from the HTML and the CSS that can be read without running
the page:

- **Contrast (WCAG 1.4.3)** — text × background wherever the pairing
  is unambiguous: inline styles, `<style>` blocks, fetched
  stylesheets with simple tag/class/id selectors. `color` and
  `background` follow the **ancestor chain**, more specific rules
  win over later ones, `@media print` and dark-scheme blocks stay
  out, and a background image or gradient makes the pair *unknown*
  rather than white. The color parser is the one written for Color
  Palette (every CSS syntax → RGB, including `rgb(0 0 0 / 50%)`,
  `hsl(210 100% 50%)` and `oklch()`); the ratio is the WCAG
  relative-luminance formula; large text (24px, or 19px bold —
  headings included, at their browser defaults) gets the 3:1 bar
  instead of 4.5:1. Nothing statically pairable → the report says
  **"not checked"**, never "passed".
- **Forms** — controls without a label; placeholder-only and
  title-only are warnings (neither is a label), and a `for=` or
  `aria-labelledby` pointing at an id that is not on the page counts
  as no label at all. `<fieldset>` without `<legend>`.
- **Headings** — level skips, first-heading-not-h1, several h1.
- **Language** — `lang` on `<html>` (WCAG 3.1.1, level A), invalid
  codes, foreign-language inserts (`en-US` inside `en` is the same
  language, not an insert).
- **ARIA misuse** — roles without their required state
  (checkbox/slider/…), `aria-hidden` on a genuinely focusable
  element (`tabindex="-1"` is the correct way to hide one, and is
  not flagged); `role=presentation` there is a warning instead, be-
  cause ARIA ignores a presentational role on anything focusable.
  `aria-labelledby`/`aria-describedby` pointing at nothing.
- **Focus** — positive `tabindex` (the DOM order is the right order).
- **Links** — empty links, "click here" generic text.
- **Tables** — data tables without `<th>`, `<th>` without `scope`.
- **Media** — `<iframe>` without a title, autoplaying audio or
  unmuted video, `<video>` without a `<track>`.
- **Meta** — a viewport that blocks zoom (WCAG 1.4.4), a
  `<meta http-equiv="refresh">` timer (WCAG 2.2.1).
- **Duplicate ids** (WCAG 4.1.1) — they break every `for=` and
  `aria-labelledby` that points at them.
- **Landmarks & skip link** — main/nav/header as elements *or* ARIA
  roles, the first `#` link.

Identical findings are folded into one row with a count and a few
examples — one stylesheet mistake is one finding, not six hundred.

Image `alt` stays **Page SEO Audit's** column — this script counts
them for context and points there.

## Using with PyShell

1. Enter the **URL** to check.
2. Press **Prepare Env** (installs `requests` + `lxml`), then
   **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --url https://example.com/
python3 main.py --url https://example.com/ --max-stylesheets 5
python3 main.py --url https://example.com/ --timeout 30
```

## Result

- **Results tab** — a table (severity · check · finding · where) and
  the report grouped by check, each finding with its fix.
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

🔴 errors (contrast failures, missing labels, ARIA misuse) · 🟠
warnings only · 🟢 clean. Info items (landmarks, skip link, generic
links) are context, not failures.

### The honest boundary

No JS execution, no computed styles. Contrast is checked where the
cascade can be followed statically — inline styles, simple selectors
and inheritance, which is a deterministic mechanism, not a guess.
Compound and descendant selectors, JS-set styles, custom properties
(`var()`) and text over an image are out of scope and reported as
such, together with the count of pairs that *were* checked. Where no
background is declared anywhere up the chain, the browser's white
canvas is assumed and the finding says so. Same contract as Color
Palette's "static CSS only, honestly".

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results (an HTTP 404 page is audited too) |
| 1 | unreachable, or the response is not an HTML page to audit |
| 2 | bad arguments (no http(s) URL) |

## Layout

```
a11y-check/
├── pyshell.yaml      # manifest
├── main.py           # color engine · CSS engine · 12 audits · report
├── requirements.txt  # requests, lxml
├── docs/             # EN + UA docs
└── README.md
```

## Siblings

- [Contrast Matrix](../contrast-matrix) — the same WCAG math on a
  whole palette *before* the page exists, plus APCA (Lc) as a second
  opinion and the nearest passing shade for every failing pair.
- [Color Palette](../color-palette) — the color engine this script's
  parser is shared with.
- [Page SEO Audit](../page-seo-audit) — the same one-fetch pass for
  the search-visibility signals, and the home of the `alt` audit.

## License

MIT — see the root [LICENSE](../LICENSE).
