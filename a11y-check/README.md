# A11y Check

**The accessibility pass a page deserves** — statically and
honestly. One fetch (the Page SEO Audit principle), everything
computed from the HTML and the CSS that can be read without running
the page:

- **Contrast (WCAG 1.4.3)** — text × background wherever the pairing
  is unambiguous: inline styles, `<style>` blocks, fetched
  stylesheets with simple tag/class/id selectors. The color parser
  is the one written for Color Palette (every CSS syntax → RGB); the
  ratio is the WCAG relative-luminance formula; large text (24px, or
  19px bold) gets the 3:1 bar instead of 4.5:1. Nothing statically
  pairable → the report says **"not checked"**, never "passed".
- **Forms** — inputs/selects/textareas without a label (placeholder-
  only is a warning: it is not a label).
- **Headings** — level skips, first-heading-not-h1, several h1.
- **Language** — `lang` on `<html>` (WCAG 3.1.1, level A), invalid
  codes, foreign-language inserts.
- **ARIA misuse** — roles without their required state
  (checkbox/slider/…), `aria-hidden`/`role=presentation` on focusable
  elements.
- **Focus** — positive `tabindex` (the DOM order is the right order).
- **Links** — empty links, "click here" generic text.
- **Tables** — data tables without `<th>`, `<th>` without `scope`.
- **Landmarks & skip link** — main/nav/header, the first `#` link.

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

No JS execution, no computed styles: contrast is checked where a
rule unambiguously maps to an element (inline styles and simple
selectors); descendant selectors, inheritance chains and JS-set
styles are out of scope and reported as such. This is the same
contract as Color Palette's "static CSS only, honestly".

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | unreachable |
| 2 | bad arguments (no http(s) URL) |

## Layout

```
a11y-check/
├── pyshell.yaml      # manifest
├── main.py           # color engine · 9 audits · report
├── requirements.txt  # requests, lxml
├── docs/             # EN + UA docs
└── tests/            # 24 tests over offline HTML fixtures
```

## License

MIT — see the root [LICENSE](../LICENSE).
