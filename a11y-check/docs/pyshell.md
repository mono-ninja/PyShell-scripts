# A11y Check

The static accessibility pass: WCAG text contrast computed from the
CSS that can be read without running the page (the Color Palette
color engine + the WCAG relative-luminance ratio, large text at
3:1), forms without labels, heading skips, `lang` on `<html>`, ARIA
roles without their required state, `aria-hidden` on focusable
elements, positive `tabindex`, empty and "click here" links, data
tables without `<th>`, landmarks and the skip link.

One fetch — the Page SEO Audit principle. What static analysis
cannot see is reported as **not checked**, never as passed.

---

## Before running

1. Enter the **URL** of the page to check.
2. **Prepare Env** — installs `requests` and `lxml`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the page to check; redirects are followed, the report
  shows the final URL.
- **Per-request timeout (s)** — the page fetch and each stylesheet
  fetch.
- **Stylesheets for contrast** — how many linked stylesheets to
  fetch for the contrast pass (0–10, default 3). Only rules with a
  *single simple* selector (tag / `.class` / `#id`) participate —
  that is the static scope.

---

## Result

- **Results tab** — the table (severity · check · finding · where)
  and the report grouped by check:
  - **contrast** — the ratio, the pair, the threshold it missed, per
    element (`tag#id.class — "text snippet"`); when nothing is
    statically pairable, the honest "not checked" note.
  - **forms** — every unlabelled control, placeholder-only flagged
    as a warning.
  - **headings / lang / aria / focus / links / tables / landmarks** —
    each finding with its fix.
  - **images** — the count without alt, with a pointer to **Page SEO
    Audit** (alt is its column; this script does not double-audit).
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

🔴 errors · 🟠 warnings only · 🟢 clean. Errors are the WCAG-shaped
musts (contrast below ratio, no label at all, aria-hidden on a
focusable element, no `lang`); warnings the shoulds (placeholder,
heading skip, positive tabindex, generic link text); info the
context (landmarks, skip link, multiple h1, foreign-language
inserts).

### The honest boundary

No JS execution, no computed styles. Contrast is checked where a
rule unambiguously maps to an element; nothing declared → the white
canvas assumption (documented); JS-set styles, descendant selectors
and inheritance chains are out of scope and reported as such. A
DevTools contrast spot-check covers the rest.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | unreachable — connection failed |
| 2 | bad arguments: no http(s) URL |

## Related

- **Page SEO Audit** — the same one-fetch pass for the
  search-visibility signals (title, meta, headings, alt).
- **Color Palette** — the color engine this contrast math grew out
  of; use it when picking an accessible palette.
- **Site Crawler → SEO Checks** — the whole-site pass; this script
  is the deep single-page one.
