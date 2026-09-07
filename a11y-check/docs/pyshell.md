# A11y Check

The static accessibility pass: WCAG text contrast computed from the
CSS that can be read without running the page (the Color Palette
color engine + the WCAG relative-luminance ratio, large text at
3:1), forms without labels, heading skips, `lang` on `<html>`, ARIA
roles without their required state, `aria-hidden` on focusable
elements, presentational roles that ARIA ignores, positive
`tabindex`, empty and "click here" links, data
tables without `<th>`, iframes without a title, autoplaying media,
zoom-blocking viewports, `<meta http-equiv="refresh">` timers,
duplicate ids, landmarks and the skip link.

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
  shows the final URL. A page that answers 404 or 500 is audited as
  it was served (people land on error pages too) — the report says
  which status it was.
- **Per-request timeout (s)** — the page fetch and each stylesheet
  fetch.
- **Stylesheets for contrast** — how many linked stylesheets to
  fetch for the contrast pass (0–10, default 3). Only rules with a
  *single simple* selector (tag / `.class` / `#id`) participate —
  that is the static scope. Print-only and alternate stylesheets are
  skipped, so the budget is spent on what actually renders; `<base
  href>` and relative paths are resolved the way the browser does.

---

## Result

- **Results tab** — the table (severity · check · finding · where)
  and the report grouped by check:
  - **contrast** — the ratio, the pair, the threshold it missed, per
    element (`tag#id.class — "text snippet"`); plus a note saying how
    many pairs static CSS could pin down, or the honest "not checked"
    when it could pin down none.
  - **forms** — every unlabelled control; placeholder-only,
    title-only and a `for=`/`aria-labelledby` that points at a
    missing id, each as a warning of its own.
  - **headings / lang / aria / focus / links / tables / media /
    meta / ids / landmarks** — each finding with its fix.
  - **images** — the count without alt, with a pointer to **Page SEO
    Audit** (alt is its column; this script does not double-audit).
- **Artifacts** — `report.md`, `findings.json` (each finding carries
  its `count` and up to three `examples`).

Findings that repeat verbatim are folded into one row with a count
and a few examples: one CSS mistake is one finding, however many
elements inherit it. The table shows the first 60 rows and says how
many more are in `report.md`.

### Verdicts

🔴 errors · 🟠 warnings only · 🟢 clean. Errors are the WCAG-shaped
musts (contrast below ratio, no label at all, aria-hidden on a
focusable element, no `lang`, a refresh timer); warnings the shoulds
(placeholder, title-only label, heading skip, positive tabindex,
generic link text, blocked zoom, duplicate ids, untitled iframe);
info the context (landmarks, skip link, multiple h1,
foreign-language inserts).

### The honest boundary

No JS execution, no computed styles. Contrast is checked wherever the
cascade can be followed statically: inline styles, simple selectors,
specificity, and inheritance up the ancestor chain — inheritance is a
deterministic CSS mechanism, not a guess. Out of scope, and reported
as not checked rather than passed: compound/descendant selectors,
JS-set styles, custom properties (`var()`), `color-mix()`, and text
sitting on a background image or gradient. When no background is
declared anywhere up the chain the browser's white canvas is assumed,
and the finding says so. A DevTools contrast spot-check covers the
rest.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results (an HTTP 404 page is audited too) |
| 1 | unreachable, an empty body, or a response that is not HTML |
| 2 | bad arguments: no http(s) URL |

## Related

- **Contrast Matrix** — the same WCAG math on a whole palette before
  the page exists, plus APCA (Lc) as the second opinion and the
  nearest passing shade for every pair this report flagged.
- **Page SEO Audit** — the same one-fetch pass for the
  search-visibility signals (title, meta, headings, alt).
- **Color Palette** — the color engine this contrast math grew out
  of; use it when picking an accessible palette.
- **Site Crawler → SEO Checks** — the whole-site pass; this script
  is the deep single-page one.
