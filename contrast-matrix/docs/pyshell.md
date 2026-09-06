# Contrast Matrix

Can you write with these colors? A11y Check audits the **page**
post-factum and honestly admits what static analysis cannot see;
this runs a stage earlier, where the data is complete because you
bring the palette: **every text/background pair judged before a
single line of layout is written.**

- **WCAG 2.2** — the ratio for each ordered pair, AA and AAA, body
  text and large text separately (4.5 / 3.0 / 7.0 / 4.5).
- **APCA (Lc)** — the second opinion: the newer model that knows
  dark-on-light and light-on-dark are not symmetric, so pairs
  where the two models disagree are exactly the interesting ones.
  Bands: Lc 75+ preferred body · 60 minimum body · 45 large text.
- **The nearest passing shade** — for every pair failing AA body,
  the text color's lightness is shifted in HSL (the smallest shift
  that crosses 4.5:1, either direction) and the hex is offered: a
  fix, not a lecture.

The chain this closes: **Color Palette** extracts the palette →
this says what can be written on what → **A11y Check** verifies it
survived the real page.

Offline, stdlib only — the matrix is math. Diagonal pairs (a color
on itself) are not pairs; the matrix is the ordered off-diagonal.

---

## Before running

1. Bring the colors: paste hexes into **Colors** (any separator),
   or point **palette.json** at Color Palette's artifact (every
   hex in it joins — the explicit list wins when both are given).
2. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **Colors** — hex colors, any separator (comma, space, newline) —
  e.g. the palette Color Palette extracted; takes precedence over
  the JSON file.
- **Or color-palette's palette.json** — every hex found in the
  file joins the matrix (used when the field above is empty).

Up to 24 colors (the cap is a note, never a silent stop).

---

## Result

- **Results tab** — the pairs table, worst first (text · on ·
  ratio · WCAG verdict · APCA Lc), and the report:
  - the full matrix;
  - **failing pairs with the nearest fix** — the hex of the
    closest text shade that passes AA (or the honest "no lightness
    of this hue reaches 4.5:1 — change the hue or the
    background");
  - **the two models read together** — pairs that pass WCAG AA
    but sit under APCA's body minimum are flagged as the known gap
    between the models.
- **Artifacts** — `report.md`, `findings.json` (every pair with
  all verdicts and fixes).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the matrix is computed |
| 1 | fewer than two usable colors |
| 2 | — |

## Related

- **Color Palette** — where the hexes come from.
- **A11y Check** — the live page's contrast, post-factum.
