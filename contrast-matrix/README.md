# Contrast Matrix

**Can you write with these colors?** A11y Check audits the page
post-factum; this runs at the design stage, where the data is
complete because you bring the palette: every text/background pair
judged before a single line of layout is written.

- **WCAG 2.2** — AA and AAA, body and large text separately
  (4.5 / 3.0 / 7.0 / 4.5), every ordered pair.
- **APCA (Lc)** — the second opinion that knows polarity
  (dark-on-light ≠ light-on-dark): pairs where the models disagree
  are exactly the interesting ones. Lc 75+ preferred body · 60
  minimum · 45 large.
- **The nearest passing shade** — for every AA-body failure, the
  smallest HSL-lightness shift of the text color that crosses
  4.5:1, offered as a hex. A fix, not a lecture.

Input: pasted hexes (any separator) or Color Palette's
`palette.json` — the palette chain closed: Color Palette extracts
→ this judges → A11y Check verifies on the live page.

Offline, stdlib only.

## Using with PyShell

1. Paste the colors (or point at `palette.json`).
2. Press **Run** (⌘↩) — nothing to install.

## Running standalone

```bash
python3 main.py --colors "#ffffff #101828 #667085 #4f46e5"
python3 main.py --palette-file palette.json
```

## Result

- **Results tab** — the pairs table (worst first) and the report:
  the full matrix, failing pairs with their nearest fixes, the
  two models read together.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the matrix is computed |
| 1 | fewer than two usable colors |

## Layout

```
contrast-matrix/
├── pyshell.yaml      # manifest
├── main.py           # WCAG 2.2 · APCA Lc · nearest-passing fixer
├── docs/             # EN + UA docs
└── tests/            # 14 tests: the math against known anchors
```

## License

MIT — see the root [LICENSE](../LICENSE).
