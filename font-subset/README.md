# Font Subset

**A font cut to what a page actually serves.** Web fonts ship
whole — the visitor downloads every glyph of every alphabet the
typeface supports, to render one paragraph. This script cuts:
Montserrat-shape savings (64.6 KB → 15 KB, −76%), as woff2 — the
97%+ container.

Three ways to say what to keep, in precedence order:

- **Pages actually served** — HTML/CSS scanned for the glyphs
  really used (tags stripped, CSS syntax dropped): one woff2, the
  honest "what the site needs" cut.
- **A text sample** — exactly the glyphs of the copy you paste.
- **Language subsets** — Google's ranges (latin, latin-ext,
  cyrillic, cyrillic-ext, greek, greek-ext, vietnamese): one woff2
  per subset with its `unicode-range`, so a Cyrillic page never
  fetches the Greek block.

Every subset ships with a ready `@font-face` — `font-display:
swap`, the real weight/style read from the font's own tables — and
the measured savings table. The **Inventory** mode is the other
half: family, weight, per-language coverage, what the pages use,
what the font is missing.

Honesty: zero-coverage subsets are skipped (an empty woff2 is not
a deliverable), partial coverage is reported per subset, and the
swap flash is named as the price of `font-display: swap`.

## Using with PyShell

1. Pick the **Font file** and the **Mode**.
2. Press **Run** (⌘↩) — **Prepare Env** installs fontTools +
   brotli once.

## Running standalone

```bash
pip install -r requirements.txt
python3 main.py --font-file montserrat.ttf --subset latin --subset cyrillic
python3 main.py --font-file montserrat.ttf --text-sample "The exact copy served"
python3 main.py --font-file montserrat.ttf --scan-file index.html --scan-file style.css
python3 main.py --mode inventory --font-file montserrat.ttf
```

## Result

- **Results tab** — the savings table and the report with the
  `@font-face` blocks.
- **Artifacts** — `<family>-<subset>.woff2`, `fontface.css`,
  `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the subsets (or inventory) are the result |
| 1 | font unreadable / no subset produced |
| 2 | bad arguments (missing file, nothing to subset by, unknown subset) |

## Layout

```
font-subset/
├── pyshell.yaml      # manifest
├── main.py           # ranges · subsetter · @font-face · inventory
├── requirements.txt  # fonttools, brotli
├── docs/             # EN + UA docs
└── tests/            # 13 tests over a FontBuilder-built real font
```

## License

MIT — see the root [LICENSE](../LICENSE).
