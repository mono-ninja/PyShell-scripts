# OG Image

**Social cards produced, not checked.** Page SEO Audit verifies
the `og:image` tag; this makes the file it points at — at the
1200×630 standard every preview renderer reads. The
favicon-generator form applied to the social side: one input → the
set + the snippet, and **batch mode** drives hundreds of pages
through the same template from one CSV.

- **Three fixed templates, not a constructor** — gradient (two
  brand colors), accent banner (solid base + bar), background
  image (cover-fit, never squashed, darkened for legibility).
- Titles wrap and auto-shrink to fit; subtitle under the title;
  optional logo top-left; optional brand font.
- **The complete meta snippet** per card: `og:image`,
  `og:image:width/height`, `og:image:alt`, `twitter:card` —
  relative filenames or absolute URLs with **Base URL**.
- The brand synergy runs both ways: Color Palette extracts the
  site's hexes — paste them here.

## Using with PyShell

1. Pick the **Mode**, the **Template**, the two colors.
2. Press **Run** (⌘↩) — **Prepare Env** installs Pillow once.

## Running standalone

```bash
pip install -r requirements.txt
python3 main.py --title "Launch Week" --subtitle "six posts" --color-accent "#f59e0b"
python3 main.py --mode batch --csv-file pages.csv --base-url "https://site.com/og"
python3 main.py --title "Over Photo" --template image --bg-image hero.png
```

## Result

- **Results tab** — the cards table and the report with every
  card's head block.
- **Artifacts** — `<slug>.png` per card, `meta-snippets.html`,
  `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the cards rendered |
| 1 | a card failed to render |
| 2 | bad arguments (no title, no CSV, missing files, image template without a background) |

## Layout

```
og-image/
├── pyshell.yaml      # manifest
├── main.py           # three templates · fit/wrap · snippets · CSV batch
├── requirements.txt  # Pillow
├── docs/             # EN + UA docs
└── tests/            # 14 tests: renderers, snippets, CSV, CLI
```

## License

MIT — see the root [LICENSE](../LICENSE).
