# Icon Audit

**What's wrong with the icon set, before the sprite bakes it in.**
SVG Optimize and SVG Sprite Build take the folder as given — the
first minifies whatever it finds, the second silently renames,
synthesizes and prefixes, and dies only on the one collision it
cannot survive. This script is the gate before both: everything
the set gets wrong while fixing is still cheap.

- **viewBox diversity** — the 24/20/16 mix; missing viewBoxes (the
  build's synthesis noted as the guess it is).
- **Naming vs the sprite's own slug convention** — the silent
  renames listed as the names they become; the collisions the
  build hard-fails on, caught here first.
- **Fill vs stroke mix**, **stroke-width outliers** — a set that
  reads as two sets.
- **Geometry duplicates** — identical path data (paint excluded)
  under different names.
- **Embedded rasters** — `<image>`/`data:image/` inside an "SVG".
- **The a11y shape** — `<title>` stripped at build (belongs at the
  `<use>` site), the `aria-hidden` reminder.
- **Unused icons** — with a code folder given, every symbol id and
  slug grepped against your codebase; dead weight in the sprite is
  bytes every visitor pays for.

The conveyor this gates: **Figma Export → this → SVG Optimize →
SVG Sprite Build**.

## Using with PyShell

1. Pick the **Icon folder** (and optionally the **Code folder**
   for the unused check).
2. Press **Run** (⌘↩) — **Prepare Env** installs lxml once.

## Running standalone

```bash
pip install -r requirements.txt
python3 main.py --icons-dir ./assets/icons
python3 main.py --icons-dir ./assets/icons --code-dir ./src
```

## Result

- **Results tab** — the summary table and the per-check report
  with named icons and fixes.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the audit ran; findings are results |
| 1 | no `.svg` files in the folder |
| 2 | bad arguments (folder not found) |

## Layout

```
icon-audit/
├── pyshell.yaml      # manifest
├── main.py           # facts · checks · unused-grep · report
├── requirements.txt  # lxml
├── docs/             # EN + UA docs
└── tests/            # 8 tests: a synthetic set + code folder
```

## License

MIT — see the root [LICENSE](../LICENSE).
