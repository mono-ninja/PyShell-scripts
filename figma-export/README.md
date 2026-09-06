# Figma Export

**The design tool meets the code pipeline.** The icon conveyor
(Icon Audit → SVG Optimize → SVG Sprite Build) always started with
"somehow the SVGs appear in a folder" — this script is that
somehow: the components of a Figma file or frame, exported as SVG
with names normalized to the sprite's own slug convention.

- **Personal access token via the Keychain** (env `FIGMA_TOKEN`
  standalone, never argv). Without it: an honest exit with the
  where-to-get-one line — never an imitated export.
- **Scope** — the whole file, or the frame in the URL's
  `?node-id=`; component sets walk to their variants.
- **Names** — the exact slugify SVG Sprite Build applies
  (kebab-case, `icon-` stripped): nothing renames twice;
  collisions get `-2` and are said aloud.
- **PNG at 1x/2x** — optional, for the places SVG cannot go.
- **The honest limit, surfaced live** — the Variables API is
  Enterprise-only: a 403 reads "not checked", never "no
  variables". Nodes and published styles — what icons need —
  work on every plan.

## Using with PyShell

1. Paste the token once (Keychain) and the file URL.
2. Press **Run** (⌘↩) — **Prepare Env** installs requests once.

## Running standalone

```bash
export FIGMA_TOKEN=figd_…
python3 main.py --figma-url "https://www.figma.com/design/<key>/Icons"
python3 main.py --figma-url "https://www.figma.com/file/<key>/Icons?node-id=12-34" --png-scale 2
```

## Result

- **Results tab** — the exports table and the report (name
  normalizations, collisions, the variables note, the conveyor
  steps).
- **Artifacts** — `<slug>.svg` (`.png` when chosen),
  `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | exported |
| 1 | no token / nothing to export / downloads failed |
| 2 | bad arguments (not a figma.com URL) |

## Layout

```
figma-export/
├── pyshell.yaml      # manifest (token: secret → env)
├── main.py           # URL parse · component walk · slugify · export
├── requirements.txt  # requests
├── docs/             # EN + UA docs
└── tests/            # 14 tests: pure logic + a fake API
```

## License

MIT — see the root [LICENSE](../LICENSE).
