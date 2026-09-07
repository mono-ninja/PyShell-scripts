# Color Palette

A [PyShell](https://github.com/mono-ninja/PyShell) script that extracts
a site's **color palette from its CSS** — every color in the
background, text, border, shadow and SVG/icon declarations — and hands
it back ready to use:

- a **chart** of color groups per category,
- a **table** of the most-used colors (hex · category · uses ·
  variants · dark/light tone · primary/secondary role),
- **`palette.css`** — ready-to-paste `:root` variables
  (`--color-bg-primary`, `--color-text-secondary`, …),
- **`palette.json`** — every group with its variants,
  machine-readable.

Every CSS color syntax parses (`#fff`, `#rrggbb`, `#rrggbbaa`,
`rgb()/rgba()` and `hsl()/hsla()` in both the comma and the modern
space form, `oklch()`/`oklab()`, all 148 named colors); syntax
variants merge at parse time, and **near-identical colors group
together** by perceptual distance (ΔE in OKLab) — the hand-tuned
`#343434` next to `#333333` becomes one group, and so do two whites
apart by one bit.

**Custom properties are resolved where they are unambiguous**: a
`--token` the page defines exactly once with a literal color resolves
every `var()` that references it. A token redefined per theme needs the
whole cascade to settle, so it is left out rather than guessed at —
and a custom-property *name* is never read as a color:
`var(--brand-red-500)` is a name, not the color red.

**Static CSS only.** The page is fetched once; each linked stylesheet
is fetched once (politely capped). Relative links resolve against the
URL the page finally answered from, so a site that redirects keeps its
stylesheets. Colors painted by JavaScript at runtime are not seen — an
empty palette says so honestly instead of guessing.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **Site URL** — press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --url https://example.org
python3 main.py --url https://example.org --max-stylesheets 40 --top-n 12
```

## Result

- **Results tab** — the bar chart (color groups per category), the
  color table, and the per-category report with variants listed.
- **Artifacts** — `palette.css`, `palette.json`, `report.md`.

## Exit codes

- `0` — the run completed (an empty palette is an honest finding —
  the page may paint itself with JavaScript).
- `1` — the page could not be read (no answer, or over 5 MB).
- `2` — bad arguments.

## Layout

```
color-palette/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # thin entry point: fetch, count, group
├── requirements.txt     # requests
├── src/
│   ├── colors.py        # parse/convert/distance/group (pure, ported)
│   ├── extract.py       # CSS + HTML extraction (pure regex)
│   └── report.py        # chart, table, markdown, artifacts
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
