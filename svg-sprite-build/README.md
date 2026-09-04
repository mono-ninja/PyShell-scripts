# SVG Sprite — Build

Bundle a folder of SVG icons into a single `<symbol>` sprite — with an icon
catalog and an optional WordPress include.

One direction only: a folder of `.svg` files in, `sprite.svg` (plus
`catalog.html` and `sprite.php`) out. Built as a standalone
[PyShell](https://github.com/mono-ninja/PyShell) script, but it runs just as well from a plain
terminal.

## Features

- **Deterministic output** — files are sorted and serialized stably, so the
  sprite is diffable in git.
- **Safe ID/class deduplication** — every `id` is prefixed with the symbol id
  and every reference (`href`, `xlink:href`, `url(#…)`, `begin`/`end`,
  inline `<style>` selectors) is rewritten. Illustrator's `.st0 { … }` blocks
  no longer leak across icons.
- **Outline icons stay outline** — root `fill`/`stroke` attributes are carried
  onto the `<symbol>`, so Lucide/Feather-style icons don't turn into solid
  blobs.
- **currentColor substitution** — applied only when a symbol uses exactly one
  non-`none` colour; duotone icons are left untouched.
- **Conservative optimization** — comments, empty groups, unreferenced defs
  and default-valued attributes are removed; path numerics are rounded to a
  configurable precision. Optional `npx svgo` pre-pass for heavy compression.
- **Resilient batches** — one malformed export is logged and skipped; it never
  kills a rebuild of 300 icons. Only a naming collision (two files slugifying
  to the same id) is a hard error.

## Requirements

- Python 3.11+ (plain `venv`, no packaging)
- [lxml](https://lxml.de/) ≥ 5.0, [tinycss2](https://tinycss2.readthedocs.io/) ≥ 1.2,
  [Jinja2](https://jinja.palletsprojects.com/) ≥ 3.1 — see `requirements.txt`
- Optional: Node.js/npx for the SVGO pre-pass; [watchdog](https://pypi.org/project/watchdog/)
  for the dev watcher

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `lxml`, `tinycss2`, `jinja2`.
3. Pick the icons folder and output folder, toggle the options, press
   **Run** (⌘↩) — the sprite, catalog and WordPress include land as artifacts
   with a per-symbol result table.

Field-by-field documentation lives in
[`docs/pyshell.md`](docs/pyshell.md) — the same text is shown in PyShell's
**Docs** panel (⌘D).

## Running standalone

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main.py --src assets/icons --out dist/icons
```

| Flag | Description | Default |
|---|---|---|
| `--src` | Folder of `.svg` files (required) | — |
| `--out` | Output folder (required) | — |
| `--prefix` | Symbol ID prefix | `icon-` |
| `--current-color` | Substitute `currentColor` when exactly one non-`none` colour is used | off |
| `--a11y-titles` | Add a `<title>` from the filename slug to each symbol | off |
| `--precision` | Decimals to round path numerics to (0–6) | `3` |
| `--svgo` | Run `npx svgo` as a pre-pass (falls back to originals on failure) | off |
| `--catalog` | Generate `catalog.html` | off (on in the PyShell form) |
| `--wordpress` | Generate `sprite.php` (WordPress include) | off |

### Watch mode (local dev)

Not a PyShell entry point — run it from a terminal:

```bash
pip install watchdog
python -m src.watch assets/icons --out dist/icons
```

Watches for `.svg` changes (300 ms debounce) and does a full rebuild on each
change — under a second for a few hundred icons. One log line per rebuild:
timestamp, icon count, output size, warning count.

## Exit codes

- `0` — sprite built (skipped files appear as warnings in the result table)
- `1` — no `.svg` files found
- `2` — bad arguments or a naming collision

## Result

| File | Description |
|---|---|
| `sprite.svg` | The symbol sprite. Reference an icon with `<svg><use href="sprite.svg#icon-name"/></svg>` |
| `catalog.html` | Self-contained preview page with every symbol rendered inline |
| `sprite.php` | The sprite defs as a PHP file to `include` once in a WordPress theme |

## Pipeline

`src/build.py` runs one pipeline; `main.py` and `src/watch.py` are both just
wrappers around it:

1. **Discover** — glob `*.svg`, sort deterministically
2. **Parse** — `lxml` with entity expansion disabled; malformed files are
   skipped and logged
3. **Normalize** — synthesize `viewBox` from `width`/`height`, carry root
   presentation attributes onto the `<symbol>`, strip editor namespaces,
   optionally substitute `currentColor`
4. **Dedupe** — prefix `id`s and classes per symbol, rewrite every reference
   (the hard part)
5. **Optimize** — drop comments/metadata/empty groups, remove default
   attributes, round numerics
6. **Assemble** — symbols → sprite document, serialized one symbol per line
   group for readable git diffs

## Layout

```
svg-sprite-build/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point — wraps the src/ pipeline
├── requirements.txt     # lxml, tinycss2, jinja2
├── src/                 # pipeline modules, emit_* writers, watch.py (dev)
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
