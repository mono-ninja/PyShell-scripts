# Asset Minify

A [PyShell](https://github.com/mono-ninja/PyShell) script that minifies
**CSS and JS** through the system binaries —
[terser](https://terser.org) for JS, [clean-css-cli](https://github.com/clean-css/clean-css-cli)
for CSS, optionally [autoprefixer](https://github.com/postcss/autoprefixer)
via postcss-cli for vendor prefixes. A **wrapper, like
[cURL](../curl)**: Python does the discovery, the per-file runs and
the honest reporting; the minifiers are the system tools you already
have.

Contracts, inherited from the collection:

- **The originals are never touched** — results land in the output
  folder as `<stem>.min.css` / `<stem>.min.js`.
- **A file that won't shrink isn't written**: a minified candidate
  that comes out bigger or equal (an already-minified source) is
  marked `already minimal`, and no `.min` file is produced — a
  byte-identical copy would be a lie.
- `*.min.css` / `*.min.js` inputs are skipped; existing `.min` files
  in the output are skipped unless **Overwrite** is on.
- **Missing binaries stop the run cleanly** (exit 1) with the exact
  `npm install -g …` line — never a crash mid-batch.

## Prerequisites

```bash
npm install -g terser clean-css-cli
# only for vendor-prefixing:
npm install -g postcss-cli autoprefixer
```

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O). No Python dependencies —
   **Prepare Env** has nothing to install.
2. Pick a source (single file / multiple files / folder + CSS/JS
   filter + recursive), choose the output folder, press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 main.py --single-asset app.js --output-folder dist/
python3 main.py --single-asset style.css --prefix --output-folder dist/
python3 main.py --mode folder --input-folder assets/ --recursive --output-folder dist/
python3 main.py --mode folder --input-folder assets/ --only css --output-folder dist/
python3 main.py --mode multiple --input-file a.css --input-file b.js --output-folder dist/
```

## Result

- **Results tab** — the per-file table (file · kind · status · saved %
  · note) and the summary: bytes saved, minified / already-minimal /
  skipped / error counts.
- **Artifacts** — `minification_report.csv` (every row,
  machine-readable).

## Exit codes

- `0` — the batch ran. Skips and already-minimal rows are results, not
  failures.
- `1` — a prerequisite binary is missing (with the install line), the
  output folder is unusable, or every file failed.
- `2` — bad arguments (the mode's input missing, no matching files).

## Layout

```
asset-minify/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # discovery, subprocess runs, safety net, report
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
