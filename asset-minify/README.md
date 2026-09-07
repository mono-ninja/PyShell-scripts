# Asset Minify

A [PyShell](https://github.com/mono-ninja/PyShell) script that minifies
**CSS and JS**. Two engines, one contract:

- **Built-in** — a pure-stdlib CSS minifier and JS minifier written into
  `main.py`. No npm, no network, no Python dependencies: it runs
  wherever Python does.
- **System** — [terser](https://terser.org) for JS and
  [clean-css-cli](https://github.com/clean-css/clean-css-cli) for CSS,
  used when they are on `PATH` because they squeeze harder: terser
  mangles names and drops dead code, which a safe stripper cannot.

**Engine → Automatic** (the default) takes the system binary per kind
when it exists and falls back to the built-in one when it doesn't — a
missing binary is no longer a dead end, only a weaker result. It also
looks in the usual npm bin folders (`/opt/homebrew/bin`,
`/usr/local/bin`, …) before believing a binary is absent: a GUI host
starts with a minimal `PATH`, and terser sitting in Homebrew's bin is
not a missing terser. If a system binary is found but fails on a file,
that file is handed to the built-in engine and the row says so.

Contracts, inherited from the collection:

- **The originals are never touched** — results land in the output
  folder as `<stem>.min.css` / `<stem>.min.js`.
- **A file that won't shrink isn't written**: a minified candidate
  that comes out bigger or equal (an already-minified source) is
  marked `already minimal`, and no `.min` file is produced — a
  byte-identical copy would be a lie.
- `*.min.css` / `*.min.js` inputs are skipped; existing `.min` files
  in the output are skipped unless **Overwrite** is on.

## Prerequisites

None. The built-in engine is always available.

For the harder squeeze on JS — name mangling and dead-code removal —
install the system tools; **Automatic** will pick them up:

```bash
npm install -g terser clean-css-cli
```

## What the built-in engine does and doesn't do

- **CSS** — drops **every** comment, `/*!` licence banners and
  `/* ===== */` section headers included, collapses whitespace, removes
  the last `;` of a block, shortens `#aabbcc` to `#abc` and `0.50em` to
  `.5em`. Spaces inside `calc()`, `clamp()` and
  friends are left alone, and `a :hover` never becomes `a:hover`.
  Typically **15–25%** off hand-written CSS.
- **JS** — tokenizes properly (regex literals told apart from
  division, template literals with nested `${…}` copied whole), then
  drops every comment — `/*!` banners too — and every space the grammar
  doesn't need. A newline
  the source had is kept wherever automatic semicolon insertion could
  depend on it, so `return\nx` stays two statements. It does **not**
  mangle names or remove dead code. Typically **20–30%**; terser
  reaches 50–70% on the same input.

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
python3 main.py --single-asset style.css --engine builtin --output-folder dist/
python3 main.py --mode folder --input-folder assets/ --recursive --output-folder dist/
python3 main.py --mode folder --input-folder assets/ --only css --output-folder dist/
python3 main.py --mode folder --input-folder assets/ --engine system --output-folder dist/
python3 main.py --mode multiple --input-file a.css --input-file b.js --output-folder dist/
```

## Result

- **Results tab** — the per-file table (file · kind · engine · status ·
  saved % · note) and the summary: bytes saved, minified /
  already-minimal / skipped / error counts.
- **Artifacts** — `minification_report.csv` (every row,
  machine-readable).

## Exit codes

- `0` — the batch ran. Skips and already-minimal rows are results, not
  failures.
- `1` — `--engine system` was asked for and its binary is missing (with
  the install line), the output folder is unusable, or every file
  failed.
- `2` — bad arguments (the mode's input missing, no matching files).

## Layout

```
asset-minify/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # discovery, the two engines, safety net, report
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
