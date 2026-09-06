# Asset Minify

Minifies CSS and JS through the **system binaries** — terser for JS,
clean-css-cli for CSS, optionally autoprefixer (postcss-cli) for
vendor prefixes. A wrapper, like [cURL](../../curl): the minifiers are
your system tools; this script is the orchestration — discovery,
per-file runs, honest reporting.

---

## Before running

1. Make sure the tools are installed (the run checks and tells you
   the exact line if not):

   ```bash
   npm install -g terser clean-css-cli
   # only for vendor-prefixing:
   npm install -g postcss-cli autoprefixer
   ```

2. Pick a **Source** — one file, several, or a folder (with the
   CSS/JS filter and the **Recursive** switch).
3. Choose the **Output folder** and press **Run** (⌘↩). No Python
   dependencies — Prepare Env has nothing to install.

## Fields

### Input

- **Source** — single / multiple / folder.
- **Only** (folder mode) — CSS, JS or both.
- **Recursive** (folder mode) — walk subfolders; the output preserves
  the structure.

### Options

- **Vendor-prefix CSS (autoprefixer)** — runs autoprefixer before
   clean-css. Needs postcss-cli + autoprefixer; checked only when a
   CSS file is actually being processed and the switch is on.

### Output

- **Output folder** — where the `.min.css` / `.min.js` files land.
  The originals are never touched.
- **Overwrite existing** — when off, `.min` files already present in
  the output are skipped (reported, not silent).

---

## Result

- **Results tab** — the per-file table and the summary (bytes saved,
  counts per status).
- **Artifacts** — `minification_report.csv`.

### The statuses

- **minified** — the `.min` file was written; sizes and saved % shown.
- **already minimal** — the minifier's output was bigger or equal to
  the source: no `.min` file written. Happens for hand-tuned or
  pre-minified sources; the row is a result, not a failure.
- **skipped** — a `*.min.*` input (minifying the minified is churn) or
  an existing output without Overwrite.
- **error** — the binary failed on this file; the note carries its
  first stderr line.

## Exit codes

- `0` — the batch ran.
- `1` — missing system binaries (with the exact
  `npm install -g …` line), unusable output folder, or every file
  failed.
- `2` — bad arguments.
