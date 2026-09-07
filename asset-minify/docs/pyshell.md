# Asset Minify

Minifies CSS and JS with a **built-in, pure-Python engine** — no npm,
no dependencies — and hands the work to the **system binaries** (terser
for JS, clean-css-cli for CSS) whenever they are installed, because
they compress harder. Python does the orchestration either way:
discovery, per-file runs, honest reporting.

---

## Before running

Nothing to install: the built-in engine always works, and **Prepare
Env** has nothing to do (no Python dependencies).

No comment survives a run, whichever engine does the work: the system
binaries are called with `--comments false` / `specialComments:0` so
they match the built-in one.

Optional, for the harder squeeze on JS — terser mangles names and drops
dead code, which the built-in engine deliberately does not:

```bash
npm install -g terser clean-css-cli
```

1. Pick a **Source** — one file, several, or a folder (with the
   CSS/JS filter and the **Recursive** switch).
2. Choose the **Output folder** and press **Run** (⌘↩).

## Fields

### Input

- **Source** — single / multiple / folder.
- **Only** (folder mode) — CSS, JS or both.
- **Recursive** (folder mode) — walk subfolders; the output preserves
  the structure.

### Options

- **Engine**
  - *Automatic* (default) — the system binary per kind when it is
    installed, the built-in minifier when it is not. A missing binary
    is never a failure here, only a weaker result. The lookup goes
    beyond `PATH` into the usual npm bin folders
    (`/opt/homebrew/bin`, `/usr/local/bin`, `~/.npm-global/bin`, …),
    because an app-launched run inherits a minimal `PATH` and would
    otherwise miss an installed terser. If the binary is found but
    fails on a file, that file falls back to the built-in engine and
    the row's note carries the binary's own complaint.
  - *Built-in* — never shells out. Predictable, dependency-free, and
    the only option on a machine without Node.
  - *System binaries* — demands terser / clean-css-cli and stops with
    the exact `npm install -g …` line if one is missing. Use it when
    the extra compression is the point and a silent fallback would be
    worse than an error.

### Output

- **Output folder** — where the `.min.css` / `.min.js` files land.
  The originals are never touched.
- **Overwrite existing** — when off, `.min` files already present in
  the output are skipped (reported, not silent).

---

## What the built-in engine does

- **CSS** — drops **every** comment, `/*!` licence banners and
  `/* ===== */` section headers alike, collapses whitespace, removes the
  last `;` in a block, shortens `#aabbcc` to `#abc` and `0.50em` to
  `.5em`. It stays out of the places where a
  space carries meaning: inside `calc()` / `clamp()` / `min()` /
  `max()`, and before a `:` — `a :hover` and `a:hover` are different
  selectors. Typically 15–25% off hand-written CSS.
- **JS** — a real tokenizer: regex literals are told apart from
  division, template literals (with nested `${…}`) are copied whole.
  Every comment (`/*!` banners included) and every unnecessary space
  go; a newline that was in the source is **kept** wherever ASI could
  depend on it, so `return` never joins the line below it. It does not
  mangle names or eliminate dead code — that needs a full parser, which
  is what terser is for. Typically 20–30%, against terser's 50–70%.

## Result

- **Results tab** — the per-file table (file · kind · engine · status ·
  saved % · note) and the summary (bytes saved, counts per status).
- **Artifacts** — `minification_report.csv`.

### The statuses

- **minified** — the `.min` file was written; sizes and saved % shown.
- **already minimal** — the minifier's output was bigger or equal to
  the source: no `.min` file written. Happens for hand-tuned or
  pre-minified sources; the row is a result, not a failure.
- **skipped** — a `*.min.*` input (minifying the minified is churn) or
  an existing output without Overwrite.
- **error** — this file failed; the note carries the binary's first
  stderr line, or the built-in engine's complaint (an unterminated
  literal, a file that isn't UTF-8). One bad file never stops the
  batch.

## Exit codes

- `0` — the batch ran.
- `1` — **Engine: System binaries** with a missing binary (the exact
  `npm install -g …` line is printed), an unusable output folder, or
  every file failed.
- `2` — bad arguments.
