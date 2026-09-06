# SVG Optimize

Minifies SVG files with [scour](https://github.com/scour-project/scour)
— one file, several, or a whole folder (optionally recursive). The
contract, inherited from [Image Optimizer](../../image-optimizer):
**never write a file bigger than the input** — when scour's output would
be larger, the original bytes pass through unchanged as `kept original`.
The originals are never touched; everything lands in the output folder.

The natural pre-pass before [SVG Sprite — Build](../../svg-sprite-build):
optimize the icons first, bundle them second.

---

## Before running

1. Pick a **Source** — one SVG, several, or a folder (with the
   **Recursive** switch for subfolders; the structure is preserved in
   the output).
2. Click **Prepare Env** — installs `scour`.
3. Choose the **Output folder** and press **Run** (⌘↩).

## Fields

### Input

- **Source** — single file, multiple selected files, or a folder.
- **Recursive** (folder mode) — walk subfolders too.

### Optimize

- **Number precision (digits)** — decimal places kept in coordinates.
  5 (the default) keeps rendering identical; 2–3 shrinks paths further
  with a real, usually invisible, tradeoff.
- **Strip metadata** — drops the `<metadata>` element: the editor junk
  (Inkscape, Illustrator) that often outweighs the drawing itself.
  **`<title>` and `<desc>` are kept** — accessibility labels, not bloat.
- **Strip comments** — XML comments inside the file.
- **Strip XML prolog** — the `<?xml …?>` line, unnecessary for SVG
  served over HTTP; keep it if a downstream tool wants it.
- **Shorten IDs** — renames long element IDs to short ones. Bigger
  savings, but **breaks any reference to those IDs from outside the
  file** — that's why it's off by default.

### Output

- **Output folder** — where the optimized copies land. Originals are
  never touched.
- **Overwrite existing** — when off, files already present in the output
  folder are skipped (reported, not silently dropped).

---

## Result

- **Results tab** — the per-file table (file · status · before · after ·
  saved %) and the summary: total bytes saved, optimized / kept-original
  / skipped / error counts.
- **Artifacts** — `optimization_report.csv`: every row with sizes,
  percent and note, machine-readable.

### Reading the statuses

- **optimized** — scour's output is smaller; the copy in the output
  folder is the minified one.
- **kept original** — scour's output was equal or larger (already
  minified, or hand-tuned): the copy is byte-identical to the input.
  A safety net, not a failure.
- **skipped** — a file with that name already exists in the output
  folder and **Overwrite existing** is off.
- **error** — unreadable or unwritable; the note says which.

## Exit codes

- `0` — the batch ran; kept-originals are results, not failures.
- `1` — nothing to optimize, scour not installed, the output folder is
  unusable, or every file failed.
- `2` — bad arguments (the mode's input is missing, a path isn't a
  file/folder, an empty folder).
