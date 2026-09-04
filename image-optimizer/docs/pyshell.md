# Image Optimizer

Shrinks **JPEG / PNG / WebP** file size **without changing the format** —
the narrow sibling of Image Converter (which changes format). For a folder
of screenshots or exported assets that must stay PNG/JPEG but are needlessly
large: EXIF blocks, non-optimal Huffman tables, more colors than the image
uses.

The contract: **never write a file bigger than the input.** When an
"optimized" candidate comes out larger (already-optimized sources, tiny
images where format overhead dominates), the original bytes are copied
through unchanged and the row says `kept original`.

---

## Before running

1. Click **Prepare Env** — installs Pillow, `pyoxipng` (the PyPI package
   that provides the `oxipng` module), and
   `mozjpeg-lossless-optimization`. The last two degrade gracefully if
   unavailable: PNG falls back to Pillow's zlib pass (noted in the row),
   JPEG lossless falls back to "kept original" — never a silent quality
   loss.
2. Pick a source and an **output folder**. The originals are never touched —
   this is "make a smaller copy", not an in-place mutation.

---

## Fields

### Input

Same three modes as Image Converter: **single image**, **multiple images**,
or **folder** (+ **recursive**, which preserves the subfolder structure in
the output). Unsupported formats (GIF/TIFF/BMP/AVIF) found in a folder are
**skipped rows, not errors** — a batch of 200 files with 3 GIFs finishes
with 197 optimized and 3 noted as skipped.

### Optimize

- **JPEG mode**
  - *Lossless* (default) — mozjpeg re-Huffman pass only: typically 5–15%
    smaller, pixel-identical output. Nothing to tune, nothing that can
    visibly degrade.
  - *Lossy* — re-encode at **JPEG quality** (default 82) with progressive
    scan and Huffman optimization. Bigger savings, real tradeoff.
- **PNG** — always passed through oxipng for the final DEFLATE pass (never
  changes a pixel). **Allow color quantization** (off by default) reduces
  the image to at most **max colors** when it has more — this is where the
  real size wins are for photographic PNGs, at a real quality cost.
- **WebP quality** — applies to *lossy sources only*. A **lossless WebP
  source is re-saved lossless** — detected from the file, never silently
  converted to lossy.
- **Strip metadata** (on) — drops EXIF/GPS/XMP and PNG text chunks.
- **Keep color profile (ICC)** (off, independent of the above) — keep it on
  for print/photography workflows where color accuracy matters.
- **Skip unsupported formats** (on) — see above.

### Output

- **Output folder** — required; subfolders are created as needed.
- **Overwrite existing** — off by default: files left from a previous run
  are skipped. Two sources claiming the same name get a `-1`, `-2`… suffix
  (the row shows the real output name).

## Result

- **Results tab** — a table: File / Original / Optimized / Saved % / Note
  (`kept original`, `skipped: unsupported format`, `quantized to ≤256
  colors`, …).
- **Artifact** — `optimization_report.csv`: the same rows with raw byte
  counts, so a build pipeline can consume the savings numbers.

## Exit code

- `0` — the batch ran. Individual failures (corrupt image, unsupported
  format with skip off) are rows in the table, not a failed run.
- `1` — no input files found, or the output folder isn't writable.
- `2` — invalid arguments (quality out of range, …).

## From a terminal

The boolean toggles that default **on** in the form (`strip metadata`,
`skip unsupported`) are passed as flags (`--strip-metadata`,
`--skip-unsupported`) and default **off** in a bare terminal run — same
convention as `http-request`'s redirect toggle. Pass them explicitly when
running outside PyShell.
