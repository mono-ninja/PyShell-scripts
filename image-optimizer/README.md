# Image Optimizer

A [PyShell](https://github.com/mono-ninja/PyShell) script that shrinks
**JPEG / PNG / WebP** file size **without changing the format** — the
narrow sibling of [Image Converter](../image-converter) (which changes
format). For a folder of screenshots or exported assets that must stay
PNG/JPEG but are needlessly large: EXIF blocks, non-optimal Huffman
tables, more colors than the image uses.

The contract: **never write a file bigger than the input.** When an
"optimized" candidate comes out larger (already-optimized sources, tiny
images where format overhead dominates), the original bytes are copied
through unchanged and the row says `kept original`. The originals are
never touched — this is "make a smaller copy", not an in-place mutation.

## What it does

- **JPEG** — *lossless* (default): a mozjpeg re-Huffman pass only,
  typically 5–15% smaller, pixel-identical output. Or *lossy*: re-encode
  at a chosen quality (default 82) with progressive scan and Huffman
  optimization.
- **PNG** — always passed through oxipng for the final DEFLATE pass
  (never changes a pixel). Optional color quantization (off by default)
  reduces the image to at most *max colors* — where the real wins are for
  photographic PNGs, at a real quality cost.
- **WebP** — quality applies to *lossy sources only*. A lossless WebP
  source is re-saved lossless — detected from the file, never silently
  converted.
- **Metadata** — strips EXIF/GPS/XMP and PNG text chunks; the ICC color
  profile can be kept independently for print/photography workflows.
- **Batches** — single image, multiple images, or a folder (recursive
  mode preserves subfolder structure). Unsupported formats found in a
  folder are skipped rows, not errors. Name collisions get a `-1`, `-2`…
  suffix.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs Pillow, `pyoxipng` and
   `mozjpeg-lossless-optimization`. The last two degrade gracefully:
   PNG falls back to Pillow's zlib pass, JPEG lossless falls back to
   "kept original" — never a silent quality loss.
3. Pick a source and an **output folder**, press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

# single file, lossless defaults
python3 main.py --mode single --single-image photo.jpg --output-folder out/

# whole folder, lossy JPEG + metadata stripping
python3 main.py --mode folder --input-folder assets --recursive \
  --jpeg-mode lossy --jpeg-quality 82 --strip-metadata --output-folder out/
```

Note: toggles that default **on** in the form (`--strip-metadata`,
`--skip-unsupported`) default **off** in a bare terminal run — pass them
explicitly when running outside PyShell.

## Result

- **Results tab** — a table: File / Original / Optimized / Saved % / Note
  (`kept original`, `skipped: unsupported format`, `quantized to ≤256
  colors`, …).
- **Artifact** — `optimization_report.csv`: the same rows with raw byte
  counts, so a build pipeline can consume the savings numbers.

## Exit codes

- `0` — the batch ran. Individual failures (a corrupt image, an
  unsupported format with skip off) are rows in the table, not a failed
  run.
- `1` — no input files found, or the output folder isn't writable.
- `2` — invalid arguments (quality out of range, …).

## Layout

```
image-optimizer/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point
├── requirements.txt     # Pillow, pyoxipng, mozjpeg-lossless-optimization
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
