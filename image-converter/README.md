# Image Converter

A [PyShell](https://github.com/mono-ninja/PyShell) script that converts
images to **AVIF**, **WebP**, **JPEG**, **PNG**, **TIFF** or **BMP** with
adjustable quality and optional proportional downscaling. It works with a
single file, an arbitrary set of files, or a whole folder (optionally
recursive, preserving the subfolder structure in the output).

The script sends nothing over the network and never modifies the originals —
it only writes new files to the folder you pick.

## Features

- **Sources** — single image, multiple selected files, or a folder
  (recursive mode reproduces subfolder structure in the output)
- **Formats** — AVIF (best compression), WebP (small, browser-friendly),
  JPEG, PNG (lossless), TIFF, BMP
- **Quality** — 1–100: lossy compression quality for AVIF/WebP/JPEG,
  compression level for PNG; TIFF/BMP are written uncompressed
- **Max size (px)** — proportionally shrink to the given longest side;
  never upscales
- **Animated images** — GIF/WebP/AVIF keep all frames when converted to
  WebP or AVIF; other formats keep the first frame
- **Batch conversion** runs in parallel; a corrupt file never stops the
  batch — its status shows up in the results table
- Name collisions get a suffix (`photo.png` + `photo.jpg` → `photo.webp`
  and `photo-1.webp`), so no image is ever lost

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — PyShell installs `Pillow` and
   `pillow-avif-plugin` into an isolated venv.
3. Fill in the form and press **Run** (⌘↩).

The **Results** tab shows a per-file table (status, original and new size,
percentage change) plus a summary report. Field-by-field documentation lives
in [`docs/pyshell.md`](docs/pyshell.md) — the same text is shown in PyShell's
**Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

# single file
python3 main.py --mode single --single-image photo.png \
  --format webp --quality 85 --output-folder out/

# whole folder with subfolders
python3 main.py --mode folder --input-folder ~/Pictures \
  --recursive --format avif --quality 60 --max-size 2048 \
  --output-folder out/
```

Flags mirror the form 1:1: `--mode` (`single` | `multiple` | `folder`),
`--single-image`, `--input-file` (repeatable), `--input-folder`,
`--recursive`, `--format`, `--quality`, `--max-size`, `--output-folder`,
`--overwrite`.

## AVIF support

AVIF is built into Pillow ≥ 11.3; older versions get it from
`pillow-avif-plugin`, which `requirements.txt` includes. The script checks
at startup whether the environment can actually write AVIF and reports a
clear error instead of failing mid-batch.

## Exit codes

- `0` — the batch ran. Individual failures (a corrupt image, an unsupported
  format with skip off) are rows in the table, not a failed run.
- `1` — no input images found, or every image failed.
- `2` — invalid arguments (quality out of 1–100, negative max size), or AVIF
  output requested on a Pillow build that cannot write it.

## Layout

```
image-converter/
├── pyshell.yaml         # manifest: form fields, bindings
├── main.py               # entry point — collection + parallel conversion
├── requirements.txt      # Pillow, pillow-avif-plugin
└── docs/
    ├── pyshell.md         # operator docs (Docs panel)
    └── pyshell_ua.md       # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
