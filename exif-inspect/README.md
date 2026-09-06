# EXIF Inspect

A [PyShell](https://github.com/mono-ninja/PyShell) script that shows
**what your photos say about you** — the privacy inventory of their
EXIF:

- **GPS coordinates** — the single loudest leak: where you stood when
  the shutter clicked, in decimal degrees with a map link;
- **camera and lens** — a device fingerprint;
- **software** — the editing chain the file carries;
- **dates** — when you were where;
- **author / copyright / user comment** — the fields people type in
  and forget.

And, optionally, **clean copies**: EXIF stripped, orientation baked
into the pixels first (so the photo stays upright), originals never
touched. The EXIF-specific sibling of [Image Optimizer](../image-optimizer)
— there stripping is a size side effect, here it is the point.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `Pillow`.
3. Pick a source (single / multiple / folder), press **Run** (⌘↩). Turn
   on **Also write clean copies** to get EXIF-free copies in an output
   folder.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --single-image photo.jpg
python3 main.py --mode folder --input-folder ~/Pictures/vacation --recursive
python3 main.py --mode folder --input-folder ~/Pictures/vacation --strip --output-folder clean/
```

## Result

- **Results tab** — the per-photo table (file · status · what it leaks
  · GPS) and the report: every field found, GPS with a map link, and
  the privacy headline.
- **Artifacts** — `report.md`, `exif_report.csv` (every photo, every
  field, machine-readable).

A photo with no EXIF reports as 🟢 **clean** — an honest status, not
an error (PNG files usually carry none).

## Exit codes

- `0` — the run completed. EXIF findings are results, not failures.
- `1` — no images found, Pillow missing, or every image unreadable.
- `2` — bad arguments (mode input missing, `--strip` without
  `--output-folder`).

## Layout

```
exif-inspect/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # EXIF reading, GPS math, stripping, report
├── requirements.txt     # Pillow
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
