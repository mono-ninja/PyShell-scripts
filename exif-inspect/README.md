# EXIF Inspect

A [PyShell](https://github.com/mono-ninja/PyShell) script that shows
**what your photos say about you** — the privacy inventory of their
EXIF:

- **GPS coordinates** — the single loudest leak: where you stood when
  the shutter clicked, in decimal degrees with a map link, plus the
  satellite clock (UTC) and which way the camera faced;
- **camera and lens** — a device fingerprint;
- **body and lens serial numbers** — the strongest link of all: GPS
  says where you were once, a serial ties every photo you ever posted
  to the same camera;
- **software** — the editing chain the file carries;
- **dates and timezone** — when you were where;
- **author / copyright / owner / user comment** — the fields people
  type in and forget;
- **XMP, IPTC and PNG text chunks** — the metadata that outlives EXIF:
  a file with no EXIF at all can still carry `dc:creator`, a city and
  a contact address — including the Extended part Photoshop splits
  across segments — so 🟢 **clean** means *no metadata anywhere*, not
  merely "no EXIF". The XMP packet is **enumerated, not searched**: a
  drone's own namespace, `xmpMM:DocumentID` (which ties every export of
  one original together) and `plus:LicensorName` all get named, while
  the develop settings nobody's privacy turns on are counted rather
  than printed;
- **the embedded thumbnail** — EXIF keeps a small copy of the photo,
  and editors do not always rewrite it: crop or paint over a photo and
  the thumbnail may still show what you removed. Every thumbnail is
  compared against the picture it claims to preview;
- **hidden frames (MPF)** — a motion photo or multi-picture file is
  several images inside one JPEG: the video frame, panorama frames,
  and on some cameras the *unedited original*. They live in the file
  body, not the EXIF, so "remove metadata" usually leaves them — the
  clean copies here re-encode and drop them;
- **a non-generic colour profile** — everybody ships sRGB, but a
  profile named after somebody's actual monitor is a fingerprint.

Across a folder it also reports **the places you keep going back to** —
GPS points grouped by proximity. One photo of a beach is a holiday;
forty photos inside one city block is an address.

And, optionally, **clean copies**: EXIF stripped, orientation baked
into the pixels first (so the photo stays upright), originals never
touched — a copy that would land on its own source is refused, not
written. In folder mode the copies keep the subfolder shape, so two
`IMG_0001.jpg` from two subfolders stay two files. The EXIF-specific
sibling of [Image Optimizer](../image-optimizer) — there stripping is
a size side effect, here it is the point.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `Pillow` and `pillow-heif`
   (HEIC: Pillow alone reads AVIF but never the format iPhones
   shoot by default; without it those files report as unreadable
   with a note saying so).
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
├── requirements.txt     # Pillow, pillow-heif (HEIC)
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
