# EXIF Inspect

Shows **what your photos say about you**: the privacy inventory of
their EXIF — GPS coordinates (with a map link), camera and lens,
software, dates, authorship — plus optional EXIF-free clean copies
(orientation applied first, originals untouched).

---

## Before running

1. Pick a **Source** — one photo, several, or a folder (recursive for
   subfolders).
2. Click **Prepare Env** — installs `Pillow`.
3. Press **Run** (⌘↩). Turn on **Also write clean copies** when you
   want the stripped versions in an output folder.

## Fields

### Input

- **Source** — single / multiple / folder. JPEG, TIFF, WebP, PNG, HEIC,
  AVIF; files with no EXIF report as 🟢 clean, not as errors.

### Strip

- **Also write clean copies (strip EXIF)** — off by default. When on:
  EXIF-free copies land in the **Output folder**; **orientation is
  applied to the pixels first** (strip the tag without applying it and
  rotated photos turn sideways). The originals are never touched.

---

## Result

- **Results tab** — the table (file · status · what it leaks · GPS)
  and the per-photo report: every found field, GPS in decimal degrees
  with an on-the-map link, and the privacy headline — a photo's
  coordinates pin where you stood; every share of the original file
  shares that.
- **Artifacts** — `report.md`, `exif_report.csv`.

### What "leaks" means here

- **GPS location** — where you were (home, work, the kid's school).
- **Device fingerprint** — camera make/model, lens.
- **Editing software** — the processing chain.
- **Timestamps** — when you were there.
- **Authorship** — author, copyright, user comment fields.

## Exit codes

- `0` — the run completed; findings are results, not failures.
- `1` — no images found, Pillow missing, or every image unreadable.
- `2` — bad arguments (missing mode input, `--strip` without
  `--output-folder`).
