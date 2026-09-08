# EXIF Inspect

Shows **what your photos say about you**: the privacy inventory of
their EXIF — GPS coordinates (with a map link), camera and lens,
software, dates, authorship — plus optional EXIF-free clean copies
(orientation applied first, originals untouched).

---

## Before running

1. Pick a **Source** — one photo, several, or a folder (recursive for
   subfolders).
2. Click **Prepare Env** — installs `Pillow` and `pillow-heif`.
   HEIC needs the second one: Pillow reads AVIF on its own but
   never HEIC, the iPhone default. Without it such photos report
   as unreadable, with a note that says exactly that.
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
  rotated photos turn sideways). The originals are never touched — set
  an **Output folder** other than the source, or every copy is refused
  rather than written over its own original. In folder mode the output
  keeps the subfolder shape, so same-named photos from different
  subfolders never overwrite each other. An unrotated JPEG re-uses the
  source's own quantization tables, so the copy does not lose a
  generation of quality.

---

## Result

- **Results tab** — the table (file · status · what it leaks · GPS)
  and the per-photo report: every found field, GPS in decimal degrees
  with an on-the-map link, and the privacy headline — a photo's
  coordinates pin where you stood; every share of the original file
  shares that.
- **Places you keep going back to** — when several photos share a
  spot (within ~150 m), the report groups them. One photo somewhere is
  a visit; a pile of photos in one block is usually home, work or the
  school run, and any single photo from that pile gives the address
  away.
- **Artifacts** — `report.md`, `exif_report.csv`.

### What "leaks" means here

- **GPS location** — where you were (home, work, the kid's school);
  `location` instead when the place comes from XMP/IPTC rather than
  from coordinates.
- **Device fingerprint** — camera make/model, lens.
- **Device serial** — body/lens serial numbers and the vendor
  MakerNote blob. The one that links all your photos together.
- **Editing software** — the processing chain.
- **Timestamps** — when you were there, plus the timezone offset and
  the GPS satellite clock (UTC).
- **Authorship** — author, copyright, camera owner, user comment.
- **XMP/IPTC metadata** — the file carries a non-EXIF metadata block
  (XMP packet, IPTC record, or PNG text chunks). XMP is read whole:
  all standard segments plus the Extended part Photoshop splits off
  into separate chunks.
- **Stale thumbnail** — the small copy EXIF carries is not the photo
  you are looking at: a different shape (cropped since) or a different
  picture (painted over, replaced). The embedded copy may still show
  what the edit was meant to remove — the reason to check.
- **Hidden frames** — one JPEG holding several images: the video frame
  of a motion photo, panorama frames, or the unedited original some
  cameras embed. They ride in the file body, not the EXIF, so most
  metadata strippers leave them behind; the clean copies here drop
  them.

A photo reports 🟢 **clean** only when *none* of these blocks carry
anything — "no EXIF" alone is not clean, because XMP and PNG text
chunks survive on their own.

## Exit codes

- `0` — the run completed; findings are results, not failures.
- `1` — no images found, Pillow missing, or every image unreadable.
- `2` — bad arguments (missing mode input, `--strip` without
  `--output-folder`).
