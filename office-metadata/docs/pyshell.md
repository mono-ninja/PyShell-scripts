# Office Metadata

Shows **what your Word/Excel/PowerPoint files say about you**: the
privacy inventory hidden in the document — author, last editor,
company, manager, editing minutes, software fingerprint, sheet and
slide names, custom properties, the embedded thumbnail, tracked
changes, comments, macro flags — plus optional metadata-free clean
copies (originals untouched).

A modern Office file is a ZIP of XML parts, and several parts exist
purely to describe you. Everything is read straight from the ZIP with
the standard library — no Office, no dependencies, the file never
leaves the machine.

---

## Before running

1. Pick a **Source** — one document, several, or a folder (recursive
   for subfolders). Modern formats only: `docx docm dotx xlsx xlsm
   xltx pptx pptm potx`; the legacy binary `.doc/.xls/.ppt` are not
   ZIP containers and are reported as unsupported, not as errors.
2. No **Prepare Env** needed — stdlib only.
3. Press **Run** (⌘↩). Turn on **Also write clean copies** and pick an
   **Output folder** when you want the stripped versions.

## Fields

### Input

- **Source** — single / multiple / folder. Files with no metadata
  report as 🟢 clean; unreadable files (not a ZIP) are reported, not
  fatal — unless *every* file fails (exit 1).
- **Recursive (with subfolders)** — folder mode: descend into
  subfolders; non-Office files are noted as skipped.

### Strip

- **Also write clean copies (strip metadata)** — off by default. When
  on: `<name>_clean.<ext>` copies land in the **Output folder**. The
  docProps parts (author, company, minutes, thumbnail, custom
  properties) are dropped and `core.xml` is replaced with a blank one.
  Tracked changes, comments, embedded objects and macros are
  **content** — reported, but left for the author to resolve by hand.
  The originals are never touched.

---

## Result

- **Results tab** — the table (file · kind · leaks · verdict) and the
  per-document report: every found field as a story. The verdict is
  🔴 **identity leak** when the document names real people or
  organizations (author, last editor, company, manager), 🟠
  **metadata** for technical-only leaks, 🟢 **clean** otherwise.
- **Artifacts** — `report.md`, `office_metadata.csv` (one row per
  document, every field as a column), `*_clean.*` when stripping.

### What "leaks" means here

- **Identity** — author, last modified by, company, manager.
- **Fingerprint** — application + version, template, editing minutes,
  revision, rsids (save-history signatures).
- **Content structure** — sheet/slide names, the thumbnail preview,
  comments (reviewer names), tracked changes (pending edits),
  embedded objects.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report lists what was found |
| 1 | every document unreadable, or the output folder can't be created |
| 2 | bad arguments: wrong format, missing file/folder, `--strip` without `--output-folder` |

## Related

- **EXIF Inspect** — the same privacy check for photos (GPS, camera).
- **PDF Toolkit** — for PDFs: strip sees and removes author, producer,
  dates, attachments.
- **Secret Scan** — scans code and configs for leaked credentials (the
  "what did I leak" check for developers).
