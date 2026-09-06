# PDF Toolkit

The six PDF jobs that actually come up — merge, split, extract,
rotate, **strip metadata**, compress — with privacy as the headline:
strip (and compress) rebuild the document from pages only, and the
report shows **what the metadata would have leaked** before removing
it. The originals are never touched.

---

## Before running

1. Pick the **Operation**.
2. Click **Prepare Env** — installs `pypdf`.
3. Select one or more **PDF files** (merge joins them in the selection
   order; every other operation runs on each file separately), press
   **Run** (⌘↩).

## Fields

### Operation

- **Operation** — what to do:
  - **Strip metadata (privacy)** — drop the info dict, the Adobe XMP
    stream and embedded attachments; the clean copy keeps only the
    pages. `name_clean.pdf`.
  - **Merge** — `merged.pdf`, in selection order.
  - **Split** — one PDF per page: `name_page_001.pdf` …
  - **Extract** — the given page ranges into `name_extracted.pdf`.
  - **Rotate** — 90/180/270°, all pages or a subset →
    `name_rotated.pdf`.
  - **Compress** — metadata strip + duplicate-object dedupe →
    `name_min.pdf`.
- **PDF files** — one or many. The same page spec applies to every
  file in a batch; a spec that doesn't fit the smallest file is an
  honest error, not a surprise.

### Pages

- **Pages** — `1-3,7,10-`, 1-based, open ranges allowed. Required for
  extract; for rotate, empty means all pages. Setting it for any other
  operation is rejected loudly (exit 2) — a flag that is silently
  ignored is a bug, not a convenience.

### Output

- **Output folder** — optional; defaults to PyShell's output directory
  or the current folder standalone.

---

## Result

- **Results tab** — the per-file table (✓/✗ · what happened · sizes
  for strip/compress) and the report. For strip and compress the
  report includes the **what-would-have-leaked** section: author,
  created-with, produced-by, creation/modification dates, keywords,
  XMP presence, attachments. Content can still leak (text, images,
  visible watermarks) — the section says so.
- **Artifacts** — the operation's PDFs plus
  `pdf_toolkit_results.json`.

### Honest limits

- **Compress never re-encodes images.** A scanned PDF is one big image
  per page and won't shrink much; re-encoding it would lose quality
  and isn't done silently.
- **Encrypted PDFs** get one empty-password try (most "encrypted"
  files are owner-locked, not password-locked); a real password means
  exit 1 with the file named.
- Size changes from strip are a side effect, never the goal.

## Exit codes

- `0` — the operation ran.
- `1` — an input isn't a readable PDF, the output folder is unusable,
  or every file failed.
- `2` — bad arguments (a non-applicable flag, a page spec that doesn't
  parse or doesn't fit).
