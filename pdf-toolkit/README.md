# PDF Toolkit

A [PyShell](https://github.com/mono-ninja/PyShell) script for the six
PDF jobs that actually come up — with **privacy as the headline**:

- **Strip metadata** — rebuild the document from pages only, dropping
  everything it was about to leak: the author, the producer (which app
  and version made it), creation/modification timestamps, keywords, the
  Adobe XMP stream and embedded attachments. The report shows **what
  would have leaked** before removing it — the same story
  [EXIF Inspect](../exif-inspect) tells for photos.
- **Merge** — several PDFs, in order, into `merged.pdf`.
- **Split** — one PDF per page: `report_page_001.pdf` …
- **Extract** — page ranges (`1-3,7,10-`) into a new PDF.
- **Rotate** — 90/180/270°, all pages or a subset.
- **Compress** — metadata strip + duplicate-object dedupe. Image
  streams are **never re-encoded**: a scanned PDF won't shrink much,
  and that's said honestly rather than done silently.

Every operation works on one file or a batch (the same page spec
applies to each). The originals are never touched — results land in
the output folder as `<stem>_<op>.pdf`.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `pypdf`.
3. Pick the operation, select the PDF(s), press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --operation strip --pdfs cv.pdf
python3 main.py --operation merge --pdfs a.pdf --pdfs b.pdf --pdfs c.pdf
python3 main.py --operation split --pdfs big.pdf
python3 main.py --operation extract --pdfs big.pdf --pages 1-3,7
python3 main.py --operation rotate --pdfs scan.pdf --angle 270
python3 main.py --operation rotate --pdfs scan.pdf --pages 2,5 --angle 90
python3 main.py --operation compress --pdfs *.pdf --output-dir out/
```

## Result

- **Results tab** — the per-file table and the report; for strip and
  compress it includes the **what-would-have-leaked** section (author,
  producer, dates, attachments — exactly what the clean copy no longer
  carries).
- **Artifacts** — the operation's output PDFs plus
  `pdf_toolkit_results.json` (machine-readable, including the removed
  metadata).

## Exit codes

- `0` — the operation ran (a file that got smaller/leaks removed are
  results, not failures).
- `1` — an input isn't a readable PDF (or is password-encrypted), the
  output folder is unusable, or every file failed.
- `2` — bad arguments (a flag that doesn't apply to the chosen
  operation, a page spec that doesn't parse or doesn't fit).

## Layout

```
pdf-toolkit/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # thin entry point: validation, dispatch
├── requirements.txt     # pypdf
├── src/
│   ├── pagespec.py      # the "1-3,7,10-" grammar
│   ├── inspection.py    # safe open + the metadata-leak description
│   ├── ops.py           # the six operations
│   └── report.py        # table, markdown, artifacts
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
