# Office Metadata

See **what your Word / Excel / PowerPoint files say about you** — the
privacy inventory hidden inside a modern Office document: the author and
the last editor, your **company** and **manager** fields, the minutes
spent editing, the template it came from, the *names of your sheets and
slides*, custom document-management properties, the embedded thumbnail
preview — plus tracked changes, comments and macro flags. Optional
**clean copies** strip the metadata parts; originals are never touched.

A modern `.docx/.xlsx/.pptx` is a ZIP of XML parts — several of them
exist purely to describe you. Everything here is read straight from the
ZIP with the Python standard library: no Office, no dependencies, and
the file never leaves the machine.

## Using with PyShell

1. Pick a **Source** — one document, several, or a folder (recursive
   for subfolders). Modern formats only: `.docx .docm .dotx .xlsx
   .xlsm .xltx .pptx .pptm .potx` — the legacy binary `.doc/.xls/.ppt`
   are not ZIP containers and are reported as unsupported.
2. Press **Run** (⌘↩). Turn on **Also write clean copies** and pick an
   output folder when you want the stripped versions.

## Running standalone

```bash
python3 main.py --single-file report.xlsx
python3 main.py --mode multiple --input-file a.docx --input-file b.pptx
python3 main.py --mode folder --input-folder ./docs --recursive
# with clean copies:
python3 main.py --mode folder --input-folder ./docs --strip \
    --output-folder ./clean
```

## Result

- **Results tab** — a table (file · kind · what it leaks · verdict) and
  a per-document report: every metadata field found, written as a story
  — author, last editor, company, manager, software + version, editing
  minutes, timestamps, sheet/slide names, custom properties, thumbnail,
  comments, tracked changes, embedded objects, macro warning.
- **Artifacts** — `report.md`, `office_metadata.csv`, and
  `<name>_clean.<ext>` copies when stripping.

### What "leaks" means here

- **Identity** — author, last modified by, company, manager: real
  names of real people (the red verdict).
- **Fingerprint** — application + version, template name, editing
  minutes, revision count, rsid save-history signatures.
- **Content structure** — sheet names and slide titles
  (TitlesOfParts), the thumbnail preview, comments with reviewer
  names, pending tracked changes.

### What strip does — and does not

Clean copies drop `docProps/app.xml`, `docProps/custom.xml` and the
thumbnail, and replace `core.xml` with a blank one
(`[Content_Types].xml` is updated to match). **Tracked changes,
comments, embedded objects and macros are content, not metadata** —
they are reported loudly but left in place for the author to resolve.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings (or none) are in the report |
| 1 | every document was unreadable / output folder can't be created |
| 2 | bad arguments (wrong format, missing file, `--strip` without `--output-folder`) |

## Layout

```
office-metadata/
├── pyshell.yaml      # manifest
├── main.py           # parse · classify · strip · report
├── docs/
│   ├── pyshell.md    # EN docs
│   └── pyshell_ua.md # UA docs
└── tests/            # 21 tests, stdlib-only fixtures
```

## License

MIT — see the root [LICENSE](../LICENSE).
