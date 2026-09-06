# QR Generate

A [PyShell](https://github.com/mono-ninja/PyShell) script that makes
**QR codes** — one from the Content field (a URL, text, a WiFi string,
a vCard…), or a **batch from a CSV** (a `content` column, an optional
`name` column that names the files).

The knobs that matter:

- **Error correction** — L/M/Q/H: how much damage the code survives
  (7/15/25/30%). Default M; use **H with a logo**.
- **Module size** and **quiet-zone border** (spec minimum 4).
- **Foreground/background colors** — any `#RGB`/`#RRGGBB`.
- **Center logo** — auto-sized to ~20% of the code, on a white pad;
  the run warns when the correction level is too low for it.

The codes land in the output directory as PNG artifacts — meant to be
shared, nothing secret here.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `qrcode` + `Pillow`.
3. Fill **Content** (or point **Batch CSV** at a file), press
   **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --text "https://example.org"
python3 main.py --text "https://example.org" --name launch --error-correction H
python3 main.py --text "https://example.org" --fg-color "#1a1a2e" --box-size 16
python3 main.py --text "https://example.org" --logo brand.png --error-correction H
python3 main.py --batch-csv batch.csv
```

The batch CSV: a header row, a `content` column, an optional `name`
column:

```csv
content,name
https://example.org,launch
WIFI:T:WPA;S:Guest;P:secret;;,wifi_guest
```

## Result

- **Results tab** — the file list with each code's content, and the
  summary (count, correction level, logo note, failures).
- **Artifacts** — `qr_code.png` (or the given name) in single mode;
  `qr_001.png`… / `<name>.png` per row in batch mode.

## Exit codes

- `0` — at least one code was written.
- `1` — prerequisites missing, the output folder unusable, or every
  code failed.
- `2` — bad arguments (no content, unusable colors, a batch CSV
  without a `content` column).

## Layout

```
qr-generate/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # QR build, logo paste, batch parsing, report
├── requirements.txt     # qrcode[pil]
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
