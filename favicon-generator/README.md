# Favicon Generator

A [PyShell](https://github.com/mono-ninja/PyShell) script that turns one
image into the **complete modern favicon set**: multi-size `favicon.ico`
(16+32+48), classic PNGs, the opaque `apple-touch-icon.png`, PWA icons
(192/512), a `site.webmanifest`, and the ready-to-paste `<head>` snippet.
Eight files from one source — everything a browser, iOS or a PWA linter
asks for.

Conservative by design: the source is contained, never cropped; non-square
images letterbox onto a square canvas; transparency survives everywhere
it's legal. `apple-touch-icon.png` is the one deliberate exception — iOS
composites it onto black, so it's always flattened (your background
color, or white by default).

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `Pillow`.
3. **Source image** — square ≥512px recommended (smaller is upscaled
   with a warning). Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --source-image logo.png
python3 main.py --source-image logo.png --name "My App" --padding 8
python3 main.py --source-image logo.png --background '#1a5ac8' --out-dir ./dist
```

## Result

- **Results tab** — the file table (name, bytes, purpose) and the
  `<head>` snippet to paste.
- **Artifacts** — `favicon.ico`, `favicon-16x16.png`, `favicon-32x32.png`,
  `apple-touch-icon.png`, `icon-192.png`, `icon-512.png`,
  `site.webmanifest`, `snippet.html`.

## Exit codes

- `0` — the set was generated; source-quality warnings are results,
  not failures.
- `1` — the source can't be read as an image, or the files can't be
  written.
- `2` — bad arguments (unknown background color, padding outside 0–25).

## Layout

```
favicon-generator/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: geometry, rendering, manifest, snippet
├── requirements.txt     # Pillow
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
