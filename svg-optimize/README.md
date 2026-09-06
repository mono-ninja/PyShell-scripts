# SVG Optimize

A [PyShell](https://github.com/mono-ninja/PyShell) script that minifies
SVG files with [scour](https://github.com/scour-project/scour) — one
file, several, or a whole folder — with the knobs exposed honestly:
coordinate precision, `<metadata>` / comment / XML-prolog stripping,
opt-in ID shortening.

The contract, inherited from [Image Optimizer](../image-optimizer):
**never write a file bigger than the input.** When scour's output would
come out larger (an already-minified source, a hand-tuned file), the
original bytes pass through unchanged and the row is marked
`kept original`. The run can only make a folder lighter, never heavier —
and the originals are never touched: everything lands in the output
folder.

The natural pre-pass before [SVG Sprite — Build](../svg-sprite-build):
optimize first, bundle second.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `scour`.
3. Pick a source (single file / multiple files / folder), choose the
   output folder, press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --single-svg icon.svg --output-folder out/
python3 main.py --mode folder --input-folder icons/ --recursive --output-folder out/
python3 main.py --mode folder --input-folder icons/ --precision 3 --output-folder out/
python3 main.py --mode multiple --input-file a.svg --input-file b.svg --output-folder out/
python3 main.py --single-svg icon.svg --no-strip-metadata --no-strip-comments --output-folder out/
```

## Result

- **Results tab** — the per-file table (file · status · before · after ·
  saved %) and the summary: bytes saved, optimized / kept-original /
  skipped / error counts.
- **Artifacts** — `optimization_report.csv` (every row, machine-readable).

`<title>` and `<desc>` elements are **kept** — they're the accessibility
labels, not bloat. ID shortening is opt-in precisely because it breaks
references from outside the file.

## Exit codes

- `0` — the batch ran. Kept-originals are results, not failures.
- `1` — nothing to optimize, or a prerequisite is missing (scour not
  installed, output folder unusable, every file failed).
- `2` — bad arguments (mode input missing, path is not a file/folder).

## Layout

```
svg-optimize/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: collection, scour pass, safety net
├── requirements.txt     # scour
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
