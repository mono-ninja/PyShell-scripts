# QR Generate

Makes **QR codes** — one from the Content field, or a batch from a
CSV — with the error-correction level, module size, quiet-zone
border, colors, and an optional center logo (auto-sized to ~20%,
meant for H-level correction). Results land as PNG artifacts in the
output directory.

---

## Before running

1. Fill **Content** (a URL, text, a WiFi string, a vCard…) — or point
   **Batch CSV** at a file with a `content` column (an optional `name`
   column names the files; `qr_001.png` otherwise).
2. Click **Prepare Env** — installs `qrcode` + `Pillow`.
3. Press **Run** (⌘↩).

## Fields

### Content

- **Content** — what the code carries. Ignored in batch mode.
- **Batch CSV** — a header row + `content` column (optional `name`);
  one QR per non-empty row, up to 500 rows per run.
- **Filename** — the single code's artifact name (`qr_code.png` by
  default).

### QR

- **Error correction** — L 7% / M 15% (default) / Q 25% / H 30%: how
  much of the code can be damaged and still scan. **Use H with a
  logo** — the logo eats modules, and the run warns when the pairing
  is fragile.
- **Module size (px)** — pixels per module, the code's resolution.
- **Border (modules)** — the quiet zone; the spec minimum is 4.

### Colors

- **Foreground / Background** — any `#RGB` or `#RRGGBB`. Keep the
  contrast high: scanners read dark-on-light best.
- **Center logo** — pasted at the code's center on a white pad,
  auto-sized to 20% of the side.

---

## Result

- **Results tab** — the file list with each code's content preview,
  and the summary (count, level, logo note, failures).
- **Artifacts** — the PNG files, named `qr_code.png` / `<name>.png`
  in single mode, `qr_001.png`… / `<name>.png` per row in batch.

## Exit codes

- `0` — at least one code was written.
- `1` — prerequisites missing, output folder unusable, or every code
  failed.
- `2` — bad arguments (no content, unusable colors, a batch CSV
  without a `content` column).
