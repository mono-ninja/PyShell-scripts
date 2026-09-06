# Responsive Images

**One image in, a delivery ladder out.** The collection could make
one file light (Image Optimizer) or convert it (Image Converter) —
this builds the **set** a real page needs: the same picture at
several widths, in the formats browsers negotiate, with the markup
that ties it together. A proper `srcset` cuts image weight 40–60%
in pure HTML.

- **The ladder** — every requested width (default
  320/640/960/1280/1920) as AVIF + WebP + a fallback (JPEG for
  photos, PNG for alpha sources). Steps wider than the source are
  skipped, **never upscaled** — and the skip is reported.
- **The snippet** — ready to paste: AVIF source first, WebP source,
  the fallback `<img>` with `srcset`, `sizes`, `width`/`height`,
  `loading="lazy"`, `decoding="async"`, your alt text.
- **The weight table, measured** — what the original weighed, what
  each step weighs in every format.
- **The one honest warning** — `sizes` describes *your layout*; the
  snippet ships with what you gave it, and the report says plainly
  that a wrong `sizes` makes the browser download the largest step
  anyway.

Originals never touched; EXIF orientation baked in, metadata
dropped.

## Using with PyShell

1. Pick the **Source image**.
2. Press **Run** (⌘↩) — **Prepare Env** installs Pillow + the AVIF
   plugin once.

## Running standalone

```bash
pip install -r requirements.txt
python3 main.py --source hero.png --alt "Team at the beach"
python3 main.py --source hero.png --widths 480,768,1200 --sizes "(max-width: 768px) 100vw, 50vw"
```

## Result

- **Results tab** — the weight table and the report with the
  snippet.
- **Artifacts** — `<stem>-<width>.avif/.webp/.jpg|.png`,
  `snippet.html`, `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the ladder was built |
| 1 | unusable source (unreadable / smaller than the smallest step / AVIF missing) |
| 2 | bad arguments (bad ladder, quality out of range, missing file) |

## Layout

```
responsive-images/
├── pyshell.yaml      # manifest
├── main.py           # ladder · encoders · snippet · weight table
├── requirements.txt  # Pillow, pillow-avif-plugin
├── docs/             # EN + UA docs
└── tests/            # 10 tests over the real encoders
```

## License

MIT — see the root [LICENSE](../LICENSE).
