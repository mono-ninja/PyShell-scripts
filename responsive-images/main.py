#!/usr/bin/env python3
"""responsive-images/main.py — one image in, a delivery ladder out.

The collection could make **one file** light (Image Optimizer) or
convert it (Image Converter) — but it could not build the **set**
a real page needs: the same picture at several widths, in the
formats browsers negotiate, with the markup that ties it together.
That is this script — the delivery link of the chain Image
Converter → Image Optimizer → **here** → Page SEO Audit (which
checks the result on the page).

The ladder:

- every requested width (default 320/640/960/1280/1920) becomes
  `<stem>-<width>.avif`, `.webp` and a fallback — JPEG for
  photographic sources, PNG when the source carried alpha;
- **never upscaled** — steps wider than the source are skipped and
  the skip is reported, not hidden;
- the fallback is the largest produced step, so the `<img>` inside
  the `<picture>` works everywhere;
- the **snippet** is ready to paste: AVIF source, WebP source, the
  fallback `<img>` with `srcset`, `sizes`, `width`/`height` (so
  the browser reserves the box before loading), `loading="lazy"`,
  `decoding="async"`, and your alt text.

The honesty lines:

- **`sizes` is the part no script can know** — it describes your
  layout. The default `100vw` ships in the snippet, and the report
  says plainly: with a wrong `sizes` the browser downloads the
  largest step anyway, and the ladder saves nothing.
- The weight table is measured, not promised: what the original
  weighed, what each step weighs, in every format.

Originals are never touched; everything lands in the output
folder. EXIF orientation is baked in, the rest of the metadata is
dropped (delivery copies don't need it — EXIF Inspect's privacy
point applies to shipped files too).

Exit codes: 0 = ladder built, 1 = unusable source (unreadable, or
smaller than the smallest step; AVIF support missing), 2 = bad
arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from PIL import Image, ImageOps

try:                                  # registered right after import
    import pillow_avif  # noqa: F401
    AVIF_OK = True
except ImportError:
    AVIF_OK = False

STEP_EXTS = ("avif", "webp")
FALLBACK_BY_MODE = {"photo": "jpg", "alpha": "png"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ parsing

def parse_widths(raw: str) -> list[int]:
    """'320, 640' → [320, 640] — unique, ascending; ValueError on
    anything that is not a positive integer."""
    out: set[int] = set()
    for chunk in (raw or "").replace(" ", "").split(","):
        if not chunk:
            continue
        try:
            w = int(chunk)
        except ValueError:
            raise ValueError(f"width {chunk!r} is not an integer")
        if w < 16 or w > 16000:
            raise ValueError(f"width {w} outside the sane 16–16000 "
                             "range")
        out.add(w)
    if not out:
        raise ValueError("no widths given")
    return sorted(out)


def human(n: int) -> str:
    return f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


# ------------------------------------------------------------------- ladder

def mode_of(img: Image.Image) -> str:
    """photo (JPEG fallback) vs alpha (PNG fallback)."""
    return "alpha" if img.mode in ("RGBA", "LA", "PA") or \
        (img.mode == "P" and "transparency" in img.info) else "photo"


def prepare(img: Image.Image) -> Image.Image:
    """Orientation baked in, metadata dropped — a delivery copy."""
    fixed = ImageOps.exif_transpose(img)
    fixed.info = {}                    # no EXIF, no ICC surprises
    return fixed


def resize_to(img: Image.Image, width: int) -> Image.Image:
    height = round(img.height * width / img.width)
    return img.resize((width, height), Image.LANCZOS)


def save_step(img: Image.Image, path: str, fmt: str,
              quality: int) -> int:
    """One file of the ladder; returns its byte size."""
    target = img
    if fmt == "jpg" and img.mode not in ("RGB", "L"):
        # JPEG cannot carry alpha — composite onto white
        bg = Image.new("RGB", img.size, (255, 255, 255))
        if img.mode == "RGBA":
            bg.paste(img, mask=img.split()[3])
        else:
            bg.paste(img.convert("RGB"))
        target = bg
    target.save(path, format={"jpg": "JPEG"}.get(fmt, fmt.upper()),
                quality=quality,
                **({"optimize": True} if fmt == "jpg" else {}))
    return os.path.getsize(path)


def build_ladder(source: Path, out_dir: str, widths: list[int],
                 quality: int) -> tuple[list[dict], dict, str]:
    """(steps, meta, fallback_format). Steps carry their sizes."""
    os.makedirs(out_dir, exist_ok=True)
    img = Image.open(source)
    img.load()
    img = prepare(img)
    src_w = img.width
    mode = mode_of(img)
    fallback_ext = FALLBACK_BY_MODE[mode]

    usable = [w for w in widths if w <= src_w]
    skipped = [w for w in widths if w > src_w]
    if not usable:
        raise ValueError(
            f"the source is {src_w}px wide — smaller than the "
            f"smallest requested step ({widths[0]}px); nothing to "
            "build without upscaling")

    stem = source.stem.lower().replace(" ", "-")
    steps: list[dict] = []
    for i, w in enumerate(usable, 1):
        row = {"width": w,
               "height": round(img.height * w / img.width)}
        resized = resize_to(img, w)
        for ext in STEP_EXTS + (fallback_ext,):
            path = os.path.join(out_dir, f"{stem}-{w}.{ext}")
            row[ext] = save_step(resized, path, ext, quality)
        steps.append(row)
        emit({"type": "progress",
              "pct": int(100 * i / len(usable)),
              "message": f"{w}px"})
    meta = {"source_width": src_w, "source_height": img.height,
            "source_bytes": os.path.getsize(source),
            "skipped_steps": skipped, "mode": mode,
            "stem": stem, "alt_mode": mode}
    return steps, meta, fallback_ext


# ------------------------------------------------------------------ snippet

def build_snippet(meta: dict, steps: list[dict], sizes: str,
                  alt: str, fallback_ext: str) -> str:
    stem = meta["stem"]
    biggest = steps[-1]

    def srcset(ext: str) -> str:
        return ", ".join(f"{stem}-{s['width']}.{ext} {s['width']}w"
                         for s in steps)

    alt_attr = alt.replace('"', "&quot;")
    return (
        "<picture>\n"
        f'  <source type="image/avif" srcset="{srcset("avif")}" '
        f'sizes="{sizes}">\n'
        f'  <source type="image/webp" srcset="{srcset("webp")}" '
        f'sizes="{sizes}">\n'
        f'  <img src="{stem}-{biggest["width"]}.{fallback_ext}"\n'
        f'       srcset="{srcset(fallback_ext)}"\n'
        f'       sizes="{sizes}"\n'
        f'       width="{biggest["width"]}" '
        f'height="{biggest["height"]}"\n'
        f'       alt="{alt_attr}"\n'
        '       loading="lazy" decoding="async">\n'
        "</picture>")


# ------------------------------------------------------------------- report

def build_table_event(meta: dict, steps: list[dict],
                      fallback_ext: str) -> dict:
    src = meta["source_bytes"]

    def pct(n: int) -> str:
        return f"{100 * n // src}%"

    # rows are ARRAYS of cells (scripting-guide's shape) — the UI
    # renders row.map(cell => <td>); a dict row crashes it with
    # "g.map is not a function"
    rows = [[f"{s['width']}w",
             human(s["avif"]) + f" ({pct(s['avif'])})",
             human(s["webp"]) + f" ({pct(s['webp'])})",
             human(s[fallback_ext]) + f" ({pct(s[fallback_ext])})"]
            for s in steps]
    rows.insert(0, ["original", human(src), "—",
                    f"{meta['source_width']}×{meta['source_height']}"])
    return {"type": "table",
            "columns": ["width", "avif", "webp", "fallback"],
            "rows": rows}


def build_markdown(source: Path, meta: dict, steps: list[dict],
                   snippet: str, fallback_ext: str) -> str:
    src = meta["source_bytes"]
    best_avif = min(s["avif"] for s in steps)
    saving = min(99, 100 - 100 * best_avif // src)
    out = [f"# Responsive Images — Report\n",
           f"Source: `{source.name}` · {meta['source_width']}×"
           f"{meta['source_height']} · {human(src)}\n",
           f"**{len(steps)} step(s)** · {len(steps) * 3} file(s) · "
           f"best AVIF step is **{saving}% lighter than the "
           "original**\n"]
    if meta["skipped_steps"]:
        out.append(f"- ⚫ skipped (never upscaled): "
                   f"{', '.join(f'{w}px' for w in meta['skipped_steps'])}"
                   " — wider than the source")
    if meta["mode"] == "alpha":
        out.append("- the source carries transparency — the fallback "
                   "is PNG (AVIF and WebP keep alpha everywhere "
                   "modern)")
    out.append("")
    out.append("## The weight table\n")
    out.append("| width | AVIF | WebP | fallback |")
    out.append("|---|---|---|---|")
    out.append(f"| original | {human(src)} | — | "
               f"{meta['source_width']}×{meta['source_height']} |")
    for s in steps:
        out.append(f"| {s['width']}w | {human(s['avif'])} "
                   f"({100 * s['avif'] // src}%) | "
                   f"{human(s['webp'])} ({100 * s['webp'] // src}%) | "
                   f"{human(s[fallback_ext])} "
                   f"({100 * s[fallback_ext] // src}%) |")
    out.append("")
    out.append("## The snippet — and the one honest warning\n")
    out.append("```html\n" + snippet + "\n```")
    out.append("")
    out.append(f"⚠️ **`sizes` is yours to write.** The snippet ships "
               f"with the `sizes` you gave it — but `sizes` describes "
               "*your layout*, and no script can know it. With a "
               "wrong `sizes` the browser downloads the largest step "
               "anyway, and the ladder saves nothing. Measure the "
               "rendered box, then write it (e.g. "
               "`(max-width: 768px) 100vw, 50vw`).")
    out.append("")
    out.append("Deploy the files next to the page (or rewrite the "
               "paths to your CDN), paste the snippet, and verify "
               "with **Page SEO Audit** that the sizes attributes "
               "survived your CMS.")
    out.append("\n## Related\n")
    out.append("- **Image Converter / Image Optimizer** — the format "
               "and weight steps before this one.")
    out.append("- **Page SEO Audit** — checks `srcset`/`sizes` on "
               "the live page.")
    out.append("- **OG Image** — the social-card sibling of this "
               "delivery step.")
    return "\n".join(out)


def write_artifacts(out_dir: str, source: Path, meta: dict,
                    steps: list[dict], snippet: str,
                    fallback_ext: str, report: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "snippet.html"), "w",
              encoding="utf-8") as fh:
        fh.write(snippet + "\n")
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"source": str(source), "meta": meta,
                   "steps": steps, "fallback": fallback_ext,
                   "snippet": snippet}, fh, ensure_ascii=False,
                  indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Responsive Images — one image into an AVIF+WebP+"
                    "fallback ladder with a ready <picture> snippet "
                    "and the measured weight table")
    parser.add_argument("--source", required=True,
                        help="the source image (never touched)")
    parser.add_argument("--widths", default="320,640,960,1280,1920",
                        help="comma-separated width ladder, ascending")
    parser.add_argument("--sizes", default="100vw",
                        help="the sizes attribute for the snippet — "
                             "describe YOUR layout")
    parser.add_argument("--quality", type=int, default=80,
                        help="encoder quality, 10–95 (default 80)")
    parser.add_argument("--alt", default="",
                        help="alt text for the snippet")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is read or written",
              flush=True)
        return 0

    if not AVIF_OK:
        print("✗ pillow-avif-plugin is missing — AVIF is the core of "
              "the ladder; press Prepare Env (or pip install "
              "pillow-avif-plugin)", file=sys.stderr, flush=True)
        return 1

    source = Path(args.source)
    if not source.is_file():
        print(f"✗ {args.source}: file not found", file=sys.stderr,
              flush=True)
        return 2
    try:
        widths = parse_widths(args.widths)
    except ValueError as exc:
        print(f"✗ widths: {exc}", file=sys.stderr, flush=True)
        return 2
    if not 10 <= args.quality <= 95:
        print("✗ quality must be 10–95", file=sys.stderr, flush=True)
        return 2

    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    try:
        steps, meta, fallback_ext = build_ladder(
            source, out_dir, widths, args.quality)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1
    except OSError as exc:
        print(f"✗ cannot read {args.source}: {exc}",
              file=sys.stderr, flush=True)
        return 1

    snippet = build_snippet(meta, steps, args.sizes, args.alt,
                            fallback_ext)
    report = build_markdown(source, meta, steps, snippet,
                            fallback_ext)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(meta, steps, fallback_ext))
    emit({"type": "markdown", "content": report})
    write_artifacts(out_dir, source, meta, steps, snippet,
                    fallback_ext, report)

    src = meta["source_bytes"]
    best = min(s["avif"] for s in steps)
    summary = (f"{len(steps)} step(s) · {len(steps) * 3} file(s) · "
               f"best AVIF {min(99, 100 - 100 * best // src)}% "
               "lighter")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
