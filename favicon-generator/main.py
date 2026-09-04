#!/usr/bin/env python3
"""favicon-generator/main.py — one image in, the complete favicon set out.

Feeds the whole modern favicon stack from a single square-ish source
image: the legacy multi-size ``favicon.ico`` (16+32+48), classic
``favicon-16x16/32x32.png``, the opaque ``apple-touch-icon.png``
(180×180), PWA manifest icons (192/512), a ready ``site.webmanifest``,
and a ``snippet.html`` with the ``<head>`` tags to paste. Everything a
browser or a PWA linter asks for, from one file — that is the promise.

Processing is deliberately conservative: **contain**, never crop (a
logo is not something to chop), LANCZOS resampling, and transparency
preserved everywhere it is legal — except ``apple-touch-icon.png``,
which iOS composites onto black, so it is flattened onto the configured
background (or white when the background is transparent; the report
says so). A non-square source letterboxes onto a square canvas; a
source smaller than a target size is upscaled with a warning rather
than refused — the operator decides whether the result is good enough.

Structured events on stderr, human log on stdout. Exit codes: 0 = the
set was generated (however degraded the source), 1 = the source cannot
be read as an image or the artifacts can't be written, 2 = bad
arguments (unknown background color, padding out of range).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass

from PIL import Image

Image.MAX_IMAGE_PIXELS = 120_000_000     # favicon sources; anything bigger is a mistake

# The set: filename -> (pixel size, purpose, must-be-opaque)
TARGETS: list[tuple[str, int, str, bool]] = [
    ("favicon.ico", 48, "legacy browsers — multi-size 16+32+48 ICO", False),
    ("favicon-16x16.png", 16, "browser tab (classic)", False),
    ("favicon-32x32.png", 32, "browser tab (retina)", False),
    ("apple-touch-icon.png", 180, "iOS home screen — must be opaque", True),
    ("icon-192.png", 192, "PWA / Android manifest icon", False),
    ("icon-512.png", 512, "PWA splash / store listing", False),
]

MANIFEST_ICONS = [
    {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png",
     "purpose": "any maskable"},
    {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
     "purpose": "any maskable"},
]

RECOMMENDED_SOURCE = 512


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

class OptionsError(ValueError):
    """Bad argument values argparse can't see (colors, ranges)."""


def parse_background(raw: str) -> tuple[int, int, int] | None:
    """'#rgb'/'#rrggbb' -> (r, g, b); the literal 'transparent' -> None.

    The ``#`` is required — a bare hex or a color name must be refused,
    not silently accepted as one letterbox color or another.
    """
    text = (raw or "").strip().lower()
    if text in ("transparent", "none", ""):
        return None
    if not text.startswith("#"):
        raise OptionsError(f"background {raw!r} is neither 'transparent' "
                           f"nor a #rrggbb / #rgb color")
    hexpart = text.removeprefix("#")
    if len(hexpart) == 3:
        hexpart = "".join(ch * 2 for ch in hexpart)
    if len(hexpart) != 6:
        raise OptionsError(f"background {raw!r} is neither 'transparent' "
                           f"nor a #rrggbb / #rgb color")
    try:
        return tuple(int(hexpart[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
    except ValueError as exc:
        raise OptionsError(f"background {raw!r} is not a valid color") from exc


# ---------------------------------------------------------------------------
# Image geometry (pure — unit-tested)
# ---------------------------------------------------------------------------

def square_contain(img: Image.Image, canvas: int, background,
                   padding_pct: int) -> Image.Image:
    """The master square: the source contained (never cropped) on a
    ``canvas``×``canvas`` RGBA image, inset by ``padding_pct`` percent.

    ``background`` None leaves the letterbox transparent; an (r, g, b)
    tuple fills it. Padding shrinks the content box so the icon breathes
    inside rounded-corner masks (iOS, adaptive icons).
    """
    out = Image.new("RGBA", (canvas, canvas),
                    (*background, 255) if background else (0, 0, 0, 0))
    inset = canvas - round(2 * canvas * padding_pct / 100)
    inset = max(1, inset)
    content = img if padding_pct == 0 else img.copy()
    ratio = min(inset / content.width, inset / content.height)
    if ratio == 1 and content.width == content.height:
        placed = content
    else:
        placed = content.resize((max(1, round(content.width * ratio)),
                                 max(1, round(content.height * ratio))),
                                Image.LANCZOS)
    x = (canvas - placed.width) // 2
    y = (canvas - placed.height) // 2
    out.paste(placed, (x, y), placed)
    return out


def render_size(master: Image.Image, size: int, opaque: bool,
                background) -> Image.Image:
    """One target rendered from the master square. ``opaque`` flattens
    onto the background (white when the configured background is
    transparent — iOS composites onto black, and a black-box icon is
    nobody's intent)."""
    img = master.resize((size, size), Image.LANCZOS)
    if opaque:
        img = img.convert("RGBA")
        flat = Image.new("RGBA", (size, size),
                         (*(background or (255, 255, 255)), 255))
        flat.paste(img, (0, 0), img)
        return flat
    return img


def build_webmanifest(app_name: str | None) -> dict:
    """site.webmanifest content: the icon entries plus the name when
    the operator gave one (a manifest without a name fails PWA
    installability checks)."""
    manifest = {"icons": MANIFEST_ICONS}
    if app_name:
        manifest["name"] = app_name
        manifest["short_name"] = app_name[:12]
    return manifest


def build_snippet() -> str:
    """The <head> block, ready to paste — one line per asset, in the
    order browsers evaluate them."""
    return "\n".join([
        '<link rel="icon" href="/favicon.ico" sizes="any">',
        '<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">',
        '<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">',
        '<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">',
        '<link rel="manifest" href="/site.webmanifest">',
    ])


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

@dataclass
class GeneratedFile:
    name: str
    path: str
    bytes: int
    purpose: str


def generate(source_path: str, out_dir: str, *, background,
             padding_pct: int, app_name: str | None) -> list[GeneratedFile]:
    """Render the full set into ``out_dir``. Raises OSError/ValueError —
    the caller maps them to exit codes."""
    try:
        source = Image.open(source_path)
        source.load()                       # force the decode here, not later
    except FileNotFoundError as exc:
        raise ValueError(f"source not found: {source_path}") from exc
    except Exception as exc:                # unidentified image, truncated…
        raise ValueError(f"{source_path} is not a readable image: {exc}") from exc

    if source.width < RECOMMENDED_SOURCE or source.height < RECOMMENDED_SOURCE:
        status(f"⚠ source is {source.width}×{source.height} — smaller than the "
               f"recommended {RECOMMENDED_SOURCE}px; icon-512 will be upscaled "
               f"and may look soft")
    if abs(source.width - source.height) > max(source.width, source.height) / 2:
        status(f"⚠ source is strongly non-square ({source.width}×{source.height}) "
               f"— it will be letterboxed onto a square canvas")

    rgba = source.convert("RGBA")
    master = square_contain(rgba, RECOMMENDED_SOURCE, background, padding_pct)

    os.makedirs(out_dir, exist_ok=True)
    written: list[GeneratedFile] = []

    def record(name: str, purpose: str) -> None:
        path = os.path.join(out_dir, name)
        written.append(GeneratedFile(name, path, os.path.getsize(path), purpose))

    # favicon.ico — one file, three sizes inside.
    ico_path = os.path.join(out_dir, "favicon.ico")
    master.save(ico_path, format="ICO",
                sizes=[(16, 16), (32, 32), (48, 48)])
    record("favicon.ico", TARGETS[0][2])

    for name, size, purpose, opaque in TARGETS[1:]:
        render_size(master, size, opaque, background).save(
            os.path.join(out_dir, name), format="PNG", optimize=True)
        record(name, purpose)

    manifest_path = os.path.join(out_dir, "site.webmanifest")
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(build_webmanifest(app_name), fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    record("site.webmanifest", "PWA manifest (icon entries"
           + (" + name" if app_name else " — add a name before shipping") + ")")

    snippet_path = os.path.join(out_dir, "snippet.html")
    with open(snippet_path, "w", encoding="utf-8") as fh:
        fh.write(build_snippet() + "\n")
    record("snippet.html", "the <head> tags, ready to paste")

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Favicon Generator — one image in, the complete "
                    "favicon set out (ICO, PNGs, apple-touch, PWA icons, "
                    "webmanifest, head snippet)")
    parser.add_argument("--source-image", required=True,
                        help="source image (PNG/JPEG/WebP/GIF/BMP/TIFF; "
                             "square ≥512px recommended)")
    parser.add_argument("--name", default=None,
                        help="app name for site.webmanifest (optional)")
    parser.add_argument("--background", default="transparent",
                        help="letterbox/flatten color: 'transparent' or "
                             "#rrggbb (default transparent; apple-touch-icon "
                             "is always opaque — white when this is "
                             "transparent)")
    parser.add_argument("--padding", type=int, default=0,
                        help="percent of the canvas to inset the icon "
                             "(0–25; iOS home-screen icons benefit from "
                             "5–10) (default 0)")
    parser.add_argument("--out-dir", default=None,
                        help="where to write the set (default: next to the "
                             "source; always also written to PyShell's run "
                             "folder)")
    return parser


def artifact_dirs(out_dir: str | None, source_path: str) -> list[str]:
    """Durable location first, PyShell's run folder second — the favicon
    set must survive the run to be uploaded."""
    durable = out_dir or os.path.dirname(os.path.abspath(source_path)) or "."
    dirs = [durable]
    psd = os.environ.get("PYSHELL_OUTPUT_DIR", "")
    if psd and os.path.abspath(psd) not in {os.path.abspath(d) for d in dirs}:
        dirs.append(psd)
    return dirs


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is generated", flush=True)
        return 0

    try:
        background = parse_background(args.background)
    except OptionsError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2
    if not 0 <= args.padding <= 25:
        print("✗ --padding must be 0–25", file=sys.stderr, flush=True)
        return 2

    log(f"Generating the favicon set from {args.source_image}")
    emit({"type": "progress", "pct": 10, "message": "Reading the source"})

    dirs = artifact_dirs(args.out_dir, args.source_image)
    written: list[GeneratedFile] = []
    try:
        for i, out_dir in enumerate(dirs):
            emit({"type": "progress",
                  "pct": 20 + round(60 * i / len(dirs)),
                  "message": f"Writing to {out_dir}"})
            written = generate(args.source_image, out_dir,
                               background=background,
                               padding_pct=args.padding,
                               app_name=args.name)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1
    except OSError as exc:
        print(f"✗ cannot write the favicon set: {exc}", file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 90, "message": "Reporting"})

    table = {
        "type": "table",
        "columns": ["File", "Size", "Purpose"],
        "rows": [[f.name, f"{f.bytes:,} B", f.purpose] for f in written],
    }
    emit(table)

    lines = ["## Favicon set generated", "",
             f"Source: `{args.source_image}` → {len(written)} files in "
             f"`{dirs[0]}`" + (f" and `{dirs[1]}`" if len(dirs) > 1 else ""),
             "",
             "Paste this into `<head>`:", "", "```html",
             build_snippet(), "```", "",
             "Upload every file to the site root — the paths above are "
             "root-relative.", ""]
    if background is None:
        lines.append("_apple-touch-icon.png was flattened onto white: iOS "
                     "composites transparent icons onto black. Give "
                     "--background a color to change that._")
        lines.append("")
    emit({"type": "markdown", "content": "\n".join(lines)})

    emit({"type": "progress", "pct": 100, "message": "Done"})
    total = sum(f.bytes for f in written)
    status(f"{len(written)} files, {total:,} bytes total")
    log(f"← {len(written)} files, {total:,} bytes — favicon.ico, PNGs, "
        f"apple-touch-icon, PWA icons, site.webmanifest, snippet.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
