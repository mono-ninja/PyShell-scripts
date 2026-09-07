#!/usr/bin/env python3
"""og-image/main.py — social cards produced, not checked.

Page SEO Audit checks that the `og:image` tag exists; this script
makes the file it points at.  The standard card is 1200×630; every
network that renders previews (the Open Graph family, X/Twitter's
`summary_large_image`) reads it.

The favicon-generator form, applied to the social side: one input
→ a set + the snippet to paste.  Batch mode is the point of the
script — a real site has hundreds of pages, and a CSV drives them
all through the same template in one run.

Three **fixed** templates, not a constructor (the pdf-toolkit
scope rule):

- **gradient** — a diagonal blend of the two brand colors, title
  bottom-left;
- **banner** — solid base, an accent bar on the left, title
  centered;
- **image** — your background photo, cover-fit and darkened so
  text reads (legibility over the picture, said aloud).

Every card ships with the meta snippet: `og:image`,
`og:image:width/height`, `og:image:alt`, `twitter:card`.  Titles
wrap and auto-shrink to fit; the subtitle sits under the title; an
optional logo goes top-left.

The brand-color synergy runs both ways: Color Palette extracts the
site's palette — paste the hexes here; Page SEO Audit verifies the
result on the live page.

Exit codes: 0 = cards rendered, 1 = unusable inputs (no font
anywhere, unreadable CSV), 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import quote

from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630                     # the Open Graph standard
MARGIN = 72
SYSTEM_FONTS = [                      # first found wins
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
]
MAX_BATCH = 500


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ helpers

def parse_hex(value: str, fallback: str) -> tuple[int, int, int]:
    raw = (value or "").strip().lstrip("#")
    if re.fullmatch(r"[0-9a-fA-F]{6}", raw):
        return tuple(int(raw[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
    return tuple(int(fallback.lstrip("#")[i:i + 2], 16)  # type: ignore[return-value]
                 for i in (0, 2, 4))


def slug(name: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return (out or "card")[:60]


def load_font(font_file: str, size: int):
    if font_file:
        return ImageFont.truetype(font_file, size)
    for path in SYSTEM_FONTS:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    try:                               # Pillow ≥ 10.1: sized default
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def fit_font(font_file: str, text: str, max_width: int,
             start: int, floor: int) -> ImageFont.FreeTypeFont:
    """The largest size ≤ start whose longest wrapped line fits."""
    size = start
    while size > floor:
        font = load_font(font_file, size)
        if max(draw_textlength(font, line)
               for line in wrap(text, font, max_width)) <= max_width:
            return font
        size -= 4
    return load_font(font_file, floor)


def draw_textlength(font, text: str) -> int:
    box = font.getbbox(text)
    return box[2] - box[0] if text else 0


def wrap(text: str, font, max_width: int) -> list[str]:
    words = (text or "").split()
    if not words:
        return [""]
    lines, current = [], words[0]
    for word in words[1:]:
        if draw_textlength(font, current + " " + word) <= max_width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def cover_fit(img: Image.Image, w: int, h: int) -> Image.Image:
    """Scale to cover, center-crop — the photo never squashes."""
    ratio = max(w / img.width, h / img.height)
    scaled = img.resize((round(img.width * ratio),
                         round(img.height * ratio)),
                        Image.LANCZOS)
    left = (scaled.width - w) // 2
    top = (scaled.height - h) // 2
    return scaled.crop((left, top, left + w, top + h))


def darken(img: Image.Image, amount: int) -> Image.Image:
    overlay = Image.new("RGB", img.size, (10, 12, 20))
    return Image.blend(img.convert("RGB"), overlay, amount)


# ---------------------------------------------------------------- templates

def render_card(title: str, subtitle: str, template: str,
                primary: tuple, accent: tuple,
                logo_path: str, bg_path: str,
                font_file: str) -> Image.Image:
    """One 1200×630 card — the three fixed layouts."""
    if template == "image":
        base_img = Image.open(bg_path)
        base_img.load()
        card = darken(cover_fit(base_img, W, H), 0.55)
    elif template == "banner":
        card = Image.new("RGB", (W, H), primary)
        bar = Image.new("RGB", (24, H), accent)
        card.paste(bar, (MARGIN - 32, 0))
    else:                             # gradient
        card = Image.new("RGB", (W, H))
        px = card.load()
        for x in range(W):
            t = x / W
            color = tuple(round(primary[i] * (1 - t) + accent[i] * t)
                          for i in range(3))
            for y in range(H):
                px[x, y] = color
    draw = ImageDraw.Draw(card)

    # logo, top-left
    if logo_path:
        try:
            logo = Image.open(logo_path)
            logo.load()
            logo.thumbnail((160, 160), Image.LANCZOS)
            card.paste(logo, (MARGIN, MARGIN - 12), logo
                       if logo.mode in ("RGBA", "LA") else None)
        except OSError:
            pass                       # a broken logo never kills the card

    # title — wrapped, auto-shrunk
    text_left = MARGIN + (56 if template == "banner" else 0)
    max_width = W - text_left - MARGIN
    title_font = fit_font(font_file, title, max_width, 84, 40)
    lines = wrap(title, title_font, max_width)[:4]
    line_h = round(title_font.size * 1.18)
    block_h = line_h * len(lines)

    sub_lines, sub_font = [], None
    if subtitle:
        sub_font = load_font(font_file, 34)
        sub_lines = wrap(subtitle, sub_font, max_width)[:2]

    total_h = block_h + (16 + round(sub_font.size * 1.3) * len(sub_lines)
                         if sub_lines else 0)
    y = H - MARGIN - total_h

    for line in lines:
        draw.text((text_left, y), line, font=title_font,
                  fill=(255, 255, 255))
        y += line_h
    if sub_lines:
        y += 16
        for line in sub_lines:
            draw.text((text_left, y), line, font=sub_font,
                      fill=(214, 219, 228))
            y += round(sub_font.size * 1.3)
    return card


def build_snippet(filename: str, title: str,
                  base_url: str) -> str:
    if base_url:
        url = base_url.rstrip("/") + "/" + quote(filename)
    else:
        url = filename
    safe_title = title.replace('"', "&quot;")
    return (f'<meta property="og:image" content="{url}">\n'
            f'<meta property="og:image:width" content="{W}">\n'
            f'<meta property="og:image:height" content="{H}">\n'
            f'<meta property="og:image:alt" content="{safe_title}">\n'
            f'<meta name="twitter:card" content="summary_large_image">')


# -------------------------------------------------------------------- input

def read_batch(csv_path: str) -> list[dict]:
    rows: list[dict] = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fieldmap = {f.lower().strip(): f for f in
                    (reader.fieldnames or [])}
        if "title" not in fieldmap:
            raise ValueError(f"{csv_path}: no 'title' column")
        for row in reader:
            title = (row.get(fieldmap["title"]) or "").strip()
            if not title:
                continue
            out = (row.get(fieldmap.get("out", "out")) or "").strip()
            subtitle = ""
            if "subtitle" in fieldmap:
                subtitle = (row.get(fieldmap["subtitle"]) or "").strip()
            rows.append({"title": title, "subtitle": subtitle,
                         "out": out})
    if not rows:
        raise ValueError(f"{csv_path}: no usable rows")
    if len(rows) > MAX_BATCH:
        raise ValueError(f"{csv_path}: {len(rows)} rows — the cap "
                         f"is {MAX_BATCH}")
    return rows


# ------------------------------------------------------------------- report

def human(n: int) -> str:
    return f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


def build_table_event(cards: list[dict]) -> dict:
    rows = [[c["file"], c["title"][:44],
             human(c["bytes"])] for c in cards]
    return {"type": "table", "columns": ["file", "title", "size"],
            "rows": rows or [["—", "—", "—"]]}


def build_markdown(cards: list[dict], template: str,
                   base_url: str) -> str:
    total = sum(c["bytes"] for c in cards)
    out = [f"# OG Image — Report\n",
           f"**{len(cards)} card(s)** · {template} template · "
           f"{W}×{H} · {human(total)} total\n",
           "The standard every preview renderer reads; the snippet "
           "below each card is the complete head block.\n"]
    for c in cards:
        out.append(f"## `{c['file']}` — {human(c['bytes'])}\n")
        out.append(f"Title: {c['title']}"
                   + (f" · {c['subtitle']}" if c["subtitle"] else ""))
        out.append("")
        out.append(f"```html\n{c['snippet']}\n```")
        out.append("")
    if not base_url:
        out.append("⚫ the snippets use relative filenames — pass "
                   "the **Base URL** to make them absolute for "
                   "production.")
    out.append("Deploy: the PNGs go to the paths the snippets "
               "point at (a `/og/` folder is the convention), the "
               "head block into each page's `<head>`. Verify with "
               "**Page SEO Audit** that the tags survived the CMS, "
               "and preview with the networks' card debuggers "
               "before shipping.")
    out.append("\n## Related\n")
    out.append("- **Page SEO Audit** — checks the og:image tag on "
               "the live page; this makes the file it points at.")
    out.append("- **Color Palette** — extract the site's brand "
               "colors, paste the hexes here.")
    out.append("- **Responsive Images / Font Subset** — the other "
               "delivery steps of the G-line.")
    return "\n".join(out)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OG Image — 1200×630 social cards from a fixed "
                    "template set, single or batch from CSV, with "
                    "the ready meta snippets")
    parser.add_argument("--mode", choices=["single", "batch"],
                        default="single")
    parser.add_argument("--title", default="",
                        help="the card title (single mode)")
    parser.add_argument("--subtitle", default="",
                        help="the smaller line (single mode)")
    parser.add_argument("--csv-file", default="",
                        help="title/subtitle/out CSV (batch mode)")
    parser.add_argument("--template",
                        choices=["gradient", "banner", "image"],
                        default="gradient")
    parser.add_argument("--color-primary", default="#101828")
    parser.add_argument("--color-accent", default="#4f46e5")
    parser.add_argument("--logo", default="",
                        help="optional logo PNG (top-left)")
    parser.add_argument("--bg-image", default="",
                        help="background photo (image template)")
    parser.add_argument("--font-file", default="",
                        help="brand TTF/OTF; system sans otherwise")
    parser.add_argument("--base-url", default="",
                        help="absolute-URL prefix for the snippets")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is rendered",
              flush=True)
        return 0

    if args.template == "image" and not args.bg_image:
        print("✗ the image template needs --bg-image",
              file=sys.stderr, flush=True)
        return 2
    if args.logo and not os.path.isfile(args.logo):
        print(f"✗ logo: {args.logo} not found", file=sys.stderr,
              flush=True)
        return 2
    if args.bg_image and not os.path.isfile(args.bg_image):
        print(f"✗ background: {args.bg_image} not found",
              file=sys.stderr, flush=True)
        return 2
    if args.font_file and not os.path.isfile(args.font_file):
        print(f"✗ font: {args.font_file} not found",
              file=sys.stderr, flush=True)
        return 2

    jobs: list[dict] = []
    if args.mode == "batch":
        if not args.csv_file or not os.path.isfile(args.csv_file):
            print("✗ batch mode needs --csv-file",
                  file=sys.stderr, flush=True)
            return 2
        try:
            jobs = read_batch(args.csv_file)
        except (OSError, ValueError) as exc:
            print(f"✗ {exc}", file=sys.stderr, flush=True)
            return 2
    else:
        if not args.title.strip():
            print("✗ single mode needs --title", file=sys.stderr,
                  flush=True)
            return 2
        jobs = [{"title": args.title.strip(),
                 "subtitle": args.subtitle.strip(), "out": ""}]

    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    primary = parse_hex(args.color_primary, "#101828")
    accent = parse_hex(args.color_accent, "#4f46e5")

    cards: list[dict] = []
    for i, job in enumerate(jobs, 1):
        name = slug(job["out"] or job["title"])
        filename = f"{name}.png"
        try:
            card = render_card(job["title"], job["subtitle"],
                               args.template, primary, accent,
                               args.logo, args.bg_image,
                               args.font_file)
            card.save(os.path.join(out_dir, filename),
                      format="PNG", optimize=True)
        except OSError as exc:
            print(f"✗ card {filename!r} failed: {exc}",
                  file=sys.stderr, flush=True)
            return 1
        snippet = build_snippet(filename, job["title"],
                                args.base_url)
        cards.append({"file": filename, "title": job["title"],
                      "subtitle": job["subtitle"],
                      "bytes": os.path.getsize(
                          os.path.join(out_dir, filename)),
                      "snippet": snippet})
        emit({"type": "progress", "pct": int(100 * i / len(jobs)),
              "message": filename})

    snippets = "\n\n".join(
        f"<!-- {c['file']} -->\n{c['snippet']}" for c in cards)
    with open(os.path.join(out_dir, "meta-snippets.html"), "w",
              encoding="utf-8") as fh:
        fh.write(snippets + "\n")
    report = build_markdown(cards, args.template, args.base_url)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(cards))
    emit({"type": "markdown", "content": report})
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"cards": cards, "template": args.template,
                   "base_url": args.base_url}, fh,
                  ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)

    summary = (f"{len(cards)} card(s) · "
               f"{human(sum(c['bytes'] for c in cards))}")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
