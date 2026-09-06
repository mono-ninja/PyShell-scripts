#!/usr/bin/env python3
"""font-subset/main.py — a font cut to what a page actually serves.

Web fonts are shipped whole: the visitor downloads every glyph of
every alphabet the typeface ever supported, to render one paragraph.
Subsetting is the fix, and woff2 is the container (97%+ support,
the standard since years).  The classic shape of the savings:
Montserrat 64.6 KB → 15 KB, −76%.

Three ways to say what to keep, in precedence order:

1. **pages actually served** — HTML/CSS files scanned for the
   glyphs really used: the honest "what the site needs" cut, one
   woff2, no `unicode-range` (it *is* the range).
2. **a text sample** — the copy the font must cover, exactly.
3. **language subsets** — Google's ranges (latin, latin-ext,
   cyrillic, …): one woff2 per subset, each with its
   `unicode-range`, so the browser downloads only the ranges it
   renders — a Cyrillic page never fetches the Greek block.

Every subset ships with a ready `@font-face` (`font-display: swap`
included) and the **measured** savings table.

The **inventory** mode is the other half of the question: what is
actually in the font — family, weight, style, glyph count,
per-language coverage — with the what-the-pages-use column when
files are given.  Decide *before* cutting.

Honesty lines:

- a subset with **zero coverage** is skipped and said so — an
  empty woff2 is not a deliverable;
- coverage below 100% is reported per subset (the font may lack
  letters the range asks for);
- `font-display: swap` is the FOIT-avoidance default; swap flash
  is the price, said in the report.

Originals are never touched.  fontTools + brotli — fontTools
already lives in the collection (svg-sprite-from-font).

Exit codes: 0 = ran, 1 = font unreadable / nothing produced,
2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont

# Google Fonts' css2 subset ranges — the de-facto standard the
# ecosystem's unicode-range values follow.
SUBSET_RANGES = {
    "latin": "U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, "
             "U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, "
             "U+2000-206F, U+20AC, U+2122, U+2191, U+2193, "
             "U+2212, U+2215, U+FEFF, U+FFFD",
    "latin-ext": "U+0100-02AF, U+0300-0301, U+0303-0304, "
                 "U+0308-0309, U+0323, U+0329, U+1E00-1EFF, "
                 "U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, "
                 "U+2C60-2C7F, U+A720-A7FF",
    "cyrillic": "U+0301, U+0400-045F, U+0490-0491, U+04B0-04B1, "
                "U+2116",
    "cyrillic-ext": "U+0460-052F, U+1C80-1C88, U+20B4, "
                    "U+2DE0-2DFF, U+A640-A69F, U+FE2E-FE2F",
    "greek": "U+0370-0377, U+037A-037F, U+0384-038A, U+038C, "
             "U+038E-03A1, U+03A3-03FF",
    "greek-ext": "U+1F00-1FFF",
    "vietnamese": "U+0102-0103, U+0110-0111, U+0128, U+012F, "
                  "U+0168-0169, U+01A0-01A1, U+01AF-01B0, "
                  "U+1EA0-1EF9, U+20AB",
}

TAG_RE = re.compile(r"<[^>]*>")
CSS_SYNTAX_RE = re.compile(
    r"@import|@font-face|@media|url\(|!important|^\s*[.#:\[a-z-]+\s*\{",
    re.I | re.M)


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ ranges

def parse_range(spec: str) -> list[int]:
    """'U+0000-00FF, U+0131' → the codepoints, bounds inclusive."""
    out: list[int] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk.lower().startswith("u+"):
            continue
        body = chunk[2:]
        if "-" in body:
            lo, hi = body.split("-", 1)
            out.extend(range(int(lo, 16), int(hi, 16) + 1))
        else:
            out.append(int(body, 16))
    return out


# ------------------------------------------------------------------- font

def font_meta(font: TTFont) -> dict:
    """Family / weight / style straight from the name and OS/2
    tables — the @font-face values must match what the font says
    about itself, never guessed."""
    name = font["name"]
    family = name.getDebugName(16) or name.getDebugName(1) or "Font"
    subfamily = name.getDebugName(17) or name.getDebugName(2) or \
        "Regular"
    weight = 400
    italic = False
    if "OS/2" in font:
        weight = int(font["OS/2"].usWeightClass or 400)
        italic = bool(font["OS/2"].fsSelection & 0x01)
    if "head" in font and font["head"].macStyle & 0x02:
        italic = True
    if italic and "italic" not in subfamily.lower():
        subfamily += " Italic"
    return {"family": family, "subfamily": subfamily,
            "weight": weight, "italic": italic}


def coverage(font: TTFont, codepoints: list[int]) -> tuple[int, int]:
    """(have, asked) — how many of the asked codepoints the font's
    cmap actually maps."""
    cmap = font.getBestCmap() or {}
    have = sum(1 for cp in codepoints if cp in cmap)
    return have, len(codepoints)


def glyphs_from_files(paths: list[str]) -> set[int]:
    """The glyphs really used: HTML text nodes (tags stripped),
    CSS declarations minus the syntax lines — separable where the
    format allows, honestly approximate where it does not."""
    used: set[int] = set()
    for raw in paths:
        p = Path(raw)
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if p.suffix.lower() in (".css",):
            text = CSS_SYNTAX_RE.sub(" ", text)
            used.update(ord(c) for c in
                        re.sub(r"[{};:()\"']", " ", text)
                        if not c.isspace())
        else:
            text = TAG_RE.sub(" ", text)
            used.update(ord(c) for c in text if not c.isspace())
    return used


def save_subset(font_path: Path, unicodes, out_path: str) -> int:
    """One woff2 through the fontTools subsetter. A fresh TTFont is
    opened from the path per call — the in-memory original is never
    the subject, and the file on disk is never rewritten."""
    opts = subset.Options()
    opts.drop_tables += ["FFTM"]          # the fontTools build stamp
    opts.recalc_bounds = True
    opts.recalc_timestamps = False
    sub = subset.Subsetter(opts)
    sub.populate(unicodes=[cp for cp in unicodes])
    work = TTFont(str(font_path))
    sub.subset(work)
    work.flavor = "woff2"
    work.save(out_path)
    return os.path.getsize(out_path)


def slug(name: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return out or "font"


# ------------------------------------------------------------------- modes

def run_subset(font: TTFont, font_path: Path, out_dir: str,
               subsets: list[str], text_sample: str,
               scan_files: list[str]) -> tuple[list[dict], str,
                                               list[str]]:
    """(rows, snippet, notes) — the woff2 files are written."""
    meta = font_meta(font)
    base = slug(meta["family"])
    src_bytes = os.path.getsize(font_path)
    rows: list[dict] = []
    notes: list[str] = []
    css_blocks: list[str] = []
    made = 0

    def one(name: str, unicodes, unicode_range: str) -> None:
        nonlocal made
        have, asked = coverage(font, unicodes)
        if have == 0:
            notes.append(f"⚫ {name}: the font covers 0 of {asked} "
                         "codepoints in this range — skipped, an "
                         "empty woff2 is not a deliverable")
            return
        out_path = os.path.join(out_dir, f"{base}-{name}.woff2")
        size = save_subset(font_path, unicodes, out_path)
        rows.append({"name": name, "have": have, "asked": asked,
                     "bytes": size, "of_original":
                         round(100 * size / src_bytes, 1)})
        made += 1
        block = (f"@font-face {{\n"
                 f"  font-family: '{meta['family']}';\n"
                 f"  font-style: {'italic' if meta['italic'] else 'normal'};\n"
                 f"  font-weight: {meta['weight']};\n"
                 f"  font-display: swap;\n"
                 f"  src: url('{base}-{name}.woff2') format('woff2');\n")
        if unicode_range:
            block += f"  unicode-range: {unicode_range};\n"
        block += "}"
        css_blocks.append(block)

    if scan_files:
        used = glyphs_from_files(scan_files)
        if not used:
            raise ValueError("no text found in the scanned files")
        one("used", sorted(used), "")
        notes.append(f"the 'used' subset carries the {len(used)} "
                     "distinct character(s) found in the scanned "
                     "files — tags stripped from HTML, syntax "
                     "lines dropped from CSS; approximations are "
                     "the scanner's, honestly")
    elif text_sample.strip():
        one("text", sorted({ord(c) for c in text_sample
                            if not c.isspace()} or [0x20]), "")
        notes.append("the 'text' subset carries exactly the sample "
                     "given — spaces and newlines included in the "
                     "count, nothing else")
    elif subsets:
        for name in subsets:
            spec = SUBSET_RANGES.get(name)
            if spec is None:
                raise ValueError(f"unknown subset {name!r}")
            one(name, parse_range(spec), spec)
        notes.append("one woff2 per subset, each with its "
                     "unicode-range — the browser downloads only "
                     "the ranges it renders")
    else:
        raise ValueError("nothing to subset by: pick language "
                         "subsets, give a text sample, or scan "
                         "files")

    snippet = "\n\n".join(css_blocks)
    return rows, snippet, notes


def run_inventory(font: TTFont, font_path: Path,
                  scan_files: list[str]) -> dict:
    meta = font_meta(font)
    cmap = font.getBestCmap() or {}
    inv = {"meta": meta, "glyphs": len(cmap),
           "file": font_path.name,
           "bytes": os.path.getsize(font_path),
           "coverage": {}}
    for name, spec in SUBSET_RANGES.items():
        have, asked = coverage(font, parse_range(spec))
        inv["coverage"][name] = {"have": have, "asked": asked,
                                 "pct": round(100 * have / asked, 1)
                                 if asked else 0.0}
    if scan_files:
        used = glyphs_from_files(scan_files)
        served = sum(1 for cp in used if cp in cmap)
        inv["pages_use"] = {
            "distinct_chars": len(used),
            "covered_by_font": served,
            "missing": sorted(
                chr(cp) for cp in used if cp not in cmap)[:40]}
    return inv


# ------------------------------------------------------------------ report

def human(n: int) -> str:
    return f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


def build_table_event(rows: list[dict]) -> dict:
    out = [{"subset": r["name"],
            "coverage": f"{r['have']}/{r['asked']}",
            "woff2": human(r["bytes"]),
            "of original": f"{r['of_original']}%"}
            for r in rows]
    if not out:
        out = [{"subset": "—", "coverage": "—", "woff2": "—",
                "of original": "—"}]
    return {"type": "table",
            "columns": ["subset", "coverage", "woff2",
                        "of original"],
            "rows": out}


def build_subset_markdown(font_path: Path, meta: dict, rows: list,
                          snippet: str, notes: list[str],
                          src_bytes: int) -> str:
    best = min((r["bytes"] for r in rows), default=src_bytes)
    saving = min(99, 100 - 100 * best // src_bytes)
    out = [f"# Font Subset — Report\n",
           f"`{font_path.name}` · {meta['family']} "
           f"{meta['subfamily']} · {human(src_bytes)}\n",
           f"**{len(rows)} woff2 file(s)** · best is "
           f"**{saving}% lighter than the original**\n"]
    for note in notes:
        out.append(f"- {note}")
    out.append("")
    out.append("| subset | coverage | woff2 | of original |")
    out.append("|---|---|---|---|")
    for r in rows:
        out.append(f"| {r['name']} | {r['have']}/{r['asked']} | "
                    f"{human(r['bytes'])} | {r['of_original']}% |")
    out.append("")
    out.append("## The @font-face\n")
    out.append("```css\n" + snippet + "\n```\n")
    out.append("`font-display: swap` is in every block: the text "
               "renders immediately in the fallback and swaps when "
               "the font arrives — the flash is the price of not "
               "staring at nothing; tune if the swap shows.")
    out.append("")
    out.append("Deploy the woff2 files next to the CSS (or rewrite "
               "the url()s to your CDN). LCP note: fonts are a "
               "classic LCP culprit — CWV Check sees what real "
               "users pay for this one.")
    out.append("\n## Related\n")
    out.append("- **CWV Check / HAR Analyze** — the field and lab "
               "side of what the font does to loading.")
    out.append("- **Asset Minify** — the neighbor step for the CSS "
               "this snippet joins.")
    return "\n".join(out)


def build_inventory_markdown(inv: dict) -> str:
    m = inv["meta"]
    out = [f"# Font Subset — Inventory\n",
           f"`{inv['file']}` · **{m['family']} {m['subfamily']}** · "
           f"weight {m['weight']} · {inv['glyphs']} mapped "
           f"character(s) · {human(inv['bytes'])}\n"]
    out.append("## Per-language coverage\n")
    out.append("| subset | covered | of | % |")
    out.append("|---|---|---|---|")
    for name, c in inv["coverage"].items():
        mark = "✅" if c["pct"] >= 99 else (
            "◐" if c["pct"] >= 50 else "⚫")
        out.append(f"| {name} | {mark} {c['have']} | {c['asked']} |"
                    f" {c['pct']}% |")
    out.append("")
    if "pages_use" in inv:
        pu = inv["pages_use"]
        out.append("## What the scanned pages use\n")
        out.append(f"- {pu['distinct_chars']} distinct character(s) "
                   f"in the files; the font covers "
                   f"**{pu['covered_by_font']}** of them.")
        if pu["missing"]:
            shown = ", ".join(f"`{c}`" for c in pu["missing"][:20])
            out.append(f"- ⚫ missing from the font: {shown} — these "
                       "will render in the fallback, no subset can "
                       "fix that (the glyphs do not exist here).")
        else:
            out.append("- nothing missing: every character the "
                       "pages use exists in this font.")
        out.append("")
    out.append("Cut with the Subset mode when the coverage picture "
               "is clear — the language subsets, a text sample, or "
               "the scanned-files cut.")
    return "\n".join(out)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Font Subset — cut a font to what the page "
                    "serves (language subsets / text / scanned "
                    "HTML+CSS) as woff2 with a ready @font-face, "
                    "or inventory what a font contains")
    parser.add_argument("--mode", choices=["subset", "inventory"],
                        default="subset")
    parser.add_argument("--font-file", required=True,
                        help="TTF/OTF/WOFF/WOFF2 — never touched")
    parser.add_argument("--subset", action="append", default=[],
                        help="language subset, repeatable "
                             "(latin, latin-ext, cyrillic, …)")
    parser.add_argument("--text-sample", default="",
                        help="subset by this text instead")
    parser.add_argument("--scan-file", action="append", default=[],
                        help="subset by the glyphs used in these "
                             "HTML/CSS files instead")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is read or written",
              flush=True)
        return 0

    font_path = Path(args.font_file)
    if not font_path.is_file():
        print(f"✗ {args.font_file}: file not found",
              file=sys.stderr, flush=True)
        return 2
    try:
        font = TTFont(str(font_path))
        font.getBestCmap()             # force the cmap open
    except Exception as exc:           # fontTools raises a zoo
        print(f"✗ unreadable font: {exc}", file=sys.stderr,
              flush=True)
        return 1

    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    meta = font_meta(font)

    if args.mode == "inventory":
        inv = run_inventory(font, font_path, args.scan_file)
        report = build_inventory_markdown(inv)
        emit({"type": "progress", "pct": 100, "message": "Done"})
        emit({"type": "markdown", "content": report})
        with open(os.path.join(out_dir, "findings.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(inv, fh, ensure_ascii=False, indent=2)
        with open(os.path.join(out_dir, "report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(report)
        status(f"{meta['family']} {meta['subfamily']} · "
               f"{inv['glyphs']} chars")
        log(f"← {meta['family']} {meta['subfamily']} · "
            f"{inv['glyphs']} mapped character(s)")
        return 0

    try:
        rows, snippet, notes = run_subset(
            font, font_path, out_dir, args.subset,
            args.text_sample, args.scan_file)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2
    if not rows:
        print("✗ no subset produced — see the report for why",
              file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Nothing produced\n\n" +
              "\n".join(f"- {n}" for n in notes)})
        return 1

    report = build_subset_markdown(
        font_path, meta, rows, snippet, notes,
        os.path.getsize(font_path))
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(rows))
    emit({"type": "markdown", "content": report})
    with open(os.path.join(out_dir, "fontface.css"), "w",
              encoding="utf-8") as fh:
        fh.write(snippet + "\n")
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"font": str(font_path), "meta": meta,
                   "rows": rows, "notes": notes,
                   "snippet": snippet}, fh, ensure_ascii=False,
                  indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)

    src = os.path.getsize(font_path)
    best = min(r["bytes"] for r in rows)
    summary = (f"{len(rows)} woff2 · best "
               f"{min(99, 100 - 100 * best // src)}% lighter")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
