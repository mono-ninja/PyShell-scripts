#!/usr/bin/env python3
"""contrast-matrix/main.py — can you write with these colors?

A11y Check audits the **page** post-factum and honestly admits
what static analysis cannot see.  This script works a stage
earlier, where the data is complete because you bring the palette:
**every text/background pair** judged before a single line of
layout is written.

- **WCAG 2.2** — the ratio for each ordered pair, AA and AAA,
  body text and large text separately (4.5 / 3.0 / 7.0 / 4.5).
- **APCA** — the Lc value as the second opinion: the newer model
  that accounts for polarity (dark-on-light vs light-on-dark), so
  a pair WCAG passes and APCA flags (or the reverse) is exactly
  the interesting pair.  Bands: 75+ preferred body · 60 minimum
  body · 45 large/non-text.
- **The nearest passing shade** — for every pair failing AA body,
  the text color's lightness is shifted in HSL (the smallest shift
  that crosses 4.5, in either direction) and the hex is offered:
  a fix, not a lecture.

The chain this closes: Color Palette extracts the palette → this
says what can be written on what → A11y Check verifies it survived
the real page.

Offline, stdlib only — the matrix is math.

Exit codes: 0 = matrix computed, 1 = no usable colors, 2 = bad
arguments.
"""
from __future__ import annotations

import argparse
import colorsys
import json
import os
import re
import sys

# WCAG 2.2 thresholds
WCAG = {"aa_body": 4.5, "aa_large": 3.0,
        "aaa_body": 7.0, "aaa_large": 4.5}

# APCA 0.1.9 constants (the published reference set)
APCA = {
    "trc": 2.4,
    "ro": 0.2126729, "go": 0.7151522, "bo": 0.0721750,
    "norm_bg": 0.56, "norm_txt": 0.57,
    "rev_txt": 0.62, "rev_bg": 0.65,
    "blk_thrs": 0.022, "blk_clmp": 1.414,
    "scale": 1.14, "offset": 0.027, "lo_clip": 0.1,
    "delta_ymin": 0.0005,
}
APCA_BANDS = ((75, "75+ — preferred for body text"),
              (60, "60 — minimum for body text"),
              (45, "45 — large text and non-text UI"),
              (30, "30 — the absolute floor for large/non-text"),
              (0, "below 30 — invisible-ish, do not use"))

MAX_COLORS = 24
HEX_RE = re.compile(r"#[0-9a-fA-F]{6}\b")


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ colors

def parse_hex(value: str) -> tuple[int, int, int] | None:
    raw = (value or "").strip().lstrip("#")
    if re.fullmatch(r"[0-9a-fA-F]{6}", raw):
        return tuple(int(raw[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
    return None


def collect_colors(colors_arg: str,
                   palette_file: str) -> list[str]:
    """The explicit list wins; otherwise every hex found in
    color-palette's palette.json (recursively — the file's shape
    may evolve, the hexes are the contract)."""
    found: list[str] = []
    if colors_arg.strip():
        for token in re.split(r"[\s,;]+", colors_arg):
            if parse_hex(token):
                found.append(token.strip().lstrip("#").lower())
        return dedupe(found)
    if palette_file:
        try:
            data = json.load(open(palette_file, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        for m in HEX_RE.finditer(json.dumps(data)):
            found.append(m.group(0).lstrip("#").lower())
    return dedupe(found)


def dedupe(hexes: list[str]) -> list[str]:
    out: list[str] = []
    for h in hexes:
        if h not in out:
            out.append(h)
    return out


def hex_of(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


# ------------------------------------------------------------------- WCAG

def relative_luminance(rgb: tuple[int, int, int]) -> float:
    def chan(c: int) -> float:
        c /= 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) \
            ** 2.4
    r, g, b = (chan(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg: tuple[int, int, int],
                   bg: tuple[int, int, int]) -> float:
    l1 = relative_luminance(fg)
    l2 = relative_luminance(bg)
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


# ------------------------------------------------------------------- APCA

def apca_l_value(rgb: tuple[int, int, int]) -> float:
    """The APCA luminance Y with the soft black clamp."""
    c = APCA
    r, g, b = (v / 255 for v in rgb)

    def soft(y: float) -> float:
        return y + (c["blk_thrs"] - y) ** c["blk_clmp"] \
            if y < c["blk_thrs"] else y

    y = c["ro"] * r ** c["trc"] + c["go"] * g ** c["trc"] \
        + c["bo"] * b ** c["trc"]
    return soft(y)


def apca_l_contrast(text_rgb: tuple[int, int, int],
                    bg_rgb: tuple[int, int, int]) -> float:
    """Lc: positive = dark text on light bg, negative = the
    reverse, magnitude = strength.  The 0.1.9 reference math."""
    c = APCA
    ytxt = apca_l_value(text_rgb)
    ybg = apca_l_value(bg_rgb)
    if abs(ybg - ytxt) < c["delta_ymin"]:
        return 0.0
    if ybg > ytxt:                      # dark text on light bg
        sapc = (ybg ** c["norm_bg"] - ytxt ** c["norm_txt"]) \
            * c["scale"]
        return 0.0 if sapc < c["lo_clip"] else \
            (sapc - c["offset"]) * 100
    sapc = (ybg ** c["rev_bg"] - ytxt ** c["rev_txt"]) \
        * c["scale"]                    # light text on dark bg
    return 0.0 if sapc > -c["lo_clip"] else \
        (sapc + c["offset"]) * 100


def apca_band(lc: float) -> str:
    strength = abs(lc)
    for floor, label in APCA_BANDS:
        if strength >= floor:
            return label
    return APCA_BANDS[-1][1]


# ------------------------------------------------------ the nearest passing

def nearest_passing(text_rgb: tuple[int, int, int],
                    bg_rgb: tuple[int, int, int],
                    threshold: float = WCAG["aa_body"]) -> str | None:
    """The smallest HSL-lightness shift of the TEXT color that
    crosses the threshold — both directions tried, the closer
    win.  None when neither direction can pass (a threshold no
    lightness of this hue reaches)."""
    r, g, b = (v / 255 for v in text_rgb)
    h, _l, s = colorsys.rgb_to_hls(r, g, b)
    best: tuple[float, tuple[int, int, int]] | None = None

    def try_l(lightness: float) -> None:
        nonlocal best
        rr, gg, bb = colorsys.hls_to_rgb(h, lightness, s)
        rgb = (round(rr * 255), round(gg * 255), round(bb * 255))
        if contrast_ratio(rgb, bg_rgb) >= threshold:
            shift = abs(lightness - _l)
            if best is None or shift < best[0]:
                best = (shift, rgb)

    for step in range(0, 101):
        try_l(step / 100)               # covers both directions
    if best is None:
        return None
    return hex_of(best[1])


# ------------------------------------------------------------------ matrix

def build_matrix(hexes: list[str]) -> list[dict]:
    rgbs = {h: parse_hex(h) for h in hexes}
    pairs = []
    for text in hexes:
        for bg in hexes:
            if text == bg:
                continue
            ratio = contrast_ratio(rgbs[text], rgbs[bg])
            lc = apca_l_contrast(rgbs[text], rgbs[bg])
            entry = {
                "text": "#" + text, "background": "#" + bg,
                "ratio": round(ratio, 2),
                "wcag": {k: ratio >= v
                         for k, v in WCAG.items()},
                "apca_l": round(lc, 1),
                "apca_band": apca_band(lc),
            }
            if ratio < WCAG["aa_body"]:
                fix = nearest_passing(rgbs[text], rgbs[bg])
                entry["nearest_passing_text"] = fix
            pairs.append(entry)
    pairs.sort(key=lambda p: p["ratio"])
    return pairs


# ------------------------------------------------------------------ report

def verdict(entry: dict) -> str:
    if entry["wcag"]["aaa_body"]:
        mark = "✅ AAA"
    elif entry["wcag"]["aa_body"]:
        mark = "🟢 AA"
    elif entry["wcag"]["aa_large"]:
        mark = "🟡 large only"
    else:
        mark = "🔴 fails AA"
    return mark


def build_table_event(pairs: list[dict], top: int = 30) -> dict:
    rows = [{"text": p["text"], "on background": p["background"],
             "ratio": p["ratio"], "wcag": verdict(p),
             "apca": f"{p['apca_l']:+.0f}"}
            for p in pairs[:top]]
    if len(pairs) > top:
        rows.append({"text": f"… +{len(pairs) - top} more",
                     "on background": "", "ratio": "",
                     "wcag": "", "apca": ""})
    return {"type": "table",
            "columns": ["text", "on background", "ratio", "wcag",
                        "apca"],
            "rows": rows or [{"text": "—", "on background": "—",
                              "ratio": "—", "wcag": "—",
                              "apca": "—"}]}


def build_markdown(hexes: list[str], pairs: list[dict]) -> str:
    total = len(pairs)
    aa = sum(1 for p in pairs if p["wcag"]["aa_body"])
    large_only = sum(1 for p in pairs
                     if not p["wcag"]["aa_body"]
                     and p["wcag"]["aa_large"])
    fails = total - aa - large_only
    out = [f"# Contrast Matrix — Report\n",
           f"**{len(hexes)} color(s)** → {total} text/background "
           f"pair(s): **{aa} pass AA body** · {large_only} large-only"
           f" · **{fails} fail AA**\n",
           "The design-stage sibling of A11y Check: this runs on "
           "the full palette before the page exists; A11y Check "
           "verifies what the real page shipped.\n"]

    out.append("## The matrix — worst first\n")
    out.append("| text | on | ratio | WCAG 2.2 | APCA Lc |")
    out.append("|---|---|---|---|---|")
    for p in pairs:
        out.append(f"| `{p['text']}` | `{p['background']}` | "
                    f"{p['ratio']} | {verdict(p)} | "
                    f"{p['apca_l']:+.0f} |")
    out.append("")

    bad = [p for p in pairs if not p["wcag"]["aa_body"]]
    if bad:
        out.append("## Failing pairs — and the nearest fix\n")
        for p in bad:
            fix = p.get("nearest_passing_text")
            if fix:
                out.append(f"- 🔴 `{p['text']}` on "
                           f"`{p['background']}` — "
                           f"{p['ratio']}:1 · nearest text shade "
                           f"that passes AA: **`{fix}`**")
            else:
                out.append(f"- 🔴 `{p['text']}` on "
                           f"`{p['background']}` — {p['ratio']}:1 · "
                           "no lightness of this hue reaches 4.5:1 "
                           "on that background — change the hue or "
                           "the background")
        out.append("")

    out.append("## Reading the two models\n")
    out.append("- **WCAG 2.2** is the legal floor: AA 4.5:1 body / "
               "3:1 large, AAA 7:1 body / 4.5:1 large.")
    out.append("- **APCA (Lc)** is the second opinion: it models "
               "polarity — dark-on-light and light-on-dark are not "
               "symmetric — so pairs where the two models disagree "
               "are exactly the pairs worth a designer's eye "
               "(Lc 75+ preferred body · 60 minimum · 45 large).")
    disagreement = [p for p in pairs
                    if p["wcag"]["aa_body"] and abs(p["apca_l"]) < 60]
    if disagreement:
        out.append(f"- ⚠️ {len(disagreement)} pair(s) pass WCAG AA "
                   "but sit under APCA's body minimum (Lc < 60) — "
                   "the known gap between the models; treat body "
                   "text there with care.")
    strong_dark = [p for p in pairs if p["apca_l"] < 0
                   and abs(p["apca_l"]) >= 75]
    if strong_dark:
        out.append(f"- ✅ {len(strong_dark)} light-on-dark pair(s) "
                   "clear APCA's preferred body bar (Lc ≤ −75) — "
                   "the dark-mode strengths of this palette.")
    out.append("")
    out.append("## Related\n")
    out.append("- **Color Palette** — where the hexes come from "
               "(its palette.json feeds this directly).")
    out.append("- **A11y Check** — the live page's contrast, "
               "post-factum and honest about what static analysis "
               "misses.")
    return "\n".join(out)


def write_artifacts(hexes: list[str], pairs: list[dict],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"colors": ["#" + h for h in hexes],
                   "pairs": pairs}, fh, ensure_ascii=False,
                  indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Contrast Matrix — every text/background pair "
                    "of a palette: WCAG 2.2 AA/AAA (body and large "
                    "separately), APCA Lc as the second opinion, "
                    "and the nearest passing shade for every fail")
    parser.add_argument("--colors", default="",
                        help="hex colors, any separator — takes "
                             "precedence over the file")
    parser.add_argument("--palette-file", default="",
                        help="color-palette's palette.json — every "
                             "hex in it joins the matrix")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is computed",
              flush=True)
        return 0

    hexes = collect_colors(args.colors, args.palette_file)
    if len(hexes) < 2:
        print("✗ need at least two colors (a pair to judge)",
              file=sys.stderr, flush=True)
        return 1
    if len(hexes) > MAX_COLORS:
        log(f"  ⚫ capped at the first {MAX_COLORS} of "
            f"{len(hexes)} colors")
        hexes = hexes[:MAX_COLORS]

    log(f"  {len(hexes)} color(s) → "
        f"{len(hexes) * (len(hexes) - 1)} pair(s)")
    status(f"{len(hexes)} colors")
    pairs = build_matrix(hexes)
    report = build_markdown(hexes, pairs)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(pairs))
    emit({"type": "markdown", "content": report})
    write_artifacts(hexes, pairs, report)

    aa = sum(1 for p in pairs if p["wcag"]["aa_body"])
    summary = (f"{len(pairs)} pair(s) · {aa} pass AA body · "
               f"{len(pairs) - aa} don't")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
