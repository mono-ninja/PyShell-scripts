#!/usr/bin/env python3
"""a11y-check/main.py — the accessibility pass, statically and honestly.

Accessibility was the biggest gap in the collection after 48 scripts,
and this fills it the collection's way: one fetch (the Page SEO Audit
principle), everything computed from the HTML and the CSS that can be
read statically.  The checks:

- **Contrast** (WCAG 1.4.3) — text color × background color wherever
  the pairing is unambiguous: inline styles, `<style>` blocks and
  fetched stylesheets, simple tag/class/id selectors only.  `color`
  and `background` are followed **up the ancestor chain** (the CSS
  inheritance mechanism is deterministic — it is the cascade, not a
  guess), specificity decides between rules, and the font size/weight
  that pick the 3:1 large-text bar come from the same cascade plus the
  browser's heading defaults.  Where CSS cannot be paired statically —
  JS-computed styles, compound selectors, background images — the
  report says "not checked", never "passed".
- **Forms** — inputs/selects/textareas without a `<label for>`, an
  aria-label/labelledby, or a wrapping label; placeholder-only and
  title-only are flagged as warnings (neither is a label), and a
  `for=`/`aria-labelledby` pointing at an id that does not exist
  counts as no label at all.  `<fieldset>` without `<legend>`.
- **Headings** — level skips (h2 → h4), no h1, several h1.
- **Language** — `lang` on `<html>` (WCAG 3.1.1, level A), invalid
  codes, foreign-language inserts (primary subtag, case-insensitive).
- **ARIA misuse** — roles without their required state
  (checkbox/slider/…), `aria-hidden` on a genuinely focusable
  element (an error; `role=presentation` there is a warning, since
  ARIA ignores it), dangling `aria-labelledby` / `aria-describedby`.
- **Focus** — `tabindex` above 0 (the DOM order is the right order).
- **Links** — empty links, "click here" generic text.
- **Tables** — no `<th>`, `<th>` without `scope`.
- **Media** — `<iframe>` without a title, autoplaying audio/video,
  `<video>` without a `<track>`.
- **Meta** — a viewport that blocks zoom (WCAG 1.4.4), a
  `<meta http-equiv="refresh">` timer (WCAG 2.2.1).
- **Duplicate ids** (WCAG 4.1.1) — they break every `for=` and
  `aria-labelledby` that points at them.
- **Landmarks & skip link** — main/nav/header (element *or* ARIA
  role), the first `#` link.

Image `alt` is **Page SEO Audit's** column — this script counts them
for context and points there, it does not double-audit.

Exit codes: 0 = ran (findings are results), 1 = unreachable or
unusable response, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import NamedTuple
from urllib.parse import urljoin

import lxml.html
import requests
from lxml import etree

USER_AGENT = "PyShell-a11y-check/1 (+accessibility diagnostics)"

HTML_CONTENT_TYPES = {"text/html", "application/xhtml+xml",
                      "application/xml", "text/xml"}

# Nothing declared anywhere → the browser's white canvas (documented
# assumption; the report says so in the finding).
WHITE_CANVAS = "#FFFFFF"

# ── the color parser written for color-palette, carried over ─────────────
# Kept in sync with color-palette/src/colors.py by hand — the scripts do
# not import each other, so a syntax added there is added here too.

CSS_NAMED_COLORS: dict[str, str | None] = {
    'aliceblue': '#F0F8FF', 'antiquewhite': '#FAEBD7', 'aqua': '#00FFFF',
    'aquamarine': '#7FFFD4', 'azure': '#F0FFFF', 'beige': '#F5F5DC',
    'bisque': '#FFE4C4', 'black': '#000000', 'blanchedalmond': '#FFEBCD',
    'blue': '#0000FF', 'blueviolet': '#8A2BE2', 'brown': '#A52A2A',
    'burlywood': '#DEB887', 'cadetblue': '#5F9EA0', 'chartreuse': '#7FFF00',
    'chocolate': '#D2691E', 'coral': '#FF7F50', 'cornflowerblue': '#6495ED',
    'cornsilk': '#FFF8DC', 'crimson': '#DC143C', 'cyan': '#00FFFF',
    'darkblue': '#00008B', 'darkcyan': '#008B8B', 'darkgoldenrod': '#B8860B',
    'darkgray': '#A9A9A9', 'darkgreen': '#006400', 'darkgrey': '#A9A9A9',
    'darkkhaki': '#BDB76B', 'darkmagenta': '#8B008B',
    'darkolivegreen': '#556B2F', 'darkorange': '#FF8C00',
    'darkorchid': '#9932CC', 'darkred': '#8B0000', 'darksalmon': '#E9967A',
    'darkseagreen': '#8FBC8F', 'darkslateblue': '#483D8B',
    'darkslategray': '#2F4F4F', 'darkslategrey': '#2F4F4F',
    'darkturquoise': '#00CED1', 'darkviolet': '#9400D3',
    'deeppink': '#FF1493', 'deepskyblue': '#00BFFF', 'dimgray': '#696969',
    'dimgrey': '#696969', 'dodgerblue': '#1E90FF', 'firebrick': '#B22222',
    'floralwhite': '#FFFAF0', 'forestgreen': '#228B22', 'fuchsia': '#FF00FF',
    'gainsboro': '#DCDCDC', 'ghostwhite': '#F8F8FF', 'gold': '#FFD700',
    'goldenrod': '#DAA520', 'gray': '#808080', 'green': '#008000',
    'greenyellow': '#ADFF2F', 'grey': '#808080', 'honeydew': '#F0FFF0',
    'hotpink': '#FF69B4', 'indianred': '#CD5C5C', 'indigo': '#4B0082',
    'ivory': '#FFFFF0', 'khaki': '#F0E68C', 'lavender': '#E6E6FA',
    'lavenderblush': '#FFF0F5', 'lawngreen': '#7CFC00',
    'lemonchiffon': '#FFFACD', 'lightblue': '#ADD8E6',
    'lightcoral': '#F08080', 'lightcyan': '#E0FFFF',
    'lightgoldenrodyellow': '#FAFAD2', 'lightgray': '#D3D3D3',
    'lightgreen': '#90EE90', 'lightgrey': '#D3D3D3',
    'lightpink': '#FFB6C1', 'lightsalmon': '#FFA07A',
    'lightseagreen': '#20B2AA', 'lightskyblue': '#87CEFA',
    'lightslategray': '#778899', 'lightslategrey': '#778899',
    'lightsteelblue': '#B0C4DE', 'lightyellow': '#FFFFE0',
    'lime': '#00FF00', 'limegreen': '#32CD32', 'linen': '#FAF0E6',
    'magenta': '#FF00FF', 'maroon': '#800000',
    'mediumaquamarine': '#66CDAA', 'mediumblue': '#0000CD',
    'mediumorchid': '#BA55D3', 'mediumpurple': '#9370DB',
    'mediumseagreen': '#3CB371', 'mediumslateblue': '#7B68EE',
    'mediumspringgreen': '#00FA9A', 'mediumturquoise': '#48D1CC',
    'mediumvioletred': '#C71585', 'midnightblue': '#191970',
    'mintcream': '#F5FFFA', 'mistyrose': '#FFE4E1', 'moccasin': '#FFE4B5',
    'navajowhite': '#FFDEAD', 'navy': '#000080', 'oldlace': '#FDF5E6',
    'olive': '#808000', 'olivedrab': '#6B8E23', 'orange': '#FFA500',
    'orangered': '#FF4500', 'orchid': '#DA70D6',
    'palegoldenrod': '#EEE8AA', 'palegreen': '#98FB98',
    'paleturquoise': '#AFEEEE', 'palevioletred': '#DB7093',
    'papayawhip': '#FFEFD5', 'peachpuff': '#FFDAB9', 'peru': '#CD853F',
    'pink': '#FFC0CB', 'plum': '#DDA0DD', 'powderblue': '#B0E0E6',
    'purple': '#800080', 'rebeccapurple': '#663399', 'red': '#FF0000',
    'rosybrown': '#BC8F8F', 'royalblue': '#4169E1',
    'saddlebrown': '#8B4513', 'salmon': '#FA8072', 'sandybrown': '#F4A460',
    'seagreen': '#2E8B57', 'seashell': '#FFF5EE', 'sienna': '#A0522D',
    'silver': '#C0C0C0', 'skyblue': '#87CEEB', 'slateblue': '#6A5ACD',
    'slategray': '#708090', 'slategrey': '#708090', 'snow': '#FFFAFA',
    'springgreen': '#00FF7F', 'steelblue': '#4682B4', 'tan': '#D2B48C',
    'teal': '#008080', 'thistle': '#D8BFD8', 'tomato': '#FF6347',
    'turquoise': '#40E0D0', 'violet': '#EE82EE', 'wheat': '#F5DEB3',
    'white': '#FFFFFF', 'whitesmoke': '#F5F5F5', 'yellow': '#FFFF00',
    'yellowgreen': '#9ACD32',
    # Keywords that carry no color — parse to None.
    'transparent': None, 'inherit': None, 'initial': None,
    'currentcolor': None, 'unset': None, 'revert': None,
}


def parse_color(value: str) -> str | None:
    """Any CSS color value → normalized #RRGGBB (color-palette's
    parser; alpha dropped — the contrast wants the color).

    Legacy comma syntax and the modern space syntax both parse
    (`rgb(0 0 0 / 50%)`, `hsl(210 100% 50%)` — what Tailwind and every
    current framework emit), plus `#RGB`/`#RGBA`/`#RRGGBB`/`#RRGGBBAA`
    and `oklch()`/`oklab()`.  `var()` and `color-mix()` stay None on
    purpose: resolving them needs the whole cascade, and a guess would
    break the honest boundary.
    """
    value = (value or "").strip().lower()
    if not value:
        return None
    if value in CSS_NAMED_COLORS:
        return CSS_NAMED_COLORS[value]
    if value.startswith("#"):
        return _parse_hex(value)
    m = re.fullmatch(r"(rgba?|hsla?|oklch|oklab)\(\s*(.*?)\s*\)", value,
                     re.S)
    if not m:
        return None
    func, parts = m.group(1), [p for p in re.split(r"[\s,/]+", m.group(2))
                               if p]
    if len(parts) < 3:
        return None
    if func.startswith("rgb"):
        channels = [_css_channel(p) for p in parts[:3]]
        if any(c is None for c in channels):
            return None
        return "#{:02X}{:02X}{:02X}".format(*channels)
    if func.startswith("hsl"):
        h, s, l = (_css_hue(parts[0]), _css_percent(parts[1]),
                   _css_percent(parts[2]))
        if h is None or s is None or l is None:
            return None
        return _hsl_to_hex(h, s, l)
    if func == "oklch":
        lightness = _css_scaled(parts[0], 1.0)
        chroma = _css_scaled(parts[1], 0.4)
        hue = _css_hue(parts[2])
        if lightness is None or chroma is None or hue is None:
            return None
        rad = math.radians(hue)
        return _oklab_to_hex(lightness, chroma * math.cos(rad),
                             chroma * math.sin(rad))
    lightness = _css_scaled(parts[0], 1.0)
    a, b = _css_scaled(parts[1], 0.4), _css_scaled(parts[2], 0.4)
    if lightness is None or a is None or b is None:
        return None
    return _oklab_to_hex(lightness, a, b)


def _parse_hex(value: str) -> str | None:
    digits = value[1:]
    if not re.fullmatch(r"[0-9a-f]+", digits):
        return None
    if len(digits) in (3, 4):            # #RGB, #RGBA
        return "#" + "".join(c * 2 for c in digits[:3]).upper()
    if len(digits) in (6, 8):            # #RRGGBB, #RRGGBBAA
        return "#" + digits[:6].upper()
    return None


def _css_channel(token: str) -> int | None:
    """One rgb() channel: 0–255, or a percentage of 255."""
    try:
        raw = (float(token[:-1]) * 2.55 if token.endswith("%")
               else float(token))
    except ValueError:
        return None
    return max(0, min(255, round(raw)))


def _css_percent(token: str) -> float | None:
    try:
        return float(token[:-1] if token.endswith("%") else token)
    except ValueError:
        return None


def _css_scaled(token: str, full: float) -> float | None:
    """A number, or a percentage of `full` (oklch lightness/chroma)."""
    try:
        return (float(token[:-1]) / 100 * full if token.endswith("%")
                else float(token))
    except ValueError:
        return None


def _css_hue(token: str) -> float | None:
    m = re.fullmatch(r"([-+]?[\d.]+)(deg|grad|rad|turn)?", token)
    if not m:
        return None
    try:
        value = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2) or "deg"
    if unit == "grad":
        return value * 0.9
    if unit == "rad":
        return math.degrees(value)
    if unit == "turn":
        return value * 360
    return value


def _hsl_to_hex(h: float, s: float, l: float) -> str:
    # color-palette runs this through colorsys, which lands 1/255 low on
    # exact halves (hsl(210 100% 50%) → #007FFF there, #0080FF here).
    # What the two parsers keep in sync is the syntax they accept, not
    # the last bit of a float — the ratio does not move.
    s, l = s / 100, l / 100
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = l - c / 2
    seg = int(h // 60) % 6
    rgb = [(c, x, 0), (x, c, 0), (0, c, x),
           (0, x, c), (x, 0, c), (c, 0, x)][seg]
    return "#{:02X}{:02X}{:02X}".format(*(round((v + m) * 255)
                                          for v in rgb))


def _oklab_to_hex(lightness: float, a: float, b: float) -> str:
    """OKLab → sRGB (the spec's matrices), clipped into gamut."""
    l_ = lightness + 0.3963377774 * a + 0.2158037573 * b
    m_ = lightness - 0.1055613458 * a - 0.0638541728 * b
    s_ = lightness - 0.0894841775 * a - 1.2914855480 * b
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    return "#{:02X}{:02X}{:02X}".format(
        _srgb_channel(4.0767416621 * l - 3.3077115913 * m
                      + 0.2309699292 * s),
        _srgb_channel(-1.2684380046 * l + 2.6097574011 * m
                      - 0.3413193965 * s),
        _srgb_channel(-0.0041960863 * l - 0.7034186147 * m
                      + 1.7076147010 * s))


def _srgb_channel(v: float) -> int:
    v = max(0.0, min(1.0, v))
    v = v * 12.92 if v <= 0.0031308 else 1.055 * (v ** (1 / 2.4)) - 0.055
    return max(0, min(255, round(v * 255)))


def _hex_rgb(hex_color: str) -> tuple[int, int, int]:
    return (int(hex_color[1:3], 16), int(hex_color[3:5], 16),
            int(hex_color[5:7], 16))


def _wcag_channel(v: int) -> float:
    c = v / 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def wcag_contrast(fg: str, bg: str) -> float:
    """The WCAG relative-luminance ratio, 1..21."""
    def lum(hex_color: str) -> float:
        r, g, b = _hex_rgb(hex_color)
        return (0.2126 * _wcag_channel(r) + 0.7152 * _wcag_channel(g)
                + 0.0722 * _wcag_channel(b))
    l1, l2 = lum(fg), lum(bg)
    if l1 < l2:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)


# ── events ───────────────────────────────────────────────────────────────

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ── findings model ───────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # error | warning | info
    check: str             # contrast | forms | headings | …
    message: str
    where: str = ""
    fix: str = ""
    count: int = 1                                   # identical findings
    examples: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"severity": self.severity, "check": self.check,
                "message": self.message, "where": self.where,
                "fix": self.fix, "count": self.count,
                "examples": self.examples}


ORDER = {"error": 0, "warning": 1, "info": 2}
ICON = {"error": "🔴", "warning": "🟠", "info": "ℹ️"}
MAX_EXAMPLES = 3


def group_findings(findings: list[Finding]) -> list[Finding]:
    """Fold identical findings into one row with a count and a couple
    of examples — one page can carry the same `#999999 on #FFFFFF`
    six hundred times, and six hundred rows is not a report."""
    groups: dict[tuple, Finding] = {}
    order: list[tuple] = []
    for f in findings:
        key = (f.severity, f.check, f.message, f.fix)
        head = groups.get(key)
        if head is None:
            groups[key] = replace(
                f, examples=[f.where] if f.where else [])
            order.append(key)
            continue
        head.count += 1
        if f.where and len(head.examples) < MAX_EXAMPLES:
            head.examples.append(f.where)
    return [groups[k] for k in order]


def _where_cell(f: Finding) -> str:
    if f.count == 1:
        return f.where
    shown = "; ".join(f.examples[:MAX_EXAMPLES])
    rest = f.count - min(len(f.examples), MAX_EXAMPLES)
    return shown + (f" +{rest} more" if rest > 0 else "")


def _message_cell(f: Finding) -> str:
    return f.message + (f" ×{f.count}" if f.count > 1 else "")


def _el_label(el) -> str:
    """A short human pointer to an element: tag#id.class — text…"""
    tag = el.tag if isinstance(el.tag, str) else "?"
    parts = [tag]
    if el.get("id"):
        parts.append("#" + el.get("id"))
    classes = (el.get("class") or "").split()
    if classes:
        parts.append("." + ".".join(classes[:3]))
    label = "".join(parts)
    text = " ".join(el.text_content().split())[:40]
    return f"{label} — “{text}”" if text else label


# ── fetch ────────────────────────────────────────────────────────────────

def fetch(url: str, timeout: int) -> requests.Response:
    """One GET. HTTP status is *not* raised on: a 404 page is still a
    page, and it is worth auditing — main() reports the status."""
    return requests.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": USER_AGENT})


def _resp_status(resp) -> int:
    return int(getattr(resp, "status_code", 200) or 200)


def _resp_content_type(resp) -> str:
    headers = getattr(resp, "headers", None) or {}
    try:
        raw = headers.get("Content-Type") or headers.get("content-type") or ""
    except AttributeError:
        raw = ""
    return raw.split(";", 1)[0].strip().lower()


def effective_base(doc, base_url: str) -> str:
    """<base href> wins over the response URL — page-seo-audit's rule."""
    for el in doc.iter("base"):
        href = el.get("href")
        if href:
            return urljoin(base_url, href)
    return base_url


def _media_renders_on_screen(media: str) -> bool:
    """A `media` attribute / @media condition that a screen reader's
    browser actually applies. Print-only sheets and the dark-scheme
    branch are not what the default rendering shows."""
    cond = (media or "").strip().lower()
    if not cond:
        return True
    if re.search(r"\bnot\s+print\b", cond):
        return True
    if re.search(r"\bprint\b", cond) and not re.search(r"\b(screen|all)\b",
                                                       cond):
        return False
    if "prefers-color-scheme" in cond and "dark" in cond:
        return False
    return True


def stylesheet_urls(doc, base_url: str) -> list[str]:
    """Absolute URLs of the stylesheets that render on screen —
    print-only and alternate sheets never do, and spending the fetch
    budget on them is how the contrast pass ends up empty."""
    out = []
    for el in doc.iter("link"):
        rels = (el.get("rel") or "").lower().split()
        href = el.get("href")
        if "stylesheet" not in rels or not href or "alternate" in rels:
            continue
        if el.get("disabled") is not None:
            continue
        if not _media_renders_on_screen(el.get("media") or ""):
            continue
        out.append(urljoin(base_url, href))
    return out


# ── the static CSS engine ────────────────────────────────────────────────

SIMPLE_SELECTOR_RE = re.compile(r"[a-zA-Z][\w-]*|\.[\w-]+|#[\w-]+")
# Conditional groups whose body is ordinary CSS one level down; every
# other at-rule (@font-face, @keyframes, @page…) carries declarations
# that are not element styling at all.
AT_CONDITIONAL = {"media", "supports", "layer", "container", "scope"}
IMAGE_VALUE_RE = re.compile(r"\b(url|[\w-]*gradient|image-set|cross-fade)"
                            r"\s*\(")


class Rule(NamedTuple):
    """One simple rule, reduced to what the contrast pass needs."""
    selector: str
    color: str
    background: str
    bg_image: bool
    font_px: float | None
    bold: bool | None
    hidden: bool


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", " ", css or "", flags=re.S)


def _skip_string(css: str, i: int) -> int:
    quote, n = css[i], len(css)
    j = i + 1
    while j < n:
        if css[j] == "\\":
            j += 2
            continue
        if css[j] == quote:
            return j + 1
        j += 1
    return n


def _iter_blocks(css: str):
    """(prelude, body) for every brace block at this nesting level.
    Brace-counted, so an @media body never leaks into the rule set —
    a print or dark-scheme block used to win as "the last rule"."""
    i = start = 0
    n = len(css)
    while i < n:
        ch = css[i]
        if ch in "\"'":
            i = _skip_string(css, i)
            continue
        if ch == "{":
            prelude = css[start:i]
            depth, j = 1, i + 1
            while j < n and depth:
                c = css[j]
                if c in "\"'":
                    j = _skip_string(css, j)
                    continue
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                j += 1
            yield prelude, css[i + 1:(j - 1 if depth == 0 else n)]
            i = start = j
        elif ch == "}":
            i += 1
            start = i
        else:
            i += 1


def _declarations(text: str) -> list[tuple[str, str]]:
    """(property, value) pairs — inline styles and rule bodies alike.
    `!important` is stripped: a value that carries it is still a
    value, and dropping the declaration was silently losing colors."""
    head = (text or "").split("{", 1)[0]
    out = []
    for decl in head.split(";"):
        prop, sep, value = decl.partition(":")
        if not sep:
            continue
        prop = prop.strip().lower()
        value = re.sub(r"!\s*important", "", value, flags=re.I).strip()
        if prop and value:
            out.append((prop, value))
    return out


def _css_px(value: str) -> float | None:
    """An absolute font-size → px. Relative units (em, %, clamp…) stay
    unknown rather than guessed."""
    m = re.fullmatch(r"\s*([\d.]+)\s*(px|pt|rem)?\s*", value or "", re.I)
    if not m:
        return None
    try:
        number = float(m.group(1))
    except ValueError:
        return None
    unit = (m.group(2) or "px").lower()
    return number * {"px": 1.0, "pt": 4 / 3, "rem": 16.0}[unit]


def _is_bold(value: str) -> bool | None:
    v = (value or "").strip().lower()
    if not v:
        return None
    if v in ("bold", "bolder"):
        return True
    if v in ("normal", "lighter"):
        return False
    return v.isdigit() and int(v) >= 700


def _bg_shorthand_color(value: str) -> str:
    for token in value.split():
        parsed = parse_color(token)
        if parsed:
            return parsed
    return ""


def style_facts(text: str) -> dict:
    """The declarations the contrast pass cares about, out of one
    declaration list (a rule body or a style attribute)."""
    facts = {"color": "", "background": "", "bg_image": False,
             "font_px": None, "bold": None, "hidden": False}
    for prop, value in _declarations(text):
        low = value.lower()
        if prop == "color" and not facts["color"]:
            facts["color"] = parse_color(value) or ""
        elif prop == "background-color" and not facts["background"]:
            facts["background"] = parse_color(value) or ""
        elif prop == "background-image":
            if low not in ("none", "initial", "unset"):
                facts["bg_image"] = True
        elif prop == "background":
            # the shorthand: an image or gradient anywhere in it means
            # the color underneath is not what renders
            if IMAGE_VALUE_RE.search(low):
                facts["bg_image"] = True
            elif not facts["background"]:
                facts["background"] = _bg_shorthand_color(value)
        elif prop == "font-size" and facts["font_px"] is None:
            facts["font_px"] = _css_px(value)
        elif prop == "font-weight" and facts["bold"] is None:
            facts["bold"] = _is_bold(value)
        elif prop == "font" and facts["font_px"] is None:
            m = re.search(r"([\d.]+(?:px|pt|rem))", low)
            if m:
                facts["font_px"] = _css_px(m.group(1))
            if facts["bold"] is None and re.search(r"\bbold\b", low):
                facts["bold"] = True
        elif prop == "display" and low == "none":
            facts["hidden"] = True
        elif prop == "visibility" and low in ("hidden", "collapse"):
            facts["hidden"] = True
    return facts


def css_color_rules(css_text: str) -> list[Rule]:
    """Every rule whose selector is a *single simple* tag/class/id
    selector — the static scope. Comments are stripped first (one
    `/* … */` used to swallow the whole file) and at-rule bodies are
    brace-counted, so only what renders on screen gets in."""
    return _rules_from(_strip_comments(css_text or ""))


def _rules_from(css: str) -> list[Rule]:
    out: list[Rule] = []
    for prelude, body in _iter_blocks(css):
        head = " ".join(prelude.split())
        if head.startswith("@"):
            name = re.match(r"@([\w-]+)", head)
            name = name.group(1).lower() if name else ""
            if name not in AT_CONDITIONAL:
                continue
            if name == "media" and not _media_renders_on_screen(
                    head[len("@media"):]):
                continue
            out.extend(_rules_from(body))
            continue
        if not SIMPLE_SELECTOR_RE.fullmatch(head):
            continue
        facts = style_facts(body)
        if (facts["color"] or facts["background"] or facts["bg_image"]
                or facts["font_px"] is not None or facts["bold"] is not None
                or facts["hidden"]):
            out.append(Rule(head, facts["color"], facts["background"],
                            facts["bg_image"], facts["font_px"],
                            facts["bold"], facts["hidden"]))
    return out


class StyleIndex:
    """The rules bucketed by what they can match, so resolving one
    element is three dict lookups instead of a scan over every rule —
    and sorted by specificity, so `.ok{color:#000} p{color:#bbb}` gives
    the class, like the browser does."""

    def __init__(self, rules: list[Rule]):
        self.by_tag: dict[str, list] = {}
        self.by_class: dict[str, list] = {}
        self.by_id: dict[str, list] = {}
        self.count = len(rules)
        for order, rule in enumerate(rules):
            sel = rule.selector
            if sel.startswith("."):
                bucket, key, spec = self.by_class, sel[1:], 1
            elif sel.startswith("#"):
                bucket, key, spec = self.by_id, sel[1:], 2
            else:
                bucket, key, spec = self.by_tag, sel.lower(), 0
            bucket.setdefault(key, []).append((spec, order, rule))

    def matching(self, el) -> list[tuple[int, int, Rule]]:
        tag = el.tag if isinstance(el.tag, str) else ""
        out = list(self.by_tag.get(tag, ()))
        el_id = el.get("id")
        if el_id:
            out.extend(self.by_id.get(el_id, ()))
        classes = el.get("class")
        if classes:
            for cls in classes.split():
                out.extend(self.by_class.get(cls, ()))
        out.sort(key=lambda item: (item[0], item[1]))
        return out


@dataclass
class Declared:
    """What one element declares for itself — cascade resolved, inline
    style last (it outranks every simple selector)."""
    color: str = ""
    background: str = ""
    bg_image: bool = False
    font_px: float | None = None
    bold: bool | None = None
    hidden: bool = False


def declared_style(el, css: StyleIndex, cache: dict) -> Declared:
    hit = cache.get(el)
    if hit is not None:
        return hit
    d = Declared()
    for _spec, _order, rule in css.matching(el):
        if rule.color:
            d.color = rule.color
        if rule.bg_image:
            d.bg_image, d.background = True, ""
        elif rule.background:
            d.background, d.bg_image = rule.background, False
        if rule.font_px is not None:
            d.font_px = rule.font_px
        if rule.bold is not None:
            d.bold = rule.bold
        if rule.hidden:
            d.hidden = True
    inline = el.get("style")
    if inline:
        facts = style_facts(inline)
        if facts["color"]:
            d.color = facts["color"]
        if facts["bg_image"]:
            d.bg_image, d.background = True, ""
        elif facts["background"]:
            d.background, d.bg_image = facts["background"], False
        if facts["font_px"] is not None:
            d.font_px = facts["font_px"]
        if facts["bold"] is not None:
            d.bold = facts["bold"]
        if facts["hidden"]:
            d.hidden = True
    if el.get("hidden") is not None:
        d.hidden = True
    cache[el] = d
    return d


# The UA stylesheet: headings carry their own size and weight, which is
# why an <h1> earns the 3:1 large-text bar with no CSS of its own.
HEADING_PX = {"h1": 32.0, "h2": 24.0, "h3": 18.72, "h4": 16.0,
              "h5": 13.28, "h6": 10.72}
BOLD_TAGS = set(HEADING_PX) | {"b", "strong", "th"}
LARGE_PX = 24.0
LARGE_BOLD_PX = 18.66


@dataclass
class TextStyle:
    color: str = ""
    background: str = ""
    background_assumed: bool = False   # the white-canvas fallback
    background_unknown: bool = False   # an image/gradient is in play
    font_px: float | None = None
    bold: bool | None = None
    hidden: bool = False

    @property
    def large(self) -> bool | None:
        if self.font_px is None:
            return None
        return (self.font_px >= LARGE_PX
                or (bool(self.bold) and self.font_px >= LARGE_BOLD_PX))


def resolve_text_style(el, css: StyleIndex, cache: dict) -> TextStyle:
    """The color, background and font an element actually renders with,
    as far as static CSS can honestly say.

    `color` and `font-size` inherit — that is the cascade, a
    deterministic mechanism, not a guess — so the chain is walked
    upward until something is declared. The background stops at the
    first ancestor that declares one; if that declaration is an image
    or a gradient the background is *unknown* (never white), and if
    nobody declares one it is the browser's white canvas, flagged as
    the assumption it is.
    """
    st = TextStyle()
    tag = el.tag if isinstance(el.tag, str) else ""
    bg_resolved = False
    node, own = el, True
    while node is not None and isinstance(node.tag, str):
        d = declared_style(node, css, cache)
        if d.hidden:
            st.hidden = True
        if not st.color and d.color:
            st.color = d.color
        if not bg_resolved:
            if d.bg_image:
                st.background_unknown = bg_resolved = True
            elif d.background:
                st.background, bg_resolved = d.background, True
        if st.font_px is None:
            st.font_px = d.font_px
        if st.bold is None:
            st.bold = d.bold
        if own:
            if st.font_px is None and tag in HEADING_PX:
                st.font_px = HEADING_PX[tag]
            if st.bold is None and tag in BOLD_TAGS:
                st.bold = True
            own = False
        node = node.getparent()
    if not bg_resolved:
        st.background, st.background_assumed = WHITE_CANVAS, True
    return st


# ── the audits ───────────────────────────────────────────────────────────

SKIP_TEXT_TAGS = {"script", "style", "head", "meta", "link", "title",
                  "noscript", "template", "base", "svg", "path"}


def _own_text(el) -> str:
    """The text this element renders itself: its own leading text plus
    the tails of its children (`<p><span>x</span> and y</p>` — the
    " and y" belongs to the p, and used to be checked nowhere)."""
    parts = [el.text or ""]
    parts.extend(child.tail or "" for child in el)
    return " ".join("".join(parts).split())


def audit_contrast(doc, css: StyleIndex) -> list[Finding]:
    findings: list[Finding] = []
    cache: dict = {}
    checked = 0
    for el in doc.iter():
        if not isinstance(el.tag, str) or el.tag in SKIP_TEXT_TAGS:
            continue
        if not _own_text(el):
            continue
        st = resolve_text_style(el, css, cache)
        if st.hidden or not st.color or not st.background:
            continue
        checked += 1
        ratio = wcag_contrast(st.color, st.background)
        large = st.large
        threshold = 3.0 if large else 4.5
        if ratio >= threshold:
            continue
        kind = ("large text" if large else
                "text (size unknown — 4.5 assumed)" if large is None
                else "text")
        canvas = " (assumed page canvas)" if st.background_assumed else ""
        findings.append(Finding(
            "error", "contrast",
            f"{ratio:.2f}:1 {st.color} on {st.background}{canvas} — "
            f"needs {threshold}:1 for {kind}",
            where=_el_label(el),
            fix="darken the text or lighten the background until the "
                "pair reaches the ratio — Contrast Matrix gives the "
                "nearest passing shade for exactly this pair"))
    if not checked:
        findings.append(Finding(
            "info", "contrast",
            "no statically-pairable color/background pairs on this "
            "page — contrast not checked (JS-computed styles, compound "
            "selectors and background images are beyond the static "
            "scope; a contrast spot-check in DevTools covers them)"))
    else:
        findings.append(Finding(
            "info", "contrast",
            f"{checked} text element(s) had a color/background pair "
            "static CSS could pin down; everything else on the page is "
            "not checked, which is not the same as passed"))
    return findings


def _ids(doc) -> Counter:
    return Counter(el.get("id").strip() for el in doc.iter()
                   if isinstance(el.tag, str) and (el.get("id") or "").strip())


def _points_at_existing(value: str | None, ids: Counter) -> bool:
    return bool(value) and any(token in ids for token in value.split())


def audit_forms(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    ids = _ids(doc)
    labels_for: dict[str, int] = {}
    for el in doc.iter("label"):
        target = (el.get("for") or "").strip()
        if not target:
            continue
        labels_for[target] = labels_for.get(target, 0) + 1
        if target not in ids:
            findings.append(Finding(
                "warning", "forms",
                f"<label for={target!r}> points at an id that is not on "
                "the page — the label labels nothing",
                where=_el_label(el),
                fix="match the for= to the control's id"))
    for el in doc.iter("input", "select", "textarea"):
        itype = (el.get("type") or "text").lower()
        if itype in ("hidden", "submit", "reset", "button", "image"):
            continue
        el_id = (el.get("id") or "").strip()
        labelled = (
            (el_id and el_id in labels_for)
            or (el.get("aria-label") or "").strip()
            or _points_at_existing(el.get("aria-labelledby"), ids)
            or any(a.tag == "label" for a in el.iterancestors("label")))
        if labelled:
            continue
        if (el.get("title") or "").strip():
            findings.append(Finding(
                "warning", "forms",
                "control labelled only by title — a tooltip is not "
                "reliably announced, and never on touch",
                where=_el_label(el),
                fix="add a <label for=…> or an aria-label"))
        elif el.get("placeholder"):
            findings.append(Finding(
                "warning", "forms",
                "control has only a placeholder — it disappears on "
                "input and is not a label",
                where=_el_label(el),
                fix="add a <label for=…>, aria-label or title"))
        else:
            findings.append(Finding(
                "error", "forms",
                f"{el.tag} has no label at all",
                where=_el_label(el),
                fix="give it an id and a <label for=…>, or an "
                    "aria-label"))
    for fieldset in doc.iter("fieldset"):
        if not any(child.tag == "legend" for child in fieldset
                   if isinstance(child.tag, str)):
            findings.append(Finding(
                "warning", "forms",
                "<fieldset> without a <legend> — the group has no name, "
                "so its controls are announced without their context",
                where=_el_label(fieldset),
                fix="add a <legend> as the fieldset's first child"))
    return findings


def audit_headings(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    levels = [(int(h.tag[1]), h) for h in doc.iter(*[f"h{i}"
                                                     for i in range(1, 7)])]
    if not levels:
        findings.append(Finding("warning", "headings",
                                "no headings on the page",
                                fix="structure the content with h1…h6"))
        return findings
    if levels[0][0] != 1:
        findings.append(Finding(
            "info", "headings",
            f"the first heading is h{levels[0][0]}, not h1"))
    h1s = [h for lv, h in levels if lv == 1]
    if len(h1s) > 1:
        findings.append(Finding("info", "headings",
                                f"{len(h1s)} h1 elements — one per page "
                                "is the clean shape"))
    for (prev, _el), (nxt, el) in zip(levels, levels[1:]):
        if nxt > prev + 1:
            findings.append(Finding(
                "warning", "headings",
                f"level skip: h{prev} → h{nxt}",
                where=_el_label(el),
                fix="don't skip levels — the outline is the "
                    "screen-reader navigation"))
    return findings


MAX_INSERT_LANGUAGES = 8


def _primary_subtag(lang: str) -> str:
    return (lang or "").strip().split("-")[0].lower()


def audit_lang(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    html_el = doc if doc.tag == "html" else doc.find("html")
    lang = (html_el.get("lang") if html_el is not None else "") or ""
    if not lang:
        findings.append(Finding(
            "error", "lang", "<html> has no lang attribute",
            fix="lang tells screen readers which pronunciation engine "
                "to load (WCAG 3.1.1, level A)"))
    elif not re.match(r"^[a-z]{2,3}(-[A-Za-z0-9]+)*$", lang, re.I):
        findings.append(Finding("warning", "lang",
                                f"lang={lang!r} is not a valid BCP-47 "
                                "code"))
    if not lang:
        return findings
    page = _primary_subtag(lang)
    inserts: list[tuple[str, str]] = []
    for el in doc.iter():
        if not isinstance(el.tag, str) or el.tag == "html":
            continue
        el_lang = (el.get("lang") or "").strip()
        # `en-US` inside `en`, or `EN` inside `en`, is the same
        # language — only a different primary subtag is an insert
        if el_lang and _primary_subtag(el_lang) != page:
            inserts.append((el_lang, _el_label(el)))
    codes = sorted({code for code, _where in inserts})
    if len(codes) > MAX_INSERT_LANGUAGES:
        # an interlanguage link list looks exactly like this — forty
        # correct rows are noise, one row with the codes is a report
        shown = ", ".join(codes[:MAX_INSERT_LANGUAGES])
        findings.append(Finding(
            "info", "lang",
            f"{len(inserts)} foreign-language inserts in "
            f"{len(codes)} languages ({shown}, +"
            f"{len(codes) - MAX_INSERT_LANGUAGES} more) inside a "
            f"lang={lang!r} page — fine if intentional (a language "
            "switcher marked up properly looks like this)"))
        return findings
    for el_lang, where in inserts:
        findings.append(Finding(
            "info", "lang",
            f"foreign-language insert lang={el_lang!r} inside "
            f"a lang={lang!r} page (fine if intentional)",
            where=where))
    return findings


ROLE_REQUIRED_STATE = {
    "checkbox": "aria-checked", "switch": "aria-checked",
    "radio": "aria-checked",
    "slider": "aria-valuenow", "progressbar": "aria-valuenow",
    "spinbutton": "aria-valuenow", "scrollbar": "aria-valuenow",
}
NATIVELY_FOCUSABLE = {"button", "select", "textarea", "input", "summary"}


def is_focusable(el) -> bool:
    """Keyboard-reachable, the way the browser decides it.

    `tabindex="-1"` *removes* an element from the tab sequence, so
    `aria-hidden="true" tabindex="-1"` is the correct way to hide a
    decorative control — not a finding. Hidden inputs and disabled
    controls are not focusable either.
    """
    tag = el.tag if isinstance(el.tag, str) else ""
    tabindex = (el.get("tabindex") or "").strip()
    if tabindex:
        try:
            return int(tabindex) >= 0
        except ValueError:
            return False
    if el.get("disabled") is not None:
        return False
    if tag in ("a", "area"):
        return bool(el.get("href"))
    if tag == "input":
        return (el.get("type") or "text").lower() != "hidden"
    if tag in NATIVELY_FOCUSABLE:
        return True
    if (el.get("contenteditable") or "").lower() in ("", "true") \
            and el.get("contenteditable") is not None:
        return True
    return False


def audit_aria(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    ids = _ids(doc)
    for el in doc.iter():
        if not isinstance(el.tag, str):
            continue
        role = (el.get("role") or "").strip().lower()
        if role in ROLE_REQUIRED_STATE \
                and not el.get(ROLE_REQUIRED_STATE[role]):
            findings.append(Finding(
                "error", "aria",
                f"role={role!r} without {ROLE_REQUIRED_STATE[role]} — "
                "the state is the whole point of the role",
                where=_el_label(el)))
        for attr, severity in (("aria-labelledby", "error"),
                               ("aria-describedby", "warning")):
            value = (el.get(attr) or "").strip()
            if value and not _points_at_existing(value, ids):
                findings.append(Finding(
                    severity, "aria",
                    f"{attr}={value!r} points at an id that is not on "
                    "the page — the reference resolves to nothing",
                    where=_el_label(el),
                    fix=f"point {attr} at an element that exists, or "
                        "drop it"))
        if not is_focusable(el):
            continue
        if el.get("aria-hidden") == "true":
            findings.append(Finding(
                "error", "aria",
                "focusable element hidden from assistive tech — "
                "keyboard users can still tab into the void",
                where=_el_label(el),
                fix="remove aria-hidden, or take the element out of "
                    "the tab order with tabindex=\"-1\""))
        elif role in ("presentation", "none"):
            # ARIA's presentational-roles conflict resolution: on a
            # focusable element the role is *ignored*, so this is a
            # role that does nothing — not an element in the void
            findings.append(Finding(
                "warning", "aria",
                f"role={role!r} on a focusable element is ignored — "
                "ARIA drops presentational roles that would strip a "
                "focusable element, so it is still announced with its "
                "native role",
                where=_el_label(el),
                fix="drop the role, or make the element non-focusable "
                    "(a <div> instead of a <button>)"))
    return findings


def audit_focus(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    for el in doc.iter():
        if not isinstance(el.tag, str):
            continue
        tabindex = el.get("tabindex")
        if tabindex and tabindex.lstrip("-").isdigit() \
                and int(tabindex) > 0:
            findings.append(Finding(
                "warning", "focus",
                f"tabindex={tabindex} — positive values reorder the "
                "tab sequence away from the DOM order and trap users",
                where=_el_label(el),
                fix="tabindex=\"0\" to make it focusable in DOM order"))
    return findings


GENERIC_LINK_TEXT = {"click here", "here", "read more", "more", "this",
                     "link", "details", "learn more"}


def has_accessible_name(el, ids: Counter) -> bool:
    """The way a browser names a link: its text (an `<svg><title>`
    included), or an alt/aria-label/title on the element **or on any
    descendant** — `<a><svg aria-label="Fin logo"></svg></a>` is a
    named link, not an empty one — or an aria-labelledby that
    resolves."""
    if " ".join(el.text_content().split()):
        return True
    if _points_at_existing(el.get("aria-labelledby"), ids):
        return True
    for node in el.iter():
        if not isinstance(node.tag, str):
            continue
        for attr in ("aria-label", "title", "alt"):
            if (node.get(attr) or "").strip():
                return True
    return False


def audit_links(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    ids = _ids(doc)
    for el in doc.iter("a"):
        if not el.get("href"):
            continue
        text = " ".join(el.text_content().split()).lower()
        if not has_accessible_name(el, ids):
            findings.append(Finding(
                "error", "links",
                "empty link — no text, no image alt, no label anywhere "
                "inside it",
                where=_el_label(el),
                fix="give the link text, or an aria-label on the link "
                    "or on the icon inside it"))
        elif text in GENERIC_LINK_TEXT:
            findings.append(Finding(
                "warning", "links",
                f"generic link text “{text}” — out of context, in a "
                "link list, it tells a screen-reader user nothing",
                where=_el_label(el),
                fix="link text should name the destination"))
    return findings


def audit_tables(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    for table in doc.iter("table"):
        rows = list(table.iter("tr"))
        if len(rows) < 2:
            continue  # layout tables / single-row oddities
        ths = list(table.iter("th"))
        if not ths:
            findings.append(Finding(
                "warning", "tables",
                "data table without header cells",
                where=_el_label(table),
                fix="mark the header row/column with <th> so the "
                    "relationships are announced"))
        else:
            bare = [th for th in ths if not th.get("scope")
                    and not th.get("headers") and not th.get("id")]
            if bare:
                findings.append(Finding(
                    "info", "tables",
                    f"{len(bare)} <th> without scope — in tables "
                    "beyond 2×2, scope=col/row removes the ambiguity",
                    where=_el_label(table)))
    return findings


def audit_media(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    for el in doc.iter("iframe"):
        if el.get("aria-hidden") == "true":
            continue
        if not (el.get("title") or "").strip() \
                and not (el.get("aria-label") or "").strip():
            findings.append(Finding(
                "warning", "media",
                "<iframe> without a title — screen readers announce it "
                "as an unnamed frame",
                where=_el_label(el),
                fix='title="…" naming what the frame contains'))
    for el in doc.iter("video"):
        if el.get("autoplay") is not None and el.get("muted") is None:
            findings.append(Finding(
                "warning", "media",
                "<video autoplay> with sound — audio that starts by "
                "itself covers a screen reader (WCAG 1.4.2)",
                where=_el_label(el),
                fix="add muted, or let the user press play"))
        if not any(child.tag == "track" for child in el
                   if isinstance(child.tag, str)):
            findings.append(Finding(
                "warning", "media",
                "<video> without a <track> — no captions for anyone "
                "who cannot hear it (WCAG 1.2.2)",
                where=_el_label(el),
                fix='add <track kind="captions" src="…">'))
    for el in doc.iter("audio"):
        if el.get("autoplay") is not None:
            findings.append(Finding(
                "warning", "media",
                "<audio autoplay> — sound that starts by itself talks "
                "over the screen reader (WCAG 1.4.2)",
                where=_el_label(el),
                fix="let the user press play"))
    return findings


def audit_meta(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    for el in doc.iter("meta"):
        name = (el.get("name") or "").strip().lower()
        equiv = (el.get("http-equiv") or "").strip().lower()
        content = (el.get("content") or "").strip()
        if name == "viewport":
            condensed = content.lower().replace(" ", "")
            blocked = ("user-scalable=no" in condensed
                       or "user-scalable=0" in condensed)
            m = re.search(r"maximum-scale=([\d.]+)", condensed)
            if m:
                try:
                    blocked = blocked or float(m.group(1)) < 2
                except ValueError:
                    pass
            if blocked:
                findings.append(Finding(
                    "warning", "meta",
                    "the viewport blocks zoom (user-scalable=no / "
                    "maximum-scale below 2) — WCAG 1.4.4 wants 200%",
                    where=f"meta viewport: {content}",
                    fix="drop user-scalable and maximum-scale; modern "
                        "layouts do not need them"))
        elif equiv == "refresh":
            seconds = content.split(";", 1)[0].strip()
            try:
                delay = float(seconds)
            except ValueError:
                continue
            if delay > 0:
                findings.append(Finding(
                    "error", "meta",
                    f"<meta http-equiv=\"refresh\"> after {seconds}s — "
                    "a timed refresh moves the page out from under "
                    "anyone reading slowly (WCAG 2.2.1)",
                    fix="drop it, or let the user extend/turn off the "
                        "timer"))
            else:
                findings.append(Finding(
                    "info", "meta",
                    "instant <meta http-equiv=\"refresh\"> redirect — "
                    "a 301 on the server is the accessible way",
                    fix="redirect with an HTTP status instead"))
    return findings


def audit_ids(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    duplicates = [(value, n) for value, n in _ids(doc).items() if n > 1]
    duplicates.sort(key=lambda item: (-item[1], item[0]))
    for value, n in duplicates[:10]:
        findings.append(Finding(
            "warning", "ids",
            f"id={value!r} is used {n} times — every for= and "
            "aria-labelledby pointing at it resolves to the first one "
            "only (WCAG 4.1.1)",
            fix="ids are unique; generate a suffix per instance"))
    if len(duplicates) > 10:
        findings.append(Finding(
            "warning", "ids",
            f"{len(duplicates) - 10} more duplicated id(s) on the page"))
    return findings


LANDMARK_ROLES = {"main": "main", "nav": "navigation", "header": "banner"}


def audit_landmarks(doc, css) -> list[Finding]:
    findings: list[Finding] = []
    body = doc.find("body")
    roles = {(el.get("role") or "").strip().lower() for el in doc.iter()
             if isinstance(el.tag, str) and el.get("role")}
    for tag, why in (("main", "the one place screen-reader users jump "
                              "to for content"),
                     ("nav", "the skip target for the menu"),
                     ("header", "the banner landmark")):
        # role="main" is the same landmark as <main> — an ARIA-first
        # page is not a page without landmarks
        if list(doc.iter(tag)) or LANDMARK_ROLES[tag] in roles:
            continue
        findings.append(Finding(
            "info", "landmarks",
            f"no <{tag}> landmark and no role={LANDMARK_ROLES[tag]!r} — "
            f"{why}"))
    first_link = None
    if body is not None:
        for el in body.iter("a"):
            first_link = el
            break
    if first_link is not None \
            and (first_link.get("href") or "").startswith("#"):
        findings.append(Finding(
            "info", "landmarks",
            "skip link present — the keyboard path starts at the "
            "content, good"))
    else:
        findings.append(Finding(
            "info", "landmarks",
            "no skip link before the navigation — keyboard users tab "
            "through the whole menu on every page"))
    return findings


AUDITS = (audit_contrast, audit_forms, audit_headings, audit_lang,
          audit_aria, audit_focus, audit_links, audit_tables,
          audit_media, audit_meta, audit_ids, audit_landmarks)


def run_audits(doc, rules: list[Rule]) -> list[Finding]:
    css = StyleIndex(rules)
    findings: list[Finding] = []
    for audit in AUDITS:
        findings.extend(audit(doc, css))
    findings.sort(key=lambda f: (ORDER[f.severity], f.check))
    return group_findings(findings)


# ── report ───────────────────────────────────────────────────────────────

TABLE_ROWS = 60


def build_table_event(findings: list[Finding]) -> dict:
    # rows are arrays of cell values (authoring-guide contract) — the
    # UI renders each row with .map(); dicts crash it.
    rows = [[ICON[f.severity] + " " + f.severity,
             f.check, _message_cell(f), _where_cell(f)]
            for f in findings[:TABLE_ROWS]]
    if len(findings) > TABLE_ROWS:
        rows.append(["", "",
                     f"… and {len(findings) - TABLE_ROWS} more finding(s) "
                     "— the full list is in report.md", ""])
    return {"type": "table",
            "columns": ["severity", "check", "finding", "where"],
            "rows": rows}


def build_markdown(url: str, findings: list[Finding],
                   images_without_alt: int | None,
                   http_status: int | None = None,
                   final_url: str | None = None) -> str:
    errors = sum(f.count for f in findings if f.severity == "error")
    warnings = sum(f.count for f in findings if f.severity == "warning")
    infos = sum(f.count for f in findings if f.severity == "info")
    verdict = "🔴 errors" if errors else ("🟠 warnings" if warnings
                                          else "🟢 clean")
    out = ["# A11y Check — Report\n",
           f"URL: `{url}` · {errors + warnings + infos} finding(s): "
           f"**{errors} errors, {warnings} warnings, {infos} notes** · "
           f"verdict: **{verdict}**\n"]
    if final_url and final_url != url:
        out.append(f"Final URL after redirects: `{final_url}`\n")
    if http_status is not None and http_status >= 400:
        out.append(f"The page answered **HTTP {http_status}** — this is "
                   "an error page, audited as it was served.\n")
    out.append("Static pass: one fetch, the HTML and the CSS that can be "
               "read without running the page. What static analysis "
               "cannot see is reported as not checked — never as "
               "passed.\n")
    current = None
    for f in findings:
        if f.check != current:
            out.append(f"\n## {f.check}\n")
            current = f.check
        where = _where_cell(f)
        out.append(f"- {ICON[f.severity]} {_message_cell(f)}"
                   + (f" — `{where}`" if where else ""))
        if f.fix:
            out.append(f"  - fix: {f.fix}")
    if images_without_alt is not None:
        out.append("\n## images\n")
        out.append(f"- {images_without_alt} image(s) without alt — the "
                   "alt audit lives in **Page SEO Audit** (it is an "
                   "SEO signal as much as an accessibility one); run "
                   "it on the same URL.")
    out.append("\n## Where this fits\n")
    out.append("- **Contrast Matrix** — the same WCAG math on a whole "
               "palette before the page exists, plus APCA (Lc) as the "
               "second opinion and the nearest passing shade for every "
               "pair this report flagged.")
    out.append("- **Page SEO Audit** — the same one-fetch pass for "
               "title/meta/headings/alt as search-visibility signals.")
    out.append("- **Color Palette** — the color engine this script's "
               "contrast math grew out of; useful when picking an "
               "accessible palette.")
    out.append("- **Site Crawler → SEO Checks** — the whole-site pass; "
               "this script is the deep single-page one.")
    return "\n".join(out)


def write_artifacts(url: str, findings: list[Finding], report: str,
                    images_without_alt: int | None) -> str:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {"url": url,
               "findings": [f.as_dict() for f in findings],
               "images_without_alt": images_without_alt}
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)
    return os.path.abspath(out_dir)


# ── main ─────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A11y Check — the static accessibility pass: "
                    "contrast, forms, headings, ARIA, focus, links")
    parser.add_argument("--url", required=True,
                        help="the page to check")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds (default 15)")
    parser.add_argument("--max-stylesheets", type=int, default=3,
                        help="stylesheets fetched for the contrast pass")
    return parser


def collect_rules(doc, base_url: str, max_stylesheets: int,
                  timeout: int) -> tuple[list[Rule], int]:
    rules: list[Rule] = []
    for style in doc.iter("style"):
        if not _media_renders_on_screen(style.get("media") or ""):
            continue
        rules.extend(css_color_rules(style.text or ""))
    fetched = 0
    for href in stylesheet_urls(doc, base_url)[:max(max_stylesheets, 0)]:
        try:
            resp = fetch(href, timeout)
        except requests.RequestException:
            continue
        if _resp_status(resp) >= 400:
            continue
        ctype = _resp_content_type(resp)
        if ctype and "css" not in ctype and ctype not in ("text/plain", ""):
            continue          # a 404 page dressed as a stylesheet
        rules.extend(css_color_rules(resp.text or ""))
        fetched += 1
    return rules, fetched


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no pages are fetched", flush=True)
        return 0

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        print("✗ the URL must start with http:// or https://",
              file=sys.stderr, flush=True)
        return 2

    log(f"Checking the accessibility of {url}")
    status("fetching the page")
    try:
        resp = fetch(url, args.timeout)
    except requests.RequestException as exc:
        print(f"✗ cannot reach {url}: {exc}", file=sys.stderr,
              flush=True)
        return 1

    http_status = _resp_status(resp)
    content_type = _resp_content_type(resp)
    final_url = getattr(resp, "url", url) or url
    if content_type and content_type not in HTML_CONTENT_TYPES:
        print(f"✗ {url} answered with {content_type}, not HTML — there "
              "is no page to audit here", file=sys.stderr, flush=True)
        return 1
    body = getattr(resp, "content", b"") or b""
    if not body.strip():
        print(f"✗ {url} answered HTTP {http_status} with an empty body "
              "— there is nothing to audit", file=sys.stderr, flush=True)
        return 1
    if http_status >= 400:
        # a 404 page is still a page people land on — audit it, and say so
        log(f"! HTTP {http_status} — auditing the error page as served")
    emit({"type": "progress", "pct": 30, "message": "parsing"})

    try:
        doc = lxml.html.document_fromstring(body)
    except (etree.LxmlError, ValueError) as exc:
        print(f"✗ {url} answered HTTP {http_status}, but the body is not "
              f"parseable HTML: {exc}", file=sys.stderr, flush=True)
        return 1

    base_url = effective_base(doc, final_url)
    status("reading the CSS")
    rules, fetched_css = collect_rules(doc, base_url,
                                       args.max_stylesheets, args.timeout)
    emit({"type": "progress", "pct": 60,
          "message": f"{len(rules)} contrast rule(s), "
                     f"{fetched_css} stylesheet(s) fetched"})

    findings = run_audits(doc, rules)
    images_without_alt = sum(
        1 for img in doc.iter("img") if not (img.get("alt") or "").strip())

    report = build_markdown(url, findings, images_without_alt,
                            http_status, final_url)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(findings))
    emit({"type": "markdown", "content": report})
    out_dir = write_artifacts(url, findings, report, images_without_alt)

    errors = sum(f.count for f in findings if f.severity == "error")
    warnings = sum(f.count for f in findings if f.severity == "warning")
    total = sum(f.count for f in findings)
    summary = f"{total} finding(s) · {errors} errors · {warnings} warnings"
    status(summary)
    log(f"← {summary}")
    log(f"→ report.md, findings.json in {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
