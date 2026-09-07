"""src/colors.py — parse, convert, measure, group. Pure; ported from
the standalone colorPallet tool. Tests live here.

The CSS named-color table, every CSS color syntax (`#rgb`, `#rrggbb`,
`#rrggbbaa`, `rgb()/rgba()` with numbers or percentages, `hsl()/hsla()`,
named), the HSL perceptual distance, and the grouping that folds
near-identical colors (every `#333`-vs-`#333333`-vs-`rgb(51,51,51)`)
into one group with a representative.
"""
from __future__ import annotations

import colorsys
import math
import re

# ─── CSS named colors (the spec set; gray/grey aliases included) ─────────

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

# ─── conversions ───────────────────────────────────────────────────────


def rgb_to_hex(r, g, b) -> str:
    return f"#{int(r):02X}{int(g):02X}{int(b):02X}"


def hsl_to_hex(h: float, s: float, l: float) -> str:
    r, g, b = colorsys.hls_to_rgb((h % 360) / 360, l / 100, s / 100)
    return rgb_to_hex(round(r * 255), round(g * 255), round(b * 255))


def hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip('#')
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]


def rgb_to_hsl(r: float, g: float, b: float) -> tuple[float, float, float]:
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    return h * 360, s * 100, l * 100


def luminance(hex_color: str) -> float:
    """0..1 perceived brightness (Rec. 601 luma) — powers the dark/light
    label in the report."""
    r, g, b = (x / 255 for x in hex_to_rgb(hex_color))
    return 0.299 * r + 0.587 * g + 0.114 * b


# ─── parsing any CSS color value ───────────────────────────────────────


def parse_color(value: str) -> str | None:
    """Any CSS color value → normalized #RRGGBB (alpha dropped — the
    palette wants the color, not the transparency), or None.

    Legacy comma syntax and the modern space syntax both parse
    (`rgb(0 0 0 / 50%)`, `hsl(210 100% 50%)` — what Tailwind and every
    current framework emit), plus `#RGB`/`#RGBA`/`#RRGGBB`/`#RRGGBBAA`
    and `oklch()`/`oklab()`. `var()` and `color-mix()` stay None on
    purpose: resolving them needs the whole cascade, and a guess is
    worse than an honest gap. Kept in sync with a11y-check/main.py.
    """
    value = (value or '').strip().lower()
    if not value:
        return None
    if value in CSS_NAMED_COLORS:
        return CSS_NAMED_COLORS[value]
    if value.startswith('#'):
        return _parse_hex(value)
    m = re.fullmatch(r'(rgba?|hsla?|oklch|oklab)\(\s*(.*?)\s*\)', value,
                     re.S)
    if not m:
        return None
    func, parts = m.group(1), [p for p in re.split(r'[\s,/]+', m.group(2))
                               if p]
    if len(parts) < 3:
        return None
    if func.startswith('rgb'):
        channels = [_css_channel(p) for p in parts[:3]]
        if any(c is None for c in channels):
            return None
        return rgb_to_hex(*channels)
    if func.startswith('hsl'):
        h, s, l = (_css_hue(parts[0]), _css_percent(parts[1]),
                   _css_percent(parts[2]))
        if h is None or s is None or l is None:
            return None
        return hsl_to_hex(h, s, l)
    if func == 'oklch':
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
    if not re.fullmatch(r'[0-9a-f]+', digits):
        return None
    if len(digits) in (3, 4):            # #RGB, #RGBA
        return '#' + ''.join(c * 2 for c in digits[:3]).upper()
    if len(digits) in (6, 8):            # #RRGGBB, #RRGGBBAA
        return '#' + digits[:6].upper()
    return None


def _css_channel(token: str) -> int | None:
    """One rgb() channel: 0–255, or a percentage of 255."""
    try:
        raw = (float(token[:-1]) * 2.55 if token.endswith('%')
               else float(token))
    except ValueError:
        return None
    return max(0, min(255, round(raw)))


def _css_percent(token: str) -> float | None:
    try:
        return float(token[:-1] if token.endswith('%') else token)
    except ValueError:
        return None


def _css_scaled(token: str, full: float) -> float | None:
    """A number, or a percentage of `full` (oklch lightness/chroma)."""
    try:
        return (float(token[:-1]) / 100 * full if token.endswith('%')
                else float(token))
    except ValueError:
        return None


def _css_hue(token: str) -> float | None:
    m = re.fullmatch(r'([-+]?[\d.]+)(deg|grad|rad|turn)?', token)
    if not m:
        return None
    try:
        value = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2) or 'deg'
    if unit == 'grad':
        return value * 0.9
    if unit == 'rad':
        return math.degrees(value)
    if unit == 'turn':
        return value * 360
    return value


def _oklab_to_hex(lightness: float, a: float, b: float) -> str:
    """OKLab → sRGB (the spec's matrices), clipped into gamut."""
    l_ = lightness + 0.3963377774 * a + 0.2158037573 * b
    m_ = lightness - 0.1055613458 * a - 0.0638541728 * b
    s_ = lightness - 0.0894841775 * a - 1.2914855480 * b
    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3
    return rgb_to_hex(
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


# ─── distance + grouping ────────────────────────────────────────────────


def color_distance(hex1: str, hex2: str) -> float:
    """Perceptual distance in HSL space (0..1 per axis, hue wrapped)."""
    h1, s1, l1 = rgb_to_hsl(*hex_to_rgb(hex1))
    h2, s2, l2 = rgb_to_hsl(*hex_to_rgb(hex2))
    dh = min(abs(h1 - h2), 360 - abs(h1 - h2)) / 180
    ds = abs(s1 - s2) / 100
    dl = abs(l1 - l2) / 100
    return math.sqrt(dh ** 2 + ds ** 2 + dl ** 2)


def group_similar_colors(color_counts: dict[str, int],
                         threshold: float = 0.12) -> list[dict]:
    """Fold visually similar colors into groups (most-used first; the
    group's representative is its most-used member). Returns
    [{representative, count, variants: [{color, count}]}] sorted by
    count."""
    colors = sorted(color_counts.items(), key=lambda x: (-x[1], x[0]))
    groups: list[dict] = []
    for hex_color, count in colors:
        for g in groups:
            if color_distance(hex_color, g['representative']) < threshold:
                g['count'] += count
                g['variants'].append({'color': hex_color, 'count': count})
                break
        else:
            groups.append({'representative': hex_color, 'count': count,
                           'variants': [{'color': hex_color,
                                         'count': count}]})
    return sorted(groups, key=lambda g: -g['count'])
