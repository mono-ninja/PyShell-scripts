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
    palette wants the color, not the transparency), or None."""
    value = (value or '').strip().lower()
    if not value:
        return None
    if value in CSS_NAMED_COLORS:
        return CSS_NAMED_COLORS[value]
    if re.match(r'^#[0-9a-f]{3}$', value):
        return '#' + ''.join(c * 2 for c in value[1:]).upper()
    if re.match(r'^#[0-9a-f]{6}$', value):
        return value.upper()
    if re.match(r'^#[0-9a-f]{8}$', value):
        return ('#' + value[1:7]).upper()
    m = re.match(r'^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)', value)
    if m:
        return rgb_to_hex(m.group(1), m.group(2), m.group(3))
    m = re.match(r'^rgba?\(\s*([\d.]+)%\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%',
                 value)
    if m:
        return rgb_to_hex(round(float(m.group(1)) * 2.55),
                          round(float(m.group(2)) * 2.55),
                          round(float(m.group(3)) * 2.55))
    m = re.match(r'^hsla?\(\s*([\d.]+)(?:deg|turn)?\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%',
                 value)
    if m:
        h = float(m.group(1)) * 360 if 'turn' in value else float(m.group(1))
        return hsl_to_hex(h, float(m.group(2)), float(m.group(3)))
    return None


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
