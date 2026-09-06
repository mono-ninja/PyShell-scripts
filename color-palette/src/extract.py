"""src/extract.py — pull CSS and colors out of HTML. Pure regex, no
parser dependency: the three shapes we need (`<style>` blocks,
`<link rel=stylesheet>`, `style="…"` attributes) are simple enough that
a parser would be dependency weight, not correctness.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from .colors import CSS_NAMED_COLORS, parse_color

# ─── the property → category map ─────────────────────────────────────────

COLOR_PROPERTY_CATEGORY = {
    'background': 'background',
    'background-color': 'background',
    'color': 'text',
    'border-color': 'border',
    'border-top-color': 'border',
    'border-right-color': 'border',
    'border-bottom-color': 'border',
    'border-left-color': 'border',
    'outline-color': 'border',
    'border': 'border',
    'outline': 'border',
    'box-shadow': 'shadow',
    'text-shadow': 'shadow',
    'fill': 'svg',
    'stroke': 'svg',
    'stop-color': 'svg',
}

CATEGORY_LABEL = {
    'background': 'Backgrounds',
    'text': 'Text & typography',
    'border': 'Borders & outlines',
    'shadow': 'Shadows',
    'svg': 'SVG & icons',
}

_SKIP_KEYWORDS = ('inherit', 'initial', 'transparent', 'currentcolor',
                  'unset', 'revert')
_named_pattern = '|'.join(re.escape(k) for k in CSS_NAMED_COLORS
                          if k not in _SKIP_KEYWORDS)

COLOR_REGEX = re.compile(
    r'(#[0-9a-fA-F]{8}|#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3}'
    r'|rgba?\(\s*[\d.]+%?\s*,\s*[\d.]+%?\s*,\s*[\d.]+%?'
    r'(?:\s*,\s*[\d.]+(?:%)?)?\s*\)'
    r'|hsla?\(\s*[\d.]+(?:deg|turn)?\s*,\s*[\d.]+%\s*,\s*[\d.]+%'
    r'(?:\s*,\s*[\d.]+)?\s*\)'
    r'|\b(?:' + _named_pattern + r')\b)',
    re.IGNORECASE,
)

DECLARATION_REGEX = re.compile(r'([\w-]+)\s*:\s*([^;}{]+)', re.IGNORECASE)


def extract_colors_from_css(css_text: str) -> list[tuple[str, str]]:
    """(category, hex) for every color in a color-carrying declaration.
    Non-color properties are skipped; keywords (transparent/inherit…)
    parse to None and drop out."""
    results: list[tuple[str, str]] = []
    for m in DECLARATION_REGEX.finditer(css_text or ""):
        prop = m.group(1).strip().lower()
        category = COLOR_PROPERTY_CATEGORY.get(prop)
        if not category:
            continue
        for cm in COLOR_REGEX.finditer(m.group(2)):
            color = parse_color(cm.group(0))
            if color:
                results.append((category, color))
    return results


# ─── HTML shapes ──────────────────────────────────────────────────────────

STYLE_BLOCK_RE = re.compile(r'<style\b[^>]*>(.*?)</style>',
                            re.IGNORECASE | re.DOTALL)
STYLE_ATTR_RE = re.compile(r'\bstyle\s*=\s*"([^"]*)"', re.IGNORECASE)
LINK_RE = re.compile(
    r'<link\b[^>]*?rel\s*=\s*["\']?stylesheet["\']?[^>]*?>|'
    r'<link\b[^>]*?href\s*=\s*["\'][^"\']+["\'][^>]*?rel\s*=\s*["\']?stylesheet["\']?[^>]*?>',
    re.IGNORECASE)
HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def find_style_blocks(html: str) -> list[str]:
    return [m.group(1) for m in STYLE_BLOCK_RE.finditer(html or "")]


def extract_inline_styles(html: str) -> list[str]:
    return [m.group(1) for m in STYLE_ATTR_RE.finditer(html or "")]


def find_stylesheet_links(html: str, base_url: str) -> list[str]:
    """Absolute URLs of <link rel=stylesheet> targets, order preserved,
    duplicates collapsed. Cross-origin links are kept — a site's CSS
    often lives on a CDN."""
    seen: set[str] = set()
    out: list[str] = []
    for link in LINK_RE.finditer(html or ""):
        if 'stylesheet' not in link.group(0).lower():
            continue
        href = HREF_RE.search(link.group(0))
        if not href:
            continue
        absolute = urljoin(base_url, href.group(1))
        try:
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        if absolute not in seen:
            seen.add(absolute)
            out.append(absolute)
    return out
