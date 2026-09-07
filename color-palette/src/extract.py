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
# Longest first, so `aquamarine` wins the alternation over `aqua`.
_named_pattern = '|'.join(sorted(
    (re.escape(k) for k in CSS_NAMED_COLORS if k not in _SKIP_KEYWORDS),
    key=len, reverse=True))

# Candidates only — `parse_color` stays the single authority on what a
# match means, so every syntax it knows (space-separated `rgb(0 0 0 /
# 50%)`, `hsl(210 100% 50%)`, `oklch()`, `oklab()`) is found here
# without a second color table to keep in sync. The `[\w-]` guards
# keep a named color from being read out of an identifier:
# `var(--brand-red-500)` is a name, not the color red.
COLOR_REGEX = re.compile(
    r'(#[0-9a-fA-F]{3,8}'
    r'|(?<![\w-])(?:rgba?|hsla?|oklch|oklab)\([^()]*\)'
    r'|(?<![\w-])(?:' + _named_pattern + r')(?![\w-]))',
    re.IGNORECASE,
)

DECLARATION_REGEX = re.compile(r'([\w-]+)\s*:\s*([^;}{]+)', re.IGNORECASE)

COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)

# An at-rule *prelude* — everything from `@name` to the `{` or `;` that
# ends it. It reads like a declaration but paints nothing: Tailwind
# ships `@supports (color: color-mix(in lab, red, red))` as a browser
# probe, and taking that literally made pure red the most-used text
# color on a site that never uses red. The block a prelude introduces
# is kept, so `@media … { .a { color: #ABC } }` still contributes.
AT_RULE_PRELUDE_RE = re.compile(r'@[\w-]+[^{;]*', re.IGNORECASE)

# Text inside a value that *names* a color instead of being one: a
# custom-property reference (`var(--brand-red-500)`) or an asset path
# (`url(/img/tan-hero.png)`). Blanked before the scan so the promise
# `parse_color` makes about `var()`/`color-mix()` — an honest gap beats
# a guess — survives the regex layer too. A literal fallback keeps
# counting: `var(--brand, #FF0000)` still yields #FF0000.
NOISE_RE = re.compile(
    r'url\(\s*(?:"[^"]*"|\'[^\']*\'|[^()]*)\)|--[\w-]+', re.IGNORECASE)


def extract_colors_from_css(css_text: str) -> list[tuple[str, str]]:
    """(category, hex) for every color in a color-carrying declaration.
    Comments and at-rule preludes are stripped first (neither paints
    anything); non-color properties are skipped; keywords
    (transparent/inherit…) parse to None and drop out."""
    scannable = AT_RULE_PRELUDE_RE.sub(
        ' ', COMMENT_RE.sub(' ', css_text or ""))
    results: list[tuple[str, str]] = []
    for m in DECLARATION_REGEX.finditer(scannable):
        prop = m.group(1).strip().lower()
        category = COLOR_PROPERTY_CATEGORY.get(prop)
        if not category:
            continue
        for cm in COLOR_REGEX.finditer(NOISE_RE.sub(' ', m.group(2))):
            color = parse_color(cm.group(0))
            if color:
                results.append((category, color))
    return results


# ─── HTML shapes ──────────────────────────────────────────────────────────

STYLE_BLOCK_RE = re.compile(r'<style\b[^>]*>(.*?)</style>',
                            re.IGNORECASE | re.DOTALL)
STYLE_ATTR_RE = re.compile(r'\bstyle\s*=\s*(?:"([^"]*)"|\'([^\']*)\')',
                           re.IGNORECASE)
LINK_TAG_RE = re.compile(r'<link\b[^>]*>', re.IGNORECASE)
REL_RE = re.compile(r'\brel\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))',
                    re.IGNORECASE)
HREF_RE = re.compile(r'\bhref\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))',
                     re.IGNORECASE)


def _attr(match: re.Match | None) -> str:
    """The one populated alternative of a double/single/unquoted attr."""
    if not match:
        return ""
    return next((g for g in match.groups() if g is not None), "")


def find_style_blocks(html: str) -> list[str]:
    return [m.group(1) for m in STYLE_BLOCK_RE.finditer(html or "")]


def extract_inline_styles(html: str) -> list[str]:
    """The `style="…"` values, single quotes included."""
    return [value for m in STYLE_ATTR_RE.finditer(html or "")
            if (value := _attr(m))]


def find_stylesheet_links(html: str, base_url: str) -> list[str]:
    """Absolute URLs of <link rel=stylesheet> targets, order preserved,
    duplicates collapsed. `rel` is read as a token list, so
    `rel="preload stylesheet"` counts the same as `rel="stylesheet"`.
    Cross-origin links are kept — a site's CSS often lives on a CDN."""
    seen: set[str] = set()
    out: list[str] = []
    for tag in LINK_TAG_RE.finditer(html or ""):
        rel = _attr(REL_RE.search(tag.group(0))).lower().split()
        if 'stylesheet' not in rel:
            continue
        href = _attr(HREF_RE.search(tag.group(0)))
        if not href:
            continue
        absolute = urljoin(base_url, href)
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
