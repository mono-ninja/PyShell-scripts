"""src/extract.py — pull CSS and colors out of HTML. Pure regex, no
parser dependency: the shapes we need (`<style>` blocks, `<link
rel=stylesheet>`, `<base href>`, `style="…"` attributes) are simple
enough that a parser would be dependency weight, not correctness.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from .colors import CSS_NAMED_COLORS, parse_color

# ─── the property → category map ─────────────────────────────────────────

# Every property that can paint a color, shorthands included: the
# longhands alone missed `border-bottom: 1px solid #ddd` (one of the
# most common declarations there is) and `background-image:
# linear-gradient(…)`, which on getbootstrap.com was 48 of its 363
# colors. `filter`/`backdrop-filter` are here for `drop-shadow()`;
# nothing else in either takes a color.
COLOR_PROPERTY_CATEGORY = {
    # Backgrounds and fills
    'background': 'background',
    'background-color': 'background',
    'background-image': 'background',
    'accent-color': 'background',
    'scrollbar-color': 'background',
    # Text
    'color': 'text',
    'caret-color': 'text',
    'text-decoration': 'text',
    'text-decoration-color': 'text',
    'text-emphasis': 'text',
    'text-emphasis-color': 'text',
    '-webkit-text-fill-color': 'text',
    '-webkit-text-stroke': 'text',
    '-webkit-text-stroke-color': 'text',
    # Borders and outlines
    'border': 'border',
    'border-color': 'border',
    'border-top': 'border',
    'border-right': 'border',
    'border-bottom': 'border',
    'border-left': 'border',
    'border-top-color': 'border',
    'border-right-color': 'border',
    'border-bottom-color': 'border',
    'border-left-color': 'border',
    'border-block': 'border',
    'border-block-color': 'border',
    'border-block-start': 'border',
    'border-block-start-color': 'border',
    'border-block-end': 'border',
    'border-block-end-color': 'border',
    'border-inline': 'border',
    'border-inline-color': 'border',
    'border-inline-start': 'border',
    'border-inline-start-color': 'border',
    'border-inline-end': 'border',
    'border-inline-end-color': 'border',
    'outline': 'border',
    'outline-color': 'border',
    'column-rule': 'border',
    'column-rule-color': 'border',
    # Shadows
    'box-shadow': 'shadow',
    'text-shadow': 'shadow',
    'filter': 'shadow',
    'backdrop-filter': 'shadow',
    # SVG and icons
    'fill': 'svg',
    'stroke': 'svg',
    'stop-color': 'svg',
    'flood-color': 'svg',
    'lighting-color': 'svg',
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
# custom-property reference that stayed unresolved, or an asset path
# (`url(/img/tan-hero.png)`). Blanked before the scan so the promise
# `parse_color` makes about an unresolved `var()`/`color-mix()` — an
# honest gap beats a guess — survives the regex layer too. A literal
# fallback keeps counting: `var(--brand, #FF0000)` still yields
# #FF0000.
NOISE_RE = re.compile(
    r'url\(\s*(?:"[^"]*"|\'[^\']*\'|[^()]*)\)|--[\w-]+', re.IGNORECASE)

# A `var()` reference, fallback and all. Custom-property names are
# case-sensitive in CSS, so the captured name is never folded.
VAR_REF_RE = re.compile(r'var\(\s*(--[\w-]+)\s*(?:,[^()]*)?\)',
                        re.IGNORECASE)


def _scannable(css_text: str) -> str:
    """The CSS with everything that paints nothing blanked: comments,
    and at-rule preludes."""
    return AT_RULE_PRELUDE_RE.sub(' ', COMMENT_RE.sub(' ', css_text or ""))


# ─── custom properties ────────────────────────────────────────────────────


def collect_custom_properties(
        css_text: str,
        into: dict[str, set[str]] | None = None) -> dict[str, set[str]]:
    """`--name` → the distinct literal colors it is defined as, merged
    into `into` so every stylesheet of one page builds a single map."""
    defs = {} if into is None else into
    for m in DECLARATION_REGEX.finditer(_scannable(css_text)):
        name = m.group(1).strip()
        if not name.startswith('--'):
            continue
        for cm in COLOR_REGEX.finditer(NOISE_RE.sub(' ', m.group(2))):
            color = parse_color(cm.group(0))
            if color:
                defs.setdefault(name, set()).add(color)
    return defs


def resolve_custom_properties(defs: dict[str, set[str]]) -> dict[str, str]:
    """The tokens a `var()` may be read through: those the page defines
    with exactly one literal color. A token redefined per theme
    (`:root` light, `.dark` dark) is genuinely ambiguous without the
    cascade, so it stays unresolved — the same honest gap as before,
    now narrowed to the cases that are actually ambiguous."""
    return {name: next(iter(colors)) for name, colors in defs.items()
            if len(colors) == 1}


def _resolve_vars(value: str, tokens: dict[str, str]) -> str:
    """Every `var(--known)` swapped for its literal color, fallback
    included — so `var(--brand, #FF0000)` counts the resolved `--brand`
    once instead of both it and the fallback."""
    return VAR_REF_RE.sub(lambda m: tokens.get(m.group(1), m.group(0)),
                          value)


# ─── colors ───────────────────────────────────────────────────────────────


def extract_colors_from_css(css_text: str,
                            tokens: dict[str, str] | None = None
                            ) -> list[tuple[str, str]]:
    """(category, hex) for every color in a color-carrying declaration.
    Comments and at-rule preludes are stripped first (neither paints
    anything); non-color properties are skipped; keywords
    (transparent/inherit…) parse to None and drop out. Given `tokens`
    from `resolve_custom_properties`, a `var(--brand)` reference is
    read as the color the page defines `--brand` to be."""
    results: list[tuple[str, str]] = []
    for m in DECLARATION_REGEX.finditer(_scannable(css_text)):
        prop = m.group(1).strip().lower()
        category = COLOR_PROPERTY_CATEGORY.get(prop)
        if not category:
            continue
        value = _resolve_vars(m.group(2), tokens) if tokens else m.group(2)
        for cm in COLOR_REGEX.finditer(NOISE_RE.sub(' ', value)):
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
BASE_TAG_RE = re.compile(r'<base\b[^>]*>', re.IGNORECASE)
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


def find_base_href(html: str, base_url: str) -> str:
    """`<base href>` wins over the response URL — page-seo-audit's
    rule, and a11y-check's. Only the first one counts, per the spec."""
    for tag in BASE_TAG_RE.finditer(html or ""):
        href = _attr(HREF_RE.search(tag.group(0)))
        if href:
            return urljoin(base_url, href)
    return base_url


def find_stylesheet_links(html: str, base_url: str) -> list[str]:
    """Absolute URLs of <link rel=stylesheet> targets, order preserved,
    duplicates collapsed. `rel` is read as a token list, so
    `rel="preload stylesheet"` counts the same as `rel="stylesheet"`.
    Cross-origin links are kept — a site's CSS often lives on a CDN.
    `base_url` must be the URL the page finally answered from, not the
    one that was asked for: resolving `href="theme.css"` against a
    pre-redirect `/` when the page came from `/en/` fetches nothing."""
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
