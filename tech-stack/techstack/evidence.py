"""``Evidence`` — the normalized per-page slice every detector reads.

An earlier PyShell detector took raw headers/html/cookies and re-parsed
HTML on every call. Tech Stack parses a page **once** into ``Evidence``; then all
~150 technologies read the same structure. ``merge()`` unions subresources and
headers across the sampled pages for the third-party inventory and snapshot.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .util import resolve_url

# Regex extraction, not BeautifulSoup — keeps Tech Stack
# dependency-light (requests + pyyaml only). Robust enough for fingerprinting:
# we look for attributes, not a DOM tree.
_META_RE = re.compile(r"<meta[^>]*>", re.I)
_META_KEY_RE = re.compile(r"\s(?:name|property)=[\"']([^\"']+)[\"']", re.I)
_META_VAL_RE = re.compile(r"\scontent=[\"']([^\"']*)[\"']", re.I)
_SCRIPT_SRC_RE = re.compile(r"<script[^>]*\ssrc=[\"']([^\"']+)[\"']", re.I)
_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_STYLE_RE = re.compile(
    r"<link[^>]*\srel=[\"']stylesheet[\"'][^>]*\shref=[\"']([^\"']+)[\"']", re.I)
_STYLE_RE2 = re.compile(
    r"<link[^>]*\shref=[\"']([^\"']+)[\"'][^>]*\srel=[\"']stylesheet[\"']", re.I)
_PRECONNECT_RE = re.compile(
    r"<link[^>]*\srel=[\"'](preconnect|dns-prefetch|preload|modulepreload|prefetch)[\"']"
    r"[^>]*\shref=[\"']([^\"']+)[\"']", re.I)
_IMG_RE = re.compile(r"<img[^>]*\ssrc=[\"']([^\"']+)[\"']", re.I)
_IFRAME_RE = re.compile(r"<iframe[^>]*\ssrc=[\"']([^\"']+)[\"']", re.I)
_SRCSET_RE = re.compile(r"<(?:img|source)[^>]*\ssrcset=[\"']([^\"']+)[\"']", re.I)
_OG_RE = re.compile(r"<meta[^>]*\sproperty=[\"']og:image[\"'][^>]*\scontent=[\"']([^\"']+)[\"']", re.I)


@dataclass
class Evidence:
    url: str
    final_url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)   # lower-case keys
    cookies: list[str] = field(default_factory=list)         # cookie names
    html: str = ""
    meta: dict[str, str] = field(default_factory=dict)
    scripts: list[str] = field(default_factory=list)         # absolute <script src>
    stylesheets: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)           # preconnect/prefetch/preload
    images: list[str] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    js_globals: dict[str, str] = field(default_factory=dict)  # only with --render
    bundle_text: str = ""                                    # first ~256KB of main bundle

    @property
    def inline_blob(self) -> str:
        """inline_script signals search here, plus the downloaded bundle snippet
        (grep first ~256KB of the main bundle for `react-dom` etc.)."""
        return "\n".join(self.inline_scripts) + "\n" + self.bundle_text


def _extract_meta(html: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _META_RE.finditer(html):
        tag = m.group(0)
        km = _META_KEY_RE.search(tag)
        vm = _META_VAL_RE.search(tag)
        if km and vm:
            out[km.group(1).lower()] = vm.group(1)
    return out


def _cookie_names(headers: dict[str, str]) -> list[str]:
    """Cookie names from (possibly multiple) Set-Cookie headers."""
    names: list[str] = []
    for key, val in headers.items():
        if key != "set-cookie":
            continue
        # requests folds multiple Set-Cookie into a list when accessed via
        # response.headers, but a plain dict may join with commas. Handle both.
        for part in re.split(r",(?=\s*\w+=)", val):
            first = part.strip().split("=", 1)[0].strip()
            if first:
                names.append(first)
    return names


def from_response(
    url: str,
    final_url: str,
    status: int,
    headers: dict[str, str],
    html: str,
    js_globals: Optional[dict[str, str]] = None,
    bundle_text: str = "",
) -> Evidence:
    """Parse a fetched page into Evidence. ``headers`` keys are lower-cased."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    html = html or ""
    base = final_url or url

    scripts: list[str] = []
    inline: list[str] = []
    for m in _SCRIPT_TAG_RE.finditer(html):
        block = m.group(0)
        src_m = _SCRIPT_SRC_RE.search(block)
        if src_m:
            scripts.append(resolve_url(src_m.group(1), base))
        else:
            text = m.group(1)
            if text and text.strip():
                inline.append(text)

    styles: list[str] = []
    for rx in (_STYLE_RE, _STYLE_RE2):
        for m in rx.finditer(html):
            styles.append(resolve_url(m.group(1), base))

    links: list[str] = []
    for m in _PRECONNECT_RE.finditer(html):
        links.append(resolve_url(m.group(2), base))

    images: list[str] = []
    for m in _IMG_RE.finditer(html):
        images.append(resolve_url(m.group(1), base))
    for m in _OG_RE.finditer(html):
        images.append(resolve_url(m.group(1), base))
    for m in _SRCSET_RE.finditer(html):
        # srcset may contain multiple URLs + width descriptors; take first token.
        first = m.group(1).split(",")[0].strip().split(" ")[0]
        if first:
            images.append(resolve_url(first, base))

    iframes = [resolve_url(m.group(1), base) for m in _IFRAME_RE.finditer(html)]

    return Evidence(
        url=url,
        final_url=base,
        status=status,
        headers=lower_headers,
        cookies=_cookie_names(lower_headers),
        html=html,
        meta=_extract_meta(html),
        scripts=scripts,
        stylesheets=styles,
        inline_scripts=inline,
        links=links,
        images=images,
        iframes=iframes,
        js_globals=js_globals or {},
        bundle_text=bundle_text,
    )


def merge(evidences: list[Evidence]) -> Evidence:
    """Union subresources and headers across pages.

    Used for the third-party inventory (all network requests) and the snapshot.
    Detection runs per-page and aggregates, so it does not depend on this.
    """
    if not evidences:
        return Evidence(url="", final_url="", status=0)
    first = evidences[0]
    headers: dict[str, str] = {}
    cookies: list[str] = []
    meta: dict[str, str] = {}
    scripts: list[str] = []
    styles: list[str] = []
    inline: list[str] = []
    links: list[str] = []
    images: list[str] = []
    iframes: list[str] = []
    js_globals: dict[str, str] = {}

    def _add_unique(dst: list[str], src: list[str]) -> None:
        seen = set(dst)
        for x in src:
            if x not in seen:
                seen.add(x)
                dst.append(x)

    for ev in evidences:
        headers.update({k: v for k, v in ev.headers.items() if v and k not in headers})
        _add_unique(cookies, ev.cookies)
        meta.update({k: v for k, v in ev.meta.items() if v and k not in meta})
        _add_unique(scripts, ev.scripts)
        _add_unique(styles, ev.stylesheets)
        _add_unique(inline, ev.inline_scripts)
        _add_unique(links, ev.links)
        _add_unique(images, ev.images)
        _add_unique(iframes, ev.iframes)
        js_globals.update(ev.js_globals)

    return Evidence(
        url=first.url,
        final_url=first.final_url,
        status=first.status,
        headers=headers,
        cookies=cookies,
        html="",  # merged view does not concatenate HTML
        meta=meta,
        scripts=scripts,
        stylesheets=styles,
        inline_scripts=inline,
        links=links,
        images=images,
        iframes=iframes,
        js_globals=js_globals,
    )
