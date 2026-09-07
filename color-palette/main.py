#!/usr/bin/env python3
"""color-palette/main.py — thin entry point; the logic lives in src/.

Fetches one page, reads its CSS (inline `<style>` blocks, `style="…"`
attributes, and the linked stylesheets — one GET each, politely capped),
extracts every color from color-carrying declarations, groups visually
similar colors, and hands back the site's palette: a chart of colors
per category, a table of the most-used colors, and two artifacts —
`palette.css` (ready-to-paste `:root` variables) and `palette.json`
(every group, machine-readable).

**Static CSS only, v1.** Colors painted by JavaScript at runtime are
not seen — the docs say so, and an empty palette is reported honestly
with that explanation instead of guessed at.

A port of the standalone colorPallet tool, reshaped for the collection:
one-fetch philosophy (same as [Page SEO Audit](../page-seo-audit)),
palette artifacts a [Favicon Generator](../favicon-generator) run can
draw from.
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

import requests

from src.colors import group_similar_colors
from src.events import emit, log, status
from src.extract import extract_colors_from_css, extract_inline_styles, \
    find_stylesheet_links, find_style_blocks
from src.report import build_chart_event, build_markdown, build_table_event, \
    write_artifacts

USER_AGENT = "PyShell-color-palette/1.0"
MAX_CSS_BYTES = 2_000_000  # a single stylesheet bigger than this is skipped


class Oversize(Exception):
    """A stylesheet past the cap — abandoned mid-download, not read."""


# ---------------------------------------------------------------------------
# Fetching (the only I/O)
# ---------------------------------------------------------------------------

def fetch_text(session: requests.Session, url: str, timeout: int,
               max_bytes: int | None = None) -> str | None:
    """The body as text, or None when the request failed. With
    max_bytes the download is streamed and dropped as soon as it passes
    the cap (Oversize) — the guard spends no bandwidth on a stylesheet
    it will not read."""
    try:
        with session.get(url, timeout=timeout,
                         stream=max_bytes is not None) as resp:
            resp.raise_for_status()
            if max_bytes is None:
                return resp.text or ""
            declared = resp.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise Oversize(url)
            body = bytearray()
            for chunk in resp.iter_content(65_536):
                body += chunk
                if len(body) > max_bytes:
                    raise Oversize(url)
            # Only trust a charset the server actually declared; requests
            # would otherwise guess latin-1 for text/css, which mangles a
            # UTF-8 stylesheet.
            charset = (resp.encoding if "charset" in
                       resp.headers.get("Content-Type", "").lower() else None)
            return bytes(body).decode(charset or "utf-8", errors="replace")
    except requests.RequestException as exc:
        log(f"  ⚠️ {url}: {type(exc).__name__}")
        return None


def gather_css_sources(session, url: str, max_stylesheets: int,
                       timeout: int) -> tuple[list[tuple[str, str]], int]:
    """([(label, css_text)], skipped_count) — the page's inline styles,
    its style attributes, and up to max_stylesheets linked files."""
    html = fetch_text(session, url, timeout)
    if html is None:
        raise requests.RequestException(f"{url} never answered")

    sources: list[tuple[str, str]] = []
    for block in find_style_blocks(html):
        sources.append(("inline <style>", block))
    inline = extract_inline_styles(html)
    if inline:
        sources.append(("style=\"…\" attributes", "\n".join(inline)))

    skipped = 0
    links = find_stylesheet_links(html, url)[:max_stylesheets]
    for css_url in links:
        try:
            css = fetch_text(session, css_url, timeout, MAX_CSS_BYTES)
        except Oversize:
            log(f"  ⚠️ {css_url}: over "
                f"{MAX_CSS_BYTES // 1_000_000} MB, skipped")
            skipped += 1
            continue
        if css is None:
            skipped += 1
            continue
        sources.append((css_url, css))
    return sources, skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Color Palette — a site's colors from its CSS, "
                    "grouped and ready as variables")
    parser.add_argument("--url", required=True, help="page to read")
    parser.add_argument("--max-stylesheets", type=int, default=25,
                        help="linked CSS files to read at most (default 25)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout (default 15)")
    parser.add_argument("--top-n", type=int, default=8,
                        help="colors per report section (default 8)")
    return parser


def validate_args(args: argparse.Namespace) -> str | None:
    """The first thing wrong with the arguments, or None. The manifest
    holds the GUI to these ranges; a standalone run gets the same
    answer instead of a silent surprise (a negative --max-stylesheets
    used to slice sheets off the *end* of the list)."""
    try:
        parts = urlsplit(args.url)
    except ValueError:
        return f"{args.url!r} is not a parsable URL"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return f"{args.url!r} needs a scheme and host (https://example.com/…)"
    if args.max_stylesheets < 1:
        return "--max-stylesheets must be 1 or more"
    if args.timeout < 1:
        return "--timeout must be 1 or more (seconds)"
    if args.top_n < 1:
        return "--top-n must be 1 or more"
    return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no pages are fetched", flush=True)
        return 0

    problem = validate_args(args)
    if problem:
        print(f"✗ {problem}", file=sys.stderr, flush=True)
        return 2

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    status(f"Reading the CSS of {args.url}")
    emit({"type": "progress", "pct": 5, "message": "Fetching the page"})
    try:
        sources, skipped = gather_css_sources(session, args.url,
                                              args.max_stylesheets,
                                              args.timeout)
    except requests.RequestException:
        print(f"✗ {args.url} never answered — there was nothing to read",
              file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Check failed\n\n❌ **{args.url}** never answered. "
              f"Verify the URL ([IP Search](../ip-search), "
              f"[Server Timing](../server-timing)) and re-run."})
        return 1

    log(f"  {len(sources)} CSS source(s) read"
        + (f", {skipped} skipped" if skipped else ""))
    emit({"type": "progress", "pct": 45,
          "message": f"{len(sources)} CSS source(s) — extracting colors"})

    # Extract → count per category → group similar colors.
    raw: dict[str, Counter] = defaultdict(Counter)
    for _label, css in sources:
        for category, color in extract_colors_from_css(css):
            raw[category][color] += 1
    total_found = sum(sum(c.values()) for c in raw.values())
    log(f"  {total_found} color declaration(s) across "
        f"{sum(len(c) for c in raw.values())} distinct color(s)")
    emit({"type": "progress", "pct": 70, "message": "Grouping similar colors"})

    palette = {cat: group_similar_colors(counts)
               for cat, counts in sorted(raw.items())}

    if not palette or not any(palette.values()):
        report = (f"## ⚪ No colors found in the static CSS\n\n"
                  f"`{args.url}`\n\nThe page carries no color declarations "
                  f"in its `<style>` blocks, `style=\"…\"` attributes or "
                  f"linked stylesheets. If the site paints itself with "
                  f"JavaScript at runtime, static reading can't see it — "
                  f"that's this script's documented limit, not a bug.")
        emit({"type": "progress", "pct": 100, "message": "Done"})
        emit({"type": "markdown", "content": report})
        write_artifacts(args.url, {}, report)
        status("no colors found (static CSS)")
        log("← no colors found in the static CSS")
        return 0

    emit({"type": "progress", "pct": 90, "message": "Building the palette"})
    report = build_markdown(args.url, palette, total_found, args.top_n)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_chart_event(palette))
    emit(build_table_event(palette, args.top_n))
    emit({"type": "markdown", "content": report})
    write_artifacts(args.url, palette, report)

    groups_total = sum(len(v) for v in palette.values())
    status(f"{groups_total} color group(s) across {len(palette)} category(ies)")
    log(f"← {groups_total} color group(s) across {len(palette)} "
        f"category(ies) · palette.css + palette.json written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
