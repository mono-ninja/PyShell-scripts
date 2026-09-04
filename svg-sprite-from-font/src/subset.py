"""B6 — subsetting by usage.

Most legacy fonts carry hundreds of glyphs of which a theme uses a handful.
``--scan <path>`` walks the theme directory for ``.php``, ``.html``, ``.js``
and ``.css`` files and keeps only the icons whose legacy class actually appears
in the markup. The runner reports both numbers: found in font, actually used.
"""
from __future__ import annotations

import os
import re

# File extensions that may carry icon class names in a WordPress theme.
_SCAN_EXTS = (".php", ".html", ".htm", ".js", ".css")

# Cap file size so a minified bundle does not blow up memory. 2 MB is plenty
# for a single template file; truly huge concatenated assets are skipped.
_MAX_FILE_BYTES = 2 * 1024 * 1024


def scan_usage(scan_path: str, known_classes: set[str]) -> set[str]:
    """Return the subset of ``known_classes`` referenced under ``scan_path``.

    A class is "used" if it appears as a whole token (bounded by anything that
    is not a word char or hyphen) in any scanned file. That matches it inside
    ``class="fa fa-user"``, JS string arrays, and CSS rules alike.
    """
    if not known_classes or not scan_path:
        return set()
    if not os.path.isdir(scan_path):
        return set()

    # One alternation regex is far cheaper than a per-class scan over every
    # file. Escape each name so a stray regex metacharacter is harmless.
    classes = sorted(known_classes, key=len, reverse=True)
    pattern = re.compile(
        r"(?<![\w-])(" + "|".join(re.escape(c) for c in classes) + r")(?![\w-])"
    )

    found: set[str] = set()
    for dirpath, _dirs, files in os.walk(scan_path):
        for fn in files:
            if os.path.splitext(fn)[1].lower() not in _SCAN_EXTS:
                continue
            full = os.path.join(dirpath, fn)
            try:
                size = os.path.getsize(full)
                if size > _MAX_FILE_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            for m in pattern.finditer(text):
                found.add(m.group(1))
                if found == known_classes:
                    return found
    return found
