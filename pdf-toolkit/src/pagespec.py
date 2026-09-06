"""src/pagespec.py — the "1-3,7,10-" page-list grammar.

1-based and human (page 1 is the first page); ranges may be open on
either side (`-3` = from the start, `10-` = to the end). Pure — tests
live here.
"""
from __future__ import annotations

RANGE_RE = r"^(\d*)-(\d*)$|^\d+$"


def parse_pages(spec: str, page_count: int) -> tuple[list[int] | None, str]:
    """'1-3,7,10-' + a page count → the sorted 0-based index list.
    (None, error) when the spec doesn't parse or doesn't fit."""
    spec = (spec or "").strip()
    if not spec:
        return None, "empty page spec"
    indices: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            return None, f"empty part in {spec!r}"
        if chunk.isdigit():
            start = end = int(chunk)
        elif "-" in chunk:
            left, _, right = chunk.partition("-")
            if not (left.isdigit() or left == "") or \
               not (right.isdigit() or right == ""):
                return None, f"bad range {chunk!r}"
            start = int(left) if left else 1
            end = int(right) if right else page_count
        else:
            return None, f"bad page {chunk!r}"
        if start < 1 or end < 1:
            return None, f"pages are 1-based: {chunk!r}"
        if start > end:
            return None, f"inverted range {chunk!r}"
        if start > page_count or end > page_count:
            return None, (f"out of range: the document has "
                          f"{page_count} page(s)")
        indices.update(range(start - 1, end))
    if not indices:
        return None, f"no pages selected by {spec!r}"
    return sorted(indices), ""
