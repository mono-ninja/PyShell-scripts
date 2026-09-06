"""src/ops.py — the six operations.

Every op takes `(readers, pages, angle, output_dir, progress)` — a list
of (path, PdfReader) pairs, the parsed page spec where meaningful, the
rotation angle, where to write, and a progress callback — and returns
`(results, written)`: the per-file `OpResult` rows and the list of
written paths. The originals are never modified; strip/compress rebuild
the document from pages only, which is what drops the metadata and the
attachments.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from pypdf import PdfWriter

from .events import log
from .inspection import human_size


@dataclass
class OpResult:
    source: str                # basename of the input
    status: str                # ok | error
    detail: str = ""           # human line for the table
    source_bytes: int = 0
    output_bytes: int = 0
    note: str = ""


def _write(writer: PdfWriter, path: str) -> int:
    with open(path, "wb") as fh:
        writer.write(fh)
    return os.path.getsize(path)


def _stem(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def _progress_over(readers, progress, lo, hi):
    """Progress across files, mapped onto lo..hi of the 0–100 bar."""
    total = len(readers)
    def tick(i, msg):
        if total:
            progress(lo + int((hi - lo) * i / total), msg)
    return tick


def _rebuild(reader, path_out: str, progress_note: str = "") -> int:
    """Pages-only rebuild: the metadata, XMP and attachments of the
    source do not carry over. The core of strip and compress."""
    writer = PdfWriter()
    writer.append(reader)
    # pypdf stamps its own producer on a fresh writer — blank it so the
    # output leaks nothing, not even "made with pypdf".
    writer.add_metadata({"/Producer": ""})
    return _write(writer, path_out)


# --- operations ---------------------------------------------------------------

def op_merge(readers, pages, angle, output_dir, progress) -> tuple[list, list]:
    """All files, in the given order, into one merged.pdf."""
    results: list[OpResult] = []
    written: list[str] = []
    total_in = 0
    writer = PdfWriter()
    for i, (path, reader) in enumerate(readers, 1):
        writer.append(reader)
        total_in += os.path.getsize(path)
        progress(5 + int(80 * i / len(readers)),
                 f"appending {os.path.basename(path)} ({i}/{len(readers)})")
    target = os.path.join(output_dir, "merged.pdf")
    size = _write(writer, target)
    written.append(target)
    log(f"  ✓ merged {len(readers)} file(s) → merged.pdf "
        f"({human_size(size)})")
    results.append(OpResult(
        source=f"{len(readers)} file(s)", status="ok",
        detail=f"merged → merged.pdf ({human_size(size)})",
        source_bytes=total_in, output_bytes=size))
    return results, written


def op_split(readers, pages, angle, output_dir, progress) -> tuple[list, list]:
    """Each file → one PDF per page: <stem>_page_001.pdf …"""
    results: list[OpResult] = []
    written: list[str] = []
    total = sum(len(r.pages) for _p, r in readers)
    done = 0
    for path, reader in readers:
        stem = _stem(path)
        source_bytes = os.path.getsize(path)
        try:
            for i, _page in enumerate(reader.pages, 1):
                writer = PdfWriter()
                writer.append(reader, pages=(i - 1, i))
                target = os.path.join(output_dir,
                                      f"{stem}_page_{i:03d}.pdf")
                _write(writer, target)
                written.append(target)
                done += 1
                progress(5 + int(90 * done / total),
                         f"{stem} page {i}/{len(reader.pages)}")
            results.append(OpResult(
                source=os.path.basename(path), status="ok",
                detail=f"{len(reader.pages)} page(s) → {stem}_page_*.pdf",
                source_bytes=source_bytes))
            log(f"  ✓ {os.path.basename(path)} → {len(reader.pages)} "
                f"page file(s)")
        except Exception as exc:  # a mid-file failure keeps earlier pages
            results.append(OpResult(
                source=os.path.basename(path), status="error",
                note=f"{type(exc).__name__}"))
            log(f"  ✗ {os.path.basename(path)}: {type(exc).__name__}")
    return results, written


def op_extract(readers, pages, angle, output_dir, progress) -> tuple[list, list]:
    """The parsed page spec → <stem>_extracted.pdf, per file."""
    results: list[OpResult] = []
    written: list[str] = []
    tick = _progress_over(readers, progress, 5, 95)
    for i, (path, reader) in enumerate(readers, 1):
        stem = _stem(path)
        tick(i, f"extracting {os.path.basename(path)}")
        writer = PdfWriter()
        writer.append(reader, pages=list(pages))
        target = os.path.join(output_dir, f"{stem}_extracted.pdf")
        size = _write(writer, target)
        written.append(target)
        results.append(OpResult(
            source=os.path.basename(path), status="ok",
            detail=f"pages {len(pages)} → {stem}_extracted.pdf "
                   f"({human_size(size)})",
            source_bytes=os.path.getsize(path), output_bytes=size))
        log(f"  ✓ {os.path.basename(path)}: {len(pages)} page(s) → "
            f"{stem}_extracted.pdf")
    return results, written


def op_rotate(readers, pages, angle, output_dir, progress) -> tuple[list, list]:
    """Rotate the given pages (or all) by the angle → <stem>_rotated.pdf."""
    results: list[OpResult] = []
    written: list[str] = []
    tick = _progress_over(readers, progress, 5, 95)
    for i, (path, reader) in enumerate(readers, 1):
        stem = _stem(path)
        tick(i, f"rotating {os.path.basename(path)}")
        writer = PdfWriter()
        writer.append(reader)
        targets = pages if pages is not None else range(len(writer.pages))
        for idx in targets:
            writer.pages[idx].rotate(angle)
        target = os.path.join(output_dir, f"{stem}_rotated.pdf")
        size = _write(writer, target)
        written.append(target)
        n = len(targets) if pages is not None else len(writer.pages)
        results.append(OpResult(
            source=os.path.basename(path), status="ok",
            detail=f"{n} page(s) × {angle}° → {stem}_rotated.pdf",
            source_bytes=os.path.getsize(path), output_bytes=size))
        log(f"  ✓ {os.path.basename(path)}: {n} page(s) rotated {angle}°")
    return results, written


def op_strip(readers, pages, angle, output_dir, progress) -> tuple[list, list]:
    """The privacy operation: pages-only rebuild → <stem>_clean.pdf."""
    results: list[OpResult] = []
    written: list[str] = []
    tick = _progress_over(readers, progress, 5, 95)
    for i, (path, reader) in enumerate(readers, 1):
        stem = _stem(path)
        tick(i, f"stripping {os.path.basename(path)}")
        target = os.path.join(output_dir, f"{stem}_clean.pdf")
        size = _rebuild(reader, target)
        written.append(target)
        results.append(OpResult(
            source=os.path.basename(path), status="ok",
            detail=f"{len(reader.pages)} page(s), metadata dropped → "
                   f"{stem}_clean.pdf ({human_size(size)})",
            source_bytes=os.path.getsize(path), output_bytes=size))
        log(f"  ✓ {os.path.basename(path)} → {stem}_clean.pdf "
            f"({human_size(os.path.getsize(path))} → {human_size(size)})")
    return results, written


def op_compress(readers, pages, angle, output_dir, progress) -> tuple[list, list]:
    """Metadata strip + duplicate-object dedupe → <stem>_min.pdf. Image
    streams are never re-encoded — honest about what that means for
    savings."""
    results: list[OpResult] = []
    written: list[str] = []
    tick = _progress_over(readers, progress, 5, 95)
    for i, (path, reader) in enumerate(readers, 1):
        stem = _stem(path)
        tick(i, f"compressing {os.path.basename(path)}")
        writer = PdfWriter()
        writer.append(reader)
        writer.add_metadata({"/Producer": ""})
        try:
            writer.compress_identical_objects()
        except Exception:
            pass  # dedupe is best-effort; the rebuild still stands
        target = os.path.join(output_dir, f"{stem}_min.pdf")
        size = _write(writer, target)
        written.append(target)
        before = os.path.getsize(path)
        delta = 100 * (before - size) / before if before else 0
        results.append(OpResult(
            source=os.path.basename(path), status="ok",
            detail=f"{human_size(before)} → {human_size(size)} "
                   f"({delta:+.1f}%) → {stem}_min.pdf",
            source_bytes=before, output_bytes=size))
        log(f"  ✓ {os.path.basename(path)}: {human_size(before)} → "
            f"{human_size(size)} ({delta:+.1f}%)")
    return results, written
