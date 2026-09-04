#!/usr/bin/env python3
"""image-optimizer/main.py — shrink image file size without changing format.

The narrow sibling of image-converter: where that one changes format, this
one re-encodes in the SAME format — mozjpeg lossless recompression for
JPEG, an oxipng (or Pillow-zlib fallback) DEFLATE pass for PNG, a libwebp
re-save for WebP — plus metadata stripping (EXIF/GPS/XMP/text chunks) and
optional PNG color quantization.

The safety net (A6) is the contract: **never write a file bigger than the
input.** When an "optimized" candidate comes out larger (already-optimized
sources, tiny images where format overhead dominates), the original bytes
are copied through unchanged and the row is marked `kept original`.

Three input modes (single / multiple / folder+recursive) mirror
image-converter exactly, so anyone who has used one script knows the other.

PyShell runs the script through pipes, not a PTY, so `rich`/`tqdm` do not
work here — progress and results are emitted as structured JSON events on
stderr. Running from a terminal works too.
"""
import argparse
import concurrent.futures
import csv
import io
import json
import os
import sys
import tempfile
import threading
from collections import namedtuple

from PIL import Image, PngImagePlugin

# Both compressors are optional at import time: the script degrades to a
# Pillow fallback (PNG) or a "kept original" note (JPEG lossless) rather
# than refusing to run — same philosophy as ip-search's optional dnspython.
#
# NOTE: the PyPI package is named `pyoxipng`; the module it installs is
# `oxipng`. There is no PyPI project called "oxipng" — requirements.txt
# must say pyoxipng or the environment build fails to resolve.
try:
    import oxipng
except ImportError:
    oxipng = None

try:
    import mozjpeg_lossless_optimization as mozjpeg
except ImportError:
    mozjpeg = None

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ

# Extensions dispatched to an optimizer.
SUPPORTED = {".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".webp": "webp"}

# Extensions discovered in folder mode but not optimizable in v1 — reported
# as skipped rows rather than invisible (GIF needs frame-diffing, TIFF/BMP
# savings are marginal; both out of scope on purpose).
SCAN_ONLY = {".gif", ".tif", ".tiff", ".bmp", ".avif"}

IMAGE_EXTS = SUPPORTED.keys() | SCAN_ONLY

# Per-file row state.
ST_OK, ST_KEPT, ST_SKIP, ST_ERROR = "ok", "kept", "skip", "error"

Result = namedtuple("Result", "name code note orig new saved orig_bytes new_bytes")


def emit(event: dict) -> None:
    """One event — one line on stderr. Never pretty-printed."""
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.0f} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def images(n: int) -> str:
    return "image" if n == 1 else "images"


# ---------------------------------------------------------------------------
# A1. Input handling — same three-mode pattern as image-converter
# ---------------------------------------------------------------------------

def collect_inputs(args) -> list[tuple[str, str]]:
    """Returns a list of (abs_path, rel_path); rel_path builds the output
    path (basename for single/multiple, path relative to the folder root
    for folder mode)."""
    mode = args.mode
    if mode == "single":
        if not args.single_image:
            return []
        return [(os.path.abspath(args.single_image),
                 os.path.basename(args.single_image))]
    if mode == "multiple":
        return [(os.path.abspath(f), os.path.basename(f))
                for f in (args.input_file or [])]
    if mode == "folder":
        if not args.input_folder:
            return []
        root = os.path.abspath(args.input_folder)
        out = []
        if args.recursive:
            for dirpath, _dirs, files in os.walk(root):
                for fn in sorted(files):
                    if os.path.splitext(fn)[1].lower() in IMAGE_EXTS:
                        full = os.path.join(dirpath, fn)
                        out.append((full, os.path.relpath(full, root)))
        else:
            for fn in sorted(os.listdir(root)):
                full = os.path.join(root, fn)
                if os.path.isfile(full) and os.path.splitext(fn)[1].lower() in IMAGE_EXTS:
                    out.append((full, fn))
        return out
    return []


# ---------------------------------------------------------------------------
# WebP lossless detection — read the RIFF container, don't guess
# ---------------------------------------------------------------------------

def webp_is_lossless(data: bytes) -> bool:
    """True when the WebP bitstream is VP8L (lossless).

    Detecting this from the source — rather than always re-saving lossy —
    matters: silently converting a lossless WebP to a lossy one would be a
    surprising quality regression for a tool whose premise is "smaller,
    not worse than the user asked for".
    """
    if len(data) < 16 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return False
    off = 12
    while off + 8 <= len(data):
        fourcc = data[off:off + 4]
        size = int.from_bytes(data[off + 4:off + 8], "little")
        if fourcc == b"VP8L":
            return True
        if fourcc == b"VP8 ":
            return False
        # VP8X (extended) just wraps the real chunk — keep walking top-level
        # chunks; they are padded to even sizes.
        off += 8 + size + (size & 1)
    return False


# ---------------------------------------------------------------------------
# A2. JPEG
# ---------------------------------------------------------------------------

def optimize_jpeg(src: bytes, opts) -> tuple[bytes, str]:
    """Returns (candidate_bytes, note). Never raises for a missing
    compressor — the caller applies the safety net either way."""
    if opts.jpeg_mode == "lossless":
        if mozjpeg is None:
            # Pillow cannot re-Huffman a JPEG losslessly; without mozjpeg the
            # honest result is "no change", not a silent lossy re-encode.
            return src, "kept original (mozjpeg-lossless-optimization not installed)"
        # copy= controls which markers survive: NONE drops EXIF/ICC/comments
        # (the strip default), ICC keeps only the color profile, ALL keeps
        # everything, ALL_EXCEPT_ICC keeps everything but the profile.
        if opts.strip_metadata:
            copy = (mozjpeg.COPY_MARKERS.ICC if opts.keep_icc_profile
                    else mozjpeg.COPY_MARKERS.NONE)
        else:
            copy = (mozjpeg.COPY_MARKERS.ALL if opts.keep_icc_profile
                    else mozjpeg.COPY_MARKERS.ALL_EXCEPT_ICC)
        return mozjpeg.optimize(src, copy=copy), ""

    # lossy: Pillow re-save — the metadata kwargs are what strip (Pillow
    # re-embeds info keys unless explicitly overridden with empty values).
    with Image.open(io.BytesIO(src)) as img:
        img.load()
        kwargs = {
            "quality": opts.jpeg_quality,
            "optimize": True,
            "progressive": True,
            "exif": b"" if opts.strip_metadata else img.info.get("exif", b""),
            "xmp": b"" if opts.strip_metadata else img.info.get("xmp", b""),
            "icc_profile": (img.info.get("icc_profile")
                            if opts.keep_icc_profile else None),
        }
        out = io.BytesIO()
        img.save(out, format="JPEG", **kwargs)
        return out.getvalue(), ""


# ---------------------------------------------------------------------------
# A3. PNG
# ---------------------------------------------------------------------------

def oxipng_pass(data: bytes) -> bytes | None:
    """oxipng DEFLATE pass; None when oxipng is unavailable or fails —
    the caller falls back to the Pillow-produced bytes."""
    if oxipng is None:
        return None
    try:
        if hasattr(oxipng, "optimize_from_memory"):
            return oxipng.optimize_from_memory(data)
        # File-based API: round-trip through a temp file.
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            tf.write(data)
            path = tf.name
        try:
            oxipng.optimize(path)
            with open(path, "rb") as fh:
                return fh.read()
        finally:
            os.unlink(path)
    except Exception:
        return None


def optimize_png(src: bytes, opts) -> tuple[bytes, str]:
    notes: list[str] = []
    needs_reencode = (opts.strip_metadata
                      or not opts.keep_icc_profile
                      or opts.allow_lossy_png
                      or oxipng is None)

    if not needs_reencode:
        # Nothing to change inside the file — feed the original bytes
        # straight to oxipng. Skipping the Pillow round-trip keeps this path
        # byte-faithful apart from the DEFLATE pass itself.
        out = oxipng_pass(src)
        if out is not None:
            return out, ""
        return src, "kept original (oxipng pass failed)"

    with Image.open(io.BytesIO(src)) as img:
        img.load()
        if (opts.allow_lossy_png
                and img.getcolors(opts.png_max_colors) is None):
            # More distinct colors than the ceiling and the user allowed
            # lossy: quantize. This is where the real size wins live for
            # photographic PNGs, at a real quality cost — hence opt-in.
            img = img.quantize(colors=opts.png_max_colors)
            notes.append(f"quantized to ≤{opts.png_max_colors} colors")
        out = io.BytesIO()
        save_kwargs = {
            "exif": b"" if opts.strip_metadata else img.info.get("exif", b""),
            "icc_profile": (img.info.get("icc_profile")
                            if opts.keep_icc_profile else None),
            "compress_level": 9,
        }
        if opts.strip_metadata:
            # an explicitly empty PngInfo suppresses text chunks
            save_kwargs["pnginfo"] = PngImagePlugin.PngInfo()
        elif getattr(img, "text", None):
            # Pillow only writes text chunks from an explicit pnginfo (no
            # fallback to img.text), so keeping them means rebuilding it
            kept = PngImagePlugin.PngInfo()
            for key, value in img.text.items():
                kept.add_text(key, value)
            save_kwargs["pnginfo"] = kept
        img.save(out, format="PNG", **save_kwargs)
        pillow_bytes = out.getvalue()

    if oxipng is None:
        notes.append("oxipng not installed — Pillow zlib pass only")
        return pillow_bytes, "; ".join(notes)

    # Final DEFLATE pass regardless of whether quantization ran — the PNG
    # equivalent of the JPEG lossless mode, never changes a pixel.
    final = oxipng_pass(pillow_bytes)
    if final is None:
        notes.append("oxipng pass failed — Pillow output kept")
        return pillow_bytes, "; ".join(notes)
    return final, "; ".join(notes)


# ---------------------------------------------------------------------------
# A4. WebP
# ---------------------------------------------------------------------------

def optimize_webp(src: bytes, opts) -> tuple[bytes, str]:
    lossless_source = webp_is_lossless(src)
    with Image.open(io.BytesIO(src)) as img:
        img.load()
        kwargs = {
            "exif": b"" if opts.strip_metadata else img.info.get("exif", b""),
            "xmp": b"" if opts.strip_metadata else img.info.get("xmp", b""),
            "icc_profile": (img.info.get("icc_profile")
                            if opts.keep_icc_profile else None),
            "method": 6,  # slowest, best compression
        }
        if lossless_source:
            # Never silently convert a lossless source to lossy.
            kwargs["lossless"] = True
            kwargs["quality"] = 100
        else:
            kwargs["quality"] = opts.webp_quality
        out = io.BytesIO()
        img.save(out, format="WEBP", **kwargs)
    note = "lossless source — re-saved lossless" if lossless_source else ""
    return out.getvalue(), note


# ---------------------------------------------------------------------------
# Per-file pipeline: dispatch → optimize → safety net (A6)
# ---------------------------------------------------------------------------

OPTIMIZERS = {"jpeg": optimize_jpeg, "png": optimize_png, "webp": optimize_webp}


def process_file(src: str, rel: str, opts, registry: "OutputRegistry") -> Result:
    name = os.path.basename(rel)
    ext = os.path.splitext(name)[1].lower()
    kind = SUPPORTED.get(ext)

    try:
        orig_size = os.path.getsize(src)
    except OSError as e:
        return Result(name, ST_ERROR, f"error: {e}", "—", "—", "—", 0, 0)

    if kind is None:
        # Unsupported format: skipped-not-errored by default, so a batch of
        # 200 files with 3 GIFs finishes with 197 rows and 3 skips.
        if opts.skip_unsupported:
            return Result(name, ST_SKIP, f"skipped: unsupported format ({ext})",
                          human_size(orig_size), "—", "—", orig_size, orig_size)
        return Result(name, ST_ERROR, f"error: unsupported format ({ext})",
                      human_size(orig_size), "—", "—", orig_size, orig_size)

    out_path = registry.reserve(rel, ext)
    if out_path is None:
        return Result(name, ST_SKIP, "skipped (exists)",
                      human_size(orig_size), "—", "—", orig_size, orig_size)

    try:
        with open(src, "rb") as fh:
            src_bytes = fh.read()
        candidate, note = OPTIMIZERS[kind](src_bytes, opts)
    except Exception as e:
        return Result(name, ST_ERROR, f"error: {e}",
                      human_size(orig_size), "—", "—", orig_size, orig_size)

    # A6 safety net: never write a file bigger than the input. Equal size
    # also keeps the original — there is nothing to gain and the bytes are
    # already on disk provenance-wise.
    if len(candidate) >= len(src_bytes):
        candidate = src_bytes
        note = "kept original" + (f" ({note})" if note else "")

    try:
        with open(out_path, "wb") as fh:
            fh.write(candidate)
    except OSError as e:
        return Result(name, ST_ERROR, f"error: {e}",
                      human_size(orig_size), "—", "—")

    new_size = len(candidate)
    if orig_size:
        saved = (orig_size - new_size) / orig_size * 100
        saved_str = f"{saved:.0f}%"
    else:
        saved_str = "—"
    if new_size == orig_size:
        # Equal size also keeps the original — nothing to gain, and the
        # note (if any) explains why no compression happened.
        code = ST_KEPT
        text = (note if note.startswith("kept original")
                else "kept original" + (f" ({note})" if note else ""))
    else:
        code = ST_OK
        text = "OK" + (f" ({note})" if note else "")
    # The name was taken by another source — show the real output file.
    out_name = os.path.basename(out_path)
    if out_name != name:
        text += f" → {out_name}"
    return Result(name, code, text, human_size(orig_size),
                  human_size(new_size), saved_str, orig_size, new_size)


class OutputRegistry:
    """Hands out unique output paths (same contract as image-converter's):
    `photo.png` from two different folders must not overwrite each other —
    the second gets a `-1` suffix; existing files are skipped unless
    `overwrite` is on."""

    def __init__(self, output_dir: str, overwrite: bool) -> None:
        self.output_dir = output_dir
        self.overwrite = overwrite
        self._taken: set[str] = set()
        self._lock = threading.Lock()

    def reserve(self, rel_path: str, ext: str) -> str | None:
        stem = os.path.join(self.output_dir, os.path.splitext(rel_path)[0])
        candidate, n = f"{stem}{ext}", 0
        with self._lock:
            while True:
                if candidate in self._taken:
                    n += 1
                elif os.path.exists(candidate) and not self.overwrite:
                    if n == 0:
                        return None
                    n += 1
                else:
                    self._taken.add(candidate)
                    break
                candidate = f"{stem}-{n}{ext}"
        parent = os.path.dirname(candidate)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return candidate


def run_batch(sources, opts, registry, workers: int) -> list[Result]:
    """Optimize all files, in parallel where possible. Progress is throttled
    to whole percents under a lock, so events do not overlap."""
    total = len(sources)
    rows: list[Result | None] = [None] * total
    lock = threading.Lock()
    done = 0
    last_pct = -1

    def task(idx: int, src: str, rel: str) -> None:
        nonlocal done, last_pct
        r = process_file(src, rel, opts, registry)
        with lock:
            rows[idx] = r
            done += 1
            pct = int(done * 100 / total)
            if pct != last_pct:
                last_pct = pct
                emit({"type": "progress", "pct": pct,
                      "message": f"{done}/{total} · {r.name}"})

    if workers <= 1 or total <= 1:
        for i, (src, rel) in enumerate(sources):
            task(i, src, rel)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(task, i, src, rel)
                    for i, (src, rel) in enumerate(sources)]
            for f in concurrent.futures.as_completed(futs):
                f.result()

    return [r for r in rows if r is not None]


# ---------------------------------------------------------------------------
# Report CSV — durable savings record for build pipelines
# ---------------------------------------------------------------------------

def write_report_csv(rows: list[Result]) -> str | None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return None
    path = os.path.join(out_dir, "optimization_report.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "status", "note",
                         "original_bytes", "optimized_bytes", "saved_percent"])
        for r in rows:
            # raw byte counts, not the human-readable table strings — this
            # file exists so pipelines can consume the numbers
            writer.writerow([r.name, r.code, r.note,
                             r.orig_bytes, r.new_bytes, r.saved])
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Image optimizer — shrink JPEG/PNG/WebP without changing format")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single")
    parser.add_argument("--single-image", default=None)
    parser.add_argument("--input-file", action="append", default=None)
    parser.add_argument("--input-folder", default=None)
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--output-folder", required=True)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--jpeg-mode", choices=["lossless", "lossy"],
                        default="lossless",
                        help="lossless: mozjpeg re-Huffman only (safest); "
                             "lossy: re-encode at --jpeg-quality")
    parser.add_argument("--jpeg-quality", type=int, default=82)
    parser.add_argument("--allow-lossy-png", action="store_true",
                        help="Allow PNG color quantization down to "
                             "--png-max-colors (real quality tradeoff)")
    parser.add_argument("--png-max-colors", type=int, default=256)
    parser.add_argument("--webp-quality", type=int, default=80,
                        help="Re-save quality for LOSSY WebP sources only; "
                             "lossless sources are re-saved lossless")
    parser.add_argument("--strip-metadata", action="store_true",
                        help="Strip EXIF/GPS/XMP/PNG text chunks (on by "
                             "default in the PyShell form)")
    parser.add_argument("--keep-icc-profile", action="store_true",
                        help="Keep the color profile even when stripping")
    parser.add_argument("--skip-unsupported", action="store_true",
                        help="Skip unsupported formats (GIF/TIFF/BMP) "
                             "instead of erroring (on by default in the "
                             "PyShell form)")
    parser.add_argument("--workers", type=int, default=0,
                        help="Number of threads (0 = automatic)")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files processed", flush=True)
        return 0

    for name, value in (("jpeg quality", args.jpeg_quality),
                        ("webp quality", args.webp_quality)):
        if not 1 <= value <= 100:
            print(f"{name.capitalize()} must be between 1 and 100",
                  file=sys.stderr, flush=True)
            return 2
    if not 2 <= args.png_max_colors <= 256:
        print("PNG max colors must be between 2 and 256",
              file=sys.stderr, flush=True)
        return 2

    opts = args  # the optimizers read the argparse namespace directly

    output_dir = os.path.abspath(args.output_folder)
    print(
        f"JPEG: {args.jpeg_mode}"
        + (f" (q{args.jpeg_quality})" if args.jpeg_mode == "lossy" else "")
        + f" · PNG: oxipng {'available' if oxipng else 'NOT installed (Pillow fallback)'}"
        + (" + quantization" if args.allow_lossy_png else "")
        + f" · WebP: q{args.webp_quality} (lossless stays lossless)"
        + f" · Output: {output_dir}",
        flush=True,
    )

    status("Collecting images…")
    sources = collect_inputs(args)
    if not sources:
        print("No images found to optimize.", file=sys.stderr, flush=True)
        status("No input images")
        emit({"type": "progress", "pct": 100, "message": "No images"})
        return 1

    found = f"Found {len(sources)} {images(len(sources))}"
    status(found)
    print(found, flush=True)

    # Create the folder only now: nothing to do → no empty directory on disk.
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as e:
        print(f"✗ output folder not writable: {e}", file=sys.stderr, flush=True)
        return 1

    workers = args.workers if args.workers > 0 else min(os.cpu_count() or 4, 8)
    workers = min(workers, len(sources))
    if workers > 1:
        print(f"Parallel optimization: {workers} threads", flush=True)

    rows = run_batch(sources, opts, OutputRegistry(output_dir, args.overwrite),
                     workers)

    ok = sum(1 for r in rows if r.code == ST_OK)
    kept = sum(1 for r in rows if r.code == ST_KEPT)
    skipped = sum(1 for r in rows if r.code == ST_SKIP)
    failed = sum(1 for r in rows if r.code == ST_ERROR)

    # The table — once, in full (it replaces, it does not append).
    emit({
        "type": "table",
        "columns": ["File", "Original", "Optimized", "Saved", "Note"],
        "rows": [[r.name, r.orig, r.new, r.saved, r.note] for r in rows],
    })

    csv_path = write_report_csv(rows)
    if csv_path:
        print(f"Wrote {csv_path}", flush=True)

    emit({"type": "progress", "pct": 100, "message": "Done"})
    status(f"Optimized {ok} · kept {kept} · skipped {skipped} · failed {failed}")

    # Exit codes: individual failures are rows in the table, not a failed
    # run. 1 only when nothing was found or nothing could be written.
    return 0 if (ok + kept + skipped) > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
