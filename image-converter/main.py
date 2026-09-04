#!/usr/bin/env python3
"""convertImage/main.py — convert images to various formats.

Supports three sources (single file, multiple files, folder), target formats
AVIF / WebP / JPEG / PNG / TIFF / BMP, quality control, proportional
downscaling by a maximum size, and parallel batch conversion. Animation
(GIF/WebP/AVIF) is preserved when converting to WebP/AVIF; EXIF orientation
is applied only for static frames. AVIF is built into Pillow >= 11.3, and in
older versions is provided by `pillow-avif-plugin`.

PyShell runs the script through pipes, not a PTY, so `rich`/`tqdm` do not
work here — progress and results are emitted as structured JSON events on
stderr (see _reference/authoring-guide.md). Running from a terminal works too: the events
degrade to ordinary log lines.
"""
import argparse
import concurrent.futures
import json
import os
import sys
import threading
from collections import namedtuple

from PIL import Image, ImageOps, ImageSequence

# In Pillow >= 11.3 the AVIF codec is built in; in older versions it is
# registered by pillow-avif-plugin right after import. So the plugin import
# is best-effort, and the real check below asks Pillow whether it can write
# AVIF, not whether a particular module is installed. The error is raised
# only when AVIF is selected — this does not break PyShell introspection in
# an unprepared environment.
try:
    import pillow_avif  # noqa: F401
except ImportError:
    pass

Image.init()  # loads all format plugins, including the built-in AVIF
AVIF_OK = "AVIF" in Image.SAVE

# Target format -> (Pillow format string, file extension).
FORMATS = {
    "avif": ("AVIF", "avif"),
    "webp": ("WEBP", "webp"),
    "jpeg": ("JPEG", "jpg"),
    "png": ("PNG", "png"),
    "tiff": ("TIFF", "tiff"),
    "bmp": ("BMP", "bmp"),
}

# Extensions treated as images when scanning a folder.
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".avif", ".tif", ".tiff", ".bmp", ".gif"}

# Formats without an alpha channel: transparency must be flattened onto a background.
NO_ALPHA = {"jpeg", "bmp"}

# Target formats that support animation. Others get only the first frame.
ANIMATED_TARGETS = {"avif", "webp"}

# Per-file conversion state — constants instead of magic strings.
ST_OK, ST_SKIP, ST_ERROR = "ok", "skip", "error"

Result = namedtuple("Result", "name code text orig new change")

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
    """Pluralize: 1 image, 2 images."""
    return "image" if n == 1 else "images"


def collect_inputs(args) -> list[tuple[str, str]]:
    """Returns a list of (abs_path, rel_path). rel_path is relative to the
    folder or just the basename; used to build the output path."""
    mode = args.mode
    if mode == "single":
        if not args.single_image:
            return []
        return [(os.path.abspath(args.single_image), os.path.basename(args.single_image))]
    if mode == "multiple":
        out = []
        for f in args.input_file or []:
            out.append((os.path.abspath(f), os.path.basename(f)))
        return out
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


def prepare_image(img: Image.Image, fmt_key: str) -> Image.Image:
    """Brings the image mode into one compatible with the target format.

    JPEG/BMP have no alpha — transparency is flattened onto a white background.
    Palette images (P) are converted to RGBA/RGB depending on transparency."""
    needs_rgb = fmt_key in NO_ALPHA
    if img.mode == "P":
        img = img.convert("RGBA" if "transparency" in img.info else "RGB")
    if img.mode in ("RGBA", "LA"):
        if needs_rgb:
            bg = Image.new("RGB", img.size, (255, 255, 255))
            rgba = img.convert("RGBA")
            bg.paste(rgba, mask=rgba.split()[-1])
            img = bg
    elif img.mode == "CMYK":
        img = img.convert("RGB")
    elif needs_rgb and img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    return img


def resize_image(img: Image.Image, max_size: int) -> Image.Image:
    """Proportionally shrinks the image if the longest side > max_size.
    max_size <= 0 disables resizing."""
    if not max_size:
        return img
    w, h = img.size
    if max(w, h) <= max_size:
        return img
    return ImageOps.contain(img, (max_size, max_size), Image.Resampling.LANCZOS)


def save_kwargs(fmt_key: str, quality: int) -> dict:
    """Save parameters depending on the format. For lossy formats the quality
    is passed through; for PNG (lossless) it means compression strength;
    TIFF/BMP ignore it."""
    if fmt_key in ("avif", "webp"):
        return {"quality": quality}
    if fmt_key == "jpeg":
        return {"quality": quality, "optimize": True}
    if fmt_key == "png":
        # Higher "quality" = stronger compression = smaller file and slower save
        # (same as described in pyshell.md). Do not pass optimize here: it forces
        # the maximum level and makes compress_level inert — every slider value
        # would produce a byte-identical file.
        # The floor is 1, not 0: compress_level=0 writes PNG with no compression
        # at all (a file several times larger than the original), and for a
        # converter that shrinks size this is never a useful mode.
        return {"compress_level": max(1, min(9, round(quality * 9 / 100)))}
    return {}


class OutputRegistry:
    """Hands out unique output paths and creates subfolders.

    Several sources can claim the same target file: `photo.png` and
    `photo.jpg` both become `photo.webp`, and in "Multiple images" mode
    identical basenames arrive from different folders. Without reservation the
    threads would write to the same path at once — some images would vanish
    while the table still showed "OK" for every row. A claimed name gets a
    `-1`, `-2`, ... suffix. Reservations live for the whole run.
    """

    def __init__(self, output_dir: str, overwrite: bool) -> None:
        self.output_dir = output_dir
        self.overwrite = overwrite
        self._taken: set[str] = set()
        self._lock = threading.Lock()

    def reserve(self, rel_path: str, ext: str) -> str | None:
        """A unique output path, or None if the file is left over from a
        previous run and overwrite is off (a normal skip)."""
        stem = os.path.join(self.output_dir, os.path.splitext(rel_path)[0])
        candidate, n = f"{stem}.{ext}", 0
        with self._lock:
            while True:
                if candidate in self._taken:
                    n += 1
                elif os.path.exists(candidate) and not self.overwrite:
                    # The name is free in this run, but the file is already on
                    # disk: with no suffix this is a normal skip, with a suffix
                    # we just look for the next free one.
                    if n == 0:
                        return None
                    n += 1
                else:
                    self._taken.add(candidate)
                    break
                candidate = f"{stem}-{n}.{ext}"
        parent = os.path.dirname(candidate)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return candidate


def convert_one(src: str, rel: str, fmt_key: str, quality: int,
                registry: OutputRegistry, max_size: int) -> Result:
    """Converts one file. Returns a Result; no corrupt file throws an
    exception outward — this lets the batch keep going."""
    pil_fmt, ext = FORMATS[fmt_key]
    name = os.path.basename(rel)

    # Original size first: a missing/unreadable file is an error for a single
    # file, not a crash of the whole batch, and there is no need to reserve a
    # name for it (or create subfolders).
    try:
        orig_size = os.path.getsize(src)
    except OSError as e:
        return Result(name, ST_ERROR, f"error: {e}", "—", "—", "—")

    out = registry.reserve(rel, ext)
    if out is None:
        return Result(name, ST_SKIP, "skipped (exists)", human_size(orig_size), "—", "—")

    try:
        with Image.open(src) as img:
            n_frames = getattr(img, "n_frames", 1)
            if n_frames > 1 and fmt_key in ANIMATED_TARGETS:
                # Each frame is copied (f.copy()) to get an independent
                # single-frame plain Image. Without this, append_images would
                # point at the same animated source object (n_frames>1), and
                # Pillow would walk N×N frames instead of N — IndexError on
                # duration.
                frames, durations = [], []
                loop = 0
                for i, f in enumerate(ImageSequence.Iterator(img)):
                    if i == 0:
                        loop = f.info.get("loop", 0)
                    durations.append(f.info.get("duration", 100))
                    c = f.copy()
                    c = prepare_image(c, fmt_key)
                    c = resize_image(c, max_size)
                    frames.append(c)
                frames[0].save(
                    out, format=pil_fmt, save_all=True,
                    append_images=frames[1:], duration=durations, loop=loop,
                    **save_kwargs(fmt_key, quality),
                )
            else:
                img = ImageOps.exif_transpose(img)  # applies EXIF orientation
                img = prepare_image(img, fmt_key)
                img = resize_image(img, max_size)
                img.save(out, format=pil_fmt, **save_kwargs(fmt_key, quality))
    except Exception as e:  # one corrupt file does not stop the batch
        return Result(name, ST_ERROR, f"error: {e}", human_size(orig_size), "—", "—")

    try:
        new_size = os.path.getsize(out)
    except OSError as e:
        return Result(name, ST_ERROR, f"error: {e}", human_size(orig_size), "—", "—")

    if orig_size:
        change = (new_size - orig_size) / orig_size * 100
        sign = "+" if change >= 0 else ""
        change_str = f"{sign}{change:.0f}%"
    else:
        change_str = "—"
    # The name was taken by another source — show the real output file.
    out_name = os.path.basename(out)
    text = "OK" if out_name == f"{os.path.splitext(name)[0]}.{ext}" else f"OK → {out_name}"
    return Result(name, ST_OK, text, human_size(orig_size), human_size(new_size), change_str)


def run_batch(sources, fmt_key, quality, registry, max_size, workers):
    """Converts all files, in parallel where possible. Progress is throttled
    to whole percents under a lock, so events do not overlap."""
    total = len(sources)
    rows: list[Result | None] = [None] * total
    lock = threading.Lock()
    done = 0
    last_pct = -1

    def task(idx: int, src: str, rel: str) -> None:
        nonlocal done, last_pct
        r = convert_one(src, rel, fmt_key, quality, registry, max_size)
        with lock:
            rows[idx] = r
            done += 1
            pct = int(done * 100 / total)
            if pct != last_pct:
                last_pct = pct
                emit({"type": "progress", "pct": pct, "message": f"{done}/{total} · {r.name}"})

    if workers <= 1 or total <= 1:
        for i, (src, rel) in enumerate(sources):
            task(i, src, rel)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(task, i, src, rel) for i, (src, rel) in enumerate(sources)]
            for f in concurrent.futures.as_completed(futs):
                f.result()  # convert_one catches everything itself, but stay safe

    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Image converter")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"], default="single")
    parser.add_argument("--single-image", default=None)
    parser.add_argument("--input-file", action="append", default=None)
    parser.add_argument("--input-folder", default=None)
    parser.add_argument("--recursive", action="store_true")
    parser.add_argument("--format", choices=list(FORMATS), default="webp")
    parser.add_argument("--quality", type=int, default=85)
    parser.add_argument("--max-size", type=int, default=0,
                        help="Proportionally shrink to this longest side (0 = no change)")
    parser.add_argument("--workers", type=int, default=0,
                        help="Number of threads (0 = automatic)")
    parser.add_argument("--output-folder", required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    # Introspection builds the form from argparse; no files are converted.
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files converted", flush=True)
        return 0

    if args.quality < 1 or args.quality > 100:
        print("Quality must be between 1 and 100", file=sys.stderr, flush=True)
        return 2

    if args.max_size < 0:
        print("Max size cannot be negative", file=sys.stderr, flush=True)
        return 2

    if args.format == "avif" and not AVIF_OK:
        print(
            "Error: this Pillow build cannot write AVIF. "
            "Pillow >= 11.3 or pillow-avif-plugin is required. "
            "Run: pip install -r requirements.txt",
            file=sys.stderr,
            flush=True,
        )
        return 2

    output_dir = os.path.abspath(args.output_folder)

    print(
        f"Format: {args.format.upper()} · Quality: {args.quality}"
        + (f" · Max size: {args.max_size}px" if args.max_size else "")
        + f" · Output: {output_dir}",
        flush=True,
    )

    status("Collecting images…")
    sources = collect_inputs(args)

    if not sources:
        print("No images found to convert.", file=sys.stderr, flush=True)
        status("No input images")
        emit({"type": "progress", "pct": 100, "message": "No images"})
        return 1

    found = f"Found {len(sources)} {images(len(sources))}"
    status(found)
    print(found, flush=True)

    # Create the folder only now: if there is nothing to convert, no empty
    # directory appears on disk.
    os.makedirs(output_dir, exist_ok=True)

    workers = args.workers if args.workers > 0 else min(os.cpu_count() or 4, 8)
    workers = min(workers, len(sources))
    if workers > 1:
        print(f"Parallel conversion: {workers} threads", flush=True)

    rows = run_batch(
        sources, args.format, args.quality,
        OutputRegistry(output_dir, args.overwrite), args.max_size, workers,
    )

    ok = sum(1 for r in rows if r.code == ST_OK)
    skipped = sum(1 for r in rows if r.code == ST_SKIP)
    failed = sum(1 for r in rows if r.code == ST_ERROR)

    # The table — once, in full (it replaces, it does not append).
    emit({
        "type": "table",
        "columns": ["File", "Status", "Original", "Converted", "Change"],
        "rows": [[r.name, r.text, r.orig, r.new, r.change] for r in rows],
    })

    summary = (
        f"## Done\n\n"
        f"Converted **{ok}** of {len(sources)} {images(len(sources))} to format "
        f"**{args.format.upper()}** (quality {args.quality}"
        + (f", max {args.max_size}px" if args.max_size else "")
        + ").\n\n"
        f"- ✅ Succeeded: {ok}\n"
        f"- ⏭ Skipped: {skipped}\n"
        f"- ❌ Failed: {failed}\n\n"
        f"Files saved to `{output_dir}`."
    )
    emit({"type": "markdown", "content": summary})
    emit({"type": "progress", "pct": 100, "message": "Done"})
    status(f"Succeeded {ok} · skipped {skipped} · failed {failed}")

    # Exit code: the results are in the table. Skipping existing files is not
    # an error. 1 only if no images were found or every file actually errored.
    return 0 if (ok > 0 or skipped > 0) else 1


if __name__ == "__main__":
    sys.exit(main())
