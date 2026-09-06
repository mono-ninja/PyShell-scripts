#!/usr/bin/env python3
"""exif-inspect/main.py — what does this photo say about you?

Dumps the EXIF of one image, several, or a folder, as a privacy
inventory: **GPS coordinates** (spelled out in decimal degrees, with a
map link — the single loudest leak), the camera and lens (a device
fingerprint), the software chain (the editing history), the dates
(when you were where), and the author/copyright fields.

Optionally writes **clean copies** with the EXIF removed — orientation
applied to the pixels first, so the photo stays upright without the
tag that made it so. The originals are never touched. This is the
EXIF-specific sibling of [Image Optimizer](../image-optimizer): there,
metadata stripping is a size optimization side effect; here, it is
the point.

Exit codes: 0 = the run completed (a photo riddled with EXIF is a
finding, not a failure), 1 = no images found / Pillow missing,
2 = bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass, field

try:  # Pillow is imported lazily — argparse and the guard run first
    from PIL import Image, ExifTags
    HAVE_PIL = True
except ImportError:  # pragma: no cover — environment-dependent
    HAVE_PIL = False

USER_AGENT = "PyShell-exif-inspect/1.0"

IMAGE_EXTS = {".jpg", ".jpeg", ".tif", ".tiff", ".webp", ".png",
              ".heic", ".avif"}

# The privacy-relevant tags, in display order — the report's outline.
# Raw EXIF ids; names via ExifTags at runtime.
INTERESTING = [
    (0x010F, "Camera make"),
    (0x0110, "Camera model"),
    (0xA434, "Lens model"),
    (0x0132, "Date taken"),
    (0x9003, "Date original"),
    (0x0131, "Software"),
    (0x013B, "Author"),
    (0x8298, "Copyright"),
    (0x9286, "User comment"),
]


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PhotoExif:
    source: str
    rel: str
    status: str = "ok"                 # ok | no exif | unreadable | error
    fields: dict[str, str] = field(default_factory=dict)
    gps: tuple[float, float] | None = None   # (lat, lon) decimal degrees
    gps_altitude: str = ""
    orientation_applied: bool = False
    note: str = ""

    @property
    def leaks(self) -> list[str]:
        """The privacy headline names for this photo."""
        out = []
        if self.gps:
            out.append("GPS location")
        if "Camera model" in self.fields or "Camera make" in self.fields:
            out.append("device fingerprint")
        if "Software" in self.fields:
            out.append("editing software")
        if any(k in self.fields for k in ("Date taken", "Date original")):
            out.append("timestamps")
        if "Author" in self.fields or "Copyright" in self.fields:
            out.append("authorship")
        return out


# ---------------------------------------------------------------------------
# GPS (pure)
# ---------------------------------------------------------------------------

def gps_to_decimal(gps_ifd: dict) -> tuple[float, float] | None:
    """(lat, lon) in decimal degrees from an EXIF GPS IFD, or None.
    South/west come out negative — the honest signed form."""
    if not gps_ifd:
        return None

    def ratio(value):
        if isinstance(value, tuple) and len(value) == 2 and value[1]:
            return value[0] / value[1]
        return float(value) if value is not None else None

    def dms(key_ref, key_dms):
        ref = gps_ifd.get(key_ref)
        parts = gps_ifd.get(key_dms)
        if not isinstance(parts, (tuple, list)) or len(parts) < 3:
            return None
        try:
            d, m, s = (ratio(p) for p in parts[:3])
        except (TypeError, ValueError):
            return None
        if d is None or m is None or s is None:
            return None
        value = d + m / 60 + s / 3600
        if ref in (b"S", "S", b"W", "W"):
            value = -value
        return value

    lat = dms(1, 2)   # GPSLatitudeRef / GPSLatitude
    lon = dms(3, 4)   # GPSLongitudeRef / GPSLongitude
    if lat is None or lon is None:
        return None
    return round(lat, 6), round(lon, 6)


def gps_altitude(gps_ifd: dict) -> str:
    alt = gps_ifd.get(6)  # GPSAltitude
    if isinstance(alt, tuple) and len(alt) == 2 and alt[1]:
        return f"{alt[0] / alt[1]:.0f} m"
    return ""


def maps_link(lat: float, lon: float) -> str:
    return f"https://maps.google.com/?q={lat},{lon}"


# ---------------------------------------------------------------------------
# Reading one image (Pillow)
# ---------------------------------------------------------------------------

def read_exif(path: str) -> PhotoExif:
    """One image's EXIF story. Never raises — failures are statuses."""
    name = os.path.basename(path)
    result = PhotoExif(source=path, rel=name)
    try:
        with Image.open(path) as img:
            raw = img.getexif()
            if not raw:
                # PNG and friends often carry none — an honest status,
                # not an error.
                result.status = "no exif"
                return result
            for tag_id, label in INTERESTING:
                value = raw.get(tag_id)
                if value:
                    result.fields[label] = str(value).strip()[:200]
            # The Exif sub-IFD: lens lives there.
            try:
                exif_ifd = raw.get_ifd(0x8769)
                lens = exif_ifd.get(0xA434)
                if lens and "Lens model" not in result.fields:
                    result.fields["Lens model"] = str(lens).strip()[:200]
            except (KeyError, AttributeError):
                pass
            # GPS lives in its own IFD.
            try:
                gps_ifd = raw.get_ifd(ExifTags.IFD.GPSInfo)
                coords = gps_to_decimal(dict(gps_ifd))
                if coords:
                    result.gps = coords
                    result.gps_altitude = gps_altitude(dict(gps_ifd))
            except (KeyError, AttributeError):
                pass
    except Exception as exc:
        result.status = "unreadable"
        result.note = type(exc).__name__
    return result


def strip_exif(src: str, dst: str) -> tuple[bool, str]:
    """Write an EXIF-free copy with orientation baked into the pixels
    (strip the tag without applying it and landscape photos turn
    sideways). (ok, note)."""
    try:
        with Image.open(src) as img:
            from PIL import ImageOps
            transposed = ImageOps.exif_transpose(img)
            if transposed is not None:
                img = transposed
            # Save through a format-aware copy: PNG/HEIC keep their
            # container, JPEG/WebP drop every EXIF segment by default.
            params = {}
            if img.format == "JPEG":
                params["quality"] = "keep"
            img.save(dst, format=img.format or None, **params)
        return True, ""
    except Exception as exc:
        return False, type(exc).__name__


# ---------------------------------------------------------------------------
# Collection + report
# ---------------------------------------------------------------------------

def collect_inputs(args) -> list[str]:
    paths: list[str] = []
    if args.mode == "single":
        if not args.single_image:
            raise ValueError("--single-image is required in single mode")
        src = os.path.abspath(args.single_image)
        if not os.path.isfile(src):
            raise ValueError(f"{args.single_image} is not a file")
        paths.append(src)
    elif args.mode == "multiple":
        if not args.input_file:
            raise ValueError("--input-file is required in multiple mode")
        for given in args.input_file:
            src = os.path.abspath(given)
            if not os.path.isfile(src):
                raise ValueError(f"{given} is not a file")
            paths.append(src)
    else:
        if not args.input_folder:
            raise ValueError("--input-folder is required in folder mode")
        root = os.path.abspath(args.input_folder)
        if not os.path.isdir(root):
            raise ValueError(f"{args.input_folder} is not a folder")
        walk = os.walk(root) if args.recursive else [next(os.walk(root))]
        for dirpath, _dirs, files in walk:
            for name in sorted(files):
                if os.path.splitext(name)[1].lower() in IMAGE_EXTS:
                    paths.append(os.path.join(dirpath, name))
        if not paths:
            raise ValueError("no images found in the folder")
    return paths


def build_table_event(photos: list[PhotoExif]) -> dict:
    rows = []
    for p in photos:
        rows.append([
            p.rel,
            {"ok": "🔴 EXIF", "no exif": "🟢 clean",
             "unreadable": "⚫ unreadable",
             "error": "⚫ error"}.get(p.status, p.status),
            ", ".join(p.leaks) or "—",
            f"{p.gps[0]}, {p.gps[1]}" if p.gps else "—",
        ])
    return {
        "type": "table",
        "columns": ["File", "Status", "What it leaks", "GPS"],
        "rows": rows,
    }


def build_markdown(photos: list[PhotoExif], stripped: list[str]) -> str:
    with_gps = [p for p in photos if p.gps]
    with_exif = [p for p in photos if p.status == "ok"]
    clean = [p for p in photos if p.status == "no exif"]
    head = f"## {'🔴' if with_gps else '📷'} {len(with_exif)} photo(s) with EXIF, " \
           f"{len(with_gps)} with GPS"
    lines = [head, ""]

    for p in photos:
        if p.status == "no exif":
            continue
        lines.append(f"### {p.rel}")
        lines.append("")
        if p.status != "ok":
            lines.append(f"- ⚫ {p.status}" + (f" ({p.note})" if p.note else ""))
            lines.append("")
            continue
        for label, value in p.fields.items():
            lines.append(f"- **{label}**: {value}")
        if p.gps:
            lines.append(f"- **GPS**: `{p.gps[0]}, {p.gps[1]}`"
                         + (f" · {p.gps_altitude}" if p.gps_altitude else "")
                         + f" — [on the map]({maps_link(*p.gps)})")
        lines.append("")

    if with_gps:
        lines += ["**The GPS rows are the headline.** A photo's coordinates "
                  "pin where you stood when you pressed the button — home, "
                  "work, the kid's school. Every share of the original "
                  "file shares that.", ""]
    lines.append(f"_Clean (EXIF-free): {len(clean)} · unreadable: "
                 f"{sum(1 for p in photos if p.status == 'unreadable')}._")
    if stripped:
        lines.append("")
        lines.append(f"_**{len(stripped)} clean cop(ies) written** — "
                     "orientation baked into the pixels, EXIF gone; "
                     "originals untouched. The size-focused stripping "
                     "lives in [Image Optimizer](../image-optimizer)._")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(photos: list[PhotoExif], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report + "\n")
    with open(os.path.join(out_dir, "exif_report.csv"), "w",
              newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "status", "leaks", "gps_lat", "gps_lon",
                         "fields"])
        for p in photos:
            writer.writerow([p.rel, p.status, "; ".join(p.leaks),
                             p.gps[0] if p.gps else "",
                             p.gps[1] if p.gps else "",
                             "; ".join(f"{k}={v}" for k, v in
                                       p.fields.items())])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EXIF Inspect — what your photos say about you, "
                    "with optional privacy-first stripping")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-image", help="the image to inspect")
    parser.add_argument("--input-file", action="append", default=[],
                        help="an image to inspect; repeatable")
    parser.add_argument("--input-folder", help="folder of images")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    parser.add_argument("--strip", action="store_true",
                        help="also write EXIF-free copies (orientation "
                             "applied first)")
    parser.add_argument("--output-folder", default="",
                        help="where the clean copies land (with --strip)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no images are read", flush=True)
        return 0

    if not HAVE_PIL:
        print("✗ Pillow is not installed — run "
              "`python3 -m pip install -r requirements.txt` (or press "
              "Prepare Env in PyShell) first", file=sys.stderr, flush=True)
        return 1

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    if args.strip and not args.output_folder:
        print("✗ --output-folder is required with --strip",
              file=sys.stderr, flush=True)
        return 2

    output_folder = os.path.abspath(args.output_folder) \
        if args.output_folder else None
    if output_folder:
        try:
            os.makedirs(output_folder, exist_ok=True)
        except OSError as exc:
            print(f"✗ cannot create the output folder: {exc}",
                  file=sys.stderr, flush=True)
            return 1

    total = len(sources)
    log(f"Inspecting EXIF of {total} image(s)")
    status(f"{total} image(s)" + (" · clean copies on" if args.strip else ""))

    photos: list[PhotoExif] = []
    stripped: list[str] = []
    for i, src in enumerate(sources, 1):
        photo = read_exif(src)
        photos.append(photo)
        rel = os.path.basename(src)
        if photo.status == "ok":
            log(f"  🔴 {rel}: {', '.join(photo.leaks) or 'EXIF present'}")
        elif photo.status == "no exif":
            log(f"  🟢 {rel}: no EXIF (clean)")
        else:
            log(f"  ⚫ {rel}: {photo.status}")
        if args.strip and photo.status in ("ok", "no exif"):
            dst = os.path.join(output_folder, rel)
            ok, note = strip_exif(src, dst)
            if ok:
                stripped.append(dst)
                photo.orientation_applied = True
            else:
                log(f"    ⚠️ strip failed: {note}")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    if photos and all(p.status == "unreadable" for p in photos):
        print("✗ every image was unreadable — nothing to inspect",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(photos, stripped)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(photos))
    emit({"type": "markdown", "content": report})
    write_artifacts(photos, report)

    with_gps = sum(1 for p in photos if p.gps)
    summary = (f"{sum(1 for p in photos if p.status == 'ok')} with EXIF · "
               f"{with_gps} with GPS"
               + (f" · {len(stripped)} cleaned" if stripped else ""))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
