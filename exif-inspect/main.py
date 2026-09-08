#!/usr/bin/env python3
"""exif-inspect/main.py — what does this photo say about you?

Dumps the EXIF of one image, several, or a folder, as a privacy
inventory: **GPS coordinates** (spelled out in decimal degrees, with a
map link — the single loudest leak), the camera and lens (a device
fingerprint), the software chain (the editing history), the dates
(when you were where), and the author/copyright fields.

Past EXIF proper it reads the container too: the frames hidden inside
multi-picture files (a motion-photo video frame, the unedited original
some cameras embed) and the Extended XMP Photoshop splits across
segments — plus the small preview copy EXIF carries, compared against
the photo it claims to show.

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
import io
import itertools
import json
import math
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

try:  # Pillow is imported lazily — argparse and the guard run first
    from PIL import Image, ExifTags, ImageChops, ImageStat, IptcImagePlugin
    HAVE_PIL = True
except ImportError:  # pragma: no cover — environment-dependent
    HAVE_PIL = False

try:  # ImageCms ships with Pillow but needs littlecms at build time
    from PIL import ImageCms
except ImportError:  # pragma: no cover — environment-dependent
    ImageCms = None

try:  # HEIC is what phones shoot by default, and Pillow cannot read it
    import pillow_heif
    pillow_heif.register_heif_opener()
    HAVE_HEIF = True
except ImportError:  # pragma: no cover — environment-dependent
    HAVE_HEIF = False

IMAGE_EXTS = {".jpg", ".jpeg", ".tif", ".tiff", ".webp", ".png",
              ".heic", ".heif", ".avif"}

# Read only with pillow-heif installed — Pillow alone opens AVIF but
# never HEIC, which is the default on every iPhone since 2017.
HEIF_EXTS = {".heic", ".heif"}

# The statuses that mean "no inventory taken" — all of them, and the
# run had nothing to inspect (exit 1).
FAILED = ("unreadable", "error")

# The privacy-relevant tags, in display order — the report's outline.
# Raw EXIF ids; names via ExifTags at runtime. Two ids may share a
# label (the two OffsetTime flavours) — the first one found wins.
INTERESTING = [
    (0x010F, "Camera make"),
    (0x0110, "Camera model"),
    (0xA434, "Lens model"),
    # Serials are the strongest link of all: GPS says where you were
    # once, a body serial ties every photo you ever posted together.
    (0xA431, "Camera serial"),
    (0xA435, "Lens serial"),
    (0xA430, "Camera owner"),
    (0x0132, "Date taken"),
    (0x9003, "Date original"),
    (0x9011, "Timezone"),       # OffsetTimeOriginal
    (0x9010, "Timezone"),       # OffsetTime — same label, first wins
    (0x0131, "Software"),
    (0x013B, "Author"),
    (0x8298, "Copyright"),
    (0x9286, "User comment"),
]

# XMP is enumerated, not searched: a shortlist of well-known keys misses
# the drone that invented its own namespace, xmpMM:DocumentID (which ties
# every export of one original together) and plus:LicensorName. These
# keys remain as the fallback for a packet too broken to parse as XML.
XMP_KEYS = (
    "dc:creator", "dc:rights", "dc:description", "xmp:CreatorTool",
    "photoshop:City", "photoshop:State", "photoshop:Country",
    "photoshop:Credit", "Iptc4xmpExt:PersonInImage",
    "exif:GPSLatitude", "exif:GPSLongitude",
    "aux:SerialNumber", "aux:LensSerialNumber",
)

# Which leak label an XMP property earns, matched as substrings of the
# lowercased local name — so a namespace nobody has heard of
# (drone-dji:GpsLatitude) still lands in the right place.
# ORDER IS PRECEDENCE, most specific first: names overlap, and
# CameraSerialNumber is a serial before it is a camera, CreatorTool is
# software before it is a creator.
XMP_CATEGORIES = (
    ("device serial", ("serial", "instanceid", "documentid", "identifier")),
    ("editing software", ("creatortool", "software", "history")),
    ("location", ("gps", "latitude", "longitude", "altitude", "location",
                  "city", "state", "province", "country", "sublocation",
                  "heading", "direction", "bearing")),
    ("authorship", ("creator", "author", "artist", "owner", "credit",
                    "rights", "copyright", "licensor", "contact", "email",
                    "phone", "person", "people", "face", "byline")),
    ("device fingerprint", ("make", "model", "lens", "camera", "device")),
    ("timestamps", ("date", "time")),
)
# Free text the photographer typed. It earns no leak label of its own —
# but it is worth printing, because people write anything in there.
XMP_DESCRIPTIVE = ("description", "caption", "comment", "title", "headline",
                   "keyword", "subject", "label", "note")

# RDF/XMP plumbing: element and attribute names that are structure, not
# properties.
RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
META_NS = "adobe:ns:meta/"
XML_NS = "http://www.w3.org/XML/1998/namespace"

# IPTC records worth naming — the fields a newsroom fills in and a
# sharer forgets, contact details included.
IPTC_FIELDS = {
    (2, 80): "IPTC by-line",
    (2, 85): "IPTC by-line title",
    (2, 90): "IPTC city",
    (2, 92): "IPTC sublocation",
    (2, 95): "IPTC state",
    (2, 101): "IPTC country",
    (2, 105): "IPTC headline",
    (2, 116): "IPTC copyright",
    (2, 118): "IPTC contact",
    (2, 120): "IPTC caption",
}

# Field-name prefixes for metadata that is not EXIF at all.
SIDECAR_PREFIXES = ("XMP ", "IPTC ", "PNG text: ")

# Thumbnail staleness, calibrated on built fixtures: an honest
# thumbnail scores <=0.51 even for pure noise at quality 30, while a
# stale one (different frame, crop, painted-over subject) scores >=6.9.
# 4.0 sits an order of magnitude clear of the honest side.
THUMBNAIL_DISTANCE_LIMIT = 4.0
# Rounding when a thumbnail is fitted into a box costs under 1%; a real
# crop moves the aspect ratio by tens of percent.
THUMBNAIL_ASPECT_TOLERANCE = 0.05

# How close two photos must be to count as the same place. 150 m is a
# city block — tight enough to separate home from the corner shop.
CLUSTER_RADIUS_M = 150

# Colour profiles everyone ships. Anything else is named after somebody's
# actual hardware, which makes it a fingerprint.
GENERIC_ICC = ("srgb", "display p3", "displayp3", "adobe rgb", "generic",
               "rec. 709", "rec709", "gray gamma", "dot gain", "coated",
               "apple wide color", "linear", "gamma 2.2", "c2ci")

# The JPEG container, past EXIF. XMP segment signatures (Adobe XMP
# Part 3) and the Multi-Picture Format tables (CIPA DC-007).
XMP_STD = b"http://ns.adobe.com/xap/1.0/\x00"
XMP_EXT = b"http://ns.adobe.com/xmp/extension/\x00"

# The MPEntry type code — the low 24 bits of the attribute word
# (Pillow's own _getmp reads the same bits). 0x030000 is the photo
# itself; the rest are other images packed into the same file.
# 0x040000 is the quiet jackpot: some cameras embed the UNEDITED
# original, so an edit can be undone by anyone who finds it.
MPF_TYPES = {
    0x000000: "hidden frame",
    0x010001: "large thumbnail (VGA)",
    0x010002: "large thumbnail (full HD)",
    0x010003: "large thumbnail (4K)",
    0x010004: "large thumbnail (8K)",
    0x010005: "large thumbnail (16K)",
    0x020001: "panorama frame",
    0x020002: "disparity frame",
    0x020003: "multi-angle frame",
    0x030000: "the photo itself",
    0x040000: "original preservation copy",
    0x050000: "gain map",
}
# A large thumbnail previews the same pixels — an inventory line, not
# a second image worth a leak label.
MPF_THUMBNAILS = frozenset(range(0x010001, 0x010006))

# Every APP segment lives before SOS, so the container scan needs the
# file's head, never its pixel stream. 1 MiB holds any normal metadata
# region; a header that runs longer (Photoshop's multi-MB Extended
# XMP) grows to the whole file rather than miss its segments.
CONTAINER_HEAD_BYTES = 1024 * 1024

# One leak label, whichever block carried the value — a name in a PNG
# text chunk is authorship exactly as much as an EXIF Artist tag is.
AUTHOR_FIELDS = ("Author", "Copyright", "Camera owner", "XMP dc:creator",
                 "XMP dc:rights", "XMP photoshop:Credit",
                 "XMP Iptc4xmpExt:PersonInImage", "IPTC by-line",
                 "IPTC by-line title", "IPTC copyright", "IPTC contact",
                 "PNG text: Author", "PNG text: Artist",
                 "PNG text: Copyright")
SERIAL_FIELDS = ("Camera serial", "Lens serial", "Maker note",
                 "XMP aux:SerialNumber", "XMP aux:LensSerialNumber")
SOFTWARE_FIELDS = ("Software", "XMP xmp:CreatorTool", "PNG text: Software")
TIME_FIELDS = ("Date taken", "Date original", "Timezone", "GPS timestamp",
               "PNG text: Creation Time")
PLACE_FIELDS = ("XMP exif:GPSLatitude", "XMP photoshop:City",
                "XMP photoshop:State", "XMP photoshop:Country",
                "IPTC city", "IPTC sublocation", "IPTC state",
                "IPTC country")


def ratio(value) -> float | None:
    """One EXIF rational as a float. Real files hand back IFDRational
    (or a plain number); the (num, den) pair form only shows up in
    hand-built EXIF — both are honest input."""
    if isinstance(value, tuple) and len(value) == 2 and value[1]:
        return value[0] / value[1]
    return float(value) if value is not None else None


def text(value) -> str:
    """One EXIF value as a readable string. UserComment arrives as
    bytes behind an 8-byte encoding prefix — decode it rather than
    printing b'ASCII\\x00\\x00\\x00...' at the user."""
    if isinstance(value, bytes):
        encoding = "utf-8"
        for prefix, prefix_encoding in ((b"ASCII\x00\x00\x00", "ascii"),
                                        (b"UNICODE\x00", "utf-16"),
                                        (b"\x00" * 8, "ascii")):
            if value.startswith(prefix):
                value = value[len(prefix):]
                encoding = prefix_encoding
                break
        value = value.decode(encoding, "replace")
    return str(value).replace("\x00", "").strip()[:200]


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
    thumbnail_stale: bool = False
    hidden_frames: bool = False
    note: str = ""

    @property
    def leaks(self) -> list[str]:
        """The privacy headline names for this photo."""
        out = []
        # The EXIF/IPTC/PNG names are a fixed vocabulary; the XMP ones
        # are open-ended, so they are classified by name instead.
        from_xmp = xmp_categories(self.fields)
        if self.gps or any(k in self.fields for k in PLACE_FIELDS) \
                or "location" in from_xmp:
            out.append("GPS location" if self.gps else "location")
        if any(k in self.fields for k in ("Camera model", "Camera make",
                                          "ICC profile")) \
                or "device fingerprint" in from_xmp:
            out.append("device fingerprint")
        if any(k in self.fields for k in SERIAL_FIELDS) \
                or "device serial" in from_xmp:
            out.append("device serial")
        if any(k in self.fields for k in SOFTWARE_FIELDS) \
                or "editing software" in from_xmp:
            out.append("editing software")
        if any(k in self.fields for k in TIME_FIELDS) \
                or "timestamps" in from_xmp:
            out.append("timestamps")
        if any(k in self.fields for k in AUTHOR_FIELDS) \
                or "authorship" in from_xmp:
            out.append("authorship")
        if any(k.startswith(SIDECAR_PREFIXES) for k in self.fields):
            out.append("XMP/IPTC metadata")
        if self.thumbnail_stale:
            out.append("stale thumbnail")
        if self.hidden_frames:
            out.append("hidden frames")
        return out


# ---------------------------------------------------------------------------
# GPS (pure)
# ---------------------------------------------------------------------------

def gps_to_decimal(gps_ifd: dict) -> tuple[float, float] | None:
    """(lat, lon) in decimal degrees from an EXIF GPS IFD, or None.
    South/west come out negative — the honest signed form."""
    if not gps_ifd:
        return None

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
    """Altitude in metres, signed — GPSAltitudeRef 1 means below sea
    level. Same rational forms as the coordinates."""
    try:
        metres = ratio(gps_ifd.get(6))  # GPSAltitude
    except (TypeError, ValueError, ZeroDivisionError):
        return ""
    if metres is None:
        return ""
    if gps_ifd.get(5) in (1, b"\x01"):  # GPSAltitudeRef: below sea level
        metres = -metres
    return f"{metres:.0f} m"


def gps_extras(gps_ifd: dict) -> dict[str, str]:
    """The GPS fields past the coordinates: the satellite clock (a
    second, independent timestamp — in UTC, so it also pins the
    timezone) and which way the camera was pointed."""
    out: dict[str, str] = {}
    when = [text(gps_ifd[29])] if gps_ifd.get(29) else []  # GPSDateStamp
    clock = gps_ifd.get(7)                                 # GPSTimeStamp
    if isinstance(clock, (tuple, list)) and len(clock) >= 3:
        try:
            h, m, sec = (ratio(part) for part in clock[:3])
        except (TypeError, ValueError, ZeroDivisionError):
            h = m = sec = None
        if None not in (h, m, sec):
            when.append(f"{int(h):02d}:{int(m):02d}:{int(sec):02d}")
    if when:
        out["GPS timestamp"] = " ".join(when) + " UTC"
    try:
        heading = ratio(gps_ifd.get(17))                   # GPSImgDirection
    except (TypeError, ValueError, ZeroDivisionError):
        heading = None
    if heading is not None:
        ref = text(gps_ifd.get(16) or "")
        out["Facing direction"] = f"{heading:.0f}°" + {
            "T": " true", "M": " magnetic"}.get(ref, "")
    return out


def xmp_category(name: str) -> str | None:
    """The leak label an XMP property name earns, or None."""
    local = name.rsplit(":", 1)[-1].lower()
    for label, words in XMP_CATEGORIES:
        if any(word in local for word in words):
            return label
    return None


def xmp_categories(names) -> set[str]:
    """The leak labels a photo's XMP property names earn between them."""
    found = set()
    for name in names:
        if name.startswith("XMP "):
            label = xmp_category(name[4:])
            if label:
                found.add(label)
    return found


def xmp_worth_naming(name: str) -> bool:
    """Whether a property belongs in the report. Lightroom writes a
    hundred develop settings per photo; nobody's privacy turns on
    crs:WhiteBalance, and printing them all would bury the line that
    matters."""
    local = name.rsplit(":", 1)[-1].lower()
    return xmp_category(name) is not None \
        or any(word in local for word in XMP_DESCRIPTIVE)


def xmp_properties(xml: str) -> dict[str, str]:
    """Every property in one XMP packet, as {"prefix:local": value}.
    XMP is RDF, so a property is either an attribute on rdf:Description
    or an element wrapping an rdf:Seq/Bag/Alt of rdf:li — both shapes
    are read here. Raises on input that is not XML; callers fall back."""
    prefixes: dict[str, str] = {}
    for _, (prefix, uri) in ET.iterparse(io.StringIO(xml),
                                         events=("start-ns",)):
        prefixes.setdefault(uri, prefix)
    root = ET.fromstring(xml)

    def name_of(tag: str) -> str | None:
        if not tag.startswith("{"):
            return tag
        uri, local = tag[1:].split("}", 1)
        if uri in (RDF_NS, META_NS, XML_NS):
            return None                   # structure, not a property
        prefix = prefixes.get(uri)
        return f"{prefix}:{local}" if prefix else local

    out: dict[str, str] = {}
    for element in root.iter():
        for key, value in element.attrib.items():   # the compact form
            name = name_of(key)
            if name and value.strip():
                out.setdefault(name, value.strip())
        name = name_of(element.tag)
        if not name:
            continue
        # itertext() flattens the rdf:Seq/Alt/li wrappers around a value.
        value = " ".join("".join(element.itertext()).split())
        if value:
            out.setdefault(name, value)
    return out


def xmp_known_keys(xml: str) -> dict[str, str]:
    """The old shortlist scan, kept for packets too broken to parse as
    XML — a truncated XMP is still worth reading for a creator name."""
    out: dict[str, str] = {}
    for key in XMP_KEYS:
        name = re.escape(key)
        found = (re.search(rf'{name}\s*=\s*"([^"]*)"', xml)
                 or re.search(rf"<{name}[^>]*>\s*"
                              rf"(?:<rdf:Seq[^>]*>\s*<rdf:li[^>]*>)?\s*"
                              rf"([^<]+)", xml))
        if found and found.group(1).strip():
            out[key] = found.group(1)
    return out


def xmp_report(properties: dict[str, str]) -> dict[str, str]:
    """Named properties as report fields, plus a count of the rest —
    develop settings are not worth a line each, but their presence is
    worth saying, so nothing is silently dropped."""
    out: dict[str, str] = {}
    namespaces: set[str] = set()
    for name, value in properties.items():
        if xmp_worth_naming(name):
            out[f"XMP {name}"] = text(value)
        else:
            namespaces.add(name.rsplit(":", 1)[0] if ":" in name else name)
    if namespaces:
        out["XMP (other)"] = (
            f"{len(properties) - len(out)} more properties in "
            f"{len(namespaces)} namespace"
            f"{'' if len(namespaces) == 1 else 's'}: "
            f"{', '.join(sorted(namespaces)[:6])}")
    return out


def xmp_fields(blob) -> dict[str, str]:
    """The privacy inventory of one XMP packet. XMP survives when EXIF
    does not — a Lightroom export with no EXIF still carries
    dc:creator — so a file is not clean just because getexif() is
    empty."""
    return xmp_fields_from([blob]) if blob else {}


def xmp_fields_from(blobs: list) -> dict[str, str]:
    """Several packets as one inventory: the one Pillow kept, the ones
    it overwrote, and the reassembled extension. Merged as properties
    rather than as text — two XML documents glued together are not one
    XML document, and the parser would rightly refuse them."""
    merged: dict[str, str] = {}
    for blob in blobs:
        if not blob:
            continue
        xml = blob.decode("utf-8", "replace") if isinstance(blob, bytes) \
            else str(blob)
        try:
            properties = xmp_properties(xml)
        except Exception:  # truncated or malformed XMP is common
            properties = xmp_known_keys(xml)
        for name, value in properties.items():
            merged.setdefault(name, value)
    return xmp_report(merged)


def maps_link(lat: float, lon: float) -> str:
    return f"https://maps.google.com/?q={lat},{lon}"


def distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Metres between two coordinates, flat-earth style. Good to a
    fraction of a percent at the scale a photo cluster spans, and it
    keeps the module dependency-free."""
    mean_lat = math.radians((lat1 + lat2) / 2)
    dx = math.radians(lon2 - lon1) * math.cos(mean_lat)
    dy = math.radians(lat2 - lat1)
    return math.hypot(dx, dy) * 6371000


def gps_clusters(points: list[tuple[str, float, float]],
                 radius_m: float = CLUSTER_RADIUS_M) -> list[dict]:
    """Group photos by place: a photo joins the first cluster whose
    centre is within radius_m, otherwise it starts one. One photo of a
    beach is a holiday; forty photos inside one city block is where you
    live — which is the thing a single-file report cannot see."""
    clusters: list[dict] = []
    for name, lat, lon in points:
        for cluster in clusters:
            if distance_m(cluster["lat"], cluster["lon"],
                          lat, lon) <= radius_m:
                cluster["points"].append((name, lat, lon))
                # Running centroid, so a cluster drifts to its members
                # instead of anchoring on whichever photo came first.
                count = len(cluster["points"])
                cluster["lat"] += (lat - cluster["lat"]) / count
                cluster["lon"] += (lon - cluster["lon"]) / count
                break
        else:
            clusters.append({"lat": lat, "lon": lon,
                             "points": [(name, lat, lon)]})
    for cluster in clusters:
        cluster["spread_m"] = max(
            distance_m(cluster["lat"], cluster["lon"], lat, lon)
            for _, lat, lon in cluster["points"])
    return sorted(clusters, key=lambda c: len(c["points"]), reverse=True)


def fingerprint(img):
    """A 16×16 grayscale print of a picture — coarse enough that JPEG
    noise and quality do not register, fine enough to tell two
    different frames apart."""
    return img.convert("L").resize((16, 16), Image.Resampling.BILINEAR)


def picture_distance(a, b) -> float:
    """Mean 0–255 difference between two fingerprints."""
    return ImageStat.Stat(ImageChops.difference(
        fingerprint(a), fingerprint(b))).mean[0]


# ---------------------------------------------------------------------------
# Reading one image (Pillow)
# ---------------------------------------------------------------------------

def read_exif_block(img, result: PhotoExif) -> None:
    """The EXIF proper: base IFD, the Exif sub-IFD, the GPS IFD."""
    raw = img.getexif()
    if not raw:
        return
    # The base IFD first, then the Exif sub-IFD — the lens, the serials,
    # the original date and the user comment live only in the sub-IFD,
    # so reading just the base one loses them.
    try:
        exif_ifd = raw.get_ifd(0x8769)
    except (KeyError, AttributeError):
        exif_ifd = {}
    for tag_id, label in INTERESTING:
        if label in result.fields:   # two ids, one label: first wins
            continue
        value = raw.get(tag_id) or exif_ifd.get(tag_id)
        if value:
            result.fields[label] = text(value)
    blob = exif_ifd.get(0x927C)      # MakerNote
    if blob:
        # Undocumented per vendor, and known to hold body serials,
        # shutter counts and on some bodies a second copy of the GPS
        # fix — report its weight rather than pretending to read it.
        result.fields["Maker note"] = f"{len(blob)} bytes (vendor blob)"
    try:
        gps_ifd = dict(raw.get_ifd(ExifTags.IFD.GPSInfo))
    except (KeyError, AttributeError):
        gps_ifd = {}
    coords = gps_to_decimal(gps_ifd)
    if coords:
        result.gps = coords
        result.gps_altitude = gps_altitude(gps_ifd)
    result.fields.update(gps_extras(gps_ifd))


def thumbnail_bytes(img) -> bytes | None:
    """The JPEG thumbnail EXIF parks in IFD1, or None. Pillow parses
    IFD1 but hands back only offsets into the raw EXIF blob, so the
    bytes have to be sliced out by hand."""
    blob = img.info.get("exif")
    if not blob:
        return None
    try:
        ifd1 = img.getexif().get_ifd(ExifTags.IFD.IFD1)
    except (KeyError, AttributeError, ValueError):
        return None
    offset, length = ifd1.get(0x0201), ifd1.get(0x0202)
    if not offset or not length:
        return None
    tiff = blob[6:] if blob[:6] == b"Exif\x00\x00" else blob
    chunk = tiff[offset:offset + length]
    return chunk if chunk[:2] == b"\xff\xd8" else None   # must be a JPEG


def read_thumbnail(img, result: PhotoExif) -> None:
    """Compare the embedded thumbnail with the photo it claims to
    preview. Editors that crop or paint over a photo do not always
    rewrite the thumbnail, so the redaction covers the big copy while
    the small one still shows what was removed."""
    data = thumbnail_bytes(img)
    if not data:
        return
    aspect = img.width / img.height       # before draft() rescales it
    try:
        with Image.open(io.BytesIO(data)) as thumb:
            thumb.load()
            size = f"{thumb.width}×{thumb.height}"
            cropped = abs(aspect - thumb.width / thumb.height) / aspect \
                > THUMBNAIL_ASPECT_TOLERANCE
            # draft() decodes the JPEG at 1/8 scale — an 8x saving on a
            # 24MP file, and the fingerprint is 16x16 either way.
            img.draft("L", (32, 32))
            distance = picture_distance(img, thumb)
    except Exception:
        result.fields["Thumbnail"] = f"{len(data)} bytes (unreadable)"
        return
    result.thumbnail_stale = cropped or distance > THUMBNAIL_DISTANCE_LIMIT
    if not result.thumbnail_stale:
        result.fields["Thumbnail"] = f"{size} (matches the photo)"
        return
    result.fields["Thumbnail"] = (
        f"{size} — ⚠️ shows "
        + ("a different shape, so the photo was cropped afterwards"
           if cropped else "a different picture")
        + "; the embedded copy may still hold what the edit removed")


def icc_fields(blob) -> dict[str, str]:
    """A colour profile is usually the same sRGB everybody ships — but
    one named after an actual monitor or scanner is a device
    fingerprint, so report only the profiles that are not generic."""
    if not blob or ImageCms is None:
        return {}
    try:
        profile = ImageCms.ImageCmsProfile(io.BytesIO(blob)).profile
        description = (profile.profile_description or "").strip()
    except Exception:  # a broken profile is not a read failure
        return {}
    if not description or any(g in description.lower() for g in GENERIC_ICC):
        return {}
    return {"ICC profile": text(description)}


def read_sidecar_blocks(img, result: PhotoExif) -> None:
    """XMP, IPTC and PNG text chunks — the metadata that outlives EXIF.
    A PNG whose tEXt chunks say `Author: Jane` has no EXIF at all, and
    calling that clean is the one mistake this script must not make."""
    result.fields.update(xmp_fields(img.info.get("xmp")))
    try:
        iptc = IptcImagePlugin.getiptcinfo(img) or {}
    except Exception:  # a malformed IPTC block is not a read failure
        iptc = {}
    for key, label in IPTC_FIELDS.items():
        value = iptc.get(key)
        if isinstance(value, (list, tuple)):
            value = b"; ".join(v for v in value if isinstance(v, bytes))
        if value:
            result.fields[label] = text(value)
    # PNG tEXt/iTXt/zTXt — free-form, so cap the count, not the trust.
    for key, value in list(getattr(img, "text", {}).items())[:10]:
        if value:
            result.fields[f"PNG text: {key}"] = text(value)
    result.fields.update(icc_fields(img.info.get("icc_profile")))


# ---------------------------------------------------------------------------
# The JPEG container: hidden frames (MPF) + Extended XMP
# ---------------------------------------------------------------------------

def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def jpeg_segments(data: bytes):
    """(marker, payload) for every JPEG segment before SOS — where all
    the APP segments (EXIF, XMP, ICC, MPF) live, so container work
    never touches the entropy-coded pixels. Anything not segment-shaped
    (a truncated or hostile file) simply ends the scan, never raises."""
    if data[:2] != b"\xff\xd8":
        return
    i, size = 2, len(data)
    while i < size:
        if data[i] != 0xFF:
            return                      # lost sync — no more segments
        j = i + 1
        while j < size and data[j] == 0xFF:    # fill bytes before a marker
            j += 1
        if j >= size:
            return
        marker = data[j]
        i = j + 1
        if marker in (0x00, 0x01, 0xC8) or 0xD0 <= marker <= 0xD9:
            return                      # stuffing / standalone / EOI
        if i + 2 > size:
            return
        length = int.from_bytes(data[i:i + 2], "big")
        if length < 2 or i + length > size:
            return                      # truncated segment — stop here
        yield marker, data[i + 2:i + length]
        if marker == 0xDA:              # SOS: the pixel stream follows
            return
        i += length


def read_mpf(payload: bytes) -> list[dict]:
    """The MPEntry list from an APP2 'MPF\\x00' payload's TIFF part —
    one entry per image in the file, the photo itself first. Offsets
    inside the block count from the TIFF header (the MP Endian field),
    per CIPA DC-007 §5.2.3 — the one layout difference from plain
    EXIF. Malformed input yields what parsed, never raises."""
    if len(payload) < 8:
        return []
    if payload[:2] == b"II":
        end = "little"
    elif payload[:2] == b"MM":
        end = "big"
    else:
        return []

    def u(off: int, width: int) -> int:
        return int.from_bytes(payload[off:off + width], end)

    ifd = u(4, 4)
    if ifd < 8 or ifd + 2 > len(payload):
        return []
    table = None
    for n in range(u(ifd, 2)):
        entry = ifd + 2 + 12 * n
        if entry + 12 > len(payload):
            break
        if u(entry, 2) != 0xB002:           # MPEntry
            continue
        count, offset = u(entry + 4, 4), u(entry + 8, 4)
        if count and count % 16 == 0 and offset + count <= len(payload):
            table = payload[offset:offset + count]
        break
    entries: list[dict] = []
    if table:
        for k in range(0, len(table) - 15, 16):
            entries.append({"attr": int.from_bytes(table[k:k + 4], end),
                            "size": int.from_bytes(table[k + 4:k + 8], end)})
    return entries


def mpf_fields(entries: list[dict]) -> tuple[dict[str, str], bool]:
    """The 'Hidden frames' field, and whether it is a leak. One entry
    alone is the photo itself — MPF saying nothing — so ({}, False).
    A large thumbnail previews the same pixels: an inventory line,
    not a leak. Anything else beyond the photo (a motion-photo video
    frame, the unedited original, panorama frames) is a second image,
    and the 'hidden frames' label is earned."""
    if len(entries) < 2:
        return {}, False
    frames = []
    leak = False
    for entry in entries[1:]:
        code = entry["attr"] & 0xFFFFFF
        name = MPF_TYPES.get(code) or f"frame (type 0x{code:06x})"
        frames.append(f"{name} ({human_bytes(entry['size'])})")
        if code not in MPF_THUMBNAILS:
            leak = True
    value = (f"{len(entries)} images in this file — beyond the photo "
             f"itself: {', '.join(frames)}. They ride in the file body, "
             "not the EXIF, so most metadata strippers leave them "
             "behind; the clean copies here drop them")
    return {"Hidden frames": value}, leak


def extended_xmp(segments: list[tuple[int, bytes]]) -> tuple[list[bytes], bool]:
    """The XMP extension part, assembled from its APP1 chunks.
    Photoshop splits a big XMP into ~64 KiB pieces: the main packet
    (the only one Pillow reads) plus 'extension' segments — a 32-char
    GUID, the total length, the chunk's offset, then the chunk bytes —
    which Pillow drops on the floor. Returns (whole packets, whether
    any chunk was seen at all)."""
    chunks: dict[str, dict[int, bytes]] = {}
    totals: dict[str, int] = {}
    for marker, payload in segments:
        if marker != 0xE1 or not payload.startswith(XMP_EXT):
            continue
        body = payload[len(XMP_EXT):]
        if len(body) < 40:
            continue
        guid = body[:32].decode("ascii", "replace")
        chunks.setdefault(guid, {})[int.from_bytes(body[36:40], "big")] \
            = body[40:]
        totals[guid] = int.from_bytes(body[32:36], "big")
    packets = []
    for guid, parts in chunks.items():
        data = b"".join(parts[offset] for offset in sorted(parts))
        if totals[guid] and len(data) == totals[guid]:
            packets.append(data)
    return packets, bool(chunks)


def read_container_blocks(img, path: str, result: PhotoExif) -> None:
    """What the JPEG container carries that Pillow never surfaces:
    the MPF index (several images inside one file — motion photos,
    multi-picture files) and the XMP split across segments (Pillow
    keeps only the last standard packet and drops the extension
    chunks entirely). TIFF, PNG and WebP have neither: the JPEG magic
    check sends them home after two bytes."""
    # MPF: Pillow already slices the APP2 'MPF\\x00' payload into
    # info["mp"] — whether or not it went on to adopt the file as MPO.
    fields, leak = mpf_fields(read_mpf(img.info.get("mp") or b""))
    result.fields.update(fields)
    result.hidden_frames = leak
    # XMP beyond the packet Pillow kept: a raw scan of the segment
    # region — every standard APP1 (not just the last) plus the
    # extension chunks, reassembled by GUID.
    try:
        with open(path, "rb") as fh:
            if fh.read(2) != b"\xff\xd8":
                return                  # Extended XMP is JPEG-only
            head = b"\xff\xd8" + fh.read(CONTAINER_HEAD_BYTES - 2)
            segments = list(jpeg_segments(head))
            if len(head) == CONTAINER_HEAD_BYTES \
                    and not any(m == 0xDA for m, _ in segments):
                # The metadata region ran past the window (Photoshop's
                # multi-MB Extended XMP) — grow to the whole file
                # rather than miss its segments.
                segments = list(jpeg_segments(head + fh.read()))
    except OSError:
        return
    xmp_blobs = [payload[len(XMP_STD):] for marker, payload in segments
                 if marker == 0xE1 and payload.startswith(XMP_STD)]
    packets, saw_chunks = extended_xmp(segments)
    xmp_blobs += packets
    if xmp_blobs:
        result.fields.update(xmp_fields_from(xmp_blobs))
    if saw_chunks and not packets:
        # Present but unassemblable — reported, never silently
        # dropped and never guessed at.
        result.fields["XMP (extended)"] = \
            "present, but the chunks do not reassemble"


def read_exif(path: str, rel: str | None = None) -> PhotoExif:
    """One image's privacy inventory. Never raises — failures are
    statuses. EXIF is the headline, but it is not the only place a
    name, a place or a serial hides."""
    result = PhotoExif(source=path, rel=rel or os.path.basename(path))
    try:
        img = Image.open(path)
    except Exception as exc:
        result.status = "unreadable"
        result.note = type(exc).__name__
        if not HAVE_HEIF and os.path.splitext(path)[1].lower() in HEIF_EXTS:
            # The commonest cause by far — name it instead of leaving
            # an iPhone photo looking like a corrupt file.
            result.note = "HEIC needs pillow-heif (press Prepare Env)"
        return result
    try:
        with img:
            read_exif_block(img, result)
            read_sidecar_blocks(img, result)
            read_container_blocks(img, path, result)
            read_thumbnail(img, result)  # last: draft() rescales the image
    except Exception as exc:  # opened fine, then the metadata parse blew up
        result.status = "error"
        result.note = type(exc).__name__
        return result
    if not result.fields and not result.gps:
        # Nothing anywhere — the honest 🟢, not an error.
        result.status = "no exif"
    return result


def strip_exif(src: str, dst: str) -> tuple[bool, str]:
    """Write an EXIF-free copy with orientation baked into the pixels
    (strip the tag without applying it and landscape photos turn
    sideways). (ok, note)."""
    if os.path.abspath(src) == os.path.abspath(dst):
        # The originals are never touched — a clean copy that lands on
        # its own source is not a copy, it is a destroyed original.
        return False, "would overwrite the original"
    try:
        with Image.open(src) as img:
            from PIL import ImageOps
            # exif_transpose() hands back a fresh image whose .format is
            # None, and quality="keep" reads the quantization tables off
            # the original JpegImageFile — so hold on to both.
            fmt = img.format
            out = img
            if img.getexif().get(0x0112, 1) in (2, 3, 4, 5, 6, 7, 8):
                # A rotated photo: bake the rotation into the pixels, or
                # dropping the Orientation tag turns the photo sideways.
                out = ImageOps.exif_transpose(img) or img
            # Save through a format-aware copy: PNG/HEIC keep their
            # container, and every format takes its EXIF from the save
            # call alone — a plain save drops the block.
            params = {}
            if fmt in ("JPEG", "MPO"):
                tables = getattr(img, "quantization", None)
                if out is not img:
                    # A rotated photo is re-encoded whatever we do.
                    params["quality"] = 95
                elif fmt == "JPEG":
                    # Untouched pixels keep the source's own tables, so
                    # the copy does not lose a generation.
                    params["quality"] = "keep"
                elif tables:
                    # An MPO (every phone HDR shot, every file with
                    # hidden frames) is a JPEG wearing another format
                    # name — and quality="keep" checks the name, not the
                    # file, so it refuses. Hand the encoder the source's
                    # own tables directly for the same lossless effect.
                    from PIL import JpegImagePlugin
                    params["qtables"] = tables
                    params["subsampling"] = JpegImagePlugin.get_sampling(img)
                else:
                    params["quality"] = 95
            elif fmt == "HEIF":
                # Alone among the savers, pillow-heif's takes EXIF and
                # XMP from the SOURCE IMAGE rather than from the save
                # call — say no explicitly or the "clean" copy keeps the
                # GPS. Its default quality is brutal as well (a 230 KB
                # photo comes back 39 KB); 90 lands on the source's own
                # size, measured.
                params.update(exif=None, xmp=None, quality=90)
            out.save(dst, format=fmt or None, **params)
        return True, ""
    except Exception as exc:
        return False, type(exc).__name__


# ---------------------------------------------------------------------------
# Collection + report
# ---------------------------------------------------------------------------

class NoImages(Exception):
    """Nothing to inspect — an empty run, not a bad command line."""


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
        # islice, not next() — an unreadable folder makes os.walk yield
        # nothing at all, and next() would raise StopIteration at the user.
        walk = os.walk(root) if args.recursive \
            else itertools.islice(os.walk(root), 1)
        for dirpath, _dirs, files in walk:
            for name in sorted(files):
                if os.path.splitext(name)[1].lower() in IMAGE_EXTS:
                    paths.append(os.path.join(dirpath, name))
        if not paths:
            raise NoImages(f"no images found in {args.input_folder} "
                           "(or the folder cannot be read)")
    return paths


def unique_dest(output_folder: str, rel: str, taken: set[str]) -> str:
    """Where this photo's clean copy lands. Folder mode keeps the
    subfolder shape, so a/IMG_0001.jpg and b/IMG_0001.jpg stay two
    files; anything that would still collide inside one run gets a
    numbered name rather than silently overwriting the copy already
    written."""
    dst = os.path.join(output_folder, rel)
    if dst not in taken:
        taken.add(dst)
        return dst
    stem, ext = os.path.splitext(dst)
    for n in itertools.count(2):
        candidate = f"{stem}_{n}{ext}"
        if candidate not in taken:
            taken.add(candidate)
            return candidate


def build_table_event(photos: list[PhotoExif]) -> dict:
    rows = []
    for p in photos:
        rows.append([
            p.rel,
            {"ok": "🔴 metadata", "no exif": "🟢 clean",
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


def build_clusters_section(photos: list[PhotoExif]) -> list[str]:
    """Places that show up again and again. One photo of a beach is a
    holiday; a pile of photos inside one city block is an address —
    and that only becomes visible across a whole folder."""
    located = [(p.rel, p.gps[0], p.gps[1]) for p in photos if p.gps]
    if len(located) < 2:
        return []
    clusters = [c for c in gps_clusters(located) if len(c["points"]) > 1]
    if not clusters:
        return []
    lines = ["### 📍 Places you keep going back to", ""]
    for cluster in clusters[:5]:
        lat, lon = round(cluster["lat"], 6), round(cluster["lon"], 6)
        names = [name for name, _, _ in cluster["points"]]
        shown = ", ".join(names[:4])
        if len(names) > 4:
            shown += f", +{len(names) - 4} more"
        lines.append(
            f"- **{len(names)} photos** within ~{cluster['spread_m']:.0f} m "
            f"of `{lat}, {lon}` — [on the map]({maps_link(lat, lon)})")
        lines.append(f"  - {shown}")
    lines += ["", "A cluster is a place you return to, and the biggest one "
              "in a personal library is usually where you live, work or "
              "drop the kids off. Any single photo from it hands over that "
              "address.", ""]
    return lines


def build_markdown(photos: list[PhotoExif], stripped: list[str]) -> str:
    with_gps = [p for p in photos if p.gps]
    with_exif = [p for p in photos if p.status == "ok"]
    clean = [p for p in photos if p.status == "no exif"]
    head = f"## {'🔴' if with_gps else '📷'} {len(with_exif)} photo(s) " \
           f"carrying metadata, {len(with_gps)} with GPS"
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

    lines += build_clusters_section(photos)

    if with_gps:
        lines += ["**The GPS rows are the headline.** A photo's coordinates "
                  "pin where you stood when you pressed the button — home, "
                  "work, the kid's school. Every share of the original "
                  "file shares that.", ""]
    lines.append(f"_Clean (no metadata at all): {len(clean)} · unreadable: "
                 f"{sum(1 for p in photos if p.status in FAILED)}._")
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
    except NoImages as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1
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

    # In folder mode a photo is named by its path under the folder —
    # two IMG_0001.jpg in different subfolders are two different rows.
    rel_root = os.path.abspath(args.input_folder) \
        if args.mode == "folder" and args.input_folder else None

    photos: list[PhotoExif] = []
    stripped: list[str] = []
    taken: set[str] = set()
    for i, src in enumerate(sources, 1):
        rel = os.path.relpath(src, rel_root) if rel_root \
            else os.path.basename(src)
        photo = read_exif(src, rel)
        photos.append(photo)
        if photo.status == "ok":
            log(f"  🔴 {rel}: {', '.join(photo.leaks) or 'metadata present'}")
        elif photo.status == "no exif":
            log(f"  🟢 {rel}: no metadata (clean)")
        else:
            # The note is where "why" lives ("HEIC needs pillow-heif") —
            # show it here, not only in the report nobody opens first.
            log(f"  ⚫ {rel}: {photo.status}"
                + (f" — {photo.note}" if photo.note else ""))
        if args.strip and photo.status in ("ok", "no exif"):
            dst = unique_dest(output_folder, rel, taken)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            ok, note = strip_exif(src, dst)
            if ok:
                stripped.append(dst)
            else:
                log(f"    ⚠️ strip failed: {note}")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    if photos and all(p.status in FAILED for p in photos):
        print("✗ every image was unreadable — nothing to inspect",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(photos, stripped)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(photos))
    emit({"type": "markdown", "content": report})
    write_artifacts(photos, report)

    with_gps = sum(1 for p in photos if p.gps)
    summary = (f"{sum(1 for p in photos if p.status == 'ok')} with metadata"
               f" · {with_gps} with GPS"
               + (f" · {len(stripped)} cleaned" if stripped else ""))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
