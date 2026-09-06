#!/usr/bin/env python3
"""qr-generate/main.py — QR codes, one or a batch.

One code from **Content** (a URL, plain text, a WiFi string, a
vCard…), or one per row of a **batch CSV** (a `content` column, an
optional `name` column). The knobs that matter are exposed: the
error-correction level (L/M/Q/H — how much damage the code survives),
module size, quiet-zone border, foreground/background colors, and an
optional **center logo** (auto-sized to ~20%, meant for H-level
correction — the run warns when the combination is fragile).

Results land in the output directory as PNG artifacts — the codes are
meant to be shared, so unlike Password Check nothing here is secret.

Exit codes: 0 = at least one code was written, 1 = prerequisites
missing / every code failed, 2 = bad arguments (no content, unusable
colors, a batch CSV without a content column).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass

try:  # lazy — argparse and the introspect guard run first
    import qrcode
    from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_L, \
        ERROR_CORRECT_M, ERROR_CORRECT_Q
    HAVE_QR = True
except ImportError:  # pragma: no cover — environment-dependent
    HAVE_QR = False

try:
    from PIL import Image
    HAVE_PIL = True
except ImportError:  # pragma: no cover
    HAVE_PIL = False

EC_LEVELS = {"L": ERROR_CORRECT_L, "M": ERROR_CORRECT_M,
             "Q": ERROR_CORRECT_Q, "H": ERROR_CORRECT_H}
HEX_RE = re.compile(r"^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
LOGO_FRACTION = 0.20       # of the code's side — the safe ceiling
BATCH_ROW_LIMIT = 500


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# Data model + pure helpers
# ---------------------------------------------------------------------------

@dataclass
class QRRequest:
    content: str
    filename: str          # without extension, safe for the filesystem


def normalize_color(value: str) -> tuple[str, str | None]:
    """(#RRGGBB, error). Accepts #RGB and #RRGGBB; 3-digit expands."""
    value = (value or "").strip()
    if not HEX_RE.match(value):
        return "", (f"{value!r} is not a #RGB or #RRGGBB hex color")
    if len(value) == 4:
        value = "#" + "".join(c * 2 for c in value[1:])
    return value.upper(), None


def safe_name(name: str, fallback: str) -> str:
    """A filename-safe stem: ASCII-ish, no path separators. A trailing
    image extension (.png/.jpg/…) is stripped — but version dots stay."""
    stem = os.path.basename((name or "").strip())
    for ext in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
        if stem.lower().endswith(ext):
            stem = stem[:-len(ext)]
            break
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")
    return stem or fallback


def parse_batch_csv(path: str) -> tuple[list[QRRequest], str]:
    """(requests, error). The CSV needs a content column; an optional
    name column names the files. Header required — no guessing."""
    requests: list[QRRequest] = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or \
                    "content" not in [f.strip().lower() for f in
                                      reader.fieldnames]:
                return [], "the CSV needs a 'content' column (header row)"
            for i, row in enumerate(reader, 1):
                content = (row.get("content") or "").strip()
                if not content:
                    continue  # blank rows are skipped, not errors
                raw_name = ""
                for key, value in row.items():
                    if key and key.strip().lower() == "name":
                        raw_name = value or ""
                requests.append(QRRequest(
                    content=content,
                    filename=safe_name(raw_name, f"qr_{i:03d}")))
                if len(requests) >= BATCH_ROW_LIMIT:
                    break
    except OSError as exc:
        return [], f"cannot read the CSV ({type(exc).__name__})"
    except csv.Error as exc:
        return [], f"CSV parse error: {exc}"
    if not requests:
        return [], "no non-empty content rows in the CSV"
    return requests, ""


# ---------------------------------------------------------------------------
# The QR build
# ---------------------------------------------------------------------------

def build_qr(req: QRRequest, ec_level, box_size: int, border: int,
             fg: str, bg: str, logo_path: str | None,
             output_dir: str) -> tuple[str | None, str]:
    """One code → one PNG. (written_path, error)."""
    try:
        qr = qrcode.QRCode(error_correction=ec_level, box_size=box_size,
                           border=border)
        qr.add_data(req.content)
        qr.make(fit=True)
        img = qr.make_image(fill_color=fg, back_color=bg)
        if logo_path:
            pasted, note = paste_logo(img, logo_path)
            if pasted is None:
                return None, note
            img = pasted
        target = os.path.join(output_dir, req.filename + ".png")
        img.save(target)
        return target, ""
    except Exception as exc:  # a broken logo image, a disk error…
        return None, f"{type(exc).__name__}"


def paste_logo(qr_img, logo_path: str):
    """Center the logo, auto-sized to LOGO_FRACTION of the code. A
    logo without H-level correction is fragile — the caller warns."""
    try:
        logo = Image.open(logo_path)
        logo.load()
    except Exception as exc:
        return None, f"logo unreadable ({type(exc).__name__})"
    side = int(min(qr_img.size) * LOGO_FRACTION)
    logo = logo.convert("RGBA")
    logo = logo.resize((side, side), Image.LANCZOS)
    # A white pad behind the logo keeps modules from bleeding through.
    pad = Image.new("RGBA", (side, side), (255, 255, 255, 255))
    x = (qr_img.size[0] - side) // 2
    y = (qr_img.size[1] - side) // 2
    canvas = qr_img.convert("RGBA")
    canvas.paste(pad, (x, y), pad)
    canvas.paste(logo, (x, y), logo)
    return canvas, ""


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_table_event(written: list[tuple[QRRequest, str]]) -> dict:
    return {
        "type": "table",
        "columns": ["File", "Content"],
        "rows": [[os.path.basename(path),
                  req.content if len(req.content) <= 60
                  else req.content[:57] + "…"]
                 for req, path in written],
    }


def build_markdown(written: list[tuple[QRRequest, str]], failed: int,
                   ec: str, logo: bool) -> str:
    lines = [f"## {'✅' if written else '⚠️'} {len(written)} QR code(s) "
             f"generated", ""]
    for req, path in written[:20]:
        preview = req.content if len(req.content) <= 60 \
            else req.content[:57] + "…"
        lines.append(f"- `{os.path.basename(path)}` — {preview}")
    if len(written) > 20:
        lines.append(f"- … {len(written) - 20} more")
    lines.append("")
    lines.append(f"_Error correction **{ec}** · "
                 + ("center logo at 20% · " if logo else "")
                 + f"{failed} failure(s)._")
    if logo and ec != "H":
        lines.append("")
        lines.append("_⚠️ A center logo eats modules — H-level correction "
                     "is the safe pairing. Re-run with H if the code "
                     "doesn't scan._")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="QR Generate — QR codes from text/URLs, one or a "
                    "batch, with colors and an optional center logo")
    parser.add_argument("--text", default="",
                        help="the QR content (ignored with --batch-csv)")
    parser.add_argument("--batch-csv", default="",
                        help="CSV with a content column (optional name "
                             "column) — one QR per row")
    parser.add_argument("--name", default="",
                        help="filename for the single code (default "
                             "qr_code)")
    parser.add_argument("--error-correction", choices=["L", "M", "Q", "H"],
                        default="M", help="L/M/Q/H (default M)")
    parser.add_argument("--box-size", type=int, default=10,
                        help="pixels per module (default 10)")
    parser.add_argument("--border", type=int, default=4,
                        help="quiet zone in modules (default 4, spec min)")
    parser.add_argument("--fg-color", default="#000000",
                        help="module color, #RGB/#RRGGBB (default "
                             "#000000)")
    parser.add_argument("--bg-color", default="#FFFFFF",
                        help="background color (default #FFFFFF)")
    parser.add_argument("--logo", default="",
                        help="optional center-logo image path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no codes are generated", flush=True)
        return 0

    if not HAVE_QR or not HAVE_PIL:
        print("✗ qrcode/Pillow not installed — run "
              "`python3 -m pip install -r requirements.txt` (or press "
              "Prepare Env in PyShell) first", file=sys.stderr, flush=True)
        return 1

    fg, problem = normalize_color(args.fg_color)
    if problem:
        print(f"✗ foreground: {problem}", file=sys.stderr, flush=True)
        return 2
    bg, problem = normalize_color(args.bg_color)
    if problem:
        print(f"✗ background: {problem}", file=sys.stderr, flush=True)
        return 2

    # The request list: batch CSV wins, else the single text.
    if args.batch_csv:
        requests, problem = parse_batch_csv(args.batch_csv)
        if problem:
            print(f"✗ {problem}", file=sys.stderr, flush=True)
            return 2
    elif args.text.strip():
        requests = [QRRequest(content=args.text.strip(),
                              filename=safe_name(args.name, "qr_code"))]
    else:
        print("✗ nothing to encode: fill Content or point Batch CSV at "
              "a CSV file", file=sys.stderr, flush=True)
        return 2

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR") or os.getcwd()
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as exc:
        print(f"✗ cannot create the output folder: {exc}",
              file=sys.stderr, flush=True)
        return 1

    ec_level = EC_LEVELS[args.error_correction]
    logo = args.logo or None
    status(f"{len(requests)} code(s) · EC {args.error_correction}"
           + (" · logo" if logo else ""))

    written: list[tuple[QRRequest, str]] = []
    failed = 0
    for i, req in enumerate(requests, 1):
        path, error = build_qr(req, ec_level, args.box_size, args.border,
                               fg, bg, logo, output_dir)
        if path:
            written.append((req, path))
            log(f"  ✓ {os.path.basename(path)} ← "
                f"{req.content[:50]}{'…' if len(req.content) > 50 else ''}")
        else:
            failed += 1
            log(f"  ✗ {req.filename}: {error}")
        emit({"type": "progress", "pct": int(100 * i / len(requests)),
              "message": f"{i}/{len(requests)} · {req.filename}"})

    if not written:
        print("✗ no code was generated", file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(written))
    emit({"type": "markdown",
          "content": build_markdown(written, failed,
                                    args.error_correction, bool(logo))})

    summary = f"{len(written)} QR code(s) written"
    if failed:
        summary += f" · {failed} failed"
    status(summary)
    log(f"← {summary} → {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
