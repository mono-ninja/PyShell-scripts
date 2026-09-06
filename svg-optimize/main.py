#!/usr/bin/env python3
"""svg-optimize/main.py — minify SVG files with scour, safely.

One SVG, several, or a whole folder (optionally recursive), each run
through [scour](https://github.com/scour-project/scour) — the SVG
minifier — with the knobs exposed honestly: coordinate precision,
metadata/comment/prolog stripping, optional ID shortening. The natural
pre-pass before [SVG Sprite — Build](../svg-sprite-build) bundles the
icons.

The contract, inherited from
[Image Optimizer](../image-optimizer): **never write a file bigger than
the input.** When scour's output comes out larger (an already-minified
source, a hand-tuned file), the original bytes are copied through
unchanged and the row is marked `kept original` — the run can only make
a folder lighter, never heavier. The originals are never touched:
results land in the output folder.

Exit codes: 0 = the batch ran (kept-originals are results, not
failures), 1 = nothing to optimize / a prerequisite is missing (scour
not installed, output folder unusable), 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass

try:  # scour is imported lazily — argparse and the introspect guard run first
    from scour.scour import generateDefaultOptions, sanitizeOptions, scourString
    HAVE_SCOUR = True
except ImportError:  # pragma: no cover — depends on the environment
    HAVE_SCOUR = False


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.0f} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Result:
    source: str          # path as given
    rel: str             # path relative to the folder (batch) or the filename
    status: str          # optimized | kept original | skipped | error
    original_bytes: int = 0
    optimized_bytes: int = 0
    note: str = ""

    @property
    def saved_percent(self) -> float:
        if self.original_bytes and self.optimized_bytes < self.original_bytes:
            return round(100 * (self.original_bytes - self.optimized_bytes)
                         / self.original_bytes, 1)
        return 0.0


def bytes_saved(results: list[Result]) -> int:
    """Only optimized rows saved anything — a kept original is a pass-through,
    a skipped or errored file wrote nothing."""
    return sum(r.original_bytes - r.optimized_bytes
               for r in results
               if r.status == "optimized" and r.optimized_bytes < r.original_bytes)


# ---------------------------------------------------------------------------
# Input collection (pure — tests live on these)
# ---------------------------------------------------------------------------

def collect_inputs(args) -> list[tuple[str, str]]:
    """(absolute_source, relative_path) for the chosen mode. Raises
    ValueError with a human message when the mode's input is unusable."""
    pairs: list[tuple[str, str]] = []
    if args.mode == "single":
        if not args.single_svg:
            raise ValueError("--single-svg is required in single mode")
        src = os.path.abspath(args.single_svg)
        if not os.path.isfile(src):
            raise ValueError(f"{args.single_svg} is not a file")
        pairs.append((src, os.path.basename(src)))
    elif args.mode == "multiple":
        if not args.input_file:
            raise ValueError("--input-file (one or more) is required in multiple mode")
        for given in args.input_file:
            src = os.path.abspath(given)
            if not os.path.isfile(src):
                raise ValueError(f"{given} is not a file")
            pairs.append((src, os.path.basename(src)))
        # Same-name collisions across folders: keep the first, note later.
        seen: set[str] = set()
        deduped = []
        for src, rel in pairs:
            if rel in seen:
                base, ext = os.path.splitext(rel)
                i = 2
                while f"{base}-{i}{ext}" in seen:
                    i += 1
                rel = f"{base}-{i}{ext}"
            seen.add(rel)
            deduped.append((src, rel))
        pairs = deduped
    else:  # folder
        if not args.input_folder:
            raise ValueError("--input-folder is required in folder mode")
        root = os.path.abspath(args.input_folder)
        if not os.path.isdir(root):
            raise ValueError(f"{args.input_folder} is not a folder")
        walk = os.walk(root) if args.recursive else [next(os.walk(root))]
        for dirpath, _dirnames, filenames in walk:
            for name in sorted(filenames):
                if name.lower().endswith(".svg"):
                    src = os.path.join(dirpath, name)
                    pairs.append((src, os.path.relpath(src, root)))
        if not pairs:
            raise ValueError(f"no .svg files found under {args.input_folder}"
                             + (" (recursive)" if args.recursive else ""))
    return pairs


def output_target(output_folder: str, rel: str, overwrite: bool,
                  existing: set[str]) -> str | None:
    """The path to write, or None when the file must be skipped. Registers
    the name so two sources can't claim one output."""
    target = os.path.join(output_folder, rel)
    name = os.path.normpath(rel)
    if name in existing:
        return None  # claimed by an earlier source — unreachable in practice
    existing.add(name)
    if os.path.exists(target) and not overwrite:
        return None
    return target


# ---------------------------------------------------------------------------
# The scour pass
# ---------------------------------------------------------------------------

def build_scour_options(args):
    """Map the CLI knobs onto a sanitized scour options object."""
    opts = generateDefaultOptions()
    opts.digits = args.precision
    opts.strip_comments = args.strip_comments
    opts.strip_xml_prolog = args.strip_xml_prolog
    opts.remove_metadata = args.strip_metadata
    # Accessibility: <title>/<desc> stay. Shortening IDs is the only
    # knob that can break external references — opt-in.
    opts.shorten_ids = args.shorten_ids
    return sanitizeOptions(opts)


def optimize_svg(data: bytes, options) -> tuple[bytes, str]:
    """One file through scour. Returns (bytes, note) — never raises;
    a parse failure returns the original bytes with an error note."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data, "not valid UTF-8"
    try:
        out = scourString(text, options)
    except Exception as exc:  # scour raises a zoo of XML/regex errors
        return data, f"scour failed ({type(exc).__name__})"
    # scour always emits text; encode back. A trailing newline keeps the
    # file POSIX-friendly and costs a byte.
    encoded = out.encode("utf-8")
    return encoded, ""


def decide(original: bytes, candidate: bytes, note: str) -> tuple[bytes, str, str]:
    """The safety net: never write a file bigger than the input. Equal
    size also keeps the original — nothing to gain, and the bytes are
    proven-good."""
    if note and len(candidate) >= len(original):
        return original, "kept original" + (f" ({note})" if note else ""), "kept original"
    if len(candidate) > len(original):
        return original, "kept original (already smaller than scour's output)", "kept original"
    if len(candidate) == len(original):
        return original, "kept original (no savings)", "kept original"
    return candidate, note, "optimized"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_table_event(results: list[Result]) -> dict:
    rows = []
    for r in results:
        rows.append([
            r.rel,
            r.status,
            human_size(r.original_bytes),
            human_size(r.optimized_bytes) if r.status != "skipped" else "—",
            f"{r.saved_percent}%" if r.status == "optimized" else "—",
        ])
    return {
        "type": "table",
        "columns": ["File", "Status", "Before", "After", "Saved"],
        "rows": rows,
    }


def build_markdown_event(results: list[Result]) -> dict:
    total_in = sum(r.original_bytes for r in results)
    total_out = sum(r.optimized_bytes for r in results if r.status != "skipped")
    saved = bytes_saved(results)
    optimized = sum(1 for r in results if r.status == "optimized")
    kept = sum(1 for r in results if r.status == "kept original")
    pct = round(100 * saved / total_in, 1) if total_in else 0.0
    lines = [
        f"## {'✨' if saved else '⚪'} {human_size(saved)} saved "
        f"({pct}% of {human_size(total_in)})",
        "",
        f"- Optimized: **{optimized}** · kept original: {kept} · "
        f"skipped: {sum(1 for r in results if r.status == 'skipped')} · "
        f"errors: {sum(1 for r in results if r.status == 'error')}",
        "",
    ]
    if kept:
        lines.append("_Kept-original rows are already smaller than scour's "
                     "output would be — the originals pass through "
                     "unchanged._")
        lines.append("")
    lines.append(f"_{len(results)} file(s) processed; originals never "
                 f"touched — results are copies in the output folder. "
                 f"Feed them to [SVG Sprite — Build](../svg-sprite-build) "
                 f"when they're icons._")
    lines.append("")
    return {"type": "markdown", "content": "\n".join(lines)}


def write_report_csv(results: list[Result]) -> str | None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return None
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "optimization_report.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "status", "original_bytes",
                         "optimized_bytes", "saved_percent", "note"])
        for r in results:
            writer.writerow([r.rel, r.status, r.original_bytes,
                             r.optimized_bytes, r.saved_percent, r.note])
    return path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SVG Optimize — minify SVG files with scour; never "
                    "writes a bigger file than the input")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-svg", help="the SVG to optimize (single mode)")
    parser.add_argument("--input-file", action="append", default=[],
                        help="an SVG to optimize; repeatable (multiple mode)")
    parser.add_argument("--input-folder", help="folder of SVGs (folder mode)")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    parser.add_argument("--precision", type=int, default=5,
                        help="decimal places kept in coordinates (default 5)")
    parser.add_argument("--strip-metadata", action=argparse.BooleanOptionalAction,
                        default=True,
                        help="drop the <metadata> element (default on)")
    parser.add_argument("--strip-comments", action=argparse.BooleanOptionalAction,
                        default=True, help="drop comments (default on)")
    parser.add_argument("--strip-xml-prolog", action=argparse.BooleanOptionalAction,
                        default=True, help="drop the <?xml?> line (default on)")
    parser.add_argument("--shorten-ids", action="store_true",
                        help="rename long IDs to short ones — breaks "
                             "external references to them (default off)")
    parser.add_argument("--output-folder", required=True,
                        help="where the optimized copies land — originals "
                             "are never touched")
    parser.add_argument("--overwrite", action="store_true",
                        help="overwrite existing files in the output folder")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files are touched", flush=True)
        return 0

    if not (1 <= args.precision <= 10):
        print("✗ --precision must be 1–10 (scour rejects 0)",
              file=sys.stderr, flush=True)
        return 2

    if not HAVE_SCOUR:
        print("✗ scour is not installed — run "
              "`python3 -m pip install -r requirements.txt` (or press "
              "Prepare Env in PyShell) first", file=sys.stderr, flush=True)
        return 1

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    output_folder = os.path.abspath(args.output_folder)
    try:
        os.makedirs(output_folder, exist_ok=True)
    except OSError as exc:
        print(f"✗ cannot create the output folder: {exc}",
              file=sys.stderr, flush=True)
        return 1

    options = build_scour_options(args)
    results: list[Result] = []
    claimed: set[str] = set()

    total = len(sources)
    log(f"Optimizing {total} SVG(s) with scour (precision {args.precision})")
    status(f"{total} file(s) · precision {args.precision} · "
           f"scour {'IDs shortened' if args.shorten_ids else 'IDs kept'}")

    for i, (src, rel) in enumerate(sources, 1):
        try:
            with open(src, "rb") as fh:
                original = fh.read()
        except OSError as exc:
            results.append(Result(src, rel, "error", note=str(exc)))
            log(f"  ✗ {rel}: {exc}")
            continue

        target = output_target(output_folder, rel, args.overwrite, claimed)
        if target is None:
            results.append(Result(src, rel, "skipped",
                                  original_bytes=len(original),
                                  note="exists in output (use --overwrite)"))
            log(f"  ⏭ {rel}: exists in output, skipped")
        else:
            candidate, note = optimize_svg(original, options)
            payload, final_note, verdict = decide(original, candidate, note)
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(payload)
            except OSError as exc:
                results.append(Result(src, rel, "error",
                                      original_bytes=len(original),
                                      note=str(exc)))
                log(f"  ✗ {rel}: {exc}")
            else:
                results.append(Result(src, rel, verdict,
                                      original_bytes=len(original),
                                      optimized_bytes=len(payload),
                                      note=final_note))
                log(f"  {'✓' if verdict == 'optimized' else '〰'} {rel}: "
                    f"{human_size(len(original))} → {human_size(len(payload))}"
                    f"{' · ' + final_note if final_note else ''}")

        done = int(100 * i / total)
        emit({"type": "progress", "pct": done, "message": f"{i}/{total} · {rel}"})

    processed = [r for r in results if r.status != "error"]
    if results and all(r.status == "error" for r in results):
        print("✗ every file failed — nothing was optimized",
              file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(results))
    emit(build_markdown_event(results))
    write_report_csv(results)

    saved = bytes_saved(results)
    status(f"{human_size(saved)} saved over {len(processed)} file(s)")
    log(f"← {human_size(saved)} saved · "
        f"{sum(1 for r in results if r.status == 'optimized')} optimized · "
        f"{sum(1 for r in results if r.status == 'kept original')} kept original")
    return 0


if __name__ == "__main__":
    sys.exit(main())
