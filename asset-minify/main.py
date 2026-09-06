#!/usr/bin/env python3
"""asset-minify/main.py — minify CSS and JS through the system binaries.

A **wrapper, like [cURL](../curl)**: the actual minifiers are the
system CLI tools — [terser](https://terser.org) for JS,
[clean-css-cli](https://github.com/clean-css/clean-css-cli) for CSS,
and optionally [autoprefixer](https://github.com/postcss/autoprefixer)
via postcss-cli for vendor prefixes. Python is the orchestration:
file discovery, per-file runs, honest reporting.

The prerequisites are checked up front, per kind actually needed: a
missing binary is a clean exit 1 with the exact
`npm install -g …` line — never a crash mid-batch.

Contracts, inherited from the collection:

- **The originals are never touched** — results land in the output
  folder as `<stem>.min.css` / `<stem>.min.js`.
- **A file that won't shrink isn't written**: when the minified
  candidate comes out bigger or equal (an already-minified source),
  the row is marked `already minimal` and no `.min` file is produced —
  a byte-identical copy would be a lie.
- `*.min.css` / `*.min.js` inputs are skipped (minifying the minified
  is churn), and files already present in the output are skipped
  unless **Overwrite** is on.

Exit codes: 0 = the batch ran (skips and no-savings rows are
results), 1 = missing prerequisite binary / unusable output folder /
every file failed, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

# The system binaries this wrapper drives. Keys match --only values.
REQUIRED_BINARIES = {
    "css": ["cleancss"],
    "js": ["terser"],
}
PREFIX_BINARIES = ["postcss"]  # + autoprefixer plugin, checked at run


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
    source: str            # path as given
    rel: str               # output-relative name
    kind: str              # css | js
    status: str            # minified | already minimal | skipped | error
    original_bytes: int = 0
    output_bytes: int = 0
    note: str = ""


# ---------------------------------------------------------------------------
# Prerequisites (the curl-precedent check)
# ---------------------------------------------------------------------------

def missing_binaries(only: str, prefix: bool) -> list[str]:
    """The binaries the requested work needs and doesn't have. Per-kind:
    a CSS-only run doesn't demand terser. Used by tests; main()
    rechecks against the kinds actually collected."""
    needed: list[str] = []
    kinds = ["css", "js"] if only == "both" else [only]
    for kind in kinds:
        needed += REQUIRED_BINARIES[kind]
    if prefix:
        needed += PREFIX_BINARIES
    return [b for b in dict.fromkeys(needed) if shutil.which(b) is None]


def install_hint(missing: list[str]) -> str:
    return ("npm install -g "
            + " ".join({"cleancss": "clean-css-cli"}.get(b, b)
                       for b in missing))


# ---------------------------------------------------------------------------
# Input collection (pure)
# ---------------------------------------------------------------------------

def is_minified(name: str) -> bool:
    return name.endswith(".min.css") or name.endswith(".min.js")


def kind_of(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith(".css"):
        return "css"
    if lower.endswith(".js"):
        return "js"
    return None


def collect_inputs(args) -> list[tuple[str, str, str]]:
    """(source, rel, kind) triples for the chosen mode. Raises
    ValueError with a human message."""
    pairs: list[tuple[str, str]] = []
    if args.mode == "single":
        if not args.single_asset:
            raise ValueError("--single-asset is required in single mode")
        src = os.path.abspath(args.single_asset)
        if not os.path.isfile(src):
            raise ValueError(f"{args.single_asset} is not a file")
        pairs.append((src, os.path.basename(src)))
    elif args.mode == "multiple":
        if not args.input_file:
            raise ValueError("--input-file (one or more) is required in multiple mode")
        for given in args.input_file:
            src = os.path.abspath(given)
            if not os.path.isfile(src):
                raise ValueError(f"{given} is not a file")
            pairs.append((src, os.path.basename(src)))
    else:
        if not args.input_folder:
            raise ValueError("--input-folder is required in folder mode")
        root = os.path.abspath(args.input_folder)
        if not os.path.isdir(root):
            raise ValueError(f"{args.input_folder} is not a folder")
        walk = os.walk(root) if args.recursive else [next(os.walk(root))]
        for dirpath, _dirs, files in walk:
            for name in sorted(files):
                if is_minified(name):
                    continue  # never minify the minified
                if kind_of(name) is None:
                    continue
                if args.only != "both" and kind_of(name) != args.only:
                    continue
                src = os.path.join(dirpath, name)
                pairs.append((src, os.path.relpath(src, root)))

    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for src, rel in pairs:
        if rel in seen:  # same-name collision across folders
            stem, ext = os.path.splitext(rel)
            i = 2
            while f"{stem}-{i}{ext}" in seen:
                i += 1
            rel = f"{stem}-{i}{ext}"
        seen.add(rel)
        out.append((src, rel, kind_of(rel)))
    if not out:
        raise ValueError("no .css/.js files to minify"
                         + (" (already-minified files are skipped)" if
                            args.mode == "folder" else ""))
    return out


# ---------------------------------------------------------------------------
# The minifier runs (one subprocess per file)
# ---------------------------------------------------------------------------

def run_minifier(kind: str, src: str, dst: str, prefix: bool,
                 timeout: int) -> tuple[bytes | None, str]:
    """One file through the system binary. Returns (candidate_bytes,
    note); the candidate is compared to the source by the caller before
    anything is written."""
    tmp = dst + ".part"
    try:
        if kind == "js":
            cmd = ["terser", src, "--compress", "--mangle", "-o", tmp]
            subprocess.run(cmd, capture_output=True, timeout=timeout,
                           check=True)
        else:
            if prefix:
                prefixed = dst + ".prefixed"
                subprocess.run(["postcss", src, "--use", "autoprefixer",
                                "-o", prefixed, "--no-map"],
                               capture_output=True, timeout=timeout,
                               check=True)
                subprocess.run(["cleancss", "-o", tmp, prefixed],
                               capture_output=True, timeout=timeout,
                               check=True)
                try:
                    os.remove(prefixed)
                except OSError:
                    pass
            else:
                subprocess.run(["cleancss", "-o", tmp, src],
                               capture_output=True, timeout=timeout,
                               check=True)
        with open(tmp, "rb") as fh:
            data = fh.read()
        return data, ""
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode("utf-8", "replace").strip()
        first = stderr.splitlines()[0] if stderr else "no error output"
        return None, first[:200]
    except subprocess.TimeoutExpired:
        return None, f"{kind} minifier timed out after {timeout}s"
    except OSError as exc:
        return None, str(exc)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def minified_name(rel: str) -> str:
    stem, ext = os.path.splitext(rel)
    return f"{stem}.min{ext}"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_table_event(results: list[Result]) -> dict:
    rows = []
    for r in results:
        saved = ""
        if r.status == "minified" and r.original_bytes:
            saved = f"{100 * (r.original_bytes - r.output_bytes) / r.original_bytes:.1f}%"
        rows.append([r.rel, r.kind, r.status, saved or "—",
                     r.note or ""])
    return {
        "type": "table",
        "columns": ["File", "Kind", "Status", "Saved", "Note"],
        "rows": rows,
    }


def build_markdown_event(results: list[Result]) -> dict:
    minified = [r for r in results if r.status == "minified"]
    saved = sum(r.original_bytes - r.output_bytes for r in minified)
    total_in = sum(r.original_bytes for r in results)
    pct = f" ({100 * saved / total_in:.1f}% of {human_size(total_in)})" \
        if total_in else ""
    lines = [
        f"## {'🗜️' if saved else '⚪'} {human_size(saved)} saved{pct}",
        "",
        f"- Minified: **{len(minified)}** · already minimal: "
        f"{sum(1 for r in results if r.status == 'already minimal')} · "
        f"skipped: {sum(1 for r in results if r.status == 'skipped')} · "
        f"errors: {sum(1 for r in results if r.status == 'error')}",
        "",
    ]
    if any(r.status == "already minimal" for r in results):
        lines.append("_`already minimal` rows produced no `.min` file — a "
                     "byte-identical copy would be a lie. The sources "
                     "stayed as they are._")
        lines.append("")
    lines.append(f"_{len(results)} file(s) through terser/clean-css; "
                 f"originals never touched._")
    lines.append("")
    return {"type": "markdown", "content": "\n".join(lines)}


def write_report_csv(results: list[Result]) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "minification_report.csv"), "w",
              newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "kind", "status", "original_bytes",
                         "minified_bytes", "saved_percent", "note"])
        for r in results:
            saved = 0.0
            if r.status == "minified" and r.original_bytes:
                saved = round(100 * (r.original_bytes - r.output_bytes)
                              / r.original_bytes, 1)
            writer.writerow([r.rel, r.kind, r.status, r.original_bytes,
                             r.output_bytes, saved, r.note])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Asset Minify — CSS/JS through the system terser and "
                    "clean-css binaries; originals never touched")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-asset", help="the .css/.js to minify")
    parser.add_argument("--input-file", action="append", default=[],
                        help="a file to minify; repeatable")
    parser.add_argument("--input-folder", help="folder of .css/.js files")
    parser.add_argument("--only", choices=["both", "css", "js"],
                        default="both",
                        help="folder mode: process CSS, JS or both")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    parser.add_argument("--prefix", action="store_true",
                        help="CSS: run autoprefixer before minifying")
    parser.add_argument("--output-folder", required=True,
                        help="where the .min files land")
    parser.add_argument("--overwrite", action="store_true",
                        help="overwrite existing .min files")
    parser.add_argument("--binary-timeout", type=int, default=120,
                        help="per-file minifier timeout (default 120s)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no binaries run, no files written",
              flush=True)
        return 0

    # Prerequisites after we know what kinds we'll actually process —
    # a missing binary is a clean stop, never a crash mid-batch
    # (the cURL-precedent check).
    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2
    kinds_needed = {kind for _s, _r, kind in sources}
    missing = []
    for kind in kinds_needed:
        missing += [b for b in REQUIRED_BINARIES[kind]
                    if shutil.which(b) is None]
    if args.prefix and "css" in kinds_needed:
        missing += [b for b in PREFIX_BINARIES
                    if shutil.which(b) is None]
    if missing:
        print(f"✗ missing system binaries: {', '.join(sorted(set(missing)))}\n"
              f"  install them with:\n"
              f"    {install_hint(sorted(set(missing)))}\n"
              f"  (this script wraps the system tools — the cURL pattern)",
              file=sys.stderr, flush=True)
        return 1

    output_folder = os.path.abspath(args.output_folder)
    try:
        os.makedirs(output_folder, exist_ok=True)
    except OSError as exc:
        print(f"✗ cannot create the output folder: {exc}",
              file=sys.stderr, flush=True)
        return 1

    total = len(sources)
    log(f"Minifying {total} file(s) with "
        f"{'terser + clean-css' if kinds_needed == {'css', 'js'} else 'the system minifier'}"
        + (" + autoprefixer" if args.prefix and "css" in kinds_needed else ""))
    status(f"{total} file(s) · {'autoprefixer on' if args.prefix else 'no prefixing'}")

    results: list[Result] = []
    for i, (src, rel, kind) in enumerate(sources, 1):
        target = os.path.join(output_folder, minified_name(rel))
        original_size = os.path.getsize(src)
        if os.path.exists(target) and not args.overwrite:
            results.append(Result(src, rel, kind, "skipped",
                                  original_size,
                                  note="exists in output (--overwrite)"))
            log(f"  ⏭ {minified_name(rel)}: exists, skipped")
        else:
            candidate, note = run_minifier(kind, src, target, args.prefix,
                                           args.binary_timeout)
            if candidate is None:
                results.append(Result(src, rel, kind, "error",
                                      original_size, note=note))
                log(f"  ✗ {rel}: {note}")
            elif len(candidate) >= original_size:
                results.append(Result(src, rel, kind, "already minimal",
                                      original_size, len(candidate),
                                      note="minifier output not smaller"))
                log(f"  〰 {rel}: already minimal "
                    f"({human_size(original_size)})")
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(candidate)
                results.append(Result(src, rel, kind, "minified",
                                      original_size, len(candidate)))
                pct = 100 * (original_size - len(candidate)) / original_size
                log(f"  ✓ {minified_name(rel)}: "
                    f"{human_size(original_size)} → "
                    f"{human_size(len(candidate))} ({pct:.1f}%)")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    if results and all(r.status == "error" for r in results):
        print("✗ every file failed — nothing was minified",
              file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(results))
    emit(build_markdown_event(results))
    write_report_csv(results)

    minified_n = sum(1 for r in results if r.status == "minified")
    saved = sum(r.original_bytes - r.output_bytes
                for r in results if r.status == "minified")
    status(f"{human_size(saved)} saved over {minified_n} file(s)")
    log(f"← {human_size(saved)} saved · {minified_n} minified · "
        f"{sum(1 for r in results if r.status == 'already minimal')} "
        f"already minimal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
