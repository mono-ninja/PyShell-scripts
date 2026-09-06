#!/usr/bin/env python3
"""pdf-toolkit/main.py — thin entry point; the operations live in src/.

Six operations over one or more PDFs: **strip** (the privacy one —
rebuild the document from pages only, dropping the metadata and
attachments it was about to leak), **merge**, **split** (a PDF per
page), **extract** (page ranges), **rotate**, and **compress**
(metadata + duplicate-object cleanup; image data is never re-encoded).

Every operation reports what it did and, for strip/compress, what the
metadata was about to leak — the author name, the producer (which app
and often which version made the file), creation/modification
timestamps. The originals are never touched: results land in the
output folder under `<stem>_<op>.pdf` names.

Flags that don't apply to the chosen operation are rejected loudly
(exit 2), never silently ignored.
"""
from __future__ import annotations

import argparse
import os
import sys

from src.events import emit, log, status
from src.inspection import read_pdf, describe_metadata, human_size
from src.ops import (
    op_compress, op_extract, op_merge, op_rotate, op_split, op_strip,
)
from src.pagespec import parse_pages
from src.report import build_markdown, build_table_event, write_artifacts

OPERATIONS = {
    "merge": op_merge,
    "split": op_split,
    "extract": op_extract,
    "rotate": op_rotate,
    "strip": op_strip,
    "compress": op_compress,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PDF Toolkit — merge/split/extract/rotate/"
                    "metadata-strip/compress, privacy-first")
    parser.add_argument("--operation", choices=sorted(OPERATIONS),
                        default="strip",
                        help="what to do (default strip)")
    parser.add_argument("--pdfs", action="append", nargs="+", required=True,
                        help="a PDF to process; repeatable, and several "
                             "may follow one flag: --pdfs a.pdf b.pdf")
    parser.add_argument("--pages", default="",
                        help="1-based pages/ranges for extract (required) "
                             "and rotate (empty = all): 1-3,7,10-")
    parser.add_argument("--angle", choices=["90", "180", "270"],
                        default="90",
                        help="rotation for the rotate operation")
    parser.add_argument("--output-dir", default="",
                        help="where results land (default: PyShell output "
                             "dir or the current folder)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files are touched", flush=True)
        return 0

    # Flags that don't apply are rejected loudly, never ignored.
    if args.operation not in ("extract", "rotate") and args.pages:
        print(f"✗ --pages doesn't apply to {args.operation!r} — it's for "
              "extract and rotate only", file=sys.stderr, flush=True)
        return 2
    if args.operation != "rotate" and args.angle != "90":
        print(f"✗ --angle doesn't apply to {args.operation!r} — it's for "
              "rotate only", file=sys.stderr, flush=True)
        return 2
    if args.operation == "extract" and not args.pages:
        print("✗ extract needs --pages (e.g. 1-3,7)", file=sys.stderr,
              flush=True)
        return 2

    # Validate the files up front: unreadable or non-PDF inputs fail
    # before any work starts. (--pdfs may be repeated or space-packed;
    # flatten into one ordered list.)
    pdfs = [p for group in args.pdfs for p in group]
    readers = []
    for given in pdfs:
        path = os.path.abspath(given)
        reader, problem = read_pdf(path)
        if problem:
            print(f"✗ {os.path.basename(given)}: {problem}",
                  file=sys.stderr, flush=True)
            return 1
        readers.append((path, reader))

    pages_spec = None
    if args.pages:
        page_count = len(readers[0][1].pages)
        pages_spec, problem = parse_pages(args.pages, page_count)
        if problem:
            print(f"✗ --pages: {problem}", file=sys.stderr, flush=True)
            return 2
        # Batch operations apply the same spec to every file; a spec that
        # overruns the smallest file is an honest error.
        for path, reader in readers:
            _, problem = parse_pages(args.pages, len(reader.pages))
            if problem:
                print(f"✗ {os.path.basename(path)} has "
                      f"{len(reader.pages)} page(s); --pages {args.pages} "
                      f"doesn't fit", file=sys.stderr, flush=True)
                return 2

    output_dir = args.output_dir or os.environ.get("PYSHELL_OUTPUT_DIR") \
        or os.getcwd()
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as exc:
        print(f"✗ cannot create the output folder: {exc}",
              file=sys.stderr, flush=True)
        return 1

    status(f"{args.operation} · {len(readers)} file(s)")
    emit({"type": "progress", "pct": 5,
          "message": f"{args.operation} on {len(readers)} file(s)"})

    results, written = OPERATIONS[args.operation](
        readers=readers,
        pages=pages_spec,
        angle=int(args.angle) if args.operation == "rotate" else 0,
        output_dir=output_dir,
        progress=lambda pct, msg: emit({"type": "progress", "pct": pct,
                                        "message": msg}),
    )

    ok = [r for r in results if r.status == "ok"]
    failed = [r for r in results if r.status == "error"]
    if failed and not ok:
        print(f"✗ every file failed — nothing was written",
              file=sys.stderr, flush=True)
        return 1

    # The privacy story: what the metadata would have leaked.
    leaks = []
    if args.operation in ("strip", "compress"):
        for path, reader in readers:
            leaks.append((os.path.basename(path),
                          describe_metadata(reader)))

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(args.operation, results))
    emit({"type": "markdown",
          "content": build_markdown(args.operation, results, written,
                                    leaks)})
    write_artifacts(args.operation, results, leaks)

    total_in = sum(r.source_bytes for r in results)
    total_out = sum(r.output_bytes for r in results)
    summary = (f"{len(ok)}/{len(results)} ok · "
               f"{len(written)} file(s) written"
               + (f" · {human_size(total_in)} → {human_size(total_out)}"
                  if args.operation in ("strip", "compress")
                  and total_out else ""))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
