#!/usr/bin/env python3
"""office-metadata/main.py — what your Office documents say about you.

A modern .docx/.xlsx/.pptx is a ZIP of XML parts, and several of those
parts are pure metadata: `docProps/core.xml` (author, last editor,
timestamps), `docProps/app.xml` (which app and version made it, your
**company** and **manager** fields, total editing minutes, the template
name, the base for relative hyperlinks, and TitlesOfParts — sheet names
in Excel, slide titles in PowerPoint), `docProps/custom.xml` (whatever
a document-management system wrote in), and `docProps/thumbnail.*` (a
preview image of the content).  On top of that: tracked changes and
comments hide reviewer names and pending edits, and `vbaProject.bin`
marks macro-enabled files.

Everything is read straight from the ZIP — stdlib only, no
dependencies, the file is never opened by Office and never leaves the
machine.

**Strip** writes clean copies: the docProps parts are dropped (core.xml
is replaced with a blank one, `[Content_Types].xml` updated), the
originals untouched.  Tracked changes, comments and macros are
**content**, not metadata — they are reported loudly but left for the
author to resolve by hand.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

OFFICE_EXTENSIONS = {".docx", ".docm", ".dotx", ".xlsx", ".xlsm", ".xltx",
                     ".pptx", ".pptm", ".potx"}

NS = {
    "dc": "http://purl.org/dc/elements/1.1/",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
    "cust": "http://schemas.openxmlformats.org/package/2006/metadata/custom-properties",
    "ct": "http://schemas.openxmlformats.org/package/2006/content-types",
}

# core.xml local-name -> report key (namespace-agnostic via local name)
CORE_FIELDS = [
    ("creator", "author"),
    ("lastModifiedBy", "last_modified_by"),
    ("created", "created"),
    ("modified", "modified"),
    ("title", "title"),
    ("subject", "subject"),
    ("description", "description"),
    ("keywords", "keywords"),
    ("category", "category"),
    ("contentStatus", "content_status"),
    ("revision", "revision"),
]

APP_FIELDS = [
    ("Application", "application"),
    ("AppVersion", "app_version"),
    ("Company", "company"),
    ("Manager", "manager"),
    ("Template", "template"),
    ("TotalTime", "total_time_min"),
    ("HyperlinkBase", "hyperlink_base"),
    ("Security", "security"),
    ("Pages", "pages"),
    ("Words", "words"),
    ("Slides", "slides"),
]

BLANK_CORE = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<cp:coreProperties'
    ' xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
    ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
    ' xmlns:dcterms="http://purl.org/dc/terms/"'
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>'
)


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------- read

@dataclass
class OfficeDoc:
    path: str
    status: str = "ok"            # ok | clean | unreadable
    kind: str = ""                # Word / Excel / PowerPoint (± macros)
    meta: dict = field(default_factory=dict)
    titles: list[str] = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    leaks: list[str] = field(default_factory=list)
    note: str = ""


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_core(data: bytes) -> dict:
    """core.xml bytes -> flat dict of the fields that carry metadata."""
    root = ET.fromstring(data)
    out: dict = {}
    for elem in root:
        name = _local(elem.tag)
        for xml_name, key in CORE_FIELDS:
            if name == xml_name and elem.text and elem.text.strip():
                out[key] = elem.text.strip()
    return out


def parse_app(data: bytes) -> dict:
    """app.xml bytes -> flat dict + TitlesOfParts vector (sheets/slides)."""
    root = ET.fromstring(data)
    out: dict = {}
    titles: list[str] = []
    for elem in root:
        name = _local(elem.tag)
        for xml_name, key in APP_FIELDS:
            if name == xml_name and elem.text and elem.text.strip():
                out[key] = elem.text.strip()
        if name == "TitlesOfParts":
            for item in elem.iter():
                if _local(item.tag) in ("lpstr", "bstr", "tstr") \
                        and item.text and item.text.strip():
                    titles.append(item.text.strip())
    return {**out, "titles": titles}


def parse_custom(data: bytes) -> list[tuple[str, str]]:
    """custom.xml bytes -> [(name, value), …] of custom properties."""
    root = ET.fromstring(data)
    out: list[tuple[str, str]] = []
    for prop in root:
        if _local(prop.tag) not in ("property", "customProp"):
            continue
        name = prop.get("name", "?")
        value = ""
        for child in prop:
            if child.text and child.text.strip():
                value = child.text.strip()
                break
        out.append((name, value))
    return out


def _norm_ts(value: str) -> str:
    """'2024-01-15T10:30:00Z' -> '2024-01-15 10:30 UTC' (best effort)."""
    try:
        return dt.datetime.fromisoformat(
            value.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M %Z") \
            .replace("UTC", "UTC").strip()
    except ValueError:
        return value


def detect_kind(names: list[str]) -> tuple[str, bool]:
    """Part names -> ('Word'|'Excel'|'PowerPoint'|'Office', has_macros)."""
    prefixes = {n.split("/", 1)[0] for n in names if "/" in n}
    macros = any(n.endswith("vbaProject.bin") for n in names)
    if "word" in prefixes:
        base = "Word"
    elif "xl" in prefixes:
        base = "Excel"
    elif "ppt" in prefixes:
        base = "PowerPoint"
    else:
        base = "Office"
    return base + (" + macros" if macros else ""), macros


def read_office(path: str) -> OfficeDoc:
    """Read one OOXML file and build its privacy inventory."""
    doc = OfficeDoc(path=path)
    if not zipfile.is_zipfile(path):
        doc.status = "unreadable"
        doc.note = ("not a ZIP container — the legacy binary .doc/.xls/.ppt "
                    "formats are not supported")
        return doc
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            def read(part: str) -> bytes:
                return zf.read(part) if part in names else b""
            core_data = read("docProps/core.xml")
            app_data = read("docProps/app.xml")
            custom_data = read("docProps/custom.xml")
            doc.kind, macros = detect_kind(names)

            if core_data:
                doc.meta.update(parse_core(core_data))
            if app_data:
                parsed = parse_app(app_data)
                doc.titles = parsed.pop("titles", [])
                doc.meta.update(parsed)
            if custom_data:
                doc.flags["custom_props"] = parse_custom(custom_data)

            doc.flags["thumbnail"] = next(
                (n for n in names
                 if n.startswith("docProps/thumbnail.")), "")
            doc.flags["macros"] = macros
            doc.flags["comments"] = any(
                n.startswith(("word/comments", "xl/comments", "ppt/comments"))
                for n in names)
            doc.flags["embedded_files"] = sum(
                1 for n in names if "/embeddings/" in n)
            if "word/settings.xml" in names:
                doc.flags["rsids"] = b"<w:rsid " in zf.read(
                    "word/settings.xml")
            if "word/document.xml" in names:
                body = zf.read("word/document.xml")
                doc.flags["tracked_changes"] = (b"<w:ins " in body
                                                or b"<w:del " in body)
    except (zipfile.BadZipFile, ET.ParseError, OSError, RuntimeError) as exc:
        doc.status = "unreadable"
        doc.note = f"cannot read the package: {exc}"
        return doc

    doc.leaks = classify_leaks(doc)
    if not doc.leaks and doc.status == "ok":
        doc.status = "clean"
    return doc


def classify_leaks(doc: OfficeDoc) -> list[str]:
    """The privacy story of one document, as short labels."""
    m, flags = doc.meta, doc.flags
    leaks: list[str] = []
    if m.get("author"):
        leaks.append(f"author: {m['author']}")
    if m.get("last_modified_by"):
        leaks.append(f"last editor: {m['last_modified_by']}")
    if m.get("company"):
        leaks.append(f"company: {m['company']}")
    if m.get("manager"):
        leaks.append(f"manager: {m['manager']}")
    if m.get("application"):
        version = f" ({m['app_version']})" if m.get("app_version") else ""
        leaks.append(f"made with: {m['application']}{version}")
    if m.get("total_time_min"):
        leaks.append(f"edited {m['total_time_min']} min")
    if m.get("template"):
        leaks.append("template name")
    if m.get("hyperlink_base"):
        leaks.append("hyperlink base")
    if doc.titles:
        leaks.append(f"{len(doc.titles)} sheet/slide name(s)")
    if flags.get("thumbnail"):
        leaks.append("embedded thumbnail")
    if flags.get("custom_props"):
        leaks.append(f"{len(flags['custom_props'])} custom prop(s)")
    if flags.get("comments"):
        leaks.append("comments")
    if flags.get("tracked_changes"):
        leaks.append("tracked changes")
    if flags.get("embedded_files"):
        leaks.append(f"{flags['embedded_files']} embedded file(s)")
    if flags.get("rsids"):
        leaks.append("revision fingerprints (rsids)")
    return leaks


def identity_leak(doc: OfficeDoc) -> bool:
    """True when the document names real people or orgs — the red ones."""
    return any(k in doc.meta for k in
               ("author", "last_modified_by", "company", "manager"))


# --------------------------------------------------------------------- strip

STRIP_DROP_EXACT = {"docProps/app.xml", "docProps/custom.xml"}
STRIP_DROP_PREFIX = ("docProps/thumbnail.",)


def strip_office(src: str, dst: str) -> tuple[bool, str]:
    """Write a metadata-free copy of src to dst; (ok, note)."""
    try:
        with zipfile.ZipFile(src) as zin:
            names = zin.namelist()
            drop = {n for n in names if n in STRIP_DROP_EXACT
                    or n.startswith(STRIP_DROP_PREFIX)}
            content_types = ""
            if "[Content_Types].xml" in names:
                content_types = zin.read("[Content_Types].xml").decode(
                    "utf-8", "replace")
            with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
                for name in names:
                    if name.endswith("/") or name in drop:
                        continue
                    if name == "docProps/core.xml":
                        zout.writestr(name, BLANK_CORE)
                        continue
                    data = zin.read(name)
                    if name == "[Content_Types].xml" and drop:
                        data = _prune_content_types(data, drop)
                    zout.writestr(name, data)
    except (zipfile.BadZipFile, OSError, ET.ParseError) as exc:
        return False, str(exc)
    return True, f"dropped {len(drop)} metadata part(s)"


def _prune_content_types(data: bytes, drop: set[str]) -> bytes:
    """Remove <Override> entries of parts that no longer exist."""
    root = ET.fromstring(data)
    for override in list(root):
        part = override.get("PartName", "")
        if _local(override.tag) == "Override" \
                and part.lstrip("/") in drop:
            root.remove(override)
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


# --------------------------------------------------------------------- input

def collect_inputs(args) -> list[str]:
    """Resolve --mode into a list of files; ValueError -> exit 2."""
    if args.mode == "single":
        if not args.single_file:
            raise ValueError("--single-file is required in single mode")
        path = args.single_file
        if os.path.splitext(path)[1].lower() not in OFFICE_EXTENSIONS:
            raise ValueError(f"{path}: not a modern Office document "
                             "(expected " + "/".join(sorted(
                                 OFFICE_EXTENSIONS)) + ")")
        if not os.path.isfile(path):
            raise ValueError(f"{path}: file not found")
        return [path]
    if args.mode == "multiple":
        if not args.input_file:
            raise ValueError("select at least one document "
                             "(--input-file, repeatable)")
        for path in args.input_file:
            if os.path.splitext(path)[1].lower() not in OFFICE_EXTENSIONS:
                raise ValueError(f"{path}: not a modern Office document")
            if not os.path.isfile(path):
                raise ValueError(f"{path}: file not found")
        return list(args.input_file)
    if not args.input_folder:
        raise ValueError("--input-folder is required in folder mode")
    if not os.path.isdir(args.input_folder):
        raise ValueError(f"{args.input_folder}: folder not found")
    found: list[str] = []
    skipped = 0
    walker = os.walk(args.input_folder) if args.recursive else [
        (args.input_folder, [], sorted(os.listdir(args.input_folder)))]
    for root, _dirs, files in walker:
        for name in sorted(files):
            full = os.path.join(root, name)
            if os.path.splitext(name)[1].lower() in OFFICE_EXTENSIONS:
                found.append(full)
            else:
                skipped += 1
    if skipped:
        log(f"  ⚫ {skipped} non-Office file(s) skipped")
    if not found:
        raise ValueError(f"{args.input_folder}: no modern Office documents "
                         "found")
    return found


# -------------------------------------------------------------------- report

def build_table_event(docs: list[OfficeDoc]) -> dict:
    rows = []
    for doc in docs:
        if doc.status == "unreadable":
            verdict = "unreadable"
        elif doc.status == "clean":
            verdict = "🟢 clean"
        else:
            verdict = "🔴 identity leak" if identity_leak(doc) else "🟠 metadata"
        rows.append([
            os.path.basename(doc.path),
            doc.kind or "?",
            ", ".join(doc.leaks) if doc.leaks else "—",
            verdict,
        ])
    return {"type": "table",
            "columns": ["file", "kind", "leaks", "verdict"],
            "rows": rows}


def build_markdown(docs: list[OfficeDoc], stripped: list[tuple[str, str]],
                   failed: list[str]) -> str:
    total = len(docs)
    red = sum(1 for d in docs if d.status == "ok" and identity_leak(d))
    clean = sum(1 for d in docs if d.status == "clean")
    out = [f"# Office Metadata — Report\n",
           f"{total} document(s): **{red} name people or orgs**, "
           f"{clean} carry nothing, "
           f"{total - red - clean - sum(1 for d in docs if d.status == 'unreadable')} "
           f"with technical metadata only.\n"]
    out.append("A modern Office file is a ZIP of XML parts — and several "
               "parts exist purely to describe you: who wrote it, who "
               "edited it last, your company, the minutes you spent, the "
               "names of your sheets and slides. Every copy you send "
               "carries all of it.\n")

    for doc in docs:
        rel = os.path.basename(doc.path)
        out.append(f"\n## {rel}\n")
        if doc.status == "unreadable":
            out.append(f"⚫ **unreadable** — {doc.note}\n")
            continue
        out.append(f"Kind: **{doc.kind}**\n")
        if doc.status == "clean":
            out.append("🟢 no metadata worth reporting.\n")
            continue
        m = doc.meta
        lines = []
        if m.get("author"):
            lines.append(f"- author: **{m['author']}**")
        if m.get("last_modified_by"):
            lines.append(f"- last modified by: **{m['last_modified_by']}**")
        if m.get("company"):
            lines.append(f"- company: **{m['company']}**")
        if m.get("manager"):
            lines.append(f"- manager: **{m['manager']}**")
        if m.get("application"):
            ver = f" {m['app_version']}" if m.get("app_version") else ""
            lines.append(f"- made with: {m['application']}{ver}")
        if m.get("total_time_min"):
            lines.append(f"- total editing time: {m['total_time_min']} min")
        if m.get("template"):
            lines.append(f"- template: `{m['template']}`")
        if m.get("hyperlink_base"):
            lines.append(f"- hyperlink base: `{m['hyperlink_base']}`")
        if m.get("created"):
            lines.append(f"- created: {_norm_ts(m['created'])}")
        if m.get("modified"):
            lines.append(f"- modified: {_norm_ts(m['modified'])}")
        if m.get("revision"):
            lines.append(f"- revision: {m['revision']}")
        if m.get("title"):
            lines.append(f"- title: {m['title']}")
        if m.get("subject"):
            lines.append(f"- subject: {m['subject']}")
        if m.get("keywords"):
            lines.append(f"- keywords: {m['keywords']}")
        if m.get("description"):
            lines.append(f"- description: {m['description'][:200]}")
        if doc.titles:
            sample = ", ".join(f"“{t}”" for t in doc.titles[:8])
            more = f" (+{len(doc.titles) - 8} more)" if len(doc.titles) > 8 \
                else ""
            lines.append(f"- internal names: {sample}{more}")
        if doc.flags.get("custom_props"):
            names = ", ".join(n for n, _ in doc.flags["custom_props"][:8])
            lines.append(f"- custom properties: {names}")
        if doc.flags.get("thumbnail"):
            lines.append("- 🖼 embedded thumbnail (a preview of the content)")
        if doc.flags.get("comments"):
            lines.append("- 💬 comments (reviewer names and text stay in "
                         "the file)")
        if doc.flags.get("tracked_changes"):
            lines.append("- ✏️ tracked changes (pending edits with author "
                         "names)")
        if doc.flags.get("embedded_files"):
            lines.append(f"- 📎 {doc.flags['embedded_files']} embedded "
                         "object(s)")
        if doc.flags.get("rsids"):
            lines.append("- revision fingerprints (rsids — a save-history "
                         "signature)")
        if doc.flags.get("macros"):
            lines.append("- ⚠️ **macros** — security, not privacy: opening "
                         "files with macros you did not write is risky")
        out.extend(lines)
        out.append("")

    if stripped:
        out.append("\n## Clean copies\n")
        for src, dst in stripped:
            out.append(f"- `{os.path.basename(src)}` → "
                       f"`{os.path.basename(dst)}` (author, company, "
                       "thumbnail and friends removed)")
        out.append("")
        out.append("Strip removes the metadata parts only. Tracked changes, "
                   "comments, embedded objects and macros are **content** — "
                   "resolve them in the app before sharing.")
    if failed:
        out.append("\n## Strip failures\n")
        for note in failed:
            out.append(f"- {note}")

    out.append("\n## What to do\n")
    out.append("- Before sending a document outside: strip it (or "
               "*File → Inspect Document* in Word) — or export to PDF and "
               "check it with PDF Toolkit.")
    out.append("- Accept documents with macros only from sources you trust.")
    out.append("- Related: **EXIF Inspect** (photos), **PDF Toolkit** "
               "(PDFs) — the same privacy check for the other formats.")
    return "\n".join(out)


CSV_FIELDS = ["file", "kind", "status", "author", "last_modified_by",
              "company", "manager", "application", "app_version",
              "template", "total_time_min", "created", "modified",
              "revision", "titles_count", "titles", "thumbnail",
              "custom_props", "comments", "tracked_changes", "macros",
              "embedded_files", "hyperlink_base", "leak_count"]


def write_artifacts(docs: list[OfficeDoc], report: str) -> str:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "office_metadata.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for doc in docs:
            m, flags = doc.meta, doc.flags
            writer.writerow({
                "file": os.path.basename(doc.path),
                "kind": doc.kind,
                "status": doc.status,
                "author": m.get("author", ""),
                "last_modified_by": m.get("last_modified_by", ""),
                "company": m.get("company", ""),
                "manager": m.get("manager", ""),
                "application": m.get("application", ""),
                "app_version": m.get("app_version", ""),
                "template": m.get("template", ""),
                "total_time_min": m.get("total_time_min", ""),
                "created": m.get("created", ""),
                "modified": m.get("modified", ""),
                "revision": m.get("revision", ""),
                "titles_count": len(doc.titles),
                "titles": " | ".join(doc.titles),
                "thumbnail": "yes" if flags.get("thumbnail") else "",
                "custom_props": len(flags.get("custom_props") or []),
                "comments": "yes" if flags.get("comments") else "",
                "tracked_changes": "yes" if flags.get("tracked_changes")
                                   else "",
                "macros": "yes" if flags.get("macros") else "",
                "embedded_files": flags.get("embedded_files", 0),
                "hyperlink_base": m.get("hyperlink_base", ""),
                "leak_count": len(doc.leaks),
            })
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)
    return csv_path


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Office Metadata — what your Word/Excel/PowerPoint "
                    "files say about you, with optional privacy-first "
                    "stripping")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-file",
                        help="the Office document to inspect")
    parser.add_argument("--input-file", action="append", default=[],
                        help="an Office document to inspect; repeatable")
    parser.add_argument("--input-folder",
                        help="folder of Office documents")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    parser.add_argument("--strip", action="store_true",
                        help="also write metadata-free copies")
    parser.add_argument("--output-folder", default="",
                        help="where the clean copies land (with --strip)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no documents are read", flush=True)
        return 0

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
    log(f"Reading metadata of {total} Office document(s)")
    status(f"{total} document(s)" + (" · clean copies on"
                                     if args.strip else ""))

    docs: list[OfficeDoc] = []
    stripped: list[tuple[str, str]] = []
    failed: list[str] = []
    for i, src in enumerate(sources, 1):
        doc = read_office(src)
        docs.append(doc)
        rel = os.path.basename(src)
        if doc.status == "ok":
            log(f"  🔴 {rel}: {', '.join(doc.leaks)}")
        elif doc.status == "clean":
            log(f"  🟢 {rel}: no metadata")
        else:
            log(f"  ⚫ {rel}: {doc.note}")
        if args.strip and doc.status in ("ok", "clean"):
            stem, ext = os.path.splitext(os.path.basename(src))
            dst = os.path.join(output_folder, f"{stem}_clean{ext}")
            ok, note = strip_office(src, dst)
            if ok:
                stripped.append((src, dst))
                log(f"    ⨯ clean copy: {os.path.basename(dst)} ({note})")
            else:
                failed.append(f"{rel}: strip failed — {note}")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    if docs and all(d.status == "unreadable" for d in docs):
        print("✗ every document was unreadable — nothing to inspect",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(docs, stripped, failed)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(docs))
    emit({"type": "markdown", "content": report})
    write_artifacts(docs, report)

    red = sum(1 for d in docs if d.status == "ok" and identity_leak(d))
    summary = (f"{sum(1 for d in docs if d.status in ('ok', 'clean'))} "
               f"read · {red} name people/orgs · "
               f"{sum(1 for d in docs if d.status == 'clean')} clean"
               + (f" · {len(stripped)} stripped" if stripped else ""))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
