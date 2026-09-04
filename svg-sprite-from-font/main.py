#!/usr/bin/env python3
"""svg-sprite-from-font/main.py — convert a legacy icon font into a symbol sprite.

Orchestrates the stages in ``src/``: triage → extract → name → geometry →
subset → assemble → emit. Progress is reported as structured JSON events on
stderr (PyShell); running from a terminal degrades those to ordinary log lines.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from src.assemble import assemble_sprite, sprite_body_xml
from src.binfont import BinaryFontError, extract_binary
from src.emit_catalog import emit_catalog
from src.emit_shim import emit_shim
from src.emit_sprite import emit_sprite
from src.emit_wordpress import emit_wordpress
from src.geometry import build_symbol
from src.model import FontMetrics, RawGlyph, Symbol
from src.naming import NameBinding, load_names_json, resolve_names
from src.subset import scan_usage
from src.svgfont import SVGFontError, parse_svg_font
from src.triage import TriageError, triage
from src.util import atomic_write_text, copy_to_output_dir

# Progress phase boundaries (see plan: B0–B7 → one 0–100 bar).
P_TRIAGE = (0, 5)
P_EXTRACT = (5, 40)
P_NAME = (40, 60)
P_GEOMETRY = (60, 80)
P_EMIT = (80, 100)


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def progress(pct: float, message: str = "") -> None:
    emit({"type": "progress", "pct": pct, "message": message})


def phase(name: str, lo: float, hi: float):
    """Return a reporter that maps a sub-phase 0..1 onto ``lo..hi``."""
    last = [-1]

    def report(done: int, total: int, msg: str = "") -> None:
        frac = (done / total) if total else 1
        pct = lo + (hi - lo) * frac
        if int(pct) != last[0] or done == total:
            last[0] = int(pct)
            emit({"type": "progress", "pct": round(pct, 1), "message": msg or name})

    return report


def output_dir() -> str:
    return os.environ.get("PYSHELL_OUTPUT_DIR", "")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Convert an icon font into an SVG symbol sprite")
    p.add_argument("--i-have-the-rights", action="store_true",
                   help="Confirm redistribution rights for the font's outlines (B0)")
    p.add_argument("--font", required=True, help="Font file (ttf/otf/woff/woff2/svg)")
    p.add_argument("--css", default=None, help="Accompanying CSS with icon class names")
    p.add_argument("--names", default=None, help="Existing names.json to re-read")
    p.add_argument("--prefix", default="icon-", help="Sprite symbol id prefix")
    p.add_argument("--flatten", action="store_true", default=False,
                   help="Bake the y-flip transform into path data")
    p.add_argument("--no-flatten", dest="flatten", action="store_false",
                   help="Keep a wrapper <g> transform instead of flattening (default)")
    p.add_argument("--fit", choices=["advance", "bbox"], default="advance",
                   help="viewBox fit: advance (faithful) or bbox (visually normalized)")
    p.add_argument("--fit-padding", type=int, default=0,
                   help="Padding around the bbox fit, in font units")
    p.add_argument("--scan-usage", action="store_true",
                   help="Restrict to icons found in the theme")
    p.add_argument("--scan", default=None, help="Theme folder to scan for class usage")
    p.add_argument("--out", required=True, help="Output folder")
    p.add_argument("--wordpress", action="store_true", default=False,
                   help="Generate sprite.php WordPress include")
    p.add_argument("--no-wordpress", dest="wordpress", action="store_false",
                   help="Skip sprite.php generation (default)")
    p.add_argument("--migration-css", action="store_true", default=False,
                   help="Generate migration.css")
    p.add_argument("--no-migration-css", dest="migration_css", action="store_false",
                   help="Skip migration.css generation (default)")
    return p


def _extract(args) -> tuple[FontMetrics, list[RawGlyph], object]:
    """Return (metrics, glyphs, licence). licence is a LicenceInfo for binary
    fonts, or a minimal stand-in for SVG fonts (which have no name table)."""
    result = triage(args.font)
    if result.kind == "svg":
        metrics, glyphs = parse_svg_font(args.font)
        # SVG fonts carry no name table; synthesise a non-restrictive licence.
        from src.binfont import LicenceInfo
        licence = LicenceInfo(family=metrics.family, classified="unknown")
        licence.license = "(SVG font — no name table; licence unknown)"
        return metrics, glyphs, licence
    bf = extract_binary(args.font)
    return bf.metrics, bf.glyphs, bf.licence


def _licence_gate(licence, have_rights: bool) -> int:
    """B0: print the licence and halt on a restrictive one without the override.

    Returns 0 to proceed, non-zero to exit immediately without writing output.
    """
    summary = licence.summary() or "(no licence information in the name table)"
    classified = getattr(licence, "classified", "unknown")
    status(f"Licence: {summary}")
    if classified == "permissive":
        status("Licence appears permissive (OFL/Apache/MIT/...).")
    elif classified == "restrictive":
        if not have_rights:
            emit({"type": "markdown", "content": (
                "## ⛔ Restrictive licence\n\n"
                f"**{licence.full_name or 'This font'}** declares a restrictive "
                f"licence:\n\n> {summary}\n\n"
                "Extracting outlines is redistribution. Tick **“I have "
                "redistribution rights”** (`--i-have-the-rights`) only if you "
                "actually do. No files were written."
            )})
            status("Halted: restrictive licence without --i-have-the-rights")
            return 1
        status("Restrictive licence, but --i-have-the-rights is set — proceeding.")
    else:
        status("Licence could not be classified; proceed at your own discretion.")
    return 0


def _subset(args, glyphs: list[RawGlyph], bindings: list[NameBinding]):
    """Apply usage subsetting. Returns the kept (glyphs, bindings) and a
    (found, used) tuple for reporting."""
    if not args.scan_usage:
        return glyphs, bindings, (len(glyphs), len(glyphs))
    if not args.scan:
        status("--scan-usage set but no --scan path; skipping subsetting")
        return glyphs, bindings, (len(glyphs), len(glyphs))
    known = {b.class_name for b in bindings if b.class_name}
    for b in bindings:
        known.update(b.aliases)
    if not known:
        status("--scan-usage: no CSS class names available to match; skipping")
        return glyphs, bindings, (len(glyphs), len(glyphs))
    used = scan_usage(args.scan, known)
    kept: list[tuple[RawGlyph, NameBinding]] = []
    for g, b in zip(glyphs, bindings, strict=False):
        classes = {b.class_name} | set(b.aliases) if b.class_name else set()
        if classes & used:
            kept.append((g, b))
    kg = [k[0] for k in kept]
    kb = [k[1] for k in kept]
    status(f"Subsetting: {len(used)} classes used in theme, {len(kg)} of {len(glyphs)} icons kept")
    return kg, kb, (len(glyphs), len(kg))


def _catalog_rows(symbols: list[Symbol], bindings: list[NameBinding]) -> list[dict]:
    rows = []
    for s, b in zip(symbols, bindings, strict=False):
        cp = s.meta.get("codepoint")
        cp_str = cp if cp else None
        cp_escape = None
        if cp and cp.startswith("U+"):
            try:
                cpval = int(cp[2:], 16)
                cp_escape = f"\\{cpval:x}"
            except ValueError:
                cp_escape = None
        rows.append({
            "sprite_id": s.id,
            "view_box": s.view_box,
            "codepoint": cp_str,
            "cp_escape": cp_escape,
            "class_name": b.class_name,
            "name_source": b.source,
            "ligature": s.meta.get("ligature"),
            "warnings": list(s.warnings),
        })
    return rows


def main() -> int:
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        build_parser()
        return 0

    args = build_parser().parse_args()
    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    progress(P_TRIAGE[0], "Triage")
    try:
        triage_result = triage(args.font)
    except TriageError as e:
        print(f"Error: {e}", file=sys.stderr, flush=True)
        status(f"Triage failed: {e}")
        progress(100, "Failed")
        return 2
    status(f"Input: {triage_result.format}")

    # B0 licence gate happens after triage but before any extraction output.
    progress(P_EXTRACT[0], "Extracting outlines")
    try:
        metrics, glyphs, licence = _extract(args)
    except (BinaryFontError, SVGFontError) as e:
        print(f"Error: {e}", file=sys.stderr, flush=True)
        status(f"Extraction failed: {e}")
        progress(100, "Failed")
        return 2

    if _licence_gate(licence, args.i_have_the_rights):
        progress(100, "Halted (licence)")
        return 3

    status(f"Extracted {len(glyphs)} glyphs from {metrics.family or triage_result.format}")
    progress(P_EXTRACT[1], f"{len(glyphs)} glyphs")

    # B4 name resolution.
    progress(P_NAME[0], "Resolving names")
    existing = load_names_json(args.names) if args.names else None
    resolution = resolve_names(glyphs, args.css, existing, args.prefix)
    bindings = resolution.bindings
    n_unnamed = sum(1 for b in bindings if b.unnamed)
    if resolution.css_prefix:
        status(f"CSS class prefix detected: {resolution.css_prefix!r}")
    status(f"Named {len(bindings)} glyphs ({n_unnamed} unnamed)")
    progress(P_NAME[1], f"{n_unnamed} unnamed")

    # B6 subsetting.
    glyphs, bindings, (found, used_n) = _subset(args, glyphs, bindings)

    # B5 geometry.
    rep = phase("Building symbols", P_GEOMETRY[0], P_GEOMETRY[1])
    symbols: list[Symbol] = []
    for i, (g, b) in enumerate(zip(glyphs, bindings, strict=False), 1):
        symbols.append(build_symbol(
            g, metrics, b, flatten=args.flatten, fit=args.fit,
            fit_padding=args.fit_padding,
        ))
        rep(i, len(glyphs))

    # B7 assemble + emit.
    progress(P_EMIT[0], "Assembling sprite")
    sprite_root = assemble_sprite(symbols)
    sprite_body = sprite_body_xml(sprite_root)

    written: list[str] = []
    sprite_path = os.path.join(out_dir, "sprite.svg")
    emit_sprite(sprite_path, sprite_root)
    written.append("sprite.svg")

    catalog_path = os.path.join(out_dir, "catalog.html")
    rows = _catalog_rows(symbols, bindings)
    fmt = triage_result.format
    # For @font-face embedding, an SVG-font input is not a webfont.
    font_for_catalog = args.font if fmt != "svg-font" else None
    emit_catalog(catalog_path, rows, sprite_body, font_for_catalog, fmt,
                 metrics.family or "icon font",
                 {"total": len(symbols), "unnamed": n_unnamed})
    written.append("catalog.html")

    names_path = os.path.join(out_dir, "names.json")
    atomic_write_text(names_path, json.dumps(resolution.names_json, indent=2, ensure_ascii=False) + "\n")
    written.append("names.json")

    if args.wordpress:
        php_path = os.path.join(out_dir, "sprite.php")
        emit_wordpress(php_path, sprite_body, args.prefix)
        written.append("sprite.php")

    if args.migration_css and resolution.class_to_sprite:
        shim_path = os.path.join(out_dir, "migration.css")
        emit_shim(shim_path, resolution.class_to_sprite, "sprite.svg")
        written.append("migration.css")
    elif args.migration_css and not resolution.class_to_sprite:
        status("Skipping migration.css — no legacy CSS classes to map")

    # Mirror artifacts into PYSHELL_OUTPUT_DIR for the UI's artifact cards.
    odir = output_dir()
    for name in written:
        copy_to_output_dir(os.path.join(out_dir, name), odir)

    # Result table: codepoint, resolved name, name source, warnings.
    table_rows = []
    for s in symbols:
        m = s.meta
        table_rows.append([
            m.get("codepoint") or m.get("ligature") or m.get("glyph_name") or "—",
            s.id,
            m.get("name_source", ""),
            "; ".join(s.warnings) if s.warnings else "",
        ])
    emit({
        "type": "table",
        "columns": ["Codepoint", "Symbol id", "Name source", "Warnings"],
        "rows": table_rows,
    })

    extras = []
    if args.scan_usage:
        extras.append(f"subset {used_n}/{found}")
    summary = (
        "## Done\n\n"
        f"Converted **{len(symbols)}** icons from "
        f"`{metrics.family or triage_result.format}` into a symbol sprite.\n\n"
        f"- Sprite: `sprite.svg` ({len(symbols)} symbols)\n"
        f"- Catalog: `catalog.html` (side-by-side verification)\n"
        f"- Names: `names.json`"
        + ("\n- WordPress include: `sprite.php`" if args.wordpress else "")
        + ("\n- Migration CSS: `migration.css`" if "migration.css" in written else "")
        + (f"\n- Unnamed glyphs: {n_unnamed}" if n_unnamed else "")
        + (f"\n- Subset: {used_n}/{found} icons used in theme" if args.scan_usage else "")
        + f"\n\nFiles written to `{out_dir}`."
    )
    emit({"type": "markdown", "content": summary})
    progress(100, "Done")
    status(f"Done — {len(symbols)} icons · {n_unnamed} unnamed · " + " ".join(extras).strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
