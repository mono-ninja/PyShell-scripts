#!/usr/bin/env python3
"""icon-audit/main.py — what's wrong with the icon set, before the
sprite bakes it in.

SVG Optimize and SVG Sprite Build take the folder as given: the
first minifies whatever it finds, the second silently renames
non-conventional filenames (slugify), synthesizes missing
viewBoxes from width/height, prefixes ids — and hard-fails only on
the one collision it cannot survive.  This script is the gate
before both: everything the set gets wrong while fixing is still
cheap.

The checks:

- **viewBox diversity** — the 24/20/16 mix that makes the sprite
  render icons at different scales; icons with no viewBox at all
  (the build will synthesize one from width/height — noted, since
  synthesis is a guess that width/height were honest).
- **Naming vs the sprite's own convention** — the build slugifies
  (lowercase, non-``[a-z0-9]`` → ``-``, leading ``icon-`` stripped);
  every file whose stem differs from its slug will be renamed
  **silently** — listed here as the rename it will become; and two
  stems collapsing to one slug is the collision the build dies on.
- **Fill vs stroke** — a set mixing solid and outline styles (root
  ``fill="none"`` carried faithfully by the build, so the mix stays
  visible in the product).
- **Stroke-width outliers** — outline sets with inconsistent
  stroke weights (2 / 2.5 / 3 in one set reads as sloppiness).
- **Geometry duplicates** — identical path data under different
  names: the same icon twice, found by hashing the sorted ``d``
  attributes (exact match — no fuzzy guessing).
- **Embedded rasters** — ``<image>`` elements or ``data:image/``
  URIs inside an "SVG": raster bloat in vector clothing, immune to
  currentColor theming.
- **The a11y shape** — icons carrying ``<title>`` (the build
  strips it: the description belongs at the ``<use>`` site), and
  the ``aria-hidden`` reminder for decorative icons at use time.
- **Unused icons** — with a code folder given, every icon's symbol
  id (``icon-<slug>``) and slug is grepped against the codebase;
  never-referenced icons are named.  Dead weight in the sprite is
  bytes every visitor pays for.

Exit codes: 0 = the audit ran (findings are results), 1 = no
icons, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from lxml import etree

# The sprite's own slug convention (svg-sprite-build/src/parse.py):
# lowercase, non-[a-z0-9] collapses to "-", edges trimmed, leading
# "icon-" stripped. Mirrored here so the audit predicts the build.
SPRITE_PREFIX = "icon-"

SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor",
             "__pycache__", ".venv", "venv", "dist", "build",
             ".idea", ".next", ".cache"}
TEXT_EXTS = {".html", ".htm", ".css", ".scss", ".js", ".jsx",
             ".ts", ".tsx", ".vue", ".svelte", ".php", ".py",
             ".rb", ".go", ".rs", ".md", ".json", ".yaml", ".yml",
             ".txt", ".twig", ".liquid", ".erb", ".astro"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


def slugify(stem: str) -> str:
    """svg-sprite-build's convention, mirrored (parse.py:72)."""
    s = stem.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    s = s.removeprefix("icon-")
    return s.strip("-")


# ------------------------------------------------------------------ parsing

def load_icon(path: Path) -> dict:
    """One icon's facts; parse errors become a fact of their own."""
    facts: dict = {"file": path.name, "parse_error": ""}
    try:
        root = etree.fromstring(
            path.read_bytes(),
            parser=etree.XMLParser(resolve_entities=False,
                                   no_network=True))
    except (etree.XMLSyntaxError, OSError) as exc:
        facts["parse_error"] = str(exc)
        return facts

    stem = path.stem
    facts["stem"] = stem
    facts["slug"] = slugify(stem)

    vb = root.get("viewBox")
    if vb:
        facts["view_box"] = re.sub(r"\s+", " ", vb.strip())
    elif root.get("width") and root.get("height"):
        facts["view_box"] = None             # the build synthesizes
        facts["view_box_from"] = f'{root.get("width")}×' \
                                 f'{root.get("height")}'
    else:
        facts["view_box"] = None
        facts["view_box_from"] = ""

    # style: fill vs stroke, on the root and everywhere below
    fills, strokes, widths = set(), set(), set()
    if root.get("fill"):
        fills.add(root.get("fill"))
    if root.get("stroke"):
        strokes.add(root.get("stroke"))
    if root.get("stroke-width"):
        widths.add(root.get("stroke-width"))
    for el in root.iter():
        tag = etree.QName(el).localname if isinstance(el.tag, str) \
            else ""
        if tag == "image":
            facts["has_image"] = True
        if el.get("fill"):
            fills.add(el.get("fill"))
        if el.get("stroke"):
            strokes.add(el.get("stroke"))
        if el.get("stroke-width"):
            widths.add(el.get("stroke-width"))
        for attr, value in el.attrib.items():
            if "data:image/" in (value or ""):
                facts["has_image"] = True
    facts["stroke_widths"] = {w for w in widths}

    non_none_fill = {f for f in fills if f and f != "none"}
    non_none_stroke = {s for s in strokes if s and s != "none"}
    if non_none_fill and non_none_stroke:
        facts["style"] = "mixed"
    elif non_none_stroke:
        facts["style"] = "stroke"
    elif non_none_fill:
        facts["style"] = "fill"
    else:
        facts["style"] = "none"

    d_attrs = sorted(el.get("d") for el in root.iter()
                     if isinstance(el.tag, str) and el.get("d"))
    facts["geometry_hash"] = hashlib.sha1(
        "\n".join(d_attrs).encode()).hexdigest() if d_attrs else ""
    facts["paths"] = len(d_attrs)
    facts["has_title"] = any(
        isinstance(el.tag, str)
        and etree.QName(el).localname == "title"
        for el in root.iter())
    facts["aria_hidden"] = root.get("aria-hidden")
    return facts


# ------------------------------------------------------------------ checks

def audit_set(icons: list[dict]) -> dict:
    a: dict = {}
    good = [i for i in icons if not i["parse_error"]]

    # viewBox groups
    groups: dict[str, list[str]] = defaultdict(list)
    synth: list[str] = []
    missing: list[str] = []
    for i in good:
        if i["view_box"]:
            groups[i["view_box"]].append(i["file"])
        elif i.get("view_box_from"):
            synth.append(i["file"])
        else:
            missing.append(i["file"])
    a["view_box_groups"] = dict(sorted(groups.items(),
                                       key=lambda kv: -len(kv[1])))
    a["view_box_synthesized"] = synth
    a["view_box_missing"] = missing

    # naming
    renames = [{"file": i["file"], "becomes": SPRITE_PREFIX + i["slug"]}
               for i in good if i["stem"] != i["slug"]]
    by_slug: dict[str, list[str]] = defaultdict(list)
    for i in good:
        by_slug[i["slug"]].append(i["file"])
    collisions = {slug: files for slug, files in by_slug.items()
                  if len(files) > 1}
    empty = [i["file"] for i in good if not i["slug"]]
    a["renames"] = renames
    a["collisions"] = collisions
    a["empty_slugs"] = empty

    # style mix + stroke widths
    styles = Counter(i["style"] for i in good)
    a["styles"] = dict(styles)
    width_map: dict[str, list[str]] = defaultdict(list)
    for i in good:
        for w in i["stroke_widths"]:
            width_map[w].append(i["file"])
    a["stroke_widths"] = dict(sorted(width_map.items(),
                                     key=lambda kv: -len(kv[1])))

    # geometry duplicates
    by_geom: dict[str, list[str]] = defaultdict(list)
    for i in good:
        if i["geometry_hash"]:
            by_geom[i["geometry_hash"]].append(i["file"])
    a["geometry_duplicates"] = {
        g: files for g, files in by_geom.items() if len(files) > 1}

    # rasters, titles, aria
    a["embedded_rasters"] = [i["file"] for i in good
                             if i.get("has_image")]
    a["with_title"] = [i["file"] for i in good if i["has_title"]]
    a["aria_hidden"] = [i["file"] for i in good
                        if i["aria_hidden"] is not None]
    a["broken"] = [i for i in icons if i["parse_error"]]
    return a


# ------------------------------------------------------------ unused icons

def iter_code_files(code_dir: Path, cap: int = 20000):
    count = 0
    for dirpath, dirnames, filenames in os.walk(code_dir):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if Path(name).suffix.lower() not in TEXT_EXTS:
                continue
            yield Path(dirpath) / name
            count += 1
            if count >= cap:
                return


def find_unused(icons: list[dict], code_dir: Path,
                cap: int = 20000) -> list[dict]:
    """Icons whose symbol id and slug appear nowhere in the code."""
    corpus: list[str] = []
    for path in iter_code_files(code_dir, cap):
        try:
            corpus.append(path.read_text(encoding="utf-8",
                                         errors="replace"))
        except OSError:
            continue
    blob = "\n".join(corpus)
    unused = []
    for i in icons:
        if i["parse_error"]:
            continue
        slug = i["slug"]
        patterns = [f"{SPRITE_PREFIX}{slug}"]
        if len(slug) >= 3:            # short slugs false-positive
            patterns.append(slug)
        if not any(p in blob for p in patterns):
            unused.append({"file": i["file"], "slug": slug})
    return unused


# ------------------------------------------------------------------ report

def build_table_event(a: dict, n_icons: int) -> dict:
    def n(key) -> int:
        v = a.get(key)
        if isinstance(v, dict):
            return sum(len(x) for x in v.values())
        return len(v) if isinstance(v, list) else 0

    rows = [
        ["icons", n_icons, ""],
        ["viewBox groups", len(a["view_box_groups"]),
         " / ".join(f"{vb}×{len(f)}"
                    for vb, f in
                    list(a["view_box_groups"].items())[:3])],
        ["silent renames", len(a["renames"]),
         "stem ≠ slug"],
        ["slug collisions",
         sum(len(f) for f in a["collisions"].values()),
         "the build hard-fails here" if a["collisions"]
         else ""],
        ["geometry duplicates", n("geometry_duplicates"),
         "same paths, different names"],
        ["embedded rasters", len(a["embedded_rasters"]),
         "<image>/data: URI inside"],
        ["with <title>", len(a["with_title"]),
         "stripped at build"],
        ["parse errors", len(a["broken"]),
         ""],
    ]
    return {"type": "table", "columns": ["check", "count", "detail"],
            "rows": rows}


def build_markdown(icons_dir: str, a: dict, n_icons: int,
                   unused: list[dict] | None) -> str:
    out = [f"# Icon Audit — Report\n",
           f"`{icons_dir}` · **{n_icons} icon(s)**\n",
           "The gate before SVG Optimize and SVG Sprite Build: "
           "everything the set gets wrong while fixing is still "
           "cheap. Findings are results — the conveyor is yours to "
           "run afterwards.\n"]

    if a["broken"]:
        out.append("## Broken XML\n")
        for i in a["broken"]:
            out.append(f"- 🔴 `{i['file']}` — {i['parse_error'][:120]}")
        out.append("")

    if len(a["view_box_groups"]) > 1:
        out.append("## viewBox mix\n")
        out.append("The sprite renders icons at their own scale — "
                   "a mixed set shows as inconsistent sizing:")
        for vb, files in a["view_box_groups"].items():
            out.append(f"- `{vb}` — {len(files)} icon(s): "
                       f"{', '.join(files[:5])}"
                       + (" …" if len(files) > 5 else ""))
        out.append("")
    if a["view_box_synthesized"]:
        out.append(f"- ⚫ {len(a['view_box_synthesized'])} icon(s) "
                   "have no viewBox — the build will synthesize one "
                   "from width/height (a guess that both were "
                   "honest).")
    if a["view_box_missing"]:
        out.append(f"- 🔴 {len(a['view_box_missing'])} icon(s) have "
                   "neither viewBox nor width/height — nothing to "
                   "size them by.")

    if a["renames"]:
        out.append("\n## Names the build will change silently\n")
        for r in a["renames"]:
            out.append(f"- ◐ `{r['file']}` → symbol "
                       f"**{r['becomes']}**")
    if a["collisions"]:
        out.append("\n## Collisions — the build dies here\n")
        for slug, files in a["collisions"].items():
            out.append(f"- 🔴 `{slug}` ← {', '.join(files)} — two "
                       "files collapse to one symbol id; rename one "
                       "before building")
    if a["empty_slugs"]:
        out.append(f"\n- 🔴 empty slug after slugify: "
                   f"{', '.join(a['empty_slugs'])}")

    styles = a["styles"]
    if len([s for s, n in styles.items() if n and s != "none"]) > 1:
        out.append("\n## Style mix\n")
        out.append(f"- fill-based: {styles.get('fill', 0)} · "
                   f"stroke-based: {styles.get('stroke', 0)} · "
                   f"mixed inside one icon: {styles.get('mixed', 0)}"
                   " — a set half solid, half outline reads as two "
                   "different sets on the page")
    if len(a["stroke_widths"]) > 1:
        out.append("\n## Stroke widths\n")
        for w, files in a["stroke_widths"].items():
            out.append(f"- `{w}` — {len(files)} icon(s)")
        out.append("- inconsistent weights in one outline set "
                   "read as sloppiness; pick one")

    if a["geometry_duplicates"]:
        out.append("\n## Geometry duplicates — same paths, "
                   "different names\n")
        for files in a["geometry_duplicates"].values():
            out.append(f"- 🔴 {', '.join(files)} — identical path "
                       "data (paint excluded from the hash): the "
                       "same geometry twice; keep one name or "
                       "confirm the difference is intentional")

    if a["embedded_rasters"]:
        out.append("\n## Embedded rasters\n")
        for f in a["embedded_rasters"]:
            out.append(f"- 🔴 `{f}` — an <image> or data:image/ URI "
                       "inside: raster bloat in vector clothing, "
                       "immune to currentColor theming")

    if a["with_title"]:
        out.append("\n## Titles — stripped at build\n")
        out.append("The build removes `<title>` (it would repeat "
                   "across every `<use>`); the description belongs "
                   "at the use site:")
        for f in a["with_title"]:
            out.append(f"- ◐ `{f}` carries a `<title>` — move it to "
                       "the `aria-label` of the referencing element")
        if a["aria_hidden"]:
            out.append(f"- ◐ {len(a['aria_hidden'])} icon(s) carry "
                       "aria-hidden — it does not survive into the "
                       "sprite; set it on the `<use>`/`<img>` at "
                       "use time")

    if unused is not None:
        if unused:
            out.append("\n## Unused icons — dead weight in the sprite\n")
            for u in unused:
                out.append(f"- ⚫ `{u['file']}` (`{u['slug']}`) — no "
                           "reference found in the code folder")
            out.append(f"\n{len(unused)} of {n_icons} icon(s) are "
                       "referenced nowhere: every sprite byte is "
                       "paid by every visitor — cut or wire them.")
        else:
            out.append("\n## Unused icons\n")
            out.append(f"- ✅ every icon of the {n_icons} is "
                       "referenced in the code folder")

    clean = not (a["broken"] or a["collisions"]
                 or a["geometry_duplicates"] or a["embedded_rasters"]
                 or len(a["view_box_groups"]) > 1
                 or a["view_box_missing"] or a["renames"])
    if clean:
        out.append("\nThe set is uniform: one viewBox, one style, "
                   "conventional names, no duplicates. Feed it to "
                   "SVG Optimize and build the sprite.")
    out.append("\n## Related\n")
    out.append("- **SVG Sprite Build** — the build this audit "
               "gates (its slug convention is mirrored here).")
    out.append("- **SVG Optimize** — the minify step after the "
               "gate.")
    out.append("- **Figma Export** — the fresh export worth "
               "running through this gate.")
    return "\n".join(out)


def write_artifacts(icons_dir: str, icons: list[dict], a: dict,
                    unused: list[dict] | None, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"icons_dir": icons_dir,
                   "icons": [{k: (sorted(v) if isinstance(v, set)
                                  else v)
                              for k, v in i.items()}
                             for i in icons],
                   "audit": a, "unused": unused},
                  fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Icon Audit — QA of an icon set before the "
                    "sprite: viewBox mix, naming vs the build's "
                    "slug convention, style mix, duplicates, "
                    "rasters, titles, and unused icons grepped "
                    "against your code")
    parser.add_argument("--icons-dir", required=True,
                        help="the folder of .svg files")
    parser.add_argument("--code-dir", default="",
                        help="optional project folder for the "
                             "unused-icons check")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files are read",
              flush=True)
        return 0

    icons_dir = Path(args.icons_dir)
    if not icons_dir.is_dir():
        print(f"✗ {args.icons_dir}: folder not found",
              file=sys.stderr, flush=True)
        return 2
    files = sorted(p for p in icons_dir.iterdir()
                   if p.suffix.lower() == ".svg"
                   and not p.name.startswith("."))
    if not files:
        print(f"✗ no .svg files in {args.icons_dir}",
              file=sys.stderr, flush=True)
        return 1

    icons = []
    for i, path in enumerate(files, 1):
        icons.append(load_icon(path))
        emit({"type": "progress",
              "pct": int(60 * i / len(files)),
              "message": path.name})

    unused = None
    if args.code_dir:
        code_dir = Path(args.code_dir)
        if not code_dir.is_dir():
            print(f"✗ {args.code_dir}: folder not found",
                  file=sys.stderr, flush=True)
            return 2
        log("  grepping the code folder for references")
        unused = find_unused(icons, code_dir)
        emit({"type": "progress", "pct": 80,
              "message": f"{len(unused)} unused"})

    a = audit_set(icons)
    report = build_markdown(args.icons_dir, a, len(icons), unused)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(a, len(icons)))
    emit({"type": "markdown", "content": report})
    write_artifacts(args.icons_dir, icons, a, unused, report)

    problems = (len(a["broken"])
                + sum(len(f) for f in a["collisions"].values())
                + len(a["geometry_duplicates"])
                + len(a["embedded_rasters"]))
    summary = (f"{len(icons)} icon(s) · {problems} hard problem(s)"
               + (f" · {len(unused)} unused" if unused is not None
                  else ""))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
