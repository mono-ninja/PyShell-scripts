#!/usr/bin/env python3
"""figma-export/main.py — the design tool meets the code pipeline.

The collection's icon conveyor ends in a sprite; its start was
always "somehow the SVGs appear in a folder".  This script is that
somehow: the components of a Figma file (or one frame of it)
exported as SVG, named by the sprite's own convention, ready for
**Icon Audit → SVG Optimize → SVG Sprite Build** — the conveyor
with a front door.

- **Token** — a Figma personal access token, through the Keychain
  (env `FIGMA_TOKEN`, never argv — the Shodan precedent).  Without
  it: an honest exit 1 with the where-to-get-one line, never an
  imitated export.
- **Scope** — the whole file, or the frame in the URL's
  `?node-id=`; every **component** under the scope is collected
  (component sets are walked to their variants).
- **Names** — Figma's names ("icon/home", "Home Icon", "ic24
  Home") slugified exactly the way svg-sprite-build does it
  (lowercase, non-``[a-z0-9]`` → ``-``, leading ``icon-``
  stripped); collisions get a ``-2`` suffix and are said aloud —
  Icon Audit will hold the mirror up afterwards.
- **PNG** — optional, at 1x or 2x, for the places SVG cannot go.

The honest limit, surfaced live: Figma's **Variables API is
Enterprise-only**.  The script asks; a 403 is reported as
"not checked — Enterprise-only", never as "no variables" (the
dnssec-check indeterminate pattern).  Nodes and published styles —
what icons need — are available on every plan.

Exit codes: 0 = exported, 1 = no token / nothing to export /
download failure, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

import requests

API = "https://api.figma.com/v1"
TOKEN_ENV = "FIGMA_TOKEN"
USER_AGENT = "PyShell-figma-export/1 (+icon conveyor)"

# svg-sprite-build's slug convention, mirrored (parse.py:72) — the
# export must produce names the build would not rename.
SLUG_STRIP_PREFIX = "icon-"


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


class FigmaError(RuntimeError):
    pass


# ------------------------------------------------------------------- token

def read_token() -> str:
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(f"✗ {TOKEN_ENV} is not set — Figma's API needs a "
              "personal access token: Figma → Settings → Security → "
              "Personal access tokens (read-only scope is enough). "
              "In PyShell the token field stores it in the "
              "Keychain; standalone: export "
              f"{TOKEN_ENV}=…", file=sys.stderr, flush=True)
    return token


# -------------------------------------------------------------------- URLs

def parse_figma_url(url: str) -> tuple[str, str]:
    """(file_key, node_id or '') — accepts /file/, /design/,
    /proto/ URLs with an optional ?node-id= (both '1:2' and
    '1-2' spellings)."""
    try:
        parts = urlparse(url.strip())
    except ValueError:
        raise FigmaError(f"{url!r} is not a URL")
    if "figma.com" not in (parts.netloc or ""):
        raise FigmaError("not a figma.com URL")
    segs = parts.path.split("/")            # empties kept: a real
    key = ""                                # key never sits after //
    for i, seg in enumerate(segs):
        if seg in ("file", "design", "proto") and i + 1 < len(segs):
            key = segs[i + 1]
            break
    if not re.fullmatch(r"[A-Za-z0-9]+", key or ""):
        raise FigmaError("no file key in the URL — expected "
                         "figma.com/design/<key>/Name")
    node = ""
    raw_node = (parse_qs(parts.query).get("node-id") or [""])[0]
    if raw_node:
        node = unquote(raw_node).replace("-", ":")
    return key, node


# ------------------------------------------------------------------ slugify

def slugify(name: str) -> str:
    """svg-sprite-build's convention: lowercase, non-[a-z0-9] →
    '-', edges trimmed, leading 'icon-' stripped."""
    s = (name or "").lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    s = s.removeprefix(SLUG_STRIP_PREFIX)
    return s.strip("-")


def unique_name(base: str, taken: dict[str, int]) -> str:
    """Collisions get -2, -3 … and are reported, never silently
    overwritten."""
    if base not in taken:
        taken[base] = 1
        return base
    taken[base] += 1
    return f"{base}-{taken[base]}"


# ------------------------------------------------------------------- figma

def figma_get(path: str, token: str, timeout: int,
              session: requests.Session | None = None) -> dict:
    requester = session or requests
    r = requester.get(API + path, timeout=timeout,
                      headers={"X-Figma-Token": token,
                               "User-Agent": USER_AGENT})
    if r.status_code == 403:
        raise FigmaError(f"403 — {path} is not available to this "
                         "token (Variables are Enterprise-only; "
                         "check the token's scope)")
    if r.status_code == 404:
        raise FigmaError("404 — no such file/key (check the URL "
                         "and the token's access to the team)")
    r.raise_for_status()
    return r.json()


def collect_components(node: dict, out: list[dict]) -> None:
    """Every COMPONENT under the node; COMPONENT_SETs walk to
    their variant children (a set is one icon with states, each
    variant exports separately — named by its own name)."""
    kind = node.get("type")
    if kind == "COMPONENT":
        out.append({"id": node["id"], "name": node.get("name", "")})
        return
    if kind == "COMPONENT_SET":
        for child in node.get("children", []):
            if child.get("type") == "COMPONENT":
                out.append({"id": child["id"],
                            "name": f'{node.get("name", "")} '
                                    f'{child.get("name", "")}'})
        return
    for child in node.get("children", []):
        collect_components(child, out)


def fetch_components(key: str, node: str, token: str,
                     timeout: int) -> tuple[list[dict], str]:
    """The export scope: one frame's subtree, or the file's first
    pages. Returns (components, document_name)."""
    if node:
        data = figma_get(f"/files/{key}/nodes?ids={node}"
                         .replace(":", "%3A"), token, timeout)
        nodes = data.get("nodes", {})
        sub = nodes.get(node) or next(iter(nodes.values()), {})
        doc = sub.get("document", {})
        name = doc.get("name", "")
        comps: list[dict] = []
        collect_components(doc, comps)
        return comps, name
    data = figma_get(f"/files/{key}?depth=4", token, timeout)
    doc = data.get("document", {})
    comps: list[dict] = []
    collect_components(doc, comps)
    return comps, doc.get("name", "")


def fetch_image_urls(key: str, ids: list[str], fmt: str,
                     scale: int, token: str,
                     timeout: int) -> dict[str, str]:
    """id → download URL, via the images endpoint (batched)."""
    query = "&".join(f"ids={i.replace(':', '%3A')}" for i in ids)
    path = (f"/images/{key}?{query}&format={fmt}"
            + (f"&scale={scale}" if fmt == "png" else ""))
    data = figma_get(path, token, timeout)
    images = data.get("images", {}) or {}
    return {i: u for i, u in images.items() if u}


def download(url: str, dest: Path, timeout: int) -> int:
    r = requests.get(url, timeout=timeout,
                     headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    dest.write_bytes(r.content)
    return len(r.content)


def check_variables(key: str, token: str,
                    timeout: int) -> dict:
    """The Enterprise-only limit, asked for and reported honestly."""
    try:
        figma_get(f"/files/{key}/variables", token, timeout)
        return {"status": "ok",
                "note": "the Variables API answered — this file's "
                        "variables are reachable"}
    except FigmaError as exc:
        if "403" in str(exc):
            return {"status": "not checked",
                    "note": "the Variables API is Enterprise-only "
                            "— not checked, never 'no variables'"}
        return {"status": "not checked", "note": str(exc)}


# ------------------------------------------------------------------ report

def build_table_event(rows: list[dict]) -> dict:
    return {"type": "table",
            "columns": ["component", "exported as", "svg", "png"],
            "rows": rows or [{"component": "—", "exported as": "—",
                              "svg": "—", "png": "—"}]}


def human(n: int) -> str:
    return f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


def build_markdown(doc_name: str, key: str, rows: list[dict],
                   variables: dict) -> str:
    svg_n = sum(1 for r in rows if r["svg"])
    png_n = sum(1 for r in rows if r["png"] not in ("—", ""))
    out = [f"# Figma Export — Report\n",
           f"`{doc_name or key}` · {len(rows)} component(s) · "
           f"**{svg_n} SVG** exported"
           + (f" · {png_n} PNG" if png_n else "")
           + "\n"]
    renamed = [r for r in rows if r["component"] != r["exported as"]]
    if renamed:
        out.append(f"- ◐ {len(renamed)} name(s) normalized to the "
                   "sprite convention (kebab-case, `icon-` "
                   "stripped) — the exact slugify SVG Sprite Build "
                   "applies, so nothing renames twice")
    suffixed = [r for r in rows if re.search(r"-\d+\.svg$",
                                             r["exported as"])]
    if suffixed:
        out.append(f"- ⚠️ {len(suffixed)} name collision(s) got a "
                   "-2 style suffix — rename the component in "
                   "Figma so each icon has one name")
    out.append(f"- variables: {variables['note']}")
    out.append("")
    out.append("## The conveyor from here\n")
    out.append("1. **Icon Audit** — the gate: viewBox mix, "
               "duplicates, unused icons against your code.")
    out.append("2. **SVG Optimize** — minify.")
    out.append("3. **SVG Sprite Build** — the sprite, with the "
               "same slugs these files already carry.")
    out.append("")
    out.append("## Exported\n")
    out.append("| component | exported as | svg | png |")
    out.append("|---|---|---|---|")
    for r in rows:
        out.append(f"| {r['component']} | `{r['exported as']}` | "
                    f"{r['svg']} | {r['png']} |")
    out.append("")
    out.append("## Related\n")
    out.append("- **Icon Audit / SVG Optimize / SVG Sprite "
               "Build** — the three steps this export feeds.")
    out.append("- **Color Palette** — the design tokens side "
               "(colors) of the same handoff.")
    return "\n".join(out)


def write_artifacts(key: str, doc_name: str, rows: list[dict],
                    variables: dict, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"file_key": key, "document": doc_name,
                   "exports": rows, "variables": variables},
                  fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Figma Export — components of a file or frame "
                    "as SVG (optional PNG 1x/2x), names normalized "
                    "to the sprite convention, feeding the icon "
                    "conveyor")
    parser.add_argument("--figma-url", required=True,
                        help="the file/design URL, optionally with "
                             "?node-id= to scope one frame")
    parser.add_argument("--png-scale", choices=["none", "1", "2"],
                        default="none",
                        help="also export PNG at this scale")
    parser.add_argument("--timeout", type=int, default=30,
                        help="per-request timeout (default 30)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is fetched",
              flush=True)
        return 0

    token = read_token()
    if not token:
        return 1
    try:
        key, node = parse_figma_url(args.figma_url)
    except FigmaError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    log(f"  file {key}"
        + (f" · frame {node}" if node else " · whole file"))
    status("reading the document tree")
    emit({"type": "progress", "pct": 10,
          "message": "document tree"})
    try:
        comps, doc_name = fetch_components(key, node, token,
                                           args.timeout)
    except (FigmaError, requests.RequestException) as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1
    if not comps:
        print("✗ no components under this scope — icons live as "
              "components (purple) in Figma; frames alone are not "
              "exported", file=sys.stderr, flush=True)
        return 1
    log(f"  {len(comps)} component(s)")

    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    taken: dict[str, int] = {}
    rows: list[dict] = []
    by_id = {}
    for c in comps:
        slug = slugify(c["name"])
        name = unique_name(slug or "icon", taken)
        by_id[c["id"]] = {"component": c["name"],
                          "exported": name}
    emit({"type": "progress", "pct": 30, "message": "SVG render"})

    try:
        svg_urls = fetch_image_urls(key, list(by_id), "svg", 1,
                                    token, args.timeout)
        png_urls = {}
        if args.png_scale != "none":
            png_urls = fetch_image_urls(
                key, list(by_id), "png", int(args.png_scale),
                token, args.timeout)
    except (FigmaError, requests.RequestException) as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1

    done = 0
    for cid, meta in by_id.items():
        entry = {"component": meta["component"],
                 "exported as": meta["exported"] + ".svg",
                 "svg": "—", "png": "—"}
        try:
            if cid in svg_urls:
                size = download(svg_urls[cid],
                                Path(out_dir)
                                / f"{meta['exported']}.svg",
                                args.timeout)
                entry["svg"] = human(size)
            if cid in png_urls:
                size = download(png_urls[cid],
                                Path(out_dir)
                                / f"{meta['exported']}.png",
                                args.timeout)
                entry["png"] = human(size)
        except (requests.RequestException, OSError) as exc:
            entry["svg"] = f"failed: {exc}"[:60]
        rows.append(entry)
        done += 1
        emit({"type": "progress",
              "pct": 30 + int(60 * done / len(by_id)),
              "message": meta["exported"]})

    variables = check_variables(key, token, args.timeout)
    emit({"type": "progress", "pct": 95, "message": "variables"})
    report = build_markdown(doc_name, key, rows, variables)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(rows))
    emit({"type": "markdown", "content": report})
    write_artifacts(key, doc_name, rows, variables, report)

    exported = sum(1 for r in rows if r["svg"] not in ("—",)
                   and not r["svg"].startswith("failed"))
    summary = (f"{exported}/{len(rows)} SVG exported"
               + (f" · {args.png_scale}x PNG"
                  if args.png_scale != "none" else ""))
    status(summary)
    log(f"← {summary}")
    return 0 if exported else 1


if __name__ == "__main__":
    sys.exit(main())
