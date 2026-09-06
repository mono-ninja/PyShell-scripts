#!/usr/bin/env python3
"""wp-vuln-check/main.py — known holes in the installed WordPress
plugins and themes.

The WP corner of the vulnerability line, and the biggest factual
gap cve-check has: **OSV has no WordPress ecosystem** — plugins are
invisible to it by principle.  The Wordfence Intelligence feed is
the source (WPScan and Patchstack want paid tiers; Wordfence's key
is free with an account), and this script speaks its v3 API.

The local-folder input is the point: versions are read **exactly**
— the `Plugin Name:` / `Version:` headers of every plugin's main
PHP file, the `Theme Name:` / `Version:` of every theme's
style.css, and `wp_version` from wp-includes when the parent of
wp-content is given.  Not a frontend guess in sight (the
remote-site shape stays cve-check's, with its honest scoping).

Matching is honest about WordPress version semantics: a PHP-style
version comparison (digits vs. letter chunks, `2.10` after `2.9`),
the affected-range operators from the feed, and the `patched` flag
as its own answer — a patched backport means the site may already
be safe on the same version number.

Exit codes: 0 = ran (findings are results), 1 = folder without
plugins/themes / feed unreachable / no API key, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field

import requests

FEED_URL = ("https://www.wordfence.com/api/intelligence/v3/"
            "vulnerabilities/production")
USER_AGENT = "PyShell-wp-vuln-check/1 (+WordPress plugin diagnostics)"


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------- version compare

def _ver_chunks(v: str) -> list[str]:
    v = (v or "").strip().lower().replace("-", ".").replace("_", ".")
    v = re.sub(r"(\d)([a-z])", r"\1.\2", v)
    v = re.sub(r"([a-z])(\d)", r"\1.\2", v)
    return [p for p in re.split(r"\.", v) if p]


def version_compare(a: str, b: str) -> int:
    """The PHP version_compare shape WordPress versions rely on:
    `2.10` > `2.9`, `6.4.1` < `6.4.10`, `1.2a` < `1.2.1`."""
    A, B = _ver_chunks(a), _ver_chunks(b)
    for i in range(max(len(A), len(B))):
        x = A[i] if i < len(A) else ("0" if B[i][0:1].isdigit() else "#")
        y = B[i] if i < len(B) else ("0" if A[i][0:1].isdigit() else "#")
        xd, yd = x[0].isdigit(), y[0].isdigit()
        if xd and yd:
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif xd:
            return 1            # numeric chunks > alphabetic in PHP
        elif yd:
            return -1
        elif x != y:
            return -1 if x < y else 1
    return 0


OPS = {
    "*": lambda v, x: True,
    ">=": lambda v, x: version_compare(v, x) >= 0,
    ">": lambda v, x: version_compare(v, x) > 0,
    "<=": lambda v, x: version_compare(v, x) <= 0,
    "<": lambda v, x: version_compare(v, x) < 0,
    "=": lambda v, x: version_compare(v, x) == 0,
}


def in_affected_range(version: str, affected: dict) -> bool:
    ft = (affected.get("from_type") or "*").strip()
    tt = (affected.get("to_type") or "*").strip()
    frm, to = affected.get("from"), affected.get("to")
    if ft not in ("*",) and not frm:
        ft = "*"
    if tt not in ("*",) and not to:
        tt = "*"
    if not OPS.get(ft, OPS["*"])(version, frm or "0"):
        return False
    if not OPS.get(tt, OPS["*"])(version, to or "9999999"):
        return False
    return True


# ------------------------------------------------------------- the headers

@dataclass
class Software:
    kind: str             # plugin | theme | core
    slug: str
    name: str
    version: str          # "" when no Version header — honest
    path: str


HEADER_KEYS = {
    "plugin": ("Plugin Name", "Version"),
    "theme": ("Theme Name", "Version"),
}


def parse_php_header(text: str) -> dict:
    """`Plugin Name: X` / `Version: 1.2` from the doc-comment
    header block (wherever it starts — `<?php` usually comes
    first)."""
    out = {}
    m = re.search(r"/\*", text)
    if not m:
        return out
    block = text[m.end():text.find("*/", m.end()) if "*/" in text
                 else len(text)]
    for line in block.splitlines():
        hm = re.match(r"^\s*\*?\s*([A-Za-z ]+?)\s*:\s*(.+)$", line)
        if hm:
            out.setdefault(hm.group(1).strip(), hm.group(2).strip())
    return out


def read_plugin(path: str) -> Software | None:
    """The plugin's main PHP file: the one carrying the header —
    by convention the file named like the folder, else the first
    header-carrying PHP file."""
    folder = os.path.basename(path.rstrip("/"))
    candidates = [os.path.join(path, f"{folder}.php")]
    candidates += sorted(
        os.path.join(path, f) for f in os.listdir(path)
        if f.endswith(".php")) if os.path.isdir(path) else []
    for cand in candidates:
        if not os.path.isfile(cand):
            continue
        try:
            text = open(cand, encoding="utf-8",
                        errors="replace").read(8192)
        except OSError:
            continue
        header = parse_php_header(text)
        if "Plugin Name" in header:
            return Software("plugin", folder,
                            header.get("Plugin Name", folder),
                            header.get("Version", ""),
                            cand)
    return None


def read_theme(path: str) -> Software | None:
    css = os.path.join(path, "style.css")
    if not os.path.isfile(css):
        return None
    text = open(css, encoding="utf-8", errors="replace").read(4096)
    header = parse_php_header(text)
    if "Theme Name" not in header:
        return None
    slug = os.path.basename(path.rstrip("/"))
    return Software("theme", slug, header.get("Theme Name", slug),
                    header.get("Version", ""), css)


def read_core_version(wp_root: str) -> str:
    version_file = os.path.join(wp_root, "wp-includes", "version.php")
    if not os.path.isfile(version_file):
        return ""
    text = open(version_file, encoding="utf-8",
                errors="replace").read()
    m = re.search(r"\$wp_version\s*=\s*'([^']+)'", text)
    return m.group(1) if m else ""


def scan_wp_content(wp_content: str) -> tuple[list[Software],
                                              list[str]]:
    """Plugins + themes (+ core when the parent folder is a WP
    root), plus the notes (unreadable, headerless)."""
    found: list[Software] = []
    notes: list[str] = []
    plugins = os.path.join(wp_content, "plugins")
    if os.path.isdir(plugins):
        for name in sorted(os.listdir(plugins)):
            sub = os.path.join(plugins, name)
            if name.startswith("."):
                continue
            if os.path.isfile(sub) and name.endswith(".php"):
                sw = read_plugin(os.path.dirname(sub))
                # single-file plugin: read its own header
                if sw is None:
                    text = open(sub, encoding="utf-8",
                                errors="replace").read(8192)
                    header = parse_php_header(text)
                    if "Plugin Name" in header:
                        sw = Software("plugin",
                                      name[:-4],
                                      header.get("Plugin Name",
                                                 name),
                                      header.get("Version", ""), sub)
                if sw:
                    found.append(sw)
            elif os.path.isdir(sub):
                sw = read_plugin(sub)
                if sw:
                    found.append(sw)
                else:
                    notes.append(f"plugins/{name}: no readable "
                                 "plugin header")
    else:
        notes.append("no plugins/ folder in wp-content")
    themes = os.path.join(wp_content, "themes")
    if os.path.isdir(themes):
        for name in sorted(os.listdir(themes)):
            sub = os.path.join(themes, name)
            if os.path.isdir(sub):
                sw = read_theme(sub)
                if sw:
                    found.append(sw)
    core = read_core_version(os.path.dirname(
        os.path.abspath(wp_content)))
    if core:
        found.append(Software("core", "wordpress", "WordPress core",
                              core, "wp-includes/version.php"))
    return found, notes


# -------------------------------------------------------------------- feed

def fetch_feed(session: requests.Session, timeout: int,
               api_key: str) -> dict:
    """The v3 feed — a Bearer key (free with a Wordfence account)."""
    r = session.get(FEED_URL, timeout=timeout,
                    headers={"User-Agent": USER_AGENT,
                             "Authorization": f"Bearer {api_key}"})
    r.raise_for_status()
    return r.json()


def build_index(feed: dict) -> dict[tuple[str, str], list[dict]]:
    """(type, slug) → the vulnerabilities naming it."""
    index: dict[tuple[str, str], list[dict]] = {}
    for vuln_id, vuln in (feed or {}).items():
        if not isinstance(vuln, dict):
            continue
        for sw in vuln.get("software") or []:
            slug = (sw.get("slug") or sw.get("name") or "").lower()
            kind = (sw.get("type") or "").lower()
            if slug and kind:
                index.setdefault((kind, slug), []).append({
                    "id": vuln_id,
                    "title": vuln.get("title", ""),
                    "cve": vuln.get("cve", ""),
                    "severity": vuln.get("severity", ""),
                    "patched": sw.get("patched", False),
                    "affected": sw.get("affected_versions") or {},
                    "software": sw,
                })
    return index


def match_software(sw: Software, index: dict) -> list[dict]:
    """The vulnerabilities whose affected range covers sw's
    version — patched ones separated by the caller."""
    hits = []
    for v in index.get((sw.kind, sw.slug.lower()), []):
        if not sw.version:
            hits.append({**v, "in_range": None,
                         "why": "version unknown — every advisory "
                                "for this plugin is listed"})
            continue
        affected = v["affected"]
        if not affected:
            hits.append({**v, "in_range": None,
                         "why": "advisory names no version range — "
                                "listed for review"})
            continue
        if in_affected_range(sw.version, affected):
            hits.append({**v, "in_range": True, "why": ""})
    return hits


# -------------------------------------------------------------------- report

def build_table_event(rows: list[dict]) -> dict:
    return {"type": "table",
            "columns": ["software", "version", "vulns", "patched"],
            "rows": rows[:60]}


def build_markdown(software: list[Software], results: list[dict],
                   notes: list[str]) -> str:
    total = sum(1 for r in results if r["vulns"])
    unpatched = sum(1 for r in results if r["unpatched"])
    unknown = sum(1 for r in results if not r["sw"].version)
    out = [f"# WP Vuln Check — Report\n",
           f"{len(software)} plugin(s)/theme(s) checked · "
           f"**{total} with known vulnerabilities** · "
           f"{unpatched} unpatched on the installed version\n"]
    for r in results:
        sw = r["sw"]
        if not r["vulns"]:
            continue
        out.append(f"\n### {sw.name} ({sw.kind} `{sw.slug}`) — "
                   f"version "
                   + (f"`{sw.version}`" if sw.version
                      else "**unknown**"))
        for v in r["vulns"]:
            line = f"- "
            if v.get("in_range") is True:
                line += "🔴 " if not v["patched"] else "🟡 "
                line += (f"[{v['title']}](https://www.wordfence.com/"
                         f"threat-intel/vulnerabilities/{v['id']})")
                if v["cve"]:
                    line += f" ({v['cve']})"
                if v["patched"]:
                    line += (" — **patched**: the vendor backported "
                             "the fix to this version line; verify "
                             "the patch level")
                else:
                    line += " — no patch for this version: update"
            else:
                line += f"⚪ {v['title']} — {v['why']}"
            out.append(line)
    if unknown:
        out.append(f"\n{unknown} item(s) carry no Version header — "
                   "their advisories are all listed above with the "
                   "unknown-version note; fix the headers or pin "
                   "the versions to narrow it down.")
    if notes:
        out.append("")
        for n in notes:
            out.append(f"- ℹ️ {n}")
    out.append("\n## How to read it\n")
    out.append("- Versions here come from the plugin files "
               "themselves — the same files the site runs. A "
               "frontend-guess shape would be less; cve-check "
               "covers that corner with its honest scoping.")
    out.append("- **Patched** in Wordfence data means the fix was "
               "backported to your version line — the advisory "
               "matches, the hole may not; verify before panicking.")
    out.append("\n## Related\n")
    out.append("- **wp-exposure-check** — what the site exposes; "
               "**wp-audit** — your own code; this — the third "
               "party's code; **log-attack-checker** — what "
               "attackers already tried.")
    out.append("- **cve-check** — the JS/npm side and the WP core "
               "as seen from the frontend.")
    return "\n".join(out)


def write_artifacts(results: list[dict], notes: list[str],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "checked": [{"kind": r["sw"].kind, "slug": r["sw"].slug,
                     "name": r["sw"].name,
                     "version": r["sw"].version,
                     "vulns": len(r["vulns"]),
                     "unpatched": r["unpatched"]}
                    for r in results],
        "vulnerable": [{"slug": r["sw"].slug,
                        "version": r["sw"].version,
                        "advisories": [{"id": v["id"],
                                        "title": v["title"],
                                        "cve": v["cve"],
                                        "patched": v["patched"],
                                        "in_range": v["in_range"]}
                                       for v in r["vulns"]]}
                       for r in results if r["vulns"]],
        "notes": notes,
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="WP Vuln Check — installed plugin/theme "
                    "versions vs the Wordfence feed (free, keyless)")
    parser.add_argument("--wp-content", required=True,
                        help="the wp-content folder (a local copy)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="feed download timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no folders are read", flush=True)
        return 0

    wp_content = args.wp_content
    if not os.path.isdir(wp_content):
        print(f"✗ {wp_content!r} is not a folder", file=sys.stderr,
              flush=True)
        return 2

    software, notes = scan_wp_content(wp_content)
    if not software:
        print(f"✗ no plugins or themes found under {wp_content}",
              file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Nothing to check\n\nNo plugin headers and no "
              "theme style.css under the given wp-content folder. "
              "Point the script at the real `wp-content` (the one "
              "with `plugins/` and `themes/`)."})
        return 1
    log(f"Reading {len(software)} plugin(s)/theme(s) from headers")
    status(f"{len(software)} item(s)")

    api_key = os.environ.get("WORDFENCE_API_KEY", "").strip()
    if not api_key:
        print("✗ WORDFENCE_API_KEY is not set — the Wordfence "
              "Intelligence feed needs a (free) key since its v3: "
              "create an account at wordfence.com, open Account → "
              "Intelligence API, generate the key and put it in "
              "WORDFENCE_API_KEY. This script will not imitate a "
              "result without it.", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## No API key\n\nThe Wordfence Intelligence feed "
              "(the source for WordPress plugin/theme advisories) "
              "moved to a keyed v3 API — the key is **free**: "
              "register at wordfence.com → Account → Wordfence "
              "Intelligence API → generate, then set "
              "`WORDFENCE_API_KEY` (in PyShell: the API key field "
              "stores it in the Keychain). Without it this script "
              "exits rather than guessing."})
        return 1

    emit({"type": "progress", "pct": 20, "message": "feed"})
    session = requests.Session()
    try:
        feed = fetch_feed(session, args.timeout, api_key)
    except requests.RequestException as exc:
        print(f"✗ Wordfence feed unreachable: {exc}", file=sys.stderr,
              flush=True)
        return 1
    index = build_index(feed)
    emit({"type": "progress", "pct": 60,
          "message": f"{sum(len(v) for v in index.values())} "
                     "advisories indexed"})

    results = []
    for i, sw in enumerate(software):
        vulns = match_software(sw, index)
        unpatched = sum(1 for v in vulns
                        if v["in_range"] and not v["patched"])
        results.append({"sw": sw, "vulns": vulns,
                        "unpatched": unpatched})
        if vulns:
            log(f"  🔴 {sw.name} {sw.version or '?'}: "
                f"{len(vulns)} advisories ({unpatched} unpatched)")
        emit({"type": "progress",
              "pct": 60 + int(40 * (i + 1) / len(software)),
              "message": sw.slug})

    rows = [{"software": f"{r['sw'].name} ({r['sw'].kind})",
             "version": r["sw"].version or "unknown",
             "vulns": len(r["vulns"]),
             "patched": len(r["vulns"]) - r["unpatched"]}
            for r in results if r["vulns"]]
    report = build_markdown(software, results, notes)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(rows))
    emit({"type": "markdown", "content": report})
    write_artifacts(results, notes, report)

    unpatched_total = sum(r["unpatched"] for r in results)
    with_vulns = sum(1 for r in results if r["vulns"])
    summary = (f"{len(software)} checked · {with_vulns} with "
               f"advisories · {unpatched_total} unpatched")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
