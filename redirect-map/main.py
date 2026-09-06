#!/usr/bin/env python3
"""redirect-map/main.py — propose the redirects, don't pretend to
know them.

The chain had a gap: Wayback Check finds the vanished URLs, SEO
Checks grades the redirects that already exist — nothing built the
map *between* them.  This script does, with the honesty contract
up front: **matching is heuristic**.  Every row carries a
confidence tier — confident / needs review / not found — and the
script *proposes* a map; it never claims to know the right answer.

Inputs:

- **old URLs** — Wayback Check's `wayback_vanished.csv`, an old
  Site Crawler snapshot (`.json` — its 200-pages that no longer
  exist become the candidates), or a plain one-URL-per-line list.
- **the fresh snapshot** — Site Crawler's `site_snapshot.json` of
  the site as it is now.

The matching ladder, per old URL:

1. **exact** — the normalized path exists in the new snapshot
   (case, trailing slash, `.html`/index suffixes folded away):
   confident.
2. **slug** — the last path segment matches exactly (`/blog/post/`
   → `/posts/post/`): confident, the classic migration move.
3. **fuzzy** — slug or title similarity ≥ 0.80 (difflib): needs
   review, with the score and what matched shown.
4. Nothing clears the bar: **not found** — the map cannot invent a
   target; 410 Gone is the honest option for truly gone pages.

Outputs: a ready nginx `map $uri` snippet (query-preserving), the
`.htaccess` twin, a CSV for editing and re-verification — and,
unless skipped, a **live check** of every proposed redirect: does
it land 301 → 200, without chains (redirect → redirect) or loops.

Exit codes: 0 = ran, 1 = nothing to work with, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import difflib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

USER_AGENT = "PyShell-redirect-map/1 (+migration redirect planner)"

SLUG_FUZZY = 0.80          # slug/title similarity for "needs review"
SNAPSHOT_MIN_SCHEMA = 1


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


class InputError(ValueError):
    pass


# ------------------------------------------------------------- normalizing

def normalize_url(url: str) -> str:
    """Compare-side form (the crawler's own rules)."""
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return (url or "").strip()
    scheme = parts.scheme.lower() or "https"
    netloc = parts.netloc.lower()
    if ":" in netloc:
        host, _, port = netloc.partition(":")
        if (scheme, port) in (("https", "443"), ("http", "80")):
            netloc = host
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


INDEX_RE = re.compile(r"^(.*)/?index\.(html?|php|aspx?)$", re.I)
EXT_RE = re.compile(r"^(.*\/[^/]+)\.(html?|php|aspx?)$", re.I)


def norm_path(path: str) -> str:
    """The path key for matching: case-folded, one trailing slash,
    index/ext suffixes folded away."""
    p = (path or "/").strip()
    m = INDEX_RE.match(p)
    if m:
        p = m.group(1) or "/"
    else:
        m = EXT_RE.match(p)
        if m:
            p = m.group(1)
    if len(p) > 1:
        p = p.rstrip("/")
    if not p.startswith("/"):
        p = "/" + p
    return p.lower()


def slug_of(path: str) -> str:
    parts = [s for s in norm_path(path).split("/") if s]
    return parts[-1] if parts else ""


def same_target(a: str, b: str) -> bool:
    return normalize_url(a).rstrip("/") == normalize_url(b).rstrip("/")


# ------------------------------------------------------------------ inputs

@dataclass
class OldUrl:
    url: str                       # as given
    title: str = ""                # only an old snapshot knows it


@dataclass
class NewPage:
    url: str
    path: str
    slug: str
    title: str = ""


def load_old_source(path: str) -> tuple[list[OldUrl], str]:
    """(.json snapshot | .csv | .txt) → old URLs + source kind."""
    if not os.path.isfile(path):
        raise InputError(f"{path}: file not found")
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        try:
            data = json.load(open(path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise InputError(f"{path}: unreadable JSON ({exc})")
        if not isinstance(data, dict) or "pages" not in data:
            raise InputError(f"{path}: no 'pages' — not a Site "
                             "Crawler snapshot")
        pages = [p for p in data["pages"]
                 if isinstance(p, dict) and p.get("url")]
        return ([OldUrl(p["url"], (p.get("title") or ""))
                 for p in pages], "old snapshot")
    if ext == ".csv":
        out: list[OldUrl] = []
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or \
                    "url" not in [f.lower() for f in
                                  reader.fieldnames]:
                raise InputError(f"{path}: no 'url' column — a "
                                 "wayback-check CSV has one")
            col = next(f for f in reader.fieldnames
                       if f.lower() == "url")
            for row in reader:
                if (row.get(col) or "").strip():
                    out.append(OldUrl(row[col].strip()))
        return out, "csv"
    if ext == ".txt":
        with open(path, encoding="utf-8") as fh:
            urls = [ln.strip() for ln in fh
                    if ln.strip() and not ln.startswith("#")]
        if not urls:
            raise InputError(f"{path}: no URLs found")
        return [OldUrl(u) for u in urls], "list"
    raise InputError(f"{path}: expected .json, .csv or .txt")


def load_new_snapshot(path: str) -> list[NewPage]:
    if not os.path.isfile(path):
        raise InputError(f"{path}: file not found")
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"{path}: unreadable JSON ({exc})")
    if not isinstance(data, dict) or "pages" not in data:
        raise InputError(f"{path}: no 'pages' — not a Site Crawler "
                         "snapshot")
    if data.get("schema", 0) < SNAPSHOT_MIN_SCHEMA:
        raise InputError(f"{path}: unknown snapshot schema "
                         f"{data.get('schema')}")
    pages: list[NewPage] = []
    for raw in data["pages"]:
        if not isinstance(raw, dict) or not raw.get("url"):
            continue
        if raw.get("status") not in (200, None):
            continue                      # only living pages are
                                          # redirect targets
        u = urlsplit(raw["url"])
        if not u.path:
            continue
        pages.append(NewPage(
            url=normalize_url(raw["url"]), path=norm_path(u.path),
            slug=slug_of(u.path),
            title=(raw.get("title") or "").strip()))
    if not pages:
        raise InputError(f"{path}: no usable pages in the snapshot")
    return pages


# ---------------------------------------------------------------- matching

@dataclass
class Match:
    old: OldUrl
    tier: str = "not found"       # confident | needs review |
                                  # not found | exists
    new_url: str = ""
    score: int = 0
    reason: str = ""
    verify: str = ""              # filled by the live check


def similarity(a: str, b: str) -> float:
    a, b = (a or "").lower().strip(), (b or "").lower().strip()
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def match_one(old: OldUrl, by_path: dict[str, NewPage],
              by_slug: dict[str, list[NewPage]], slugs: list[str],
              title_pages: dict[str, NewPage]) -> Match:
    m = Match(old=old)
    u = urlsplit(old.url)
    key = norm_path(u.path or "/")

    direct = by_path.get(key)
    if direct is not None:
        if same_target(old.url, direct.url):
            m.tier, m.new_url, m.score = "exists", direct.url, 100
            m.reason = "the page exists at this URL already"
        else:
            m.tier, m.new_url, m.score = "confident", direct.url, 100
            m.reason = ("exact path match after normalization "
                        "(case / trailing slash / index or "
                        "extension folded)")
        return m

    slug = slug_of(u.path or "/")
    if slug and slug in by_slug:
        # several new pages may share the slug — prefer the one
        # with the most similar full path
        cands = by_slug[slug]
        best = max(cands, key=lambda p: similarity(
            norm_path(u.path), p.path))
        m.tier, m.new_url, m.score = "confident", best.url, 90
        m.reason = (f"slug '{slug}' moved: {u.path or '/'} → "
                    f"{urlsplit(best.url).path}")
        return m

    # fuzzy: slug similarity, then title similarity
    if slug:
        close = difflib.get_close_matches(
            slug, slugs, n=1, cutoff=SLUG_FUZZY)
        if close:
            p = by_slug[close[0]][0]
            r = similarity(slug, p.slug)
            m.tier = "needs review"
            m.new_url, m.score = p.url, int(r * 100)
            m.reason = (f"slug similarity {r:.2f} "
                        f"('{slug}' ≈ '{p.slug}')")
            return m
    if old.title:
        titles = list(title_pages)
        close_t = difflib.get_close_matches(
            old.title, titles, n=1, cutoff=SLUG_FUZZY)
        if close_t:
            p = title_pages[close_t[0]]
            r = similarity(old.title, p.title)
            m.tier = "needs review"
            m.new_url = p.url
            m.score = int(r * 100)
            m.reason = (f"title similarity {r:.2f} "
                        f"({old.title!r} ≈ {p.title!r})")
            return m

    m.tier, m.score, m.reason = "not found", 0, \
        "no candidate cleared the bar — the map cannot invent a " \
        "target; 410 Gone is the honest option for truly gone"
    return m


def match_all(old_urls: list[OldUrl],
              new_pages: list[NewPage]) -> list[Match]:
    by_path: dict[str, NewPage] = {}
    for p in new_pages:
        by_path.setdefault(p.path, p)
    by_slug: dict[str, list[NewPage]] = {}
    for p in new_pages:
        if p.slug:
            by_slug.setdefault(p.slug, []).append(p)
    slugs = list(by_slug)
    title_pages: dict[str, NewPage] = {}
    for p in new_pages:
        if p.title:
            title_pages.setdefault(p.title, p)
    return [match_one(o, by_path, by_slug, slugs, title_pages)
            for o in old_urls]


# ------------------------------------------------------------ verification

def verify_one(m: Match, timeout: int) -> str:
    """Follow the old URL's redirects by hand: 301 → 200, chains,
    loops — named."""
    seen: set[str] = set()
    url = m.old.url
    hops: list[tuple[str, int, str]] = []
    for _ in range(6):
        if url in seen:
            return f"loop detected at {url}"
        seen.add(url)
        try:
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": USER_AGENT},
                             allow_redirects=False)
        except requests.RequestException as exc:
            return f"unreachable: {exc}"
        if r.status_code in (301, 302, 303, 307, 308):
            loc = urljoin(url, r.headers.get("Location", ""))
            if not loc:
                return f"HTTP {r.status_code} without Location"
            hops.append((url, r.status_code, loc))
            url = loc
            continue
        # a non-redirect answer closes the walk
        if not hops:
            if r.status_code in (200,):
                return "still live (200) — no redirect needed"
            return f"HTTP {r.status_code} — not redirected yet " \
                   "(expected until the map is installed)"
        final_url, final_status = url, r.status_code
        chain = len(hops) > 1
        hit = same_target(final_url, m.new_url)
        if hit and final_status == 200:
            if chain:
                chain_str = " → ".join(
                    f"{h[1]} {urlsplit(h[2]).path or '/'}"
                    for h in hops)
                return (f"chain ({len(hops)} hops: {chain_str}) → "
                        "target 200 — point the map directly at "
                        "the final URL")
            return "✅ 301 → target, 200"
        if hit:
            return (f"lands on the target with HTTP "
                    f"{final_status} — the target itself is "
                    "broken")
        first_hop = hops[0][2]
        return (f"redirected elsewhere → {first_hop} "
                f"({len(hops)} hop(s), final {final_status}) — "
                "already handled; review whether that is the "
                "right target")
    return "more than 6 hops — a chain by any measure"


# ------------------------------------------------------------------ report

def short(url: str, width: int = 56) -> str:
    if len(url) <= width:
        return url
    return url[:width - 1] + "…"


def uri_of(url: str) -> str:
    """The path(+query) a server rule keys on."""
    u = urlsplit(url)
    return u.path + (f"?{u.query}" if u.query else "")


def build_conf(matches: list[Match]) -> str:
    rows = [(m, uri_of(m.old.url), uri_of(m.new_url))
            for m in matches if m.tier in ("confident",
                                           "needs review")]
    out = ["# redirect-map output — nginx",
           "#",
           "# Confident rows are safe to install; 'needs review'",
           "# rows are proposals — check them, then uncomment.",
           "# $uri keys on the path (query strings are preserved",
           "# by the return below, not matched).",
           "",
           "map $uri $redirect_target {",
           "    default \"\";"]
    for m, old_uri, new_uri in rows:
        if m.tier == "confident":
            out.append(f"    \"{old_uri}\" \"{new_uri}\";")
        else:
            out.append(f"    # REVIEW ({m.reason}):")
            out.append(f"    # \"{old_uri}\" \"{new_uri}\";")
    out.append("}")
    out.append("")
    out.append("# in the server block:")
    out.append("#")
    out.append("#   if ($redirect_target != \"\") {")
    out.append("#       return 301 $redirect_target$is_args$args;")
    out.append("#   }")
    return "\n".join(out) + "\n"


def build_htaccess(matches: list[Match]) -> str:
    out = ["# redirect-map output — Apache .htaccess",
           "# Confident rows install as-is; REVIEW rows are",
           "# commented out until checked.",
           ""]
    for m in matches:
        if m.tier == "confident":
            out.append(f"Redirect 301 {uri_of(m.old.url)} "
                       f"{uri_of(m.new_url)}")
        elif m.tier == "needs review":
            out.append(f"# REVIEW ({m.reason})")
            out.append(f"# Redirect 301 {uri_of(m.old.url)} "
                       f"{uri_of(m.new_url)}")
    return "\n".join(out) + "\n"


def build_table_event(matches: list[Match]) -> dict:
    rows = []
    for m in matches:
        if m.tier == "exists":
            verdict = "· exists — no redirect needed"
        elif m.tier == "confident":
            verdict = "✅ confident"
        elif m.tier == "needs review":
            verdict = f"◐ review ({m.score})"
        else:
            verdict = "⚫ not found"
        if m.verify:
            verdict += f" · {m.verify}"
        rows.append({"old": short(m.old.url),
                     "new": short(m.new_url) if m.new_url else "—",
                     "confidence": m.tier, "live": m.verify or "—"})
    if not rows:
        rows = [{"old": "—", "new": "—", "confidence": "—",
                 "live": "—"}]
    return {"type": "table",
            "columns": ["old", "new", "confidence", "live"],
            "rows": rows}


def build_markdown(source_kind: str, old_count: int,
                   matches: list[Match]) -> str:
    confident = [m for m in matches if m.tier == "confident"]
    review = [m for m in matches if m.tier == "needs review"]
    missing = [m for m in matches if m.tier == "not found"]
    exists = [m for m in matches if m.tier == "exists"]
    out = [f"# Redirect Map — Report\n",
           f"Source: {source_kind} · **{old_count} old URL(s)** → "
           f"**{len(confident)} confident** · "
           f"**{len(review)} needs review** · "
           f"**{len(missing)} not found**"
           + (f" · {len(exists)} still exist" if exists else "")
           + "\n",
           "The honesty contract: matching is heuristic. Confident "
           "rows matched on an exact normalized path or an exact "
           "slug; review rows cleared a similarity bar and are "
           "**proposals**. The script proposes the map — you "
           "confirm it.\n"]

    if confident:
        out.append("## Confident\n")
        for m in confident:
            v = f" — live: {m.verify}" if m.verify else ""
            out.append(f"- ✅ `{m.old.url}` → `{m.new_url}` "
                       f"({m.reason}){v}")
        out.append("")
    if review:
        out.append("## Needs review\n")
        for m in review:
            v = f" — live: {m.verify}" if m.verify else ""
            out.append(f"- ◐ `{m.old.url}` → `{m.new_url}` — "
                       f"{m.reason}{v}")
        out.append("")
    if missing:
        out.append("## Not found\n")
        for m in missing:
            out.append(f"- ⚫ `{m.old.url}` — {m.reason}")
        out.append("")
    if exists:
        out.append("## Still exists — no redirect needed\n")
        for m in exists:
            out.append(f"- · `{m.old.url}` — {m.reason}")
        out.append("")

    out.append("## The artifacts\n")
    out.append("- **`redirect_map.conf`** — the nginx "
               "`map $uri` snippet (query strings preserved by the "
               "`return`; review rows commented).")
    out.append("- **`redirect_map_htaccess.txt`** — the Apache "
               "twin (`Redirect 301`).")
    out.append("- **`redirect_map.csv`** — old, new, tier, score, "
               "live check — edit it, argue with it, re-run.")
    out.append("")

    if matches and matches[0].verify:
        verified = [m for m in matches if m.verify]
        good = sum(1 for m in verified if m.verify.startswith("✅"))
        out.append(f"## Live check — {good} of {len(verified)} "
                   "proposed redirects verified\n")
        out.append("404s here are *expected until the map is "
                   "installed* — that is what this run measured. "
                   "Install, then run again: every row should read "
                   "✅ 301 → target, 200.\n")

    out.append("## Related\n")
    out.append("- **Wayback Check** — where the vanished URLs come "
               "from.")
    out.append("- **Site Crawler** — the fresh snapshot this map "
               "was matched against.")
    out.append("- **SEO Checks** — the chain/canonical audit for "
               "after the map is installed.")
    return "\n".join(out)


def write_artifacts(source_kind: str, matches: list[Match],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "redirect_map.conf"), "w",
              encoding="utf-8") as fh:
        fh.write(build_conf(matches))
    with open(os.path.join(out_dir,
                           "redirect_map_htaccess.txt"), "w",
              encoding="utf-8") as fh:
        fh.write(build_htaccess(matches))
    with open(os.path.join(out_dir, "redirect_map.csv"), "w",
              newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["old", "new", "tier", "score", "reason",
                         "live"])
        for m in matches:
            writer.writerow([m.old.url, m.new_url, m.tier,
                             m.score, m.reason, m.verify])
    payload = {
        "source": source_kind,
        "matches": [{
            "old": m.old.url, "old_title": m.old.title,
            "new": m.new_url, "tier": m.tier, "score": m.score,
            "reason": m.reason, "live": m.verify}
            for m in matches],
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Redirect Map — old URLs (wayback CSV / old "
                    "snapshot / plain list) matched against a fresh "
                    "Site Crawler snapshot: confidence-tiered "
                    "proposals, nginx + .htaccess maps, live "
                    "verification")
    parser.add_argument("--old-source", required=True,
                        help="wayback_vanished.csv, an old "
                             "site_snapshot.json, or a .txt list")
    parser.add_argument("--snapshot-file", required=True,
                        help="the fresh site_snapshot.json")
    parser.add_argument("--skip-verify", action="store_true",
                        help="offline pass: no live requests")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout (default 15)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is read or requested",
              flush=True)
        return 0

    try:
        old_urls, source_kind = load_old_source(args.old_source)
        new_pages = load_new_snapshot(args.snapshot_file)
    except InputError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    log(f"{len(old_urls)} old URL(s) from {source_kind} · "
        f"{len(new_pages)} living page(s) in the snapshot")
    status(f"{len(old_urls)} old · {len(new_pages)} new")

    matches = match_all(old_urls, new_pages)
    for i, m in enumerate(matches, 1):
        log(f"  {m.tier:12s} {m.old.url}"
            + (f" → {m.new_url}" if m.new_url else ""))
        if i % 10 == 0 or i == len(matches):
            emit({"type": "progress",
                  "pct": int(50 * i / max(1, len(matches))),
                  "message": f"matching {i}/{len(matches)}"})

    if not args.skip_verify:
        to_check = [m for m in matches
                    if m.tier in ("confident", "needs review")]
        log(f"live-verifying {len(to_check)} proposed redirect(s)")
        for i, m in enumerate(to_check, 1):
            m.verify = verify_one(m, args.timeout)
            emit({"type": "progress",
                  "pct": 50 + int(50 * i / max(1, len(to_check))),
                  "message": f"verifying {i}/{len(to_check)}"})

    report = build_markdown(source_kind, len(old_urls), matches)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(matches))
    emit({"type": "markdown", "content": report})
    write_artifacts(source_kind, matches, report)

    confident = sum(1 for m in matches if m.tier == "confident")
    review = sum(1 for m in matches if m.tier == "needs review")
    summary = (f"{confident} confident · {review} review · "
               f"{sum(1 for m in matches if m.tier == 'not found')}"
               " not found")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
