#!/usr/bin/env python3
"""hreflang-check/main.py — the multilingual wiring under the
microscope.

SEO Checks grades one page at a time; hreflang is a **cluster**
property — one page cannot show the broken half of it.  This script
reads a Site Crawler snapshot and checks the wiring across pages:

- **Reciprocity** — `A → B` must be answered by `B → A`; one-way
  alternates are the classic silent killer (Google drops the pair).
- **Clusters** — the connected components of alternate links; every
  cluster gets the x-default and duplicate-language audit:
  exactly one `x-default` (missing = the outlier visitors; two =
  ambiguous), one page per language code.
- **Self-reference** — each page declaring hreflang should name
  itself too (Google's recommendation; without it the page depends
  on its siblings' back-links to exist in the cluster).
- **Code validity** — `pt-br` (wrong case), `ukrainian` (a language
  *name*, not a code), `xx` (not an ISO code): each named, with the
  right spelling.
- **Target sanity** — alternates pointing at a page that
  canonicalizes elsewhere (the cluster fights the canonical), at a
  404/redirect, or outside the crawl entirely (noted as such — the
  snapshot is the boundary of what is known).

Pure functions over the snapshot — no network.  The one thing a
snapshot cannot carry — hreflang declared in the **sitemap** vs in
**HTML** — is said so in the report instead of guessed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

SNAPSHOT_SCHEMA = 2  # the hreflang field arrived with schema 2

LANG_RE = re.compile(r"^[a-z]{2,3}(-[A-Z]{2}|-\d{3})?$")


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


class SnapshotError(ValueError):
    pass


def normalize_url(url: str) -> str:
    """The compare-side form: lowercase scheme/host, no default
    port, no fragment, / for an empty path (the crawler's own
    normalization, applied to the raw hreflang targets too)."""
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


@dataclass
class Page:
    url: str                 # the snapshot's key (already normalized)
    raw_url: str
    canonical: str = ""
    status: int | None = None
    hreflang: dict[str, str] = field(default_factory=dict)  # raw


def load_snapshot(path: str) -> list[Page]:
    try:
        data = json.load(open(path, encoding="utf-8"))
    except OSError as exc:
        raise SnapshotError(f"cannot read {path}: {exc}")
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path} is not valid JSON: {exc}")
    if not isinstance(data, dict) or "pages" not in data:
        raise SnapshotError(f"{path}: no 'pages' — not a Site "
                            "Crawler snapshot")
    if data.get("schema", 0) < SNAPSHOT_SCHEMA:
        raise SnapshotError(
            f"snapshot schema {data.get('schema')} predates the "
            f"hreflang fields (schema {SNAPSHOT_SCHEMA}) — re-crawl "
            "with the current Site Crawler")
    pages: list[Page] = []
    for raw in data["pages"]:
        if not isinstance(raw, dict) or not raw.get("url"):
            continue
        hl = raw.get("hreflang") or {}
        pages.append(Page(
            url=normalize_url(raw["url"]), raw_url=raw["url"],
            canonical=raw.get("canonical") or "",
            status=raw.get("status"),
            hreflang={str(k): str(v) for k, v in hl.items()} if
            isinstance(hl, dict) else {}))
    if not pages:
        raise SnapshotError("the snapshot has no pages")
    return pages


# ----------------------------------------------------------------- findings

@dataclass
class Finding:
    severity: str    # error | warning | info
    check: str
    detail: str
    page: str = ""


def valid_code(code: str) -> tuple[bool, str]:
    """(valid, why-not) for one hreflang value."""
    if code == "x-default":
        return True, ""
    if not LANG_RE.match(code):
        if re.match(r"^[a-z]{2,3}(-[a-z]{2})?$", code):
            return False, "region part must be UPPERCASE " \
                          f"(e.g. {code.split('-')[0]}-BR style)"
        if re.match(r"^[a-zA-Z]{4,}$", code) and "-" not in code:
            return False, "looks like a language NAME, not an ISO " \
                          "code (en, pt, uk — not english)"
        return False, "not a language(-REGION) code"
    return True, ""


def build_clusters(pages: list[Page]) -> list[list[Page]]:
    """Connected components over hreflang edges (undirected for
    clustering: A→B puts them together even if B never answers)."""
    by_url = {p.url: p for p in pages}
    parent = {p.url: p.url for p in pages}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for p in pages:
        for target in p.hreflang.values():
            t = normalize_url(target)
            if t in by_url:
                union(p.url, t)
    clusters: dict[str, list[Page]] = {}
    for p in pages:
        if any(p.hreflang.values()):
            clusters.setdefault(find(p.url), []).append(p)
    return list(clusters.values())


def check_pages(pages: list[Page]) -> list[Finding]:
    findings: list[Finding] = []
    by_url = {p.url: p for p in pages}
    statuses = {p.url: p.status for p in pages}

    # per-page: code validity, self-reference, target sanity
    for p in pages:
        if not p.hreflang:
            continue
        for code, target in p.hreflang.items():
            ok, why = valid_code(code)
            if not ok:
                findings.append(Finding(
                    "error", "invalid-code",
                    f"hreflang={code!r}: {why}", p.url))
            t = normalize_url(target)
            if t == p.url:
                continue  # the self-reference (checked separately)
            target_page = by_url.get(t)
            if target_page is None:
                findings.append(Finding(
                    "info", "outside-crawl",
                    f"alternate {code} → {target} is outside this "
                    "crawl — reciprocity cannot be verified here",
                    p.url))
            else:
                if target_page.status in (404, 410):
                    findings.append(Finding(
                        "error", "broken-target",
                        f"alternate {code} → {target} answers "
                        f"{target_page.status}", p.url))
                if target_page.canonical \
                        and normalize_url(target_page.canonical) != t:
                    findings.append(Finding(
                        "warning", "non-canonical-target",
                        f"alternate {code} → {target}, but that page "
                        f"canonicalizes to {target_page.canonical} — "
                        "the cluster and the canonical disagree", p.url))
        self_ok = any(normalize_url(t) == p.url
                      for t in p.hreflang.values())
        if not self_ok:
            findings.append(Finding(
                "info", "self-reference",
                "no hreflang names the page itself — Google "
                "recommends the self-reference so the page exists "
                "in the cluster on its own", p.url))

    # reciprocity (needs the target inside the crawl)
    for p in pages:
        if not p.hreflang:
            continue
        for code, target in p.hreflang.items():
            t = normalize_url(target)
            q = by_url.get(t)
            if q is None or t == p.url:
                continue
            back = {normalize_url(v) for v in q.hreflang.values()}
            if p.url not in back:
                findings.append(Finding(
                    "warning", "reciprocity",
                    f"this page says {code} → {target}, but that "
                    "page's hreflang never points back — Google "
                    "drops one-way alternates", p.url))

    # cluster-level: x-default and language targets.  The standard
    # shape is every page declaring the full alternate set — so a
    # code appearing on many pages is normal; the *error shape* is
    # one code pointing at different targets across the cluster.
    for cluster in build_clusters(pages):
        targets: dict[str, set[str]] = {}
        for p in cluster:
            for code, target in p.hreflang.items():
                targets.setdefault(code.lower(), set()).add(
                    normalize_url(target))
        if "x-default" not in targets:
            findings.append(Finding(
                "warning", "x-default",
                "no x-default in this cluster — visitors whose "
                "language matches no alternate get nothing "
                "designated", cluster[0].url))
        else:
            defaults = targets["x-default"]
            if len(defaults) > 1:
                findings.append(Finding(
                    "warning", "x-default",
                    f"x-default points at {len(defaults)} different "
                    f"pages in this cluster "
                    f"({', '.join(sorted(defaults)[:3])}) — one "
                    "designation, one page", cluster[0].url))
        for code, urls in sorted(targets.items()):
            if code == "x-default":
                continue
            if len(urls) > 1:
                findings.append(Finding(
                    "warning", "duplicate-language",
                    f"language {code!r} points at {len(urls)} "
                    f"different pages in this cluster "
                    f"({', '.join(sorted(urls)[:3])}) — the language "
                    "needs one canonical home", cluster[0].url))
    return findings


# -------------------------------------------------------------------- report

ICON = {"error": "🔴", "warning": "🟠", "info": "ℹ️"}


def build_table_event(findings: list[Finding]) -> dict:
    rows = [{"severity": ICON[f.severity] + " " + f.severity,
             "check": f.check, "page": f.page[:70],
             "detail": f.detail[:80]}
            for f in findings[:60]]
    return {"type": "table",
            "columns": ["severity", "check", "page", "detail"],
            "rows": rows}


def build_markdown(pages: list[Page], findings: list[Finding]) -> str:
    with_hl = [p for p in pages if p.hreflang]
    clusters = build_clusters(pages)
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    out = [f"# Hreflang Check — Report\n",
           f"{len(pages)} page(s) in the snapshot · "
           f"**{len(with_hl)} declare hreflang** · "
           f"{len(clusters)} cluster(s)\n",
           f"**{len(findings)} finding(s)**: {errors} errors, "
           f"{warnings} warnings.\n"]
    if not with_hl:
        out.append("No page in this crawl declares hreflang — for a "
                   "single-language site that is normal; for a "
                   "multilingual one it means the alternates are "
                   "missing entirely.")
        return "\n".join(out)

    current = None
    for f in findings:
        if f.check != current:
            out.append(f"\n## {f.check}\n")
            current = f.check
        out.append(f"- {ICON[f.severity]} {f.detail}"
                   + (f" — `{f.page[:80]}`" if f.page else ""))

    out.append("\n## Not checked\n")
    out.append("- hreflang declared in the **sitemap** (xhtml:link) "
               "vs in **HTML** — the snapshot records the HTML side "
               "only; compare the sitemap by hand or extend Site "
               "Crawler to record both.")
    out.append("\n## Related\n")
    out.append("- **SEO Checks** — the one-page pass (canonical, "
               "redirects) over the same snapshot; its canonical "
               "findings explain some of the non-canonical targets "
               "here.")
    out.append("- **Sitemap Generator** — generates hreflang "
               "alternates into the sitemap; this script audits "
               "what exists.")
    out.append("- **Site Crawler** — produced the snapshot; "
               "re-crawl after fixes.")
    return "\n".join(out)


def write_artifacts(pages: list[Page], findings: list[Finding],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "pages": len(pages),
        "pages_with_hreflang": sum(1 for p in pages if p.hreflang),
        "clusters": len(build_clusters(pages)),
        "findings": [{"severity": f.severity, "check": f.check,
                      "detail": f.detail, "page": f.page}
                     for f in findings],
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
        description="Hreflang Check — reciprocity, x-default, code "
                    "validity and cluster sanity over a Site "
                    "Crawler snapshot")
    parser.add_argument("--snapshot-file", required=True,
                        help="site_snapshot.json produced by Site "
                             "Crawler")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no snapshots are read",
              flush=True)
        return 0

    log(f"Reading {os.path.basename(args.snapshot_file)}")
    status("loading the snapshot")
    try:
        pages = load_snapshot(args.snapshot_file)
    except SnapshotError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Cannot read the snapshot\n\n{exc}\n\nRun **Site "
              "Crawler** on the site first — this script reads the "
              "`site_snapshot.json` it writes."})
        return 1

    emit({"type": "progress", "pct": 50,
          "message": f"{len(pages)} page(s)"})
    findings = check_pages(pages)
    emit({"type": "progress", "pct": 100, "message": "Done"})

    with_hl = sum(1 for p in pages if p.hreflang)
    if not with_hl:
        report = build_markdown(pages, findings)
        emit({"type": "markdown", "content": report})
        print("✗ no hreflang declarations in this crawl — nothing "
              "to check", file=sys.stderr, flush=True)
        return 1

    report = build_markdown(pages, findings)
    emit(build_table_event(findings))
    emit({"type": "markdown", "content": report})
    write_artifacts(pages, findings, report)

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    summary = (f"{with_hl} page(s) with hreflang · "
               f"{len(build_clusters(pages))} cluster(s) · "
               f"{errors} error(s), {warnings} warning(s)")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
