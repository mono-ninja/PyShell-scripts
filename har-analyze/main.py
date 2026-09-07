#!/usr/bin/env python3
"""har-analyze/main.py — what is actually heavy on this page.

The perf line, closed from the browser side: **Server Timing** times
one URL from the client, **Cache Check** watches the cache layer,
**Load Test** degrades it under load — and this script reads the
recording the browser itself made: the `.har` DevTools exports.  A
HAR is one page load, every request with its phases, sizes, types
and timings — everything here is computed from that file with the
stdlib `json`, **zero network**.

The diagnosis (not a HAR viewer — everything answers "so what"):

- **Waterfall by phases** — dns / connect / ssl / wait (TTFB) /
  receive per request, aggregated: where this page's milliseconds
  actually went.
- **Render-blocking** — stylesheets by definition; scripts that the
  saved document loads without `async`/`defer` (needs the response
  content in the HAR — the honest note says so when it is absent).
- **Third parties** — every request to a domain other than the
  page's, with counts and bytes: the "whose weight is this" answer.
- **Size by type** — html/script/css/image/font/media/other buckets.
- **From cache** — entries served from memory/disk cache or
  revalidated with 304: the bytes that never left the server.
- **Redirect chains** — hops with their cost.
- **The worst 10** — slowest requests with their phase breakdown.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

PHASES = ["blocked", "dns", "connect", "ssl", "send", "wait",
          "receive"]
NA = -1


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ the HAR

def load_entries(path: str, max_entries: int) -> tuple[list[dict],
                                                        list[str]]:
    """Entries + notes (truncation, quirks). Raises ValueError with
    a precise message on anything that isn't a HAR."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}")
    if not isinstance(data, dict) or "log" not in data:
        raise ValueError(f"{path}: no 'log' object — not a HAR file")
    entries = data["log"].get("entries") or []
    notes: list[str] = []
    if len(entries) > max_entries:
        entries = entries[:max_entries]
        notes.append(f"HAR truncated to {max_entries} entries "
                     f"(of {len(data['log']['entries'])})")
    pages = data["log"].get("pages") or []
    if pages and pages[0].get("title"):
        notes.append(f"page: {pages[0]['title'][:80]}")
    return entries, notes


def registrable(host: str) -> str:
    """The last two labels — good enough for third-party grouping
    (the 'who is this' answer doesn't need the PSL)."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def type_of(mime: str, url: str) -> str:
    mime = (mime or "").lower()
    if "text/html" in mime:
        return "html"
    if "javascript" in mime or "ecmascript" in mime:
        return "script"
    if "css" in mime:
        return "css"
    if "image/" in mime:
        return "image"
    if "font/" in mime or "woff" in mime:
        return "font"
    if "video/" in mime or "audio/" in mime:
        return "media"
    if "json" in mime or "xml" in mime:
        return "data"
    if not mime and url.endswith((".js", ".mjs")):
        return "script"
    return "other"


def transfer_size(entry: dict) -> int:
    """What actually crossed the wire: _transferSize when present
    (Chrome), else content.size minus compression."""
    resp = entry.get("response") or {}
    ts = (entry.get("_transferSize")
          or (resp.get("_transferSize")))
    if isinstance(ts, (int, float)) and ts >= 0:
        return int(ts)
    content = resp.get("content") or {}
    size = content.get("size") or 0
    compression = content.get("compression")
    if isinstance(compression, (int, float)) and compression > 0:
        return max(0, int(size - compression))
    return int(size)


def from_cache(entry: dict) -> str:
    """'memory' | 'disk' | 'revalidated' | ''"""
    if entry.get("_fromCache") in ("memory", "disk"):
        return entry["_fromCache"]
    cache = entry.get("cache") or {}
    if cache.get("afterRequest") is not None \
            and cache.get("beforeRequest") is None:
        return "disk"
    status = (entry.get("response") or {}).get("status")
    if status == 304:
        return "revalidated"
    return ""


def timings_of(entry: dict) -> dict:
    t = entry.get("timings") or {}
    out = {}
    for phase in PHASES:
        val = t.get(phase, NA)
        out[phase] = round(val, 1) if isinstance(val, (int, float)) \
            and val >= 0 else None
    return out


# ----------------------------------------------------------------- analysis

def analyze(entries: list[dict]) -> dict:
    page_url = ""
    for e in entries:
        mime = (e.get("response") or {}).get("content", {}).get(
            "mimeType", "")
        if "text/html" in mime:
            page_url = (e.get("request") or {}).get("url", "")
            break
    page_host = urlsplit(page_url).hostname or \
        (urlsplit((entries[0].get("request") or {}).get("url", "")
                  ).hostname if entries else "")
    page_domain = registrable(page_host) if page_host else ""

    total_bytes = 0
    by_type: Counter = Counter()           # type -> bytes
    by_type_n: Counter = Counter()         # type -> count
    third_party: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "bytes": 0})
    cache_hits: list[dict] = []
    redirects: list[dict] = []
    phases_sum = {p: 0.0 for p in PHASES}
    phase_counts = {p: 0 for p in PHASES}
    slowest: list[dict] = []
    blocking_scripts: list[dict] = []
    stylesheets: list[dict] = []

    for e in entries:
        req = e.get("request") or {}
        resp = e.get("response") or {}
        url = req.get("url", "")
        mime = (resp.get("content") or {}).get("mimeType", "")
        rtype = type_of(mime, url)
        size = transfer_size(e)
        total_bytes += size
        by_type[rtype] += size
        by_type_n[rtype] += 1
        host = urlsplit(url).hostname or "?"
        if page_domain and registrable(host) != page_domain:
            third_party[registrable(host)]["count"] += 1
            third_party[registrable(host)]["bytes"] += size
        cache = from_cache(e)
        if cache:
            cache_hits.append({"url": url, "kind": cache,
                               "saved_bytes": size})
        status = resp.get("status")
        if status in (301, 302, 303, 307, 308):
            redirects.append({"url": url, "status": status,
                              "to": resp.get("redirectURL", "")})
        t = timings_of(e)
        for phase in PHASES:
            if t[phase] is not None:
                phases_sum[phase] += t[phase]
                phase_counts[phase] += 1
        slowest.append({"url": url, "time": e.get("time", 0),
                        "type": rtype, "timings": t,
                        "size": size, "status": status})
        res_type = e.get("_resourceType", "")
        if res_type == "stylesheet" or rtype == "css":
            stylesheets.append({"url": url, "size": size})
        elif res_type == "script" or rtype == "script":
            blocking_scripts.append({"url": url, "size": size})

    # render-blocking refinement: which scripts the document loads
    # synchronously (needs the saved document content)
    doc_content = ""
    for e in entries:
        resp = e.get("response") or {}
        if "text/html" in (resp.get("content") or {}).get("mimeType",
                                                          ""):
            text = (resp.get("content") or {}).get("text")
            if isinstance(text, str):
                doc_content = text
            break
    sync_scripts: list[str] = []
    if doc_content:
        for m in re.finditer(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']"
                             r"[^>]*>", doc_content, re.I):
            tag = m.group(0)
            if not re.search(r"\b(async|defer)\b", tag, re.I):
                sync_scripts.append(m.group(1))
    blocking = [s for s in blocking_scripts
                if any(s["url"].endswith(u.split("?")[0].split("/")[-1])
                       or u in s["url"] for u in sync_scripts)] \
        if doc_content else None

    slowest.sort(key=lambda x: -(x["time"] or 0))
    return {
        "page_url": page_url, "page_domain": page_domain,
        "entries": len(entries),
        "total_bytes": total_bytes,
        "by_type": dict(by_type), "by_type_n": dict(by_type_n),
        "third_party": dict(third_party),
        "cache_hits": cache_hits,
        "redirects": redirects,
        "phases_sum": phases_sum, "phase_counts": phase_counts,
        "slowest": slowest[:10],
        "stylesheets": stylesheets,
        "scripts": len(blocking_scripts),
        "sync_scripts": sync_scripts,
        "blocking": blocking,
        "has_doc_content": bool(doc_content),
    }


def human(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.0f} kB"
    return f"{n} B"


# -------------------------------------------------------------------- report

def build_table_event(a: dict) -> dict:
    rows = [[s["url"][:70], round(s["time"] or 0),
             s["type"], human(s["size"]),
             s["timings"]["wait"],
             s["timings"]["receive"]]
            for s in a["slowest"]]
    return {"type": "table",
            "columns": ["url", "ms", "type", "size", "ttfb", "receive"],
            "rows": rows}


def build_chart_event(a: dict) -> dict:
    types = sorted(a["by_type"], key=lambda t: -a["by_type"][t])
    return {"type": "chart", "chart_type": "bar",
            "title": "Transfer size by type",
            "labels": types,
            "series": [{"name": "bytes",
                        "values": [a["by_type"][t] for t in types]}]}


def build_markdown(a: dict, notes: list[str]) -> str:
    out = [f"# HAR Analyze — Report\n",
           f"Page: `{a['page_url'] or '(no document entry in this HAR)'}`"
           f" · {a['entries']} request(s) · "
           f"**{human(a['total_bytes'])}** transferred\n"]
    for n in notes:
        out.append(f"- ℹ️ {n}")
    out.append("")

    # phases
    out.append("## Where the milliseconds went\n")
    for phase in ("dns", "connect", "ssl", "send", "wait", "receive"):
        total = a["phases_sum"][phase]
        n = a["phase_counts"][phase]
        if n:
            out.append(f"- {phase}: {total:.0f} ms total over {n} "
                       f"request(s) (avg {total / n:.0f} ms)")
    out.append("")

    # types
    out.append("## Weight by type\n")
    for t, size in sorted(a["by_type"].items(),
                          key=lambda kv: -kv[1]):
        out.append(f"- {t}: {human(size)} "
                   f"({a['by_type_n'][t]} file(s), "
                   f"{100 * size / max(1, a['total_bytes']):.0f}%)")
    out.append("")

    # third parties
    if a["third_party"]:
        tp_total = sum(v["bytes"] for v in a["third_party"].values())
        out.append("## Third parties\n")
        out.append(f"{human(tp_total)} "
                   f"({100 * tp_total / max(1, a['total_bytes']):.0f}% of "
                   f"the page) comes from domains other than "
                   f"`{a['page_domain']}`:\n")
        for dom, v in sorted(a["third_party"].items(),
                             key=lambda kv: -kv[1]["bytes"])[:10]:
            out.append(f"- {dom}: {v['count']} request(s), "
                       f"{human(v['bytes'])}")
        out.append("")

    # blocking
    out.append("## Render-blocking\n")
    out.append(f"- {len(a['stylesheets'])} stylesheet(s) — CSS blocks "
               "first paint by definition")
    if a["blocking"] is None:
        out.append(f"- {a['scripts']} script(s); which of them block "
                   "cannot be told from this HAR — **the document "
                   "content was not saved** (export the HAR with "
                   "response content, or check DevTools' Coverage "
                   "tab)")
    else:
        out.append(f"- {a['scripts']} script(s), "
                   f"**{len(a['blocking'])} loaded synchronously** "
                   "(no async/defer in the saved document)")
        for s in a["blocking"][:8]:
            out.append(f"  - `{s['url'][:90]}` ({human(s['size'])})")
    out.append("")

    # cache
    if a["cache_hits"]:
        saved = sum(c["saved_bytes"] for c in a["cache_hits"])
        kinds = Counter(c["kind"] for c in a["cache_hits"])
        out.append("## Served from cache\n")
        out.append(f"- {len(a['cache_hits'])} of {a['entries']} "
                   f"request(s): " + ", ".join(f"{v}×{k}" for k, v
                                               in kinds.items())
                   + f" — {human(saved)} that never left the origin")
        out.append("")

    # redirects
    if a["redirects"]:
        out.append("## Redirects\n")
        for r in a["redirects"][:8]:
            out.append(f"- {r['status']} `{r['url'][:70]}` → "
                       f"`{r['to'][:70]}`")
        out.append("")

    # worst
    out.append("## The worst 10 (by total time)\n")
    for s in a["slowest"]:
        out.append(f"- {round(s['time'] or 0)} ms · {s['type']} · "
                   f"{human(s['size'])} · "
                   f"ttfb {s['timings']['wait']} · "
                   f"receive {s['timings']['receive']} · "
                   f"`{s['url'][:80]}`")
    out.append("")
    out.append("## Related\n")
    out.append("- **Server Timing** — the same phase math for one "
               "URL, live; **Cache Check** — the cache layer this "
               "report counts hits from; **Load Test** — how it all "
               "degrades under load.")
    out.append("- **Tech Stack** — the third-party inventory from "
               "the tech side; this report shows its byte cost.")
    return "\n".join(out)


def write_artifacts(a: dict, notes: list[str], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "har_findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({**a, "notes": notes}, fh, ensure_ascii=False,
                  indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HAR Analyze — the DevTools HAR as a diagnosis: "
                    "phases, blocking, third parties, cache, the "
                    "worst 10")
    parser.add_argument("--har-file", required=True,
                        help="the .har file saved from DevTools")
    parser.add_argument("--max-entries", type=int, default=5000,
                        help="safety cap on request entries")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no files are read", flush=True)
        return 0

    if not os.path.isfile(args.har_file):
        print(f"✗ {args.har_file}: file not found", file=sys.stderr,
              flush=True)
        return 2

    log(f"Reading {os.path.basename(args.har_file)}")
    status("parsing the HAR")
    try:
        entries, notes = load_entries(args.har_file, args.max_entries)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1
    if not entries:
        print("✗ the HAR has no request entries", file=sys.stderr,
              flush=True)
        return 1
    emit({"type": "progress", "pct": 40,
          "message": f"{len(entries)} entries"})

    a = analyze(entries)
    emit({"type": "progress", "pct": 90, "message": "analyzed"})
    report = build_markdown(a, notes)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(a))
    emit(build_chart_event(a))
    emit({"type": "markdown", "content": report})
    write_artifacts(a, notes, report)

    tp_total = sum(v["bytes"] for v in a["third_party"].values())
    summary = (f"{a['entries']} request(s) · "
               f"{human(a['total_bytes'])} · "
               f"{human(tp_total)} third-party · "
               f"{len(a['cache_hits'])} from cache")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
