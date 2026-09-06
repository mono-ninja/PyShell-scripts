#!/usr/bin/env python3
"""cache-check/main.py — is caching actually working?

The perf line of the collection: **Server Timing** shows *why* a page
is slow, **Load Test** shows how it degrades under load — and this
script answers the follow-up question: *is the cache layer doing its
job?*  Several plain requests to one URL watch the `Age` header grow
and the HIT/MISS status flip; the `Cache-Control` directives are
decoded into a TTL (with the seconds that remain); a conditional
request checks that `ETag`/`Last-Modified` revalidation works; and
the classic cache-busters — `Set-Cookie` on the response, `Vary:
Cookie`, `private`, `no-store` — are called out by name.

Honest states are part of the job: when the server does not expose
cache-status headers (`X-Cache`, `CF-Cache-Status`, …) the report
says so instead of guessing, and falls back to the Age/TTL evidence.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

import requests

USER_AGENT = "PyShell-cache-check/1 (+cache diagnostics)"

CACHE_STATUS_HEADERS = [
    "CF-Cache-Status", "X-Cache", "X-Cache-Status", "X-Cache-Hits",
    "X-Varnish", "X-Proxy-Cache", "X-Drupal-Cache", "X-NGINX-Cache",
    "X-Cache-Lite", "Fastly-Debug-Path",
]

VERDICT_BYPASS = {"bypass", "dnyamic", "dynamic", "miss"}
HIT_WORDS = {"hit", "h"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ parsing

def parse_cache_control(value: str) -> dict:
    """'public, max-age=3600, stale-while-revalidate=30' -> dict."""
    out: dict = {}
    for token in (value or "").split(","):
        token = token.strip().strip('"')
        if not token:
            continue
        if "=" in token:
            key, _, raw = token.partition("=")
            raw = raw.strip('"').strip()
            if re.fullmatch(r"\d+", raw):
                out[key.strip().lower()] = int(raw)
            else:
                out[key.strip().lower()] = raw
        else:
            out[token.lower()] = True
    return out


def cache_status_of(headers) -> str:
    """The first cache-status header the server exposes, '' if none."""
    for name in CACHE_STATUS_HEADERS:
        val = headers.get(name)
        if val:
            first = str(val).split()[0].strip('"')
            return f"{name}: {first}"
    return ""


def is_hit(cache_status: str) -> bool | None:
    """True/False/None (unknown) from a 'X-Cache: HIT' style string."""
    if not cache_status:
        return None
    word = cache_status.split(":")[-1].strip().lower()
    if word in HIT_WORDS or word.startswith("hit"):
        return True
    if word.startswith("miss") or word in ("bypass", "dynamic", "dnyamic"):
        return False
    return None


def classify_cacheability(cc: dict) -> tuple[str, str]:
    """(verdict, human sentence) from parsed Cache-Control."""
    if cc.get("no-store"):
        return ("never cached",
                "`no-store` — no cache, anywhere, may keep a copy")
    if cc.get("no-cache"):
        return ("stored, always revalidated",
                "`no-cache` — copies exist but every use is revalidated "
                "first")
    if cc.get("private"):
        return ("browser-only",
                "`private` — the visitor's browser may cache it; shared "
                "caches (CDN, page cache) must not")
    ttl = cc.get("s-maxage", cc.get("max-age"))
    if isinstance(ttl, int) and ttl > 0:
        whose = "shared caches" if "s-maxage" in cc else "any cache"
        return (f"cacheable, TTL {ttl}s",
                f"`max-age`-style TTL of {ttl}s for {whose}")
    if cc.get("max-age") == 0:
        return ("not cacheable (max-age=0)",
                "`max-age=0` — expired the moment it was served")
    return ("no TTL directives",
            "no `max-age`/`s-maxage` — caching falls back to heuristics "
            "(or nothing) without validators")


def freshness_remaining(max_age: int | None, age: int | None) -> int | None:
    if max_age is None or age is None:
        return None
    return max(0, max_age - age)


def age_is_growing(ages: list[int | None]) -> bool:
    known = [a for a in ages if a is not None]
    return len(known) >= 2 and known[-1] > known[0]


def sequence_verdict(results: list[dict]) -> str:
    """The HIT/MISS story from the plain requests."""
    hits = [is_hit(r["cache_status"]) for r in results]
    if all(h is None for h in hits):
        if age_is_growing([r["age"] for r in results]):
            return "no cache-status headers, but Age grows — something " \
                   "upstream is caching"
        return "no cache-status headers exposed — cannot see the cache " \
               "layer from here"
    trues = sum(1 for h in hits if h is True)
    falses = sum(1 for h in hits if h is False)
    if trues and falses:
        return f"MISS→HIT settle observed ({falses} miss, {trues} hit) — " \
               "the cache is working"
    if trues and not falses:
        return "every request a HIT — served from cache each time"
    if falses and not trues:
        return "every request a MISS/bypass — content is not being cached"
    return "mixed cache-status responses"


# --------------------------------------------------------------------- probe

def do_request(url: str, timeout: int, conditional: dict | None = None,
               session: requests.Session | None = None) -> dict:
    getter = (session or requests).get
    resp = getter(url, timeout=timeout, allow_redirects=True,
                  headers={"User-Agent": USER_AGENT, **(conditional or {})})
    cc = parse_cache_control(resp.headers.get("Cache-Control", ""))
    age_hdr = resp.headers.get("Age")
    return {
        "status": resp.status_code,
        "age": int(age_hdr) if age_hdr and age_hdr.isdigit() else None,
        "cache_status": cache_status_of(resp.headers),
        "size": len(resp.content),
        "etag": resp.headers.get("ETag", ""),
        "last_modified": resp.headers.get("Last-Modified", ""),
        "cache_control_raw": resp.headers.get("Cache-Control", ""),
        "cache_control": cc,
        "set_cookie": bool(resp.headers.get("Set-Cookie")),
        "vary": resp.headers.get("Vary", ""),
        "date": resp.headers.get("Date", ""),
        "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
        "redirected": bool(resp.history),
        "final_url": resp.url,
    }


# -------------------------------------------------------------------- report

def build_table_event(results: list[dict], cond: dict | None) -> dict:
    rows = []
    for i, r in enumerate(results, 1):
        rows.append({
            "#": i,
            "status": r["status"],
            "age": r["age"] if r["age"] is not None else "—",
            "cache": r["cache_status"].split(":")[-1].strip()
            if r["cache_status"] else "—",
            "size": r["size"],
            "ms": r["elapsed_ms"],
        })
    if cond:
        rows.append({"#": "cond", "status": cond["status"],
                     "age": cond["age"] if cond["age"] is not None
                     else "—",
                     "cache": cond["cache_status"].split(":")[-1].strip()
                     if cond["cache_status"] else "—",
                     "size": cond["size"], "ms": cond["elapsed_ms"]})
    return {"type": "table",
            "columns": ["#", "status", "age", "cache", "size", "ms"],
            "rows": rows}


def build_markdown(url: str, results: list[dict], cond: dict | None,
                   verdicts: list[str]) -> str:
    first = results[0]
    cc = first["cache_control"]
    cc_verdict, cc_sentence = classify_cacheability(cc)
    seq = sequence_verdict(results)
    out = [f"# Cache Check — Report\n",
           f"URL: `{first['final_url']}"
           f"{' (redirected)' if first['redirected'] else ''}`\n",
           f"- Cache-Control: `{first['cache_control_raw'] or '—'}`",
           f"- Policy: **{cc_verdict}** — {cc_sentence}",
           f"- Cache layer: {seq}"]
    max_age = cc.get("s-maxage", cc.get("max-age"))
    if isinstance(max_age, int) and first["age"] is not None:
        out.append(f"- Freshness: Age was {first['age']}s at first "
                   f"request, TTL {max_age}s → "
                   f"**{freshness_remaining(max_age, first['age'])}s of "
                   "freshness remained**")
    elif isinstance(max_age, int):
        out.append(f"- Freshness: TTL {max_age}s, no `Age` header — "
                   "probably served fresh (or the cache doesn't report)")
    if first["etag"]:
        out.append(f"- Validator: ETag `{first['etag']}`")
    elif first["last_modified"]:
        out.append(f"- Validator: Last-Modified `{first['last_modified']}`")
    else:
        out.append("- Validator: none — without ETag/Last-Modified a "
                   "cache cannot revalidate efficiently")
    out.append("")

    out.append("### Requests\n")
    for i, r in enumerate(results, 1):
        out.append(f"{i}. status {r['status']} · "
                   f"Age {r['age'] if r['age'] is not None else '—'} · "
                   f"{r['cache_status'] or 'no cache-status header'} · "
                   f"{r['size']} B · {r['elapsed_ms']} ms")
    if cond:
        if cond["status"] == 304:
            out.append(f"\nConditional request → **304 Not Modified** — "
                       "revalidation works; a cache can refresh without "
                       "re-downloading.")
        else:
            out.append(f"\nConditional request → **{cond['status']}** "
                       "(full body again) — the validator was not "
                       "honored, or none was offered.")
    out.append("")

    if first["set_cookie"]:
        out.append("### Cache-busters\n")
        out.append("- `Set-Cookie` on this response — cookies usually "
                   "switch page caches and CDNs to per-visitor mode; on "
                   "WordPress this is the classic \"cache plugin says "
                   "it's caching but every visitor misses\" cause.")
    if "cookie" in first["vary"].lower():
        out.append("- `Vary: Cookie` — the cache keeps a copy per cookie "
                   "value, which for most visitors means no reuse.")
    if first["set_cookie"] or "cookie" in first["vary"].lower():
        out.append("")

    out.append("### Verdicts\n")
    for v in verdicts:
        out.append(f"- {v}")
    out.append("")
    out.append("### What to do\n")
    out.append("- No caching where the policy allows it: on WordPress, "
               "check the page-cache plugin rules (cookie bypass list) "
               "or the CDN cache rules; a static asset should carry "
               "`Cache-Control: public, max-age=…` with a far-future "
               "value.")
    out.append("- `no-store`/`private` on public content is usually a "
               "session or security plugin being overly careful.")
    out.append("- Related: **Server Timing** (where the time goes), "
               "**Load Test** (how it degrades), **SEO Checks** (the "
               "crawler pass over the whole site).")
    return "\n".join(out)


def write_artifacts(url: str, results: list[dict], cond: dict | None,
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "url": url,
        "final_url": results[0]["final_url"],
        "requests": results,
        "conditional": cond,
        "cache_control": results[0]["cache_control"],
    }
    with open(os.path.join(out_dir, "cache_results.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cache Check — is caching actually working: Age "
                    "growth, HIT/MISS, TTL and the cache-busters")
    parser.add_argument("--url", required=True,
                        help="the URL to watch")
    parser.add_argument("--requests", type=int, default=3,
                        help="how many plain requests (default 3)")
    parser.add_argument("--interval", type=int, default=1,
                        help="seconds between requests (default 1)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds (default 15)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no requests are made", flush=True)
        return 0

    url = args.url.strip()
    if not re.match(r"^https?://", url):
        print("✗ the URL must start with http:// or https://",
              file=sys.stderr, flush=True)
        return 2
    if not (2 <= args.requests <= 10):
        print("✗ --requests must be between 2 and 10",
              file=sys.stderr, flush=True)
        return 2

    log(f"Watching the cache of {url}")
    status(f"{args.requests} + 1 conditional request(s)")

    session = requests.Session()
    results: list[dict] = []
    try:
        for i in range(args.requests):
            r = do_request(url, args.timeout, session=session)
            results.append(r)
            log(f"  {r['status']} · Age {r['age'] if r['age'] is not None else '—'}"
                f" · {r['cache_status'] or 'no cache-status header'}"
                f" · {r['elapsed_ms']} ms")
            emit({"type": "progress",
                  "pct": int(100 * (i + 1) / (args.requests + 1)),
                  "message": f"{i + 1}/{args.requests + 1}"})
            if i < args.requests - 1 and args.interval > 0:
                time.sleep(args.interval)
    except requests.RequestException as exc:
        print(f"✗ cannot reach {url}: {exc}", file=sys.stderr, flush=True)
        return 1

    # conditional request — the revalidation probe
    cond: dict | None = None
    first = results[0]
    conditional: dict = {}
    if first["etag"]:
        conditional["If-None-Match"] = first["etag"]
    elif first["last_modified"]:
        conditional["If-Modified-Since"] = first["last_modified"]
    if conditional:
        try:
            cond = do_request(url, args.timeout, conditional=conditional,
                              session=session)
        except requests.RequestException:
            cond = None
    emit({"type": "progress", "pct": 100, "message": "Done"})

    cc = first["cache_control"]
    cc_verdict, _ = classify_cacheability(cc)
    verdicts = [
        f"Policy: {cc_verdict}.",
        f"Cache layer: {sequence_verdict(results)}.",
    ]
    if age_is_growing([r["age"] for r in results]):
        verdicts.append("Age grows between requests — a cache is serving "
                        "the stored copy.")
    if cond:
        verdicts.append("Revalidation: "
                        + ("304 honored — validators work."
                           if cond["status"] == 304
                           else f"{cond['status']} — validators not "
                                "honored."))
    if first["set_cookie"]:
        verdicts.append("Cookies on the response — the likely reason a "
                        "page cache misses.")
    seq = sequence_verdict(results)
    if "not being cached" in seq:
        verdicts.append("Every request missed — combined with a "
                        "cacheable policy, something is bypassing the "
                        "cache.")

    report = build_markdown(url, results, cond, verdicts)
    emit(build_table_event(results, cond))
    emit({"type": "markdown", "content": report})
    write_artifacts(url, results, cond, report)

    summary = f"{cc_verdict} · {seq}"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
