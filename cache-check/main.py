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
from http.cookiejar import DefaultCookiePolicy

import requests

USER_AGENT = "PyShell-cache-check/1 (+cache diagnostics)"

CACHE_STATUS_HEADERS = [
    "CF-Cache-Status", "X-Cache", "X-Cache-Status", "X-Cache-Hits",
    "X-Varnish", "X-Proxy-Cache", "X-Drupal-Cache", "X-NGINX-Cache",
    "X-Cache-Lite", "Fastly-Debug-Path",
]

# Headers whose value is a hit *counter*, not a word: 0 means the copy
# came from the origin, anything above it means it came from the cache.
COUNTER_HEADERS = {"x-cache-hits"}

# X-Varnish is the odd one out — its token *count* is the signal: one
# XID on a miss, a second (parent) XID appended on a hit.
XID_HEADERS = {"x-varnish"}

HIT_WORDS = {"hit", "h", "cached", "fresh",
             "updating", "stale", "revalidated"}
MISS_WORDS = {"miss", "m", "bypass", "dynamic", "expired", "pass",
              "ignored", "none", "uncached"}

# Statuses that answer "was it cached?" but leave *why* unsaid. These
# are the ones worth spelling out — a bare `UPDATING` in a table tells
# an operator nothing.
STATUS_NOTES = {
    "updating": "the cached copy has expired and is being refreshed in "
                "the background — visitors keep being served from cache "
                "meanwhile",
    "stale": "a stale copy was served — `stale-while-revalidate` / "
             "`stale-if-error` covered for a slow or failing origin",
    "revalidated": "the copy was checked against the origin and reused — "
                   "cheap, but still a round trip every time",
    "expired": "the copy had expired, so the origin was asked again — "
               "the TTL is shorter than the traffic needs",
    "bypass": "the cache was bypassed on purpose — a page rule, a "
              "cookie, or a no-cache request",
    "dynamic": "the CDN treats this content as uncacheable and never "
               "stores it",
    "pass": "the request went straight through to the origin, uncached",
    "ignored": "the origin's cache headers were ignored; the origin "
               "answered",
    "none": "the CDN did not consider this response cacheable",
}


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


def status_word(name: str, value: str) -> bool | None:
    """True/False/None (unknown) from one cache-status header's value.

    Values come in three shapes: a counter (`X-Cache-Hits: 0`), Varnish
    XIDs whose count is the signal, and everything else — a word, but
    rarely on its own. Multi-layer caches interleave it with node names
    (`cp3070 miss, cp3070 hit/3`) or hyphenate it (`hit-front`), so the
    whole value is scanned and the **last** decisive token wins: that
    is the layer closest to the visitor.
    """
    name, value = name.strip().lower(), value.strip()
    if name in COUNTER_HEADERS:
        return int(value) > 0 if value.isdigit() else None
    if name in XID_HEADERS:
        ids = value.split()
        return len(ids) > 1 if ids and all(i.isdigit() for i in ids) else None
    verdict = None
    for token in re.split(r"[\s,;]+", value.lower()):
        parts = re.split(r"[-_/]+", token)
        if any(p in HIT_WORDS or p.startswith("hit") for p in parts):
            verdict = True
        elif any(p in MISS_WORDS or p.startswith("miss") for p in parts):
            verdict = False
    return verdict


def status_notes(results: list[dict]) -> list[tuple[str, str]]:
    """(status, what it means) for every noteworthy status observed."""
    seen: dict[str, str] = {}
    for r in results:
        value = r["cache_status"].partition(":")[2].strip().lower()
        for token in re.split(r"[\s,;]+", value):
            for part in re.split(r"[-_/]+", token):
                if part in STATUS_NOTES:
                    seen.setdefault(part, STATUS_NOTES[part])
    return list(seen.items())


def cache_status_of(headers) -> str:
    """The clearest cache-status header the server exposes, '' if none.

    The first header that actually says HIT or MISS wins — a readable
    `X-Cache-Status: hit-front` should not lose to an `X-Cache` whose
    first token happens to be a node name. When none of them is
    decisive, the first one present is still reported, so the report
    stays honest about what the server did send.
    """
    present = ""
    for name in CACHE_STATUS_HEADERS:
        raw = str(headers.get(name) or "").strip().strip('"')
        if not raw:
            continue
        present = present or f"{name}: {raw}"
        if status_word(name, raw) is not None:
            return f"{name}: {raw}"
    return present


def is_hit(cache_status: str) -> bool | None:
    """True/False/None (unknown) from a 'X-Cache: HIT' style string."""
    if not cache_status:
        return None
    name, sep, value = cache_status.partition(":")
    if not sep:                       # a bare value, no header name
        name, value = "", name
    return status_word(name, value)


def ttl_of(cc: dict) -> tuple[int | None, bool]:
    """(TTL seconds, whether it is the shared-cache one) — s-maxage wins.

    Shared caches are the interesting half for CDN diagnosis, so a
    usable `s-maxage` beats `max-age`. A non-numeric value counts as
    absent rather than shadowing the directive underneath it.
    """
    if isinstance(cc.get("s-maxage"), int):
        return cc["s-maxage"], True
    ttl = cc.get("max-age")
    return (ttl, False) if isinstance(ttl, int) else (None, False)


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
    ttl, shared = ttl_of(cc)
    if ttl is not None:
        directive = "s-maxage" if shared else "max-age"
        whose = "shared caches" if shared else "any cache"
        if ttl > 0:
            return (f"cacheable, TTL {ttl}s",
                    f"`{directive}`-style TTL of {ttl}s for {whose}")
        return (f"not cacheable ({directive}=0)",
                f"`{directive}=0` — expired the moment it was served, so "
                f"{whose} must revalidate before every use")
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


def age_reset(ages: list[int | None]) -> tuple[int, int] | None:
    """The first Age *drop* — the cache replaced the copy mid-probe."""
    known = [a for a in ages if a is not None]
    for before, after in zip(known, known[1:]):
        if after < before:
            return (before, after)
    return None


def sequence_verdict(results: list[dict]) -> str:
    """The HIT/MISS story from the plain requests."""
    hits = [is_hit(r["cache_status"]) for r in results]
    if all(h is None for h in hits):
        growing = age_is_growing([r["age"] for r in results])
        seen = next((r["cache_status"] for r in results if r["cache_status"]),
                    "")
        if seen:
            tail = ("though Age grows, so something upstream is caching"
                    if growing
                    else "the cache layer stays invisible from here")
            return f"`{seen}` is exposed but says neither HIT nor " \
                   f"MISS — {tail}"
        if growing:
            return "no cache-status headers, but Age grows — something " \
                   "upstream is caching"
        return "no cache-status headers exposed — cannot see the cache " \
               "layer from here"
    trues = sum(1 for h in hits if h is True)
    falses = sum(1 for h in hits if h is False)
    if trues and falses:
        first_hit = hits.index(True)
        last_miss = len(hits) - 1 - hits[::-1].index(False)
        if last_miss < first_hit:
            return f"MISS→HIT settle observed ({falses} miss, {trues} " \
                   "hit) — the cache is working"
        return f"a MISS came after a HIT ({trues} hit, {falses} miss) — " \
               "the cache is not holding the copy (per-visitor keying, a " \
               "very short TTL, or eviction)"
    if trues:
        return "every request a HIT — served from cache each time"
    return "every request a MISS/bypass — content is not being cached"


# --------------------------------------------------------------------- probe

def new_session() -> requests.Session:
    """A session for connection reuse, with the cookie jar switched off.

    Keep-alive across the probe is welcome; a cookie jar is not. A
    `Set-Cookie` on response 1 would otherwise ride along on requests
    2+, flipping page caches and CDNs into per-visitor mode — the probe
    would become a cache-buster of our own making and then report the
    MISSes it had just caused.
    """
    session = requests.Session()
    session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
    return session


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
        rows.append([
            i,
            r["status"],
            r["age"] if r["age"] is not None else "—",
            r["cache_status"].split(":")[-1].strip()
            if r["cache_status"] else "—",
            r["size"],
            r["elapsed_ms"],
        ])
    if cond:
        rows.append(["cond", cond["status"],
                     cond["age"] if cond["age"] is not None
                     else "—",
                     cond["cache_status"].split(":")[-1].strip()
                     if cond["cache_status"] else "—",
                     cond["size"], cond["elapsed_ms"]])
    return {"type": "table",
            "columns": ["#", "status", "age", "cache", "size", "ms"],
            "rows": rows}


def build_markdown(results: list[dict], cond: dict | None,
                   verdicts: list[str]) -> str:
    first = results[0]
    cc = first["cache_control"]
    cc_verdict, cc_sentence = classify_cacheability(cc)
    seq = sequence_verdict(results)
    out = ["# Cache Check — Report\n",
           f"URL: `{first['final_url']}"
           f"{' (redirected)' if first['redirected'] else ''}`\n",
           f"- Cache-Control: `{first['cache_control_raw'] or '—'}`",
           f"- Policy: **{cc_verdict}** — {cc_sentence}",
           f"- Cache layer: {seq}"]
    for word, note in status_notes(results):
        out.append(f"- `{word.upper()}` — {note}")
    reset = age_reset([r["age"] for r in results])
    if reset:
        out.append(f"- Age fell from {reset[0]}s to {reset[1]}s during the "
                   "probe — the stored copy was replaced mid-run (a "
                   "refresh, or another edge node answering)")
    max_age, _ = ttl_of(cc)
    if max_age is not None and first["age"] is not None:
        out.append(f"- Freshness: Age was {first['age']}s at first "
                   f"request, TTL {max_age}s → "
                   f"**{freshness_remaining(max_age, first['age'])}s of "
                   "freshness remained**")
    elif max_age == 0:
        out.append("- Freshness: TTL 0s — **nothing is ever fresh**; every "
                   "use has to revalidate before it is served")
    elif max_age is not None:
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
            out.append("\nConditional request → **304 Not Modified** — "
                       "revalidation works; a cache can refresh without "
                       "re-downloading.")
        else:
            out.append(f"\nConditional request → **{cond['status']}** "
                       "(full body again) — either the resource changed "
                       "since the first request, or the validator is not "
                       "honored.")
    out.append("")

    vary_cookie = "cookie" in first["vary"].lower()
    if first["set_cookie"] or vary_cookie:
        out.append("### Cache-busters\n")
        if first["set_cookie"]:
            out.append("- `Set-Cookie` on this response — cookies usually "
                       "switch page caches and CDNs to per-visitor mode; on "
                       "WordPress this is the classic \"cache plugin says "
                       "it's caching but every visitor misses\" cause.")
        if vary_cookie:
            out.append("- `Vary: Cookie` — the cache keeps a copy per "
                       "cookie value, which for most visitors means no "
                       "reuse.")
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
    if not (0 <= args.interval <= 60):
        print("✗ --interval must be between 0 and 60 seconds",
              file=sys.stderr, flush=True)
        return 2
    if not (3 <= args.timeout <= 60):
        print("✗ --timeout must be between 3 and 60 seconds",
              file=sys.stderr, flush=True)
        return 2

    log(f"Watching the cache of {url}")
    status(f"{args.requests} + 1 conditional request(s)")

    session = new_session()
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
                           else f"{cond['status']} — no 304: the resource "
                                "changed, or validators are not honored."))
    for word, note in status_notes(results):
        verdicts.append(f"{word.upper()}: {note}.")
    reset = age_reset([r["age"] for r in results])
    if reset:
        verdicts.append(f"Age fell {reset[0]}s → {reset[1]}s — the stored "
                        "copy was replaced during the probe.")
    if first["set_cookie"]:
        verdicts.append("Cookies on the response — the likely reason a "
                        "page cache misses.")
    seq = sequence_verdict(results)
    if "not being cached" in seq:
        verdicts.append("Every request missed — combined with a "
                        "cacheable policy, something is bypassing the "
                        "cache.")

    report = build_markdown(results, cond, verdicts)
    emit(build_table_event(results, cond))
    emit({"type": "markdown", "content": report})
    write_artifacts(url, results, cond, report)

    summary = f"{cc_verdict} · {seq}"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
