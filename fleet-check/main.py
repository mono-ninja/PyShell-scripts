#!/usr/bin/env python3
"""fleet-check/main.py — one overview of a whole portfolio of sites.

The composite the collection was building toward: for every site in
the list — **HTTP status, TLS grade + certificate days, security-
headers grade, WordPress version, sitemap presence** — in one run,
with a per-run comparison against a previous `fleet.json` baseline.

**The needs mechanics, honestly.** This script declares
`needs: tls-audit, security-headers, tech-stack` and uses them the
*invocation* way when PyShell provides them (`PYSHELL_DEPS`): each
sibling's `main.py` runs as a child process per site, and its
artifacts (`findings.json`, `tls_raw.json`, `stack.json`) are parsed
— the full grades, the real detection logic, no duplication. When a
sibling isn't installed, the same check runs as a **compact built-in**
(cert days via the `ssl` stdlib, a five-key header presence grade,
the generator-tag WordPress version) and every compact value is
*labeled* compact in the report — never passed off as the full grade.

Exit codes: 0 = the fleet ran (bad grades are findings), 1 = nothing
could be checked (no usable URLs / every site unreachable), 2 = bad
arguments (no URLs, an unreadable baseline).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from urllib.parse import urlsplit

import requests

from src.baseline import diff_against_baseline, load_baseline
from src.checks import SiteResult, check_site
from src.events import emit, log, status
from src.report import (
    build_chart_event, build_markdown, build_table_event,
    write_artifacts,
)

USER_AGENT = "PyShell-fleet-check/1.0"
MAX_SITES = 50


def parse_urls(raw: str) -> list[str]:
    """One URL per line; #-comments and blanks skipped; normalized to
    scheme://host[:port] (non-default ports kept); duplicates
    collapsed, order kept."""
    seen: set[str] = set()
    out: list[str] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        candidate = line if "://" in line else "https://" + line
        try:
            parts = urlsplit(candidate)
        except ValueError:
            continue
        if not parts.hostname:
            continue
        port = parts.port
        netloc = parts.hostname if port in (None, 80, 443) \
            else f"{parts.hostname}:{port}"
        normalized = f"{parts.scheme}://{netloc}"
        if normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no sites are checked", flush=True)
        return 0

    urls = parse_urls(args.urls)
    if not urls:
        print("✗ no usable URLs in the list (one per line, "
              "example.com or https://example.com)",
              file=sys.stderr, flush=True)
        return 2
    if len(urls) > MAX_SITES:
        print(f"✗ {len(urls)} URLs given; the cap is {MAX_SITES} per "
              f"run", file=sys.stderr, flush=True)
        return 2

    baseline = load_baseline(args.baseline)
    if args.baseline and baseline is None:
        print(f"✗ {args.baseline!r} is not a readable fleet.json "
              f"baseline", file=sys.stderr, flush=True)
        return 2

    # The deps map: which siblings PyShell provided.
    try:
        deps = json.loads(os.environ.get("PYSHELL_DEPS", "{}"))
    except ValueError:
        deps = {}
    have = {sid: folder for sid, folder in deps.items() if folder}
    modes = {
        "tls": "full" if "com.pyshell.tlsaudit" in have else "compact",
        "headers": "full" if "com.pyshell.securityheaders" in have
        else "compact",
        "tech": "full" if "com.pyshell.techstack" in have else "compact",
    }
    full_count = sum(1 for m in modes.values() if m == "full")
    log(f"Fleet of {len(urls)} site(s) · {full_count}/3 checks via the "
        f"sibling scripts"
        + ("" if full_count == 3 else
           " · the rest compact (labeled in the report)"))
    if baseline:
        log(f"  diffing against {os.path.basename(args.baseline)}")

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    results: list[SiteResult] = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(check_site, url, session, args.timeout,
                               have): url for url in urls}
        for future in as_completed(futures):
            url = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # a worker crash is a fact, not a run death
                result = SiteResult(url=url, host=urlsplit(url).hostname
                                    or url, reachable=False)
                result.errors.append(type(exc).__name__)
            results.append(result)
            done += 1
            mark = "✓" if result.reachable else "✗"
            log(f"  {mark} {result.http_status or '—':>3} "
                f"{result.url} · TLS {result.tls_label} · "
                f"cert {result.cert_label} · headers "
                f"{result.headers_grade or '—'}")
            emit({"type": "progress", "pct": int(100 * done / len(urls)),
                  "message": f"{done}/{len(urls)} · {url}"})

    results.sort(key=lambda r: r.url)
    reachable = [r for r in results if r.reachable]
    if not reachable:
        print("✗ every site was unreachable — there was no fleet to "
              "check", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Nothing answered\n\n❌ None of the sites answered. "
              "Check the URLs (and your network) — "
              "[IP Search](../ip-search) diagnoses one; "
              "[Server Timing](../server-timing) the other."})
        write_artifacts(results, {}, "")
        return 1

    changes = diff_against_baseline(baseline, results) if baseline else {}

    report = build_markdown(results, modes, changes)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_chart_event(results))
    emit(build_table_event(results, changes))
    emit({"type": "markdown", "content": report})
    write_artifacts(results, modes, report)

    expired = sum(1 for r in reachable
                  if r.cert_days is not None and r.cert_days < 0)
    weak_tls = sum(1 for r in reachable
                   if r.tls_grade and r.tls_grade not in ("A", "A+"))
    summary = (f"{len(reachable)}/{len(results)} up · {weak_tls} TLS "
               f"below A · {expired} expired cert(s)"
               + (f" · {sum(1 for c in changes.values() if c['direction'] == 'worse')}"
                  " slipped vs baseline" if changes else ""))
    status(summary)
    log(f"← {summary}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fleet Check — one overview of a portfolio of "
                    "sites: status, TLS, headers, WP, sitemap")
    parser.add_argument("--urls", required=True,
                        help="the sites, one per line (or a '\\n'-joined "
                             "string)")
    parser.add_argument("--workers", type=int, default=3,
                        help="sites checked in parallel (default 3)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout (default 15)")
    parser.add_argument("--baseline", default="",
                        help="a previous run's fleet.json")
    return parser


if __name__ == "__main__":
    sys.exit(main())
