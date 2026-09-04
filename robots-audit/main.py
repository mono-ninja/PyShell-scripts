#!/usr/bin/env python3
"""robots-audit/main.py — RFC 9309 audit of a robots.txt.

The third member of the crawl pipeline: [Site Crawler](../site-crawler)
respects robots.txt, [Bot Hunter](../bot-hunter) drafts one from your
logs, and this script tells you whether the file — live or draft —
actually says what you think it says. Syntax per RFC 9309, the classic
mistakes (a whole-site Disallow, duplicate user-agent groups whose
second half never runs, orphan rules, silent 500 KiB truncation), the
sitemap directives, and a URL tester: paste your key pages and see
each one's verdict with the exact rule that decided it.

Reads one robots.txt (fetches it, or reads a local draft) and — when
Sitemap verification is on — makes one request per Sitemap line.
Nothing else: no crawling, no writes to the site.

Structured events on stderr, human log on stdout. Exit codes: 0 = the
audit ran (findings are results, not failures — a blocked site is a
successful audit that found a blocked site), 1 = the robots.txt could
not be obtained (network error, unreadable file), 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from src.checks import AuditInput, SitemapCheck, TestResult, audit
from src.evaluate import describe_rule, evaluate, url_path
from src.parser import parse_robots
from src.report import (
    build_markdown,
    build_table_event,
    findings_document,
    parsed_document,
)
from src.robotsio import (
    SourceError,
    fetch_robots,
    normalize_origin,
    read_robots_file,
    verify_sitemap,
)


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Robots Audit — validate a robots.txt against RFC 9309 "
                    "and test URLs against its rules")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--site-url",
                        help="fetch and audit {origin}/robots.txt")
    source.add_argument("--robots-file",
                        help="audit a local robots.txt (e.g. a Bot Hunter draft)")
    parser.add_argument("--test-urls", default=None,
                        help="URLs to test against the rules, one per line")
    parser.add_argument("--user-agent", default="*",
                        help="user-agent whose group the tests run against "
                             "(default '*')")
    parser.add_argument("--verify-sitemaps", action="store_true",
                        help="fetch each Sitemap: line and check it answers 200")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-request timeout in seconds (default 10)")
    return parser


def parse_test_urls(raw: str | None) -> list[str]:
    """One URL per line; '#' comments allowed; blanks dropped."""
    if not raw:
        return []
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is fetched", flush=True)
        return 0

    # --- obtain the robots.txt ------------------------------------------
    emit({"type": "progress", "pct": 5, "message": "Getting robots.txt"})
    try:
        if args.site_url:
            origin = normalize_origin(args.site_url)
            source = fetch_robots(origin, args.timeout)
            log(f"Fetched {origin}/robots.txt"
                + (f" → HTTP {source.status}" if source.status else ""))
        else:
            source = read_robots_file(args.robots_file)
            log(f"Read {args.robots_file}")
    except SourceError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1

    doc = parse_robots(source.text) if source.text is not None else None
    emit({"type": "progress", "pct": 30,
          "message": "Parsed" if doc is not None else "No file to parse"})
    if doc is not None:
        status(f"{len(doc.groups)} group(s), {len(doc.sitemaps)} sitemap "
               f"directive(s)" + (f", {len(doc.notes)} parse note(s)"
                                  if doc.notes else ""))

    # --- URL tests --------------------------------------------------------
    tests: list[TestResult] = []
    raw_urls = parse_test_urls(args.test_urls)
    if raw_urls and doc is not None:
        group = doc.group_for(args.user_agent)
        if group is None:
            status(f"⚠ no group matches '{args.user_agent}' and no '*' "
                   f"group exists — every URL is allowed by default")
        for url in raw_urls:
            allowed, rule = evaluate(group, url_path(url))
            tests.append(TestResult(url=url, allowed=allowed,
                                    deciding=describe_rule(rule)))
            mark = "allowed" if allowed else "DISALLOWED"
            log(f"  {url} → {mark} ({describe_rule(rule)})")

    # --- optional sitemap verification --------------------------------------
    sitemap_checks: list[SitemapCheck] = []
    if args.verify_sitemaps and doc is not None and doc.sitemaps:
        emit({"type": "progress", "pct": 45, "message": "Verifying sitemaps"})
        for i, (url, _lineno) in enumerate(doc.sitemaps, 1):
            ok, detail = verify_sitemap(url, args.timeout)
            sitemap_checks.append(SitemapCheck(url=url, ok=ok, detail=detail))
            log(f"  Sitemap {url} → {detail}")
            emit({"type": "progress",
                  "pct": 45 + round(20 * i / len(doc.sitemaps)),
                  "message": f"Sitemaps {i}/{len(doc.sitemaps)}"})

    # --- audit + report -------------------------------------------------------
    emit({"type": "progress", "pct": 70, "message": "Auditing"})
    data = AuditInput(source=source, doc=doc, tests=tests,
                      sitemap_checks=sitemap_checks, user_agent=args.user_agent)
    findings = audit(data)
    report = build_markdown(data, findings)

    emit({"type": "progress", "pct": 90, "message": "Writing artifacts"})
    emit(build_table_event(findings))
    emit({"type": "markdown", "content": report})

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "findings.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(findings_document(data, findings), fh, indent=2,
                      ensure_ascii=False)
        with open(os.path.join(output_dir, "robots_parsed.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(parsed_document(doc) if doc else {}, fh, indent=2,
                      ensure_ascii=False)
        with open(os.path.join(output_dir, "report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(report + "\n")

    emit({"type": "progress", "pct": 100, "message": "Done"})
    fails = sum(1 for f in findings if f.severity == "fail")
    warns = sum(1 for f in findings if f.severity == "warn")
    blocked = sum(1 for t in tests if not t.allowed)
    summary = f"{fails} fail · {warns} warn"
    if tests:
        summary += f" · {blocked}/{len(tests)} test URL(s) disallowed"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
