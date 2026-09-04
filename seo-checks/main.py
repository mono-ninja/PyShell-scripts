#!/usr/bin/env python3
"""seo-checks/main.py — rule-based SEO checks over a Site Crawler snapshot.

Reads a ``site_snapshot.json`` produced by ``site-crawler/`` and runs the
selected checks — redirects, broken links, canonical issues, duplicate
content, meta quality, indexability, orphans, URL variants, rel attributes,
sitemap cross-check — as pure functions over already-collected facts.
**No crawling here, no judgment in the crawler**: this script is where "is
this actually a problem" gets decided. Crawl once, then run this as many
times as needed with a different ``checks`` selection each time — no
network, no re-crawl, seconds per run.

The one exception to "no network": verifying **external** links needs
requests to third-party hosts the crawler never visited. That's an
explicit, off-by-default toggle (``--check-external-links``), not part of
the default no-network checks.

Structured events are emitted on stderr so PyShell renders them natively;
from a terminal they degrade to plain JSON log lines. Exit codes:

* ``0`` — checks ran, however many findings turned up ("findings aren't
  failures", same philosophy as ``security-headers``);
* ``1`` — the snapshot doesn't parse, its ``schema`` version isn't
  understood, the baseline is unreadable, or the artifacts can't be
  written;
* ``2`` — bad arguments;
* ``3`` — findings reached the ``--fail-on`` severity. Opt-in only, for
  CI: the default is still "findings aren't failures".
"""
import argparse
import json
import os
import sys

from src.baseline import BaselineError, compare, load_baseline
from src.checks import ALL_CHECK_NAMES, CHECKS, external_links
from src.checks import duplicates as duplicates_check
from src.options import Options
from src.report import (
    SEVERITY_ICON,
    SEVERITY_RANK,
    build_html,
    build_markdown,
    counts,
    findings_document,
    sort_findings,
    write_artifacts,
)
from src.snapshot import SnapshotError, load_snapshot

# Keep in sync with `checks.default` in pyshell.yaml — the manifest can't
# read this constant, so the two lists are the same decision written twice.
DEFAULT_CHECKS = ["redirects", "broken_links", "canonical"]
DEFAULT_STALE_DAYS = 7
MAX_EVENT_ROWS = 300


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SEO Checks — run redirect/broken-link/canonical/duplicate-"
                    "content checks against a Site Crawler snapshot")

    parser.add_argument("--snapshot-file", required=True,
                        help="site_snapshot.json produced by Site Crawler")
    parser.add_argument("--checks", action="append",
                        choices=[*ALL_CHECK_NAMES, "all"], metavar="CHECK",
                        help=f"check to run (repeatable; 'all' selects every "
                             f"check; default: {', '.join(DEFAULT_CHECKS)})")
    parser.add_argument("--include-path", action="append", default=[],
                        metavar="GLOB",
                        help="only check URLs whose path matches this glob "
                             "(repeatable, e.g. '/blog/*')")
    parser.add_argument("--exclude-path", action="append", default=[],
                        metavar="GLOB",
                        help="skip URLs whose path matches this glob "
                             "(repeatable, e.g. '/tag/*')")
    parser.add_argument("--min-severity", choices=["info", "warn", "fail"],
                        default="info",
                        help="hide findings below this severity (default info "
                             "— show everything)")

    parser.add_argument("--duplicates-mode", choices=["exact", "normalized"],
                        default="exact",
                        help="'normalized' also groups titles differing only "
                             "in case, spacing or a trailing brand suffix")
    parser.add_argument("--flag-missing-canonical", action="store_true",
                        help="Also report pages with no canonical tag at all "
                             "(info)")

    parser.add_argument("--title-min", type=int, default=30)
    parser.add_argument("--title-max", type=int, default=60)
    parser.add_argument("--desc-min", type=int, default=70)
    parser.add_argument("--desc-max", type=int, default=158)
    parser.add_argument("--max-depth-ok", type=int, default=3,
                        help="Click depth past which a page is flagged (info)")
    parser.add_argument("--stale-after-days", type=int,
                        default=DEFAULT_STALE_DAYS,
                        help=f"Warn when the snapshot is older than this "
                             f"(default {DEFAULT_STALE_DAYS})")

    parser.add_argument("--check-external-links", action="store_true",
                        help="Also verify external links — sends requests to "
                             "third-party sites (off by default)")
    parser.add_argument("--external-concurrency", type=int, default=5,
                        help="External check concurrency (default 5)")
    parser.add_argument("--external-timeout", type=int, default=10,
                        help="External check timeout in seconds (default 10)")
    parser.add_argument("--external-max-urls", type=int,
                        default=external_links.DEFAULT_MAX_URLS,
                        help="Stop after this many unique external URLs "
                             f"(default {external_links.DEFAULT_MAX_URLS})")
    parser.add_argument("--external-skip-nofollow", action="store_true",
                        help="Skip external links marked rel=nofollow")
    parser.add_argument("--external-ignore-host", action="append", default=[],
                        metavar="HOST",
                        help="Never probe this host, subdomains included "
                             "(repeatable)")

    parser.add_argument("--baseline", default=None, metavar="FINDINGS_JSON",
                        help="findings.json from a previous run — report which "
                             "findings are new and which are fixed")
    parser.add_argument("--fail-on", choices=["none", "info", "warn", "fail"],
                        default="none",
                        help="Exit 3 when a finding of this severity or worse "
                             "is present (default none — findings aren't "
                             "failures)")
    parser.add_argument("--out-dir", default=None,
                        help="Where to write the artifacts (default: next to "
                             "the snapshot; always also written to PyShell's "
                             "run folder)")
    parser.add_argument("--format", choices=["md", "html", "both"],
                        default="md",
                        help="Also write report.html (default md only)")
    parser.add_argument("--group-by", choices=["check", "page"],
                        default="check",
                        help="'page' lists every finding under the page it "
                             "belongs to")
    return parser


def artifact_dirs(args) -> list[str]:
    """Where the artifacts go.

    Under PyShell, always the run folder (that's what the artifact card
    reads). Plus a durable location — ``--out-dir`` if given, otherwise
    next to the snapshot, so a terminal run still produces findings.json
    for CI and a PyShell run leaves something behind after the run folder
    is gone.
    """
    durable = args.out_dir or os.path.dirname(
        os.path.abspath(args.snapshot_file)) or "."
    return [durable, os.environ.get("PYSHELL_OUTPUT_DIR", "")]


def snapshot_notes(snapshot, stale_after_days: int) -> None:
    """Findings against a stale or partial snapshot can already be fixed or
    plain wrong, so say so before showing any of them."""
    age_days = snapshot.snapshot_age()
    if age_days is None:
        status("Snapshot date unknown — findings may be stale")
    elif age_days < 1:
        hours = max(1, round(age_days * 24))
        status(f"Snapshot crawled {hours}h ago")
    elif age_days >= stale_after_days:
        status(f"⚠ Snapshot is {round(age_days)} days old — findings may "
               f"already be fixed or wrong; consider re-crawling")
    else:
        status(f"Snapshot crawled {round(age_days)} day(s) ago")

    if snapshot.capped:
        status(f"⚠ The crawl was capped ({snapshot.pages_crawled} of "
               f"{snapshot.pages_discovered} discovered pages) — findings "
               f"only cover the crawled part")
    if snapshot.partial:
        status(f"⚠ The crawl stopped early "
               f"({snapshot.stopped_reason or 'reason not recorded'}) — "
               f"findings only cover what it reached")
    if snapshot.include_paths or snapshot.exclude_paths:
        status(f"Path filters keep {len(snapshot.pages)} of "
               f"{len(snapshot.all_pages)} pages (links and redirects still "
               f"resolve site-wide)")


def run_checks(snapshot, planned, options, external, args) -> list:
    """Every selected check, in registry order, with progress in between."""
    findings: list = []
    total = len(planned) + (1 if external else 0)

    for i, name in enumerate(planned):
        emit({"type": "progress", "pct": round(100 * i / max(total, 1)),
              "message": f"Running {name}"})
        findings.extend(CHECKS[name](snapshot, options))

    if external:
        base = len(planned)
        emit({"type": "progress", "pct": round(100 * base / total),
              "message": "Verifying external links"})
        findings.extend(external_links.run(
            snapshot,
            concurrency=args.external_concurrency,
            timeout=args.external_timeout,
            max_urls=args.external_max_urls,
            skip_nofollow=args.external_skip_nofollow,
            ignore_hosts=frozenset(h.lower() for h in args.external_ignore_host),
            on_progress=lambda done, total_urls: emit({
                "type": "progress",
                "pct": round(100 * (base + done / max(total_urls, 1)) / total),
                "message": f"External links {done}/{total_urls}",
            }),
        ))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no checks run", flush=True)
        return 0

    if args.title_min > args.title_max or args.desc_min > args.desc_max:
        print("error: --title-min/--desc-min must not exceed their max",
              file=sys.stderr, flush=True)
        return 2
    if args.external_concurrency < 1 or args.external_timeout < 1:
        print("error: --external-concurrency and --external-timeout must be >= 1",
              file=sys.stderr, flush=True)
        return 2

    # --- load + validate the snapshot -------------------------------
    try:
        snapshot = load_snapshot(args.snapshot_file,
                                 include_paths=args.include_path,
                                 exclude_paths=args.exclude_path)
    except SnapshotError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1

    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"✗ {exc}", file=sys.stderr, flush=True)
            return 1
        if baseline is None:
            status(f"No baseline at {args.baseline} yet — this run becomes one")

    snapshot_notes(snapshot, args.stale_after_days)

    selected = args.checks or DEFAULT_CHECKS
    if "all" in selected:
        planned = list(ALL_CHECK_NAMES)
    else:
        planned = [name for name in ALL_CHECK_NAMES if name in selected]

    options = Options(
        duplicates_mode=args.duplicates_mode,
        title_min=args.title_min, title_max=args.title_max,
        desc_min=args.desc_min, desc_max=args.desc_max,
        max_depth=args.max_depth_ok,
        flag_missing_canonical=args.flag_missing_canonical,
    )
    if "canonical" in planned and "duplicates" in planned:
        # canonical's duplicate cross-check runs only when the duplicates
        # check is also selected — otherwise it's skipped, not half-run.
        options.duplicate_groups = duplicates_check.duplicate_groups(
            snapshot.pages, args.duplicates_mode)

    findings = run_checks(snapshot, planned, options,
                          args.check_external_links, args)

    floor = SEVERITY_RANK[args.min_severity]
    hidden = sum(1 for f in findings if SEVERITY_RANK[f.severity] > floor)
    if hidden:
        findings = [f for f in findings if SEVERITY_RANK[f.severity] <= floor]
        status(f"{hidden} finding(s) below {args.min_severity} hidden by "
               f"--min-severity")

    findings = sort_findings(findings, ALL_CHECK_NAMES)
    diff = compare(findings, baseline, args.baseline) if baseline else None

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit({"type": "table",
          "columns": ["Check", "Severity", "Page", "Detail", "Fix"],
          "rows": [[f.check, f"{SEVERITY_ICON[f.severity]} {f.severity}",
                    f.page[:200], f.detail[:200], f.recommendation[:200]]
                   for f in findings[:MAX_EVENT_ROWS]]})

    report = build_markdown(snapshot, findings, diff=diff,
                            group_by=args.group_by)
    emit({"type": "markdown", "content": report})

    document = findings_document(snapshot, findings, {
        "checks": planned,
        "external_links": args.check_external_links,
        "duplicates_mode": args.duplicates_mode,
        "min_severity": args.min_severity,
        "include_paths": list(args.include_path),
        "exclude_paths": list(args.exclude_path),
    })
    html_report = (build_html(snapshot, findings, diff=diff)
                   if args.format in ("html", "both") else None)
    try:
        written = write_artifacts(artifact_dirs(args), document, findings,
                                  report, html_report)
    except OSError as exc:
        print(f"✗ cannot write artifacts: {exc}", file=sys.stderr, flush=True)
        return 1

    c = counts(findings)
    summary = (f"{len(findings)} finding(s): {c['fail']} fail · "
               f"{c['warn']} warn · {c['info']} info")
    if diff is not None:
        summary += (f" · {len(diff.new)} new, {len(diff.fixed)} fixed since "
                    f"the baseline")
    status(summary)
    names = "findings.json, findings.csv, report.md" + (
        ", report.html" if html_report is not None else "")
    print(f"Artifacts: {', '.join(written)} ({names})", flush=True)

    # Findings aren't failures — a check run that found problems is still a
    # successful run, unless the caller explicitly asked for a CI gate.
    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        tripped = [f for f in findings if SEVERITY_RANK[f.severity] <= threshold]
        if tripped:
            print(f"✗ {len(tripped)} finding(s) at or above '{args.fail_on}' "
                  f"(--fail-on)", file=sys.stderr, flush=True)
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
