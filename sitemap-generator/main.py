#!/usr/bin/env python3
"""sitemap-generator/main.py — build sitemap.xml from a Site Crawler snapshot.

Reads the ``site_snapshot.json`` written by ``site-crawler/`` and produces
a sitemap holding every URL that clears the bar a sitemap promises:
indexable, canonical, final, on this host, actually fetched and alive.
Every URL that doesn't clear it is reported with the reason — the
exclusion CSV is half the deliverable, because a sitemap you can't audit
is a sitemap you can't trust.

Reads the snapshot only: no network, no writes to the crawled site. The
one deliberate refusal: a **capped or partial** crawl is not good enough
evidence to build a deployable sitemap from (it would silently drop
every URL the crawl never reached), so the run exits 1 unless
``--allow-partial`` says otherwise. Same logic, same reason, when *zero*
URLs qualify — an empty sitemap deployed over a working one drops the
whole site.

Structured events are emitted on stderr so PyShell renders them natively;
from a terminal they degrade to plain JSON log lines. Exit codes:

* ``0`` — the sitemap was generated, however many URLs were excluded
  ("exclusions aren't failures" — they are the report);
* ``1`` — the snapshot doesn't parse, its ``schema`` version isn't
  understood, the crawl was capped/partial without ``--allow-partial``,
  nothing qualified for the sitemap, or the artifacts can't be written;
* ``2`` — bad arguments (argparse).
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from src.eligibility import Outcome, decide
from src.report import (
    Phase,
    artifact_dirs,
    build_chart_event,
    build_excluded_csv,
    build_markdown,
    build_table_event,
    emit,
    status,
    write_text_artifact,
)
from src.sitemap import write_sitemaps
from src.snapshot import SnapshotError, load_snapshot

STALE_AFTER_DAYS = 7


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sitemap Generator — build sitemap.xml from a Site "
                    "Crawler snapshot; every exclusion is shown with its reason")

    parser.add_argument("--snapshot-file", required=True,
                        help="site_snapshot.json produced by Site Crawler")
    parser.add_argument("--allow-partial", action="store_true",
                        help="Generate even from a capped/partial crawl. Off "
                             "by default: such a sitemap silently drops the "
                             "URLs the crawl never reached, and deploying it "
                             "over a working sitemap would remove them")
    parser.add_argument("--include-path", action="append", default=[],
                        metavar="GLOB",
                        help="only include URLs whose path matches this glob "
                             "(repeatable, e.g. '/blog/*')")
    parser.add_argument("--exclude-path", action="append", default=[],
                        metavar="GLOB",
                        help="skip URLs whose path matches this glob "
                             "(repeatable, e.g. '/tag/*')")
    parser.add_argument("--lastmod-mode", choices=["preserve", "crawl", "none"],
                        default="preserve",
                        help="<lastmod> source: 'preserve' keeps the previous "
                             "sitemap's value (schema 5+) falling back to "
                             "crawl time; 'crawl' uses crawl time; 'none' "
                             "omits lastmod (default preserve)")
    parser.add_argument("--no-hreflang", action="store_true",
                        help="Skip hreflang alternates (xhtml:link rows) — "
                             "emitted by default when the snapshot has them")
    parser.add_argument("--out-dir", default=None,
                        help="Where to write the artifacts (default: next to "
                             "the snapshot; always also written to PyShell's "
                             "run folder)")
    return parser


def snapshot_notes(snapshot, stale_after_days: int = STALE_AFTER_DAYS) -> None:
    """Age and coverage of the snapshot, said out loud before anything
    depends on it — the same discipline as seo-checks."""
    age_days = snapshot.snapshot_age()
    if age_days is None:
        status("Snapshot date unknown — the sitemap may be stale")
    elif age_days < 1:
        hours = max(1, round(age_days * 24))
        status(f"Snapshot crawled {hours}h ago")
    elif age_days >= stale_after_days:
        status(f"⚠ Snapshot is {round(age_days)} days old — the site may have "
               f"changed since; consider re-crawling")
    else:
        status(f"Snapshot crawled {round(age_days)} day(s) ago")


def partial_refusal(snapshot) -> str:
    """The exit-1 message for a capped/partial snapshot."""
    which = []
    if snapshot.capped:
        which.append(f"capped at {snapshot.pages_crawled} of "
                     f"{snapshot.pages_discovered} discovered pages")
    if snapshot.partial:
        which.append(f"stopped early ({snapshot.stopped_reason or 'reason not recorded'})")
    return ("✗ The crawl this snapshot came from was "
            + " and ".join(which).lower() +
            " — a sitemap built from it would silently drop every URL the "
            "crawl never reached, and deploying that file over a working "
            "sitemap would remove them. Re-crawl without the cap, or pass "
            "--allow-partial when you understand the gap.")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is generated", flush=True)
        return 0

    # --- load + validate the snapshot -------------------------------
    emit({"type": "progress", "pct": 0, "message": "Reading snapshot"})
    try:
        snapshot = load_snapshot(args.snapshot_file,
                                 include_paths=args.include_path,
                                 exclude_paths=args.exclude_path)
    except SnapshotError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1

    snapshot_notes(snapshot)

    partial_allowed = False
    if snapshot.capped or snapshot.partial:
        if not args.allow_partial:
            print(partial_refusal(snapshot), file=sys.stderr, flush=True)
            return 1
        partial_allowed = True
        status("⚠ Generating from a capped/partial crawl (--allow-partial) — "
               "the sitemap covers only what the crawl reached")

    # --- decide every URL --------------------------------------------
    emit({"type": "progress", "pct": 10, "message": "Deciding URLs"})
    phase = Phase("Deciding URLs", 10, 30)
    total_records = len(snapshot.pages)
    outcome = decide(snapshot,
                     lastmod_mode=args.lastmod_mode,
                     hreflang=not args.no_hreflang,
                     on_progress=lambda done: phase.update(done, total_records))
    emit({"type": "progress", "pct": 30,
          "message": f"{len(outcome.included)} of {outcome.total} URL(s) qualify"})

    dirs = artifact_dirs(args.out_dir, args.snapshot_file)

    # --- the empty case: report, but no deployable file --------------
    written = None
    if not outcome.included:
        print("✗ Nothing qualifies for the sitemap — every URL was excluded "
              "(see the report for the reasons). No sitemap.xml was written: "
              "deploying an empty one over a working sitemap would drop the "
              "whole site.", file=sys.stderr, flush=True)
        empty = True
    else:
        empty = False
        emit({"type": "progress", "pct": 35, "message": "Writing sitemap XML"})
        try:
            written = write_sitemaps(
                outcome.included, dirs, snapshot.site_origin,
                generated_at=datetime.now(timezone.utc))
        except OSError as exc:
            print(f"✗ cannot write the sitemap: {exc}", file=sys.stderr, flush=True)
            return 1
        emit({"type": "progress", "pct": 70,
              "message": f"Sitemap written ({len(written.files)} file(s))"})

    # --- report + audit trail ----------------------------------------
    emit({"type": "progress", "pct": 75, "message": "Writing report"})
    try:
        report = build_markdown(
            snapshot, outcome, written,
            partial_allowed=partial_allowed,
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            sitemap_url=f"{snapshot.site_origin}/sitemap.xml" if not empty else "",
            files_note=_files_note(written, dirs))
        write_text_artifact(dirs, "sitemap_excluded.csv",
                            build_excluded_csv(outcome))
        write_text_artifact(dirs, "report.md", report)
    except OSError as exc:
        print(f"✗ cannot write artifacts: {exc}", file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(outcome))
    chart = build_chart_event(outcome)
    if chart:
        emit(chart)
    emit({"type": "markdown", "content": report})

    if empty:
        return 1

    parts = f" in {written.parts + 1} file(s)" if written.indexed else ""
    status(f"Sitemap: {len(outcome.included)} URL(s){parts}, "
           f"{len(outcome.excluded)} excluded with reasons")
    print(f"Artifacts: {', '.join(written.files)}, sitemap_excluded.csv, "
          f"report.md", flush=True)
    return 0


def _files_note(written, dirs: list[str]) -> str:
    """The 'Files written' block for the report — names plus locations."""
    names = list(written.files) + ["sitemap_excluded.csv", "report.md"] \
        if written else ["sitemap_excluded.csv", "report.md"]
    lines = [f"- `{name}`" for name in names]
    lines.append("")
    lines.append(f"Written to: {' and '.join(f'`{d}`' for d in dirs)}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
