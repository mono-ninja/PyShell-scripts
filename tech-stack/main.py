#!/usr/bin/env python3
"""Tech Stack — site stack fingerprinting for PyShell.

Insert a URL, get the stack: web server, language, CMS, JS framework, build
tool, UI kit, analytics, CDN, payments, fonts, tags — each with a version
(where one is knowable), the evidence that says so, and a stale/EOL/vulnerable
flag. Plus a full third-party inventory and an optional diff against a previous
``stack.json``. Nothing is changed on the target — Tech Stack only reads.

Phases share one 0–100 bar: fetch 0–45, detect 45–70, versions & third-party
70–90, advisories 90–100. Exit 0 on a successful scan — an EOL PHP is a
finding in the report, not a script failure.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback

from techstack.pyshell_io import emit, status, progress, log, Phase, finish_progress
from techstack.util import normalize_url, hostname_of, is_valid_hostname, registrable_domain
from techstack.fetch import SiteFetcher
from techstack.evidence import Evidence
from techstack.pages import select_pages
from techstack.signatures import (
    technologies as all_technologies, db_date,
    generated_db_date,
)
from techstack.detect import detect_technology, Detection
from techstack.graph import apply_graph, note_cdn_hidden_origin
from techstack.versions import pick_version, parse_public_file, VersionResult
from techstack.thirdparty import inventory as tp_inventory
from techstack.advisories import check as advisory_check, online_eol, db_date as adv_date
from techstack.report import (
    build_table_event, build_markdown, build_snapshot, build_chart_event,
    write_artifacts, build_diff,
)
from techstack.render import render_url

# Public files probed only with --probe-known-paths.
PROBE_PATHS = [
    "/readme.html", "/composer.json", "/CHANGELOG.txt",
]
PROBE_SLUG_MAP = {
    "/readme.html": ["wordpress"],
    "/CHANGELOG.txt": ["drupal"],
    "/composer.json": ["php"],
}


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Tech Stack — site stack fingerprinting")
    p.add_argument("--url", required=True, help="Target URL")
    p.add_argument("--pages", type=int, default=3, help="Pages to sample (1–10)")
    p.add_argument("--extra-urls", default="", help="Temp file: extra URLs, one per line")
    p.add_argument("--user-agent", default="", help="Custom User-Agent")
    p.add_argument("--category", action="append", default=[], help="Category filter (repeat)")
    p.add_argument("--min-confidence", type=int, default=50, help="Min confidence 0–100")
    p.add_argument("--versions", action="store_true", help="Detect versions")
    p.add_argument("--probe-known-paths", action="store_true", help="Probe public files")
    p.add_argument("--render", action="store_true", help="Render JS via Playwright")
    p.add_argument("--third-party", action="store_true", help="Build third-party inventory")
    p.add_argument("--advisories", action="store_true", help="Check EOL / vulnerabilities")
    p.add_argument("--online-eol", action="store_true", help="Online EOL via endoflife.date")
    p.add_argument("--baseline", default="", help="Previous stack.json for diff")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout (s)")
    p.add_argument("--delay", type=float, default=0.5, help="Delay between requests (s)")
    p.add_argument("--verbose", action="store_true", help="Verbose log")
    return p


def _read_extra_urls(path: str) -> list[str]:
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError:
        return []


def _merge_render_into(ev: Evidence, rendered) -> None:
    """Fold a RenderResult's network requests into the page evidence (in place)."""
    for url, kind in rendered.requests:
        host = hostname_of(url)
        if not host:
            continue
        if kind == "script" and url not in ev.scripts:
            ev.scripts.append(url)
        elif kind == "stylesheet" and url not in ev.stylesheets:
            ev.stylesheets.append(url)
        elif kind in ("image", "font") and url not in ev.images:
            ev.images.append(url)
        elif kind == "iframe" and url not in ev.iframes:
            ev.iframes.append(url)
        elif url not in ev.links:
            ev.links.append(url)


def main() -> None:
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        _build_parser()
        return

    parser = _build_parser()
    args = parser.parse_args()
    verbose = args.verbose

    url = normalize_url(args.url)
    hostname = hostname_of(url)
    if not hostname or not is_valid_hostname(hostname):
        status(f"Invalid URL or host: {args.url}")
        log(f"Invalid URL or host: {args.url}")
        sys.exit(1)

    target_domain = registrable_domain(hostname)
    extra_urls = _read_extra_urls(args.extra_urls)
    want_versions = args.versions
    want_thirdparty = args.third_party
    want_advisories = args.advisories

    status(f"Tech Stack → {url}")
    progress(0, "Start")

    fetcher = SiteFetcher(timeout=args.timeout, delay=args.delay, user_agent=args.user_agent)
    warnings: list[str] = []

    try:
        # ── Phase 1: fetch pages (0–45) ──────────────────────────────────────
        fetch_phase = Phase("Fetching pages", 0, 45)
        status("Fetching the homepage…")
        if verbose:
            log(f"[fetch] {url}")
        main_ev, main_warn = fetcher.fetch_evidence(url)
        warnings.extend(main_warn)
        if main_ev is None:
            status(f"Target unreachable: {url}")
            log(f"Failed to fetch {url}")
            sys.exit(1)

        evidences: list[Evidence] = [main_ev]
        page_urls = select_pages(url, main_ev, args.pages, extra_urls)

        # Collect js_global exprs once for rendering.
        render_exprs = []
        if args.render:
            for tech in all_technologies():
                for sig in tech.signals:
                    if sig.where == "js_global" and sig.expr and sig.expr not in render_exprs:
                        render_exprs.append(sig.expr)

        total_pages = 1 + len(page_urls)
        for i, purl in enumerate(page_urls, 1):
            fetch_phase.report(i, total_pages, purl)
            status(f"Page {i + 1}/{total_pages}: {purl}")
            if verbose:
                log(f"[fetch] {purl}")
            ev, ew = fetcher.fetch_evidence(purl)
            if ev is None:
                warnings.extend(ew)
                continue
            warnings.extend(ew)
            evidences.append(ev)

        # Render (optional, per page) and bundle-text snippet.
        if args.render:
            status("Rendering JS (Playwright)…")
            for ev in evidences:
                rurl = ev.final_url or ev.url
                if verbose:
                    log(f"[render] {rurl}")
                res = render_url(rurl, render_exprs, timeout=args.timeout)
                if res.error == "playwright-not-installed":
                    warnings.append("Playwright is not installed — rendering skipped. "
                                    "Uncomment `playwright` in requirements.txt "
                                    "and press Prepare Env.")
                    status("Rendering skipped (Playwright not installed)")
                    break
                elif res.error == "browsers-not-installed":
                    # Package present, browser never downloaded. One line, once —
                    # retrying per page would repeat it for every sampled page.
                    warnings.append("Playwright is present, but the browser is not "
                                    "downloaded — rendering skipped. Run once: "
                                    "`playwright install chromium` (~400 MB, "
                                    "a machine-wide shared cache).")
                    status("Rendering skipped (browser not downloaded)")
                    break
                elif res.error:
                    warnings.append(f"Rendering failed: {res.error}")
                else:
                    ev.js_globals.update(res.js_globals)
                    _merge_render_into(ev, res)
        rendered = args.render and any(ev.js_globals for ev in evidences)

        for ev in evidences:
            ev.bundle_text = fetcher.fetch_bundle_text(ev)

        fetch_phase.done()
        if verbose:
            log(f"[fetch] fetched {len(evidences)} pages")

        # ── Phase 2: detect (45–70) ──────────────────────────────────────────
        detect_phase = Phase("Signature detection", 45, 70)
        status(f"Detecting ({len(all_technologies())} signatures)…")
        cat_filter = set(args.category) if args.category else set()
        by_s = {t.slug: t for t in all_technologies()}

        detections: dict[str, Detection] = {}
        techs = list(all_technologies())
        for i, tech in enumerate(techs):
            if cat_filter and not (set(tech.categories) & cat_filter):
                continue
            d = detect_technology(tech, evidences, rendered)
            if d is not None:
                detections[tech.slug] = d
            if i % 25 == 0:
                detect_phase.report(i, len(techs), f"{len(detections)} found")
        detect_phase.done()

        # Implies / excludes, then threshold + category filter on the result.
        detections = apply_graph(detections, by_s)
        detections = {
            s: d for s, d in detections.items()
            if d.confidence >= args.min_confidence
            and (not cat_filter or (set(d.categories) & cat_filter))
        }
        # CDN hides origin — add "unknown (behind Cloudflare)" after the
        # threshold filter so the placeholder (confidence 0) is not dropped.
        detections = note_cdn_hidden_origin(detections, by_s)
        if verbose:
            log(f"[detect] {len(detections)} technologies after filtering")

        # ── Phase 3: versions & third-party (70–90) ──────────────────────────
        vt_phase = Phase("Versions & third parties", 70, 90)
        versions: dict[str, VersionResult] = {}
        if want_versions:
            status("Detecting versions…")
            for slug, d in detections.items():
                versions[slug] = pick_version(d.version_candidates)

            # Optional public-file probing.
            if args.probe_known_paths:
                status("Probing public files…")
                for path in PROBE_PATHS:
                    probe_url = url.rstrip("/") + path
                    if verbose:
                        log(f"[probe] {probe_url}")
                    resp = fetcher.probe_path(probe_url)
                    if resp is None or resp.status_code >= 400 or not resp.text:
                        continue
                    cand = parse_public_file(path, resp.text[:200_000])
                    if cand is None:
                        continue
                    for slug in PROBE_SLUG_MAP.get(path, []):
                        if slug in detections:
                            detections[slug].version_candidates.append(cand)
                            versions[slug] = pick_version(detections[slug].version_candidates)

        parties: list = []
        if want_thirdparty:
            status("Third-party inventory…")
            parties = tp_inventory(evidences, target_domain)
            if verbose:
                log(f"[thirdparty] {len(parties)} external domains")
        vt_phase.done()

        # ── Phase 4: advisories (90–100) ─────────────────────────────────────
        adv_phase = Phase("EOL/CVE lookups", 90, 100)
        advisories: dict = {}
        if want_advisories:
            status("Checking EOL / vulnerabilities…")
            for slug, d in detections.items():
                ver = versions.get(slug)
                adv = advisory_check(slug, ver.version if ver else None)
                if adv:
                    advisories[slug] = adv
            if args.online_eol and want_versions:
                for slug in list(detections):
                    if slug in advisories:
                        extra = online_eol(slug, fetcher)
                        if extra:
                            advisories[slug].detail += f" · {extra}"
        adv_phase.done()

        # ── Report ───────────────────────────────────────────────────────────
        status("Building the report…")
        sig_date = db_date()
        gen_date = generated_db_date()
        if gen_date:
            sig_date = f"{sig_date} (+generated {gen_date})"
        a_date = adv_date()
        markdown = build_markdown(
            url, detections, versions, advisories, parties,
            rendered=rendered, pages=len(evidences), sig_date=sig_date,
            adv_date=a_date, warnings=warnings,
        )
        snapshot = build_snapshot(
            url, detections, versions, advisories, parties,
            rendered=rendered, pages=len(evidences), sig_date=sig_date,
            # What this run measured — a later --baseline diff needs it to tell
            # "disappeared" from "never looked" (report.build_diff).
            scope={
                "categories": sorted(cat_filter),
                "third_party": want_thirdparty,
                "versions": want_versions,
                "advisories": want_advisories,
                "min_confidence": args.min_confidence,
            },
        )

        emit(build_table_event(detections, versions, advisories))
        chart = build_chart_event(parties)
        if chart:
            emit(chart)
        emit({"type": "markdown", "content": markdown})

        # ── Artifacts ────────────────────────────────────────────────────────
        output_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
        diff_md = None
        if args.baseline:
            try:
                with open(args.baseline, "r", encoding="utf-8") as fh:
                    baseline = json.load(fh)
                diff_md = build_diff(baseline, snapshot)
                if verbose:
                    log(f"[diff] baseline {args.baseline}")
            except (OSError, ValueError) as exc:
                warnings.append(f"Failed to read the baseline: {exc}")

        try:
            written = write_artifacts(
                output_dir, markdown, snapshot, detections, versions,
                advisories, parties, diff_md,
            )
            if verbose:
                for p in written:
                    log(f"[artifact] {p}")
        except Exception as exc:
            log(f"Warning: failed to write artifacts: {exc}")

        finish_progress()
        n_adv = len(advisories)
        status(f"Done — {len(detections)} technologies, {len(parties)} third parties, "
               f"{n_adv} EOL/vulnerable")
        log(f"Tech Stack: {url} — {len(detections)} tech, {len(parties)} third-party domains")
        sys.exit(0)

    except Exception as exc:
        emit({"type": "status", "message": f"Scan failed: {exc}"})
        if verbose:
            traceback.print_exc()
        sys.exit(2)
    finally:
        fetcher.close()


if __name__ == "__main__":
    main()
