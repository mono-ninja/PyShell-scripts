"""Event plumbing, result assembly, and artifact writing.

Split follows the collection's convention: ``emit``/``status`` (the
PyShell structured-event channel — one JSON line per event on stderr)
plus the builders that turn an :class:`Outcome` into the three result
kinds (table, chart, markdown) and the on-disk artifacts
(``sitemap_excluded.csv``, ``report.md``). Sitemap XML files themselves
are written by :mod:`src.sitemap`; everything else lands here.

Artifacts go to **both** the durable directory (``--out-dir`` or the
snapshot's folder — so the files survive past the PyShell run folder)
and ``PYSHELL_OUTPUT_DIR`` (what the artifact cards read) — the same
dual-write ``site-crawler`` uses for its snapshot.
"""
from __future__ import annotations

import csv
import io
import json
import os
import sys
from urllib.parse import urlsplit

from src.eligibility import Outcome, REASON_ORDER
from src.snapshot import Snapshot
from src.sitemap import WrittenSitemaps

#: How many URLs the report spells out per exclusion reason before it
#: switches to "(+N more — full list in sitemap_excluded.csv)".
MAX_LISTED_PER_REASON = 10

#: Exclusion reason -> human label. Ordered by REASON_ORDER at render
#: time; the table and the chart share this ordering.
REASON_LABELS = {
    "filtered": "Filtered out (path glob)",
    "robots_blocked": "Blocked by robots.txt",
    "fetch_error": "Fetch error during crawl",
    "not_crawled": "Never fetched",
    "meta_refresh": "meta-refresh redirect",
    "broken": "Broken (4xx/5xx)",
    "redirect_status": "Redirect status, no chain",
    "non_html": "Not an HTML page",
    "noindex": "noindex",
    "non_canonical": "Non-canonical (canonicalizes elsewhere)",
    "canonical_offsite": "Canonical points off-site",
    "off_host": "Off-host URL",
    "duplicate": "Duplicate of a listed URL",
}

#: Reason -> plain-language explanation used in the report body. Sibling
#: of eligibility.REASON_EXPLANATIONS (which stays factual and stable for
#: the CSV); these are the operator-facing sentences.
REASON_EXPLANATION_TEXT = {
    "filtered": "outside the path filters given for this run",
    "robots_blocked": "robots.txt disallows it — a search engine cannot fetch what the sitemap advertises",
    "fetch_error": "the crawl itself recorded an error for it",
    "not_crawled": "discovered but never fetched — nothing vouches for it",
    "meta_refresh": "it redirects elsewhere via a meta tag",
    "broken": "it answered 4xx/5xx",
    "redirect_status": "it answered 3xx without a recorded chain — likely needs a re-crawl",
    "non_html": "it is not an HTML page",
    "noindex": "it asks not to be indexed",
    "non_canonical": "it canonicalizes to another URL on this site; that URL's own record is the one listed",
    "canonical_offsite": "its canonical points at another site",
    "off_host": "its final URL belongs to another host",
    "duplicate": "another record already lists the same URL",
}


def _group_excluded(outcome: Outcome) -> list[tuple[str, list]]:
    """Excluded decisions bucketed by reason, in REASON_ORDER — one pass."""
    buckets: dict[str, list] = {}
    for decision in outcome.excluded:
        buckets.setdefault(decision.reason, []).append(decision)
    return [(reason, buckets[reason])
            for reason in REASON_ORDER if reason in buckets]


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


class Phase:
    """Maps one stage of the run onto a slice of the single 0–100 bar.

    Usage: ``phase = Phase("Deciding URLs", 10, 30)`` then
    ``phase.update(done, total)`` — emits at most once per whole percent,
    so a 200-page snapshot emits a handful of events, not 200.
    """

    def __init__(self, name: str, lo: int, hi: int) -> None:
        self.name = name
        self.lo = lo
        self.hi = hi
        self._last_pct = None

    def update(self, done: int, total: int) -> None:
        if total <= 0:
            return
        frac = min(done / total, 1.0)
        pct = round(self.lo + frac * (self.hi - self.lo))
        if pct != self._last_pct:
            self._last_pct = pct
            emit({"type": "progress", "pct": pct,
                  "message": f"{self.name} ({done}/{total})"})


# ---------------------------------------------------------------------------
# Result kinds
# ---------------------------------------------------------------------------

def disposition_rows(outcome: Outcome) -> list[list[str]]:
    """[label, count, share] rows, included first, then reasons in order."""
    rows = []
    total = outcome.total or 1
    included_share = f"{100 * len(outcome.included) / total:.0f}%"
    rows.append(["Included", str(len(outcome.included)), included_share])
    for reason in REASON_ORDER:
        if reason in outcome.counts:
            count = outcome.counts[reason]
            rows.append([REASON_LABELS[reason], str(count),
                         f"{100 * count / total:.0f}%"])
    return rows


def build_table_event(outcome: Outcome) -> dict:
    return {
        "type": "table",
        "columns": ["Disposition", "URLs", "Share"],
        "rows": disposition_rows(outcome),
    }


def build_chart_event(outcome: Outcome) -> dict | None:
    """A bar chart of where every URL ended up — skipped when there is
    exactly one disposition (all included), where the chart would be a
    single bar stating the obvious."""
    rows = disposition_rows(outcome)
    if len(rows) < 2:
        return None
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": "URLs by disposition",
        "labels": [r[0] for r in rows],
        "series": [{"name": "URLs", "values": [int(r[1]) for r in rows]}],
    }


def _excluded_by_reason(outcome: Outcome) -> list[tuple[str, list]]:
    return _group_excluded(outcome)


def build_markdown(snapshot: Snapshot, outcome: Outcome,
                   written: WrittenSitemaps | None,
                   *, partial_allowed: bool = False,
                   generated_at: str = "",
                   sitemap_url: str = "",
                   files_note: str = "") -> str:
    """The report — identical content for the markdown event and report.md."""
    host = urlsplit(snapshot.site_origin).hostname or snapshot.site_origin
    lines: list[str] = []
    lines.append(f"# Sitemap report — {host}")
    lines.append("")
    if generated_at:
        lines.append(f"Generated {generated_at} from a snapshot crawled "
                     f"{snapshot.crawled_at.isoformat(timespec='seconds') if snapshot.crawled_at else 'at an unknown time'}.")
        lines.append("")

    total_in = len(outcome.included)
    total_out = len(outcome.excluded)
    if total_out:
        top = max(outcome.counts.items(), key=lambda kv: kv[1])[0]
        lines.append(f"**{total_in} URL(s)** in the sitemap · "
                     f"{total_out} excluded (largest group: "
                     f"{REASON_LABELS[top].lower()}, {outcome.counts[top]}).")
    else:
        lines.append(f"**{total_in} URL(s)** in the sitemap · nothing excluded.")
    lines.append("")

    # --- disposition table -------------------------------------------
    lines.append("| Disposition | URLs | Share |")
    lines.append("|---|---:|---:|")
    for label, count, share in disposition_rows(outcome):
        lines.append(f"| {label} | {count} | {share} |")
    lines.append("")

    # --- warnings ------------------------------------------------------
    warnings: list[str] = []
    if partial_allowed:
        reason = snapshot.stopped_reason or "no reason recorded"
        warnings.append(
            "**Partial crawl used** — the snapshot is marked capped/partial "
            f"({snapshot.pages_crawled} of {snapshot.pages_discovered} "
            f"discovered pages, {reason}). The sitemap only lists what the "
            "crawl reached: URLs the crawl never got to are missing, and "
            "deploying this file over a working sitemap would drop them.")
    if outcome.unfetched_canonicals:
        shown = ", ".join(outcome.unfetched_canonicals[:MAX_LISTED_PER_REASON])
        more = (f" (+{len(outcome.unfetched_canonicals) - MAX_LISTED_PER_REASON} more)"
                if len(outcome.unfetched_canonicals) > MAX_LISTED_PER_REASON else "")
        warnings.append(
            f"**{len(outcome.unfetched_canonicals)} canonical target(s) were "
            f"never crawled** ({shown}{more}) — pages canonicalize to URLs "
            "the crawler never fetched, so those targets are absent from "
            "this sitemap. Crawl again from a page that links them, or "
            "verify them by hand.")
    if snapshot.schema < 2:
        warnings.append(
            "**Schema-1 snapshot** — no response headers were recorded, so "
            "noindex detection reads the meta tag only and hreflang is "
            "unavailable. Re-crawl with a current Site Crawler for both.")
    elif snapshot.schema < 5:
        warnings.append(
            "**Pre-schema-5 snapshot** — the previous sitemap's lastmod is "
            "not recorded, so `preserve` mode falls back to crawl time for "
            "every URL.")
    if warnings:
        lines.extend(["## Warnings", ""])
        for warning in warnings:
            lines.append(f"- {warning}")
        lines.append("")

    # --- exclusions in detail ------------------------------------------
    grouped = _excluded_by_reason(outcome)
    if grouped:
        lines.extend(["## What was excluded, and why", ""])
        for reason, decisions in grouped:
            lines.append(f"**{REASON_LABELS[reason]}** — "
                         f"{REASON_EXPLANATION_TEXT.get(reason, reason)} "
                         f"({len(decisions)}):")
            for d in decisions[:MAX_LISTED_PER_REASON]:
                where = f" → {d.detail}" if d.detail else ""
                lines.append(f"- `{d.page.url}`{where}")
            if len(decisions) > MAX_LISTED_PER_REASON:
                lines.append(f"- (+{len(decisions) - MAX_LISTED_PER_REASON} more "
                             "— full list in `sitemap_excluded.csv`)")
            lines.append("")
        lines.append("Every exclusion, with its reason and target, is in "
                     "`sitemap_excluded.csv`.")
        lines.append("")

    # --- deployment -----------------------------------------------------
    if written is None:
        lines.extend([
            "## Deploying",
            "",
            "**No sitemap.xml was written** — nothing qualified. Read the "
            "exclusions above before anything else: an empty sitemap "
            "deployed over a working one would drop the whole site.",
            "",
        ])
        if files_note:
            lines.extend(["## Files written", "", files_note])
            lines.append("")
        return "\n".join(lines)

    lines.extend(["## Deploying", ""])
    if written.indexed:
        lines.append(f"Upload **all {written.parts + 1} files** — "
                     f"`sitemap.xml` (the index) plus "
                     f"`sitemap-1.xml` … `sitemap-{written.parts}.xml` — to "
                     f"the root of `{host}`.")
    else:
        lines.append(f"Upload `sitemap.xml` to the root of `{host}`.")
    if sitemap_url:
        lines.append("")
        lines.append("Then announce it in `robots.txt`:")
        lines.append("")
        lines.append("```")
        lines.append(f"Sitemap: {sitemap_url}")
        lines.append("```")
    lines.append("")
    lines.append("Submit the same URL in Google Search Console / Bing "
                 "Webmaster Tools once — the old `GET /ping?sitemap=` "
                 "endpoints are retired. `changefreq` and `priority` are "
                 "deliberately not written: search engines ignore them, and "
                 "leaving them out keeps the file honest.")
    lines.append("")

    if files_note:
        lines.extend(["## Files written", "", files_note])
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

def artifact_dirs(out_dir: str | None, snapshot_path: str) -> list[str]:
    """Where the artifacts go — durable location first, run folder second.

    Under PyShell, the run folder (``PYSHELL_OUTPUT_DIR``) is what the
    artifact cards read. The durable location is ``--out-dir`` if given,
    otherwise next to the snapshot, so a terminal run still leaves the
    sitemap somewhere that survives the run.
    """
    durable = out_dir or os.path.dirname(os.path.abspath(snapshot_path)) or "."
    dirs = [durable]
    psd = os.environ.get("PYSHELL_OUTPUT_DIR", "")
    if psd and os.path.abspath(psd) not in {os.path.abspath(d) for d in dirs}:
        dirs.append(psd)
    return dirs


def write_text_artifact(out_dirs: list[str], name: str, data: str) -> str:
    """Write ``name`` to every directory; returns the primary (first) path.

    ``newline=""`` because the CSV writer emits its own ``\\r\\n``;
    letting the platform translate those again produces ``\\r\\r\\n``
    on Windows.
    """
    primary = ""
    for out_dir in out_dirs:
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(data)
        primary = primary or path
    return primary


def build_excluded_csv(outcome: Outcome) -> str:
    """The audit trail: one row per excluded URL — what, why, where to."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["url", "reason", "detail"])
    for _, decisions in _group_excluded(outcome):
        for d in decisions:
            writer.writerow([d.page.url, d.reason, d.detail])
    return buf.getvalue()
