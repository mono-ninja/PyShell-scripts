#!/usr/bin/env python3
"""cwv-check/main.py — what real Chrome users experience.

Everything else in the collection's perf line is **laboratory**:
Server Timing times one URL from here, HAR Analyze reads the
browser's recording, Load Test degrades it, Cache Check watches
the cache.  The **field** — what actual Chrome visitors measured —
was nowhere.  This script reads it from the Chrome UX Report
(CrUX): the p75 of LCP, INP and CLS per form factor, the real
distribution of real visits.

The shape of the answer:

- **per form factor** — phone and desktop separately (the p75s
  differ by shape, and the mobile p75 is the ranking-relevant
  one);
- **URL with the origin fallback** — CrUX needs ~a few hundred
  visits per URL; thin pages have no record, and the honest
  fallback is the **origin** — reported as exactly what it is,
  never as page data;
- **the 25-week trend** — the history API as a chart: is this
  p75 improving or rotting;
- **the lab-vs-field headline** — the report ends where the plan
  pointed: the lab tools (Server Timing, HAR Analyze) say *what*
  is slow; this says *whether the field sees it*.  "Lab green,
  field red" means the lab missed the visitors' network or device
  — that divergence is the actionable conclusion.

The API key is free (150 requests/s — enable the Chrome UX Report
API in Google Cloud, create a key); without it the script exits
with instructions, never an imitated number.

Exit codes: 0 = ran, 1 = no key / no CrUX data for the origin,
2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

import requests

API_URL = ("https://chromeuxreport.googleapis.com/v1/records:"
           "{endpoint}?key={key}")
USER_AGENT = "PyShell-cwv-check/1 (+field CWV diagnostics)"

METRICS = ["largest_contentful_paint", "interaction_to_next_paint",
           "cumulative_layout_shift"]
SHORT = {"largest_contentful_paint": "LCP",
         "interaction_to_next_paint": "INP",
         "cumulative_layout_shift": "CLS"}
# the official assessment thresholds (good ≤ X, poor > Y)
THRESHOLDS = {
    "largest_contentful_paint": (2500, 4000, "ms"),
    "interaction_to_next_paint": (200, 500, "ms"),
    "cumulative_layout_shift": (0.10, 0.25, ""),
}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# -------------------------------------------------------------------- CrUX

def assess(metric: str, p75) -> str:
    """good | needs improvement | poor — the official bands."""
    good, poor, _unit = THRESHOLDS[metric]
    if p75 <= good:
        return "🟢 good"
    if p75 <= poor:
        return "🟠 needs improvement"
    return "🔴 poor"


def fmt(metric: str, p75) -> str:
    unit = THRESHOLDS[metric][2]
    if metric == "largest_contentful_paint":
        return f"{p75 / 1000:.2f} s"
    if metric == "cumulative_layout_shift":
        return f"{p75:.3f}"
    return f"{p75:.0f} ms"


def crux_query(session: requests.Session, key: str, endpoint: str,
               body: dict, timeout: int) -> dict:
    r = session.post(API_URL.format(endpoint=endpoint, key=key),
                     json=body, timeout=timeout,
                     headers={"User-Agent": USER_AGENT})
    if r.status_code == 404:
        raise LookupError("no CrUX record for this query")
    r.raise_for_status()
    return r.json()


def metric_p75(record: dict) -> dict:
    """{metric: p75-float} from a queryRecord response."""
    out = {}
    metrics = (record.get("record") or {}).get("metrics") or {}
    for name in METRICS:
        p75 = metrics.get(name, {}).get("percentiles", {}).get("p75")
        if p75 is None:
            continue
        try:
            out[name] = float(p75)
        except (TypeError, ValueError):
            continue
    return out


def history_series(response: dict) -> dict:
    """{metric: [p75 | None, …]} across the collection periods.

    queryHistoryRecord answers with **one** record whose metrics
    carry `percentilesTimeseries.p75s` — a value per collection
    period, `null` where the period had too little data.  The
    positions line up with `collectionPeriods`, so a gap is kept
    as a gap rather than closed up.
    """
    out = {}
    record = response.get("record")
    if not isinstance(record, dict):
        return out
    metrics = record.get("metrics") or {}
    for name in METRICS:
        p75s = (metrics.get(name) or {}).get(
            "percentilesTimeseries", {}).get("p75s")
        if not isinstance(p75s, list):
            continue
        values = []
        for p75 in p75s:
            try:
                values.append(None if p75 is None else float(p75))
            except (TypeError, ValueError):
                values.append(None)
        if any(v is not None for v in values):
            out[name] = values
    return out


def history_labels(response: dict) -> list[str]:
    """The collection periods' end dates — the chart's X axis."""
    record = response.get("record")
    if not isinstance(record, dict):
        return []
    out = []
    for period in record.get("collectionPeriods") or []:
        last = (period or {}).get("lastDate") or {}
        try:
            out.append(f"{int(last['year']):04d}-"
                       f"{int(last['month']):02d}-"
                       f"{int(last['day']):02d}")
        except (KeyError, TypeError, ValueError):
            return []
    return out


# -------------------------------------------------------------------- report

def build_table_event(results: dict) -> dict:
    rows = []
    for ff in ("PHONE", "DESKTOP"):
        for metric in METRICS:
            p75 = results.get(ff, {}).get(metric)
            rows.append([
                "phone" if ff == "PHONE" else "desktop",
                SHORT[metric],
                fmt(metric, p75) if p75 is not None else "—",
                assess(metric, p75)
                if p75 is not None else "no data",
            ])
    return {"type": "table",
            "columns": ["form factor", "metric", "p75",
                        "assessment"],
            "rows": rows}


def trend_window(series: dict) -> tuple[dict, int]:
    """The metrics we have, and the newest span they all cover.

    The window is the longest tail in which no metric has a gap
    (INP, added to CrUX later, is routinely null in the oldest
    periods) — a shorter honest span, never a filled-in point.
    The chart and the report's trend section share it, so the two
    always describe the same periods.
    """
    present = {m: v for m, v in series.items() if m in METRICS}
    if not present:
        return {}, 0
    window = 0
    for i in range(1, min(len(v) for v in present.values()) + 1):
        if any(v[-i] is None for v in present.values()):
            break
        window = i
    return present, window


def span_label(labels: list[str] | None, window: int) -> str:
    """"2026-06-14 → 2026-08-30", or the period count when the
    collection periods did not parse."""
    if labels and len(labels) >= window:
        return f"{labels[-window]} → {labels[-1]}"
    return f"the last {window} CrUX collection periods"


def build_chart_event(series: dict,
                      labels: list[str] | None = None) -> dict:
    """The p75 trend over the gapless window (see trend_window)."""
    present, window = trend_window(series)
    if not window:
        return {"type": "status", "message": "no history"}
    out_series = [{"name": SHORT[m], "values": present[m][-window:]}
                  for m in METRICS if m in present]
    out_labels = labels[-window:] if labels and len(labels) >= window \
        else [("now" if i == window - 1 else f"-{window - 1 - i}w")
              for i in range(window)]
    return {"type": "chart", "chart_type": "line",
            "title": f"p75 trend — last {window} CrUX collection "
                     "periods (origin, both form factors)",
            "labels": out_labels,
            "series": out_series}


def build_trend_section(series: dict,
                        labels: list[str] | None) -> list[str]:
    """The history as prose — report.md is read on its own, away
    from the Results tab where the chart lives.

    Two points are the minimum for a direction; below that the
    section is absent (the notes already say why), never a
    sentence about a trend that is one measurement.
    """
    present, window = trend_window(series)
    if window < 2:
        return []
    out = ["\n## The trend\n",
           f"{span_label(labels, window)} — the history record is "
           "**origin-level and form-factor-agnostic**, whatever "
           "level the numbers above are.\n"]
    for metric in METRICS:
        if metric not in present:
            continue
        values = present[metric][-window:]
        first, last = values[0], values[-1]
        pct = ((last - first) / first * 100) if first else 0.0
        if abs(pct) < 5:
            direction = "→ flat"
        elif pct < 0:
            direction = f"↘ improving {abs(pct):.0f}%"
        else:
            direction = f"↗ worsening {abs(pct):.0f}%"
        out.append(f"- **{SHORT[metric]}** {fmt(metric, first)} → "
                   f"{fmt(metric, last)} "
                   f"({assess(metric, last)}) — {direction}")
    return out


def build_markdown(url: str, level: str, results: dict,
                   notes: list[str], series: dict | None = None,
                   labels: list[str] | None = None) -> str:
    out = [f"# CWV Check — Report\n",
           f"URL: `{url}` · data level: **{level}** ("
           + ("page-specific" if level == "page"
              else "the whole ORIGIN — the page itself has no "
                   "record; these are site-wide numbers, said "
                   "as such") + ")\n",
           "The p75 of what real Chrome users measured — the "
           "field side of the perf line.\n"]
    for ff, label in (("PHONE", "phone"), ("DESKTOP", "desktop")):
        out.append(f"## {label}\n")
        data = results.get(ff, {})
        if not data:
            out.append("- no CrUX data for this form factor\n")
            continue
        for metric in METRICS:
            if metric in data:
                out.append(f"- **{SHORT[metric]}** p75 = "
                           f"{fmt(metric, data[metric])} — "
                           f"{assess(metric, data[metric])}")
        out.append("")
    for n in notes:
        out.append(f"- ℹ️ {n}")
    out.extend(build_trend_section(series or {}, labels))
    out.append("\n## The lab-vs-field headline\n")
    worst = ""
    for ff in ("PHONE", "DESKTOP"):
        for metric in METRICS:
            p75 = results.get(ff, {}).get(metric)
            if p75 is not None and "poor" in assess(metric, p75):
                worst += (f" {SHORT[metric]}({'phone' if ff == 'PHONE' else 'desktop'})"
                          f" {fmt(metric, p75)}")
    if worst:
        out.append(f"🔴 the field is red on:{worst}. If the lab "
                   "tools (Server Timing, HAR Analyze) show green, "
                   "the divergence is the finding: the lab missed "
                   "the visitors' network, device or real payload.")
    else:
        out.append("🟢 the field p75s sit in the good bands. If "
                   "the lab shows red here, the lab's synthetic "
                   "conditions are harsher than the field — trust "
                   "the field for ranking, the lab for diagnosing.")
    out.append("\n## Reading it\n")
    out.append("- p75 is the visitor at the 75th percentile — "
               "the ranking-relevant shape of the Core Web Vitals "
               "assessment.")
    out.append("- LCP ≤ 2.5 s, INP ≤ 200 ms, CLS ≤ 0.10 are the "
               "good bands; the table carries each metric's.")
    out.append("- Thin pages fall back to the origin record — "
               "the header of this report says which level the "
               "numbers are.")
    out.append("- The trend is always the ORIGIN's, across all "
               "form factors: it is the record stable enough to "
               "compare period to period.")
    out.append("\n## Related\n")
    out.append("- **Server Timing / HAR Analyze / Cache Check** — "
               "the lab side: what is slow and why.")
    out.append("- **Load Test** — degradation under load.")
    out.append("- **SEO Checks** — the whole-site pass.")
    return "\n".join(out)


def write_artifacts(url: str, level: str, results: dict,
                    series: dict, notes: list[str],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "url": url, "level": level,
        "form_factors": {ff: {SHORT[m]: v for m, v in
                              metrics.items()}
                         for ff, metrics in results.items()},
        "history": {SHORT[m]: v for m, v in series.items()},
        "notes": notes,
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
        description="CWV Check — the field Core Web Vitals from "
                    "CrUX: LCP/INP/CLS p75 per form factor, the "
                    "origin fallback, the 25-week trend")
    parser.add_argument("--url", required=True,
                        help="the page or origin to look up")
    parser.add_argument("--timeout", type=int, default=30,
                        help="per-request timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no queries are made",
              flush=True)
        return 0

    url = args.url.strip()
    if not re.match(r"^https?://", url):
        print("✗ the URL must start with http:// or https://",
              file=sys.stderr, flush=True)
        return 2
    key = os.environ.get("CRUX_API_KEY", "").strip()
    if not key:
        print("✗ CRUX_API_KEY is not set — the Chrome UX Report "
              "needs a free Google API key: console.cloud.google.com "
              "→ enable “Chrome UX Report API” → Credentials → "
              "Create API key. This script will not imitate field "
              "data without it.", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## No API key\n\nThe Chrome UX Report API needs a "
              "**free** Google API key (150 req/s): in Google "
              "Cloud Console enable the *Chrome UX Report API*, "
              "then create an API key and set `CRUX_API_KEY` "
              "(in PyShell: the API key field stores it in the "
              "Keychain). Without it this script exits rather "
              "than inventing numbers."})
        return 1

    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    session = requests.Session()
    notes: list[str] = []

    # page-level first; the origin fallback said aloud
    results: dict[str, dict] = {}
    level = "page"
    for ff in ("PHONE", "DESKTOP"):
        body = {"formFactor": ff, "metrics": METRICS,
                "pageUrl": url}
        try:
            record = crux_query(session, key, "queryRecord", body,
                                args.timeout)
            results[ff] = metric_p75(record)
        except LookupError:
            results[ff] = {}
        except requests.RequestException as exc:
            print(f"✗ CrUX query failed: {exc}", file=sys.stderr,
                  flush=True)
            return 1
    if not any(results.values()):
        level = "origin"
        for ff in ("PHONE", "DESKTOP"):
            body = {"formFactor": ff, "metrics": METRICS,
                    "origin": origin}
            try:
                record = crux_query(session, key, "queryRecord",
                                    body, args.timeout)
                results[ff] = metric_p75(record)
            except LookupError:
                results[ff] = {}
            except requests.RequestException as exc:
                print(f"✗ CrUX query failed: {exc}", file=sys.stderr,
                      flush=True)
                return 1
    if not any(results.values()):
        print(f"✗ no CrUX data for {url} nor {origin} — the "
              "origin has too few Chrome visits (or is too new); "
              "nothing to report", file=sys.stderr, flush=True)
        return 1
    if level == "origin":
        notes.append("the numbers below are ORIGIN-level: site-"
                     "wide, not this page's")
    else:
        # the fallback is all-or-nothing: page numbers for one form
        # factor are never mixed with origin numbers for the other
        for ff in ("PHONE", "DESKTOP"):
            if not results.get(ff):
                notes.append(
                    f"{ff.lower()}: no page-level record — too few "
                    "Chrome visits on this URL for this form "
                    "factor; run the site root to read the origin "
                    "numbers for it")
    emit({"type": "progress", "pct": 60,
          "message": f"{level} data"})

    # the 25-week trend (history, origin level — the stable record)
    series: dict = {}
    labels: list[str] = []
    try:
        hist = crux_query(session, key, "queryHistoryRecord",
                          {"origin": origin, "metrics": METRICS},
                          args.timeout)
        series = history_series(hist)
        labels = history_labels(hist)
        if not series:
            notes.append("the history record carries no p75 series "
                         "for these metrics — the trend chart is "
                         "absent, not guessed")
    except (LookupError, requests.RequestException):
        notes.append("no history record — the trend chart is "
                     "absent, not guessed")
    emit({"type": "progress", "pct": 100, "message": "Done"})

    report = build_markdown(url, level, results, notes,
                            series, labels)
    emit(build_table_event(results))
    chart = build_chart_event(series, labels)
    emit(chart)
    emit({"type": "markdown", "content": report})
    write_artifacts(url, level, results, series, notes, report)

    summary = (f"{level} level · "
               + " · ".join(f"{ff.lower()}: "
                            + ", ".join(
                                f"{SHORT[m]}={fmt(m, v)}"
                                for m, v in metrics.items())
                            for ff, metrics in results.items()
                            if metrics))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
