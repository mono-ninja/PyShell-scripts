#!/usr/bin/env python3
"""wayback-check/main.py — a site's history through the Internet Archive.

Asks the free, keyless [archive.org CDX
API](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
what it knows about a site and turns the answer into three things:

- **The timeline** — first and last capture, and a per-year bar chart of
  capture activity (months with captures; on very active sites the
  monthly collapse saturates at 12/year — a documented proxy, not a
  raw count).
- **The vanished pages** (opt-in) — URLs the archive recorded as 200
  that answer 404 on the live site today: the redirect-map candidates
  an SEO migration needs. Real GETs to the target, oldest-last-seen
  first, capped.
- **The raw history** — `wayback_history.json`, machine-readable.

The CDX server is polite-but-slow: every request gets a generous
timeout and up to three attempts with backoff on 503/timeout. Scope
defaults to **one host** (the SEO-sensible unit); the domain-wide scope
that includes subdomains is opt-in because wildcard-heavy domains can
flood or rate-limit the query.

Exit codes: 0 = the check ran (vanished pages are findings, an empty
archive is an honest finding too), 1 = the CDX server couldn't be
reached at all (there was nothing to report), 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit, urlunsplit

import requests

USER_AGENT = "PyShell-wayback-check/1.0"
CDX_URL = "https://web.archive.org/cdx/search/cdx"
CDX_ATTEMPTS = 3        # 503s and timeouts are routine on CDX
CDX_BACKOFF_S = 8
TIMELINE_ROW_CAP = 5000  # hard cap for the year scan (domain scope can flood)


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
# Target parsing (pure)
# ---------------------------------------------------------------------------

def parse_target(raw: str) -> tuple[str, str] | None:
    """(host, error) — extracts the host from a bare domain or a full
    URL. None-error means usable."""
    raw = (raw or "").strip()
    if not raw:
        return "", "the target is empty"
    candidate = raw if "://" in raw else "http://" + raw
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return "", f"{raw!r} is not a parsable domain or URL"
    host = (parts.hostname or "").lower()
    if not host or "." not in host:
        return "", (f"{raw!r} needs a domain with a dot "
                    f"(example.com or https://example.com/page)")
    if not all(c.isascii() and (c.isalnum() or c == "-" or c == ".")
               for c in host):
        return "", f"{host!r} has characters a hostname can't have"
    return host, ""


def cdx_query_url(host: str, scope: str) -> str:
    """What we hand the CDX server: `host/*` for one host (the default —
    subdomains flood the answer), or `host` + matchType=domain for the
    whole domain."""
    return f"{host}/*" if scope == "site" else host


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class History:
    host: str
    scope: str
    first_capture: str = ""      # YYYYMMDDhhmmss
    last_capture: str = ""       # YYYYMMDDhhmmss
    last_capture_url: str = ""
    months_per_year: dict[str, int] = field(default_factory=dict)
    timeline_truncated: bool = False  # hit the row cap (domain scope)


@dataclass
class VanishedCandidate:
    url: str            # as recorded by the archive
    live_url: str       # what was actually fetched
    first_seen: str     # YYYYMMDD
    live_status: int | None = None
    live_error: str = ""

    @property
    def verdict(self) -> str:
        if self.live_error:
            return "unreachable"
        if self.live_status in (404, 410):
            return "vanished"
        if self.live_status is not None and self.live_status < 400:
            return "still there"
        return "other"


# ---------------------------------------------------------------------------
# CDX helpers (pure parsing + one I/O function)
# ---------------------------------------------------------------------------

def parse_cdx_rows(payload) -> list[list[str]]:
    """CDX output=json answers with a header row + data rows. Returns
    the data rows only; anything unparseable becomes []."""
    try:
        rows = json.loads(payload) if isinstance(payload, str) else payload
    except (ValueError, TypeError):
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []
    return [r for r in rows[1:] if isinstance(r, list) and r]


def year_of(timestamp: str) -> str:
    return timestamp[:4] if len(timestamp) >= 4 else ""


def month_key(timestamp: str) -> str:
    """YYYYMM — the monthly collapse key."""
    return timestamp[:6] if len(timestamp) >= 6 else timestamp


def format_ts(timestamp: str) -> str:
    """20020120142510 → 2002-01-20 (date-only; CDX precision is honest)."""
    if len(timestamp) >= 8:
        return f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
    return timestamp


def build_history(host: str, scope: str, timeline_rows: list[list[str]],
                  latest_rows: list[list[str]]) -> History:
    """History from the two CDX answers. timeline_rows are monthly-
    collapsed timestamps (one row per month with captures)."""
    hist = History(host=host, scope=scope)
    stamps = [r[0] for r in timeline_rows if r and r[0]]
    if stamps:
        hist.first_capture = stamps[0]
        months: dict[str, int] = {}
        for ts in stamps:
            y = year_of(ts)
            if y:
                months[y] = months.get(y, 0) + 1
        hist.months_per_year = dict(sorted(months.items()))
        # The timeline is collapsed per month and keeps the FIRST capture
        # of each month — the last row is the first capture of the last
        # active month. The latest query gives the true last capture.
    if latest_rows and latest_rows[0]:
        hist.last_capture = latest_rows[0][0]
        hist.last_capture_url = (latest_rows[0][1]
                                 if len(latest_rows[0]) > 1 else "")
    elif stamps:
        hist.last_capture = stamps[-1]
    if not hist.first_capture and stamps:
        hist.first_capture = stamps[0]
    return hist


def normalize_live_url(recorded: str) -> str:
    """`http://example.com:80/a` → `http://example.com/a`. Schemeless
    records (old crawls) get https — falling back is the caller's job."""
    recorded = recorded.strip()
    if "://" not in recorded:
        recorded = "https://" + recorded
    parts = urlsplit(recorded)
    netloc = parts.netloc
    if ":" in netloc:
        host, _, port = netloc.rpartition(":")
        if (parts.scheme == "http" and port == "80") or \
           (parts.scheme == "https" and port == "443"):
            netloc = host
    return urlunsplit((parts.scheme, netloc, parts.path or "/",
                       parts.query, ""))


def same_host(url: str, host: str) -> bool:
    try:
        return (urlsplit(url).hostname or "").lower() == host
    except ValueError:
        return False


def pick_vanished_candidates(rows: list[list[str]], host: str,
                             limit: int) -> list[VanishedCandidate]:
    """From urlkey-collapsed first-seen rows: keep this host's URLs,
    prefer the oldest first-seen (vanished longest), cap at limit."""
    seen: dict[str, str] = {}  # url -> first_seen
    for row in rows:
        if len(row) < 2 or not row[0] or not row[1]:
            continue
        url, ts = normalize_live_url(row[1]), row[0]
        if not same_host(url, host):
            continue
        if url not in seen or ts < seen[url]:
            seen[url] = ts
    ordered = sorted(seen.items(), key=lambda kv: kv[1])
    return [VanishedCandidate(url=url, live_url=url, first_seen=ts[:8])
            for url, ts in ordered[:limit]]


# ---------------------------------------------------------------------------
# CDX I/O
# ---------------------------------------------------------------------------

def cdx_get(session: requests.Session, params: dict, timeout: int
            ) -> list[list[str]]:
    """One CDX query with retries. Raises requests.RequestException when
    the server won't answer at all — the caller decides what that means."""
    last_exc: Exception | None = None
    for attempt in range(1, CDX_ATTEMPTS + 1):
        try:
            resp = session.get(CDX_URL, params=params, timeout=timeout)
            if resp.status_code == 503:
                last_exc = requests.HTTPError("503 Service Unavailable")
            else:
                resp.raise_for_status()
                return parse_cdx_rows(resp.text)
        except requests.RequestException as exc:
            last_exc = exc
        if attempt < CDX_ATTEMPTS:
            status(f"CDX not answering (attempt {attempt}/{CDX_ATTEMPTS}, "
                   f"{type(last_exc).__name__}) — backing off")
            time.sleep(CDX_BACKOFF_S)
    raise last_exc or requests.RequestException("CDX unreachable")


def fetch_history(session, host: str, scope: str, timeout: int) -> History:
    """Two queries: the monthly-collapsed timeline, and the single latest
    capture (limit=-1 returns the last record)."""
    base = {"url": cdx_query_url(host, scope), "output": "json"}
    if scope == "domain":
        base["matchType"] = "domain"
    timeline = cdx_get(session, {**base, "fl": "timestamp",
                                 "collapse": "timestamp:6",
                                 "limit": TIMELINE_ROW_CAP}, timeout)
    truncated = len(timeline) >= TIMELINE_ROW_CAP
    latest = cdx_get(session, {**base, "fl": "timestamp,original",
                               "limit": -1}, timeout)
    hist = build_history(host, scope, timeline, latest)
    hist.timeline_truncated = truncated
    return hist


def fetch_candidates(session, host: str, scope: str, timeout: int,
                     limit: int) -> list[VanishedCandidate]:
    """urlkey-collapsed first-seen 200-URLs of this host."""
    params = {"url": cdx_query_url(host, scope), "output": "json",
              "fl": "timestamp,original", "filter": "statuscode:200",
              "collapse": "urlkey", "limit": 2000}
    if scope == "domain":
        params["matchType"] = "domain"
    rows = cdx_get(session, params, timeout)
    return pick_vanished_candidates(rows, host, limit)


def check_live(session, url: str, timeout: int) -> tuple[int | None, str]:
    """One GET against the live site; https first, http fallback for
    old schemeless records. (code, error) — never raises."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        return resp.status_code, ""
    except requests.RequestException:
        if url.startswith("https://"):
            try:
                resp = session.get("http://" + url[len("https://"):],
                                   timeout=timeout, allow_redirects=True)
                return resp.status_code, ""
            except requests.RequestException as exc:
                return None, type(exc).__name__
        return None, "ConnectionError"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_chart_event(hist: History) -> dict:
    years = sorted(hist.months_per_year)
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": f"Capture months per year — {hist.host}",
        "labels": years,
        "series": [{"name": "months with captures",
                    "values": [hist.months_per_year[y] for y in years]}],
    }


def build_report(hist: History, candidates: list[VanishedCandidate] | None,
                 check_enabled: bool) -> str:
    lines = []
    if hist.first_capture:
        lines.append(f"## 📜 {hist.host} — archived since "
                     f"{format_ts(hist.first_capture)}")
    else:
        lines.append(f"## ⚪ {hist.host} — no captures in the archive")
    lines += ["", f"- Scope: {'this host' if hist.scope == 'site' else 'whole domain incl. subdomains'}"]
    if hist.first_capture:
        span = int(year_of(hist.last_capture)) - int(year_of(hist.first_capture))
        lines.append(f"- First capture: **{format_ts(hist.first_capture)}** · "
                     f"last: **{format_ts(hist.last_capture)}** "
                     f"(≈{span} year span)")
        active = len(hist.months_per_year)
        lines.append(f"- Years with captures: **{len(hist.months_per_year)}** · "
                     f"months with captures: "
                     f"{sum(hist.months_per_year.values())}")
    if hist.timeline_truncated:
        lines.append(f"- ⚠️ the year scan hit the {TIMELINE_ROW_CAP:,}-row cap "
                     "(a very wildcard-heavy domain) — the chart is a "
                     "truncated sample, not the full history")
    lines.append("")

    if candidates is None:
        lines.append("_Vanished-pages check: off. Turn it on to test archived "
                     "URLs against the live site and get redirect-map "
                     "candidates._")
        lines.append("")
        lines.append("_The chart counts months with captures (a monthly "
                     "collapse over the CDX data) — an activity proxy that "
                     "saturates at 12/year on heavily archived sites._")
        lines.append("")
        return "\n".join(lines)

    vanished = [c for c in candidates if c.verdict == "vanished"]
    alive = [c for c in candidates if c.verdict == "still there"]
    unreachable = [c for c in candidates if c.verdict == "unreachable"]
    other = [c for c in candidates if c.verdict == "other"]

    head = f"### 🔗 {len(vanished)} vanished page(s) of {len(candidates)} checked"
    lines += [head, ""]
    if candidates:
        lines += ["| Archived URL | First seen | Live status | Verdict |",
                  "| --- | --- | --- | --- |"]
        for c in candidates:
            icon = {"vanished": "🔴", "still there": "🟢",
                    "unreachable": "⚫", "other": "🟡"}[c.verdict]
            live = str(c.live_status) if c.live_status is not None else c.live_error
            lines.append(f"| `{c.url}` | {format_ts(c.first_seen)} | "
                         f"{live} | {icon} {c.verdict} |")
        lines.append("")
    if vanished:
        lines += ["**The redirect map**", "",
                  "Each vanished URL once carried traffic or links; a 301 to "
                  "the closest living page recovers what's left. The full "
                  "list is in `wayback_vanished.csv` — feed it to your "
                  "redirect rules, then re-crawl with "
                  "[Site Crawler](../site-crawler) and verify with "
                  "[SEO Checks](../seo-checks).", ""]
    if not candidates and check_enabled:
        lines.append("_No archived 200-URLs on this host to test._")
        lines.append("")
    if unreachable:
        lines.append(f"_⚠️ {len(unreachable)} URL(s) couldn't be tested — "
                     "the live site didn't answer them (connection-level). "
                     "Check the host before trusting the vanished count._")
        lines.append("")
    lines.append(f"_{len(candidates)} GET(s) against the live site, "
                 "redirects followed; the archive answered "
                 "everything it had._")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(hist: History,
                    candidates: list[VanishedCandidate] | None) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "wayback_history.json"), "w",
              encoding="utf-8") as fh:
        json.dump(asdict(hist), fh, indent=2, ensure_ascii=False)
    if candidates is not None:
        with open(os.path.join(out_dir, "wayback_vanished.csv"), "w",
                  newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["url", "first_seen", "live_status",
                             "verdict"])
            for c in candidates:
                writer.writerow([c.url, format_ts(c.first_seen),
                                 c.live_status if c.live_status is not None
                                 else c.live_error, c.verdict])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Wayback Check — a site's history through the "
                    "archive.org CDX API")
    parser.add_argument("--target", required=True,
                        help="domain or URL (example.com, "
                             "https://example.com/page)")
    parser.add_argument("--scope", choices=["site", "domain"],
                        default="site",
                        help="one host (default) or the whole domain "
                             "including subdomains")
    parser.add_argument("--check-vanished", action="store_true",
                        help="test archived URLs against the live site "
                             "(real GETs)")
    parser.add_argument("--vanished-limit", type=int, default=20,
                        help="how many archived URLs to live-check "
                             "(default 20, max 50)")
    parser.add_argument("--timeout", type=int, default=45,
                        help="per-request timeout in seconds (default 45)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no CDX queries, no live checks",
              flush=True)
        return 0

    host, problem = parse_target(args.target)
    if problem:
        print(f"✗ {problem}", file=sys.stderr, flush=True)
        return 2
    if not (1 <= args.vanished_limit <= 50):
        print("✗ --vanished-limit must be 1–50", file=sys.stderr,
              flush=True)
        return 2

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    # Phase 1 — the archive's memory of this host.
    status(f"Asking the CDX API about {host} "
           f"({'host scope' if args.scope == 'site' else 'domain scope'})")
    emit({"type": "progress", "pct": 5,
          "message": "Querying archive.org CDX"})
    try:
        hist = fetch_history(session, host, args.scope, args.timeout)
    except requests.RequestException as exc:
        print(f"✗ the CDX server couldn't be reached ({exc}) — try again "
              f"later; web.archive.org is often busy", file=sys.stderr,
              flush=True)
        emit({"type": "markdown", "content":
              f"## Check failed\n\n❌ The archive.org CDX server didn't "
              f"answer ({type(exc).__name__}) after "
              f"{CDX_ATTEMPTS} attempts. This is routine load on their "
              f"side — re-run in a few minutes."})
        return 1

    if not hist.first_capture:
        log(f"  ⚪ no captures found for {host}")
        report = build_report(hist, None, False)
        emit({"type": "progress", "pct": 100, "message": "Done"})
        emit({"type": "markdown", "content": report})
        write_artifacts(hist, None)
        status(f"{host}: nothing in the archive")
        # An empty archive is a finding (site too new, never archived,
        # or archived under a different host) — the run succeeded.
        return 0

    log(f"  first capture {format_ts(hist.first_capture)} · "
        f"last {format_ts(hist.last_capture)} · "
        f"{len(hist.months_per_year)} year(s) with captures")
    emit({"type": "progress", "pct": 45, "message": "History fetched"})
    emit(build_chart_event(hist))

    # Phase 2 — the vanished pages (opt-in, real GETs).
    candidates: list[VanishedCandidate] | None = None
    if args.check_vanished:
        status(f"Fetching archived URLs of {host} for the vanished check")
        emit({"type": "progress", "pct": 55,
              "message": "Fetching vanished candidates"})
        try:
            candidates = fetch_candidates(session, host, args.scope,
                                          args.timeout, args.vanished_limit)
        except requests.RequestException as exc:
            log(f"  ⚠️ candidate query failed ({type(exc).__name__}) — "
                "skipping the vanished check")
            candidates = None
        if candidates is not None:
            log(f"  testing {len(candidates)} archived URL(s) against the "
                f"live site")
            for i, cand in enumerate(candidates, 1):
                cand.live_status, cand.live_error = check_live(
                    session, cand.live_url, args.timeout)
                icon = {"vanished": "🔴", "still there": "🟢",
                        "unreachable": "⚫", "other": "🟡"}[cand.verdict]
                log(f"  {icon} {cand.live_status or cand.live_error:>3} "
                    f"{cand.url}")
                emit({"type": "progress",
                      "pct": 55 + int(40 * i / len(candidates)),
                      "message": f"{i}/{len(candidates)} · {cand.verdict}"})

    report = build_report(hist, candidates, args.check_vanished)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit({"type": "markdown", "content": report})
    write_artifacts(hist, candidates)

    vanished_n = (sum(1 for c in candidates if c.verdict == "vanished")
                  if candidates is not None else None)
    summary = (f"{host}: archived since {format_ts(hist.first_capture)}"
               + (f", {vanished_n} vanished page(s)" if vanished_n
                  else ""))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
