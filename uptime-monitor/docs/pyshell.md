# Uptime Monitor

Polls one URL at a fixed interval for a fixed duration and watches it
**live**: a scrolling latency chart in the Results tab (redrawn on every
check), a status line with the running uptime, and a final report with
percentiles and the downtime intervals spelled out.

Every check is classified three ways — **up** (a 2xx/3xx answer), an
**HTTP error** (the server answered 4xx/5xx: reachable, but the endpoint
is failing), and **down** (timeout or connection error: nothing
answered). Uptime counts only the first; the report keeps all three
separate and honest.

Real traffic: this sends **one GET per interval** to the target, for as
long as you ask. Point it at your own endpoints.

---

## Before running

1. **URL** — the endpoint to watch, scheme included.
2. Click **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩) and watch the chart grow. The default run — 60 s
   at a 5 s interval — is 12 checks; the ceiling is ~28 minutes.

Latency is the **wall time of the whole request** — DNS, connect, TLS,
wait — the number a user experiences, not just time-to-first-byte.

## Fields

### Monitor

- **URL** — `https://…` (redirects are followed; the verdict is on the
  final endpoint).
- **Duration (s)** — how long to keep watching, 10–1700.
- **Interval (s)** — seconds between checks; the chart updates once per
  check. A check's own time counts inside the interval, so the pace
  stays exact.
- **Per-check timeout (s)** — a check slower than this counts as down:
  a timeout is a verdict, not a latency spike.

---

## Result

- **Results tab** — the live chart while the run lasts; at the end, the
  summary table (checks, up / HTTP errors / down, uptime, p50 / p95 /
  max latency, interval count) and the report. Not-up intervals are
  spelled out (`12s – 27s (4 checks)`); the recommendations point at
  [Server Timing](../../server-timing) for slow-answer diagnosis and
  [TLS Audit](../../tls-audit) when the answers fail.
- **Artifacts** — `uptime_samples.json` (every check, machine-readable:
  offset, classification, status, latency), `report.md`.

### Reading the chart

A down check draws as **0** — a chart needs a number, and a gap would
read as "no data". The truth lives in the table, the intervals and the
samples file; the chart is the trend.

## Exit codes

- `0` — the monitoring completed. Downtime is a result, not a failure —
  even 100% of it, as long as the target answered at least once (an
  all-404 run is a successful monitoring of a broken endpoint).
- `1` — the target never answered anything (DNS, refused, timeout from
  the first check to the last): there was nothing to monitor.
- `2` — bad arguments (no scheme/host, interval longer than duration).
