# Uptime Monitor

A [PyShell](https://github.com/mono-ninja/PyShell) script that polls one
URL at a fixed interval for a fixed duration and watches it **live**: a
scrolling latency chart in the Results tab, redrawn on every check, a
status line with the running uptime, and a final report with
percentiles (p50/p95/max) and downtime intervals spelled out.

Real traffic — one GET per interval, for as long as you ask. Point it
at your own endpoints.

## What it does

- **Live chart** — the PyShell chart event is replaced wholesale on
  every check, each emission carrying the whole window: the Results tab
  redraws as a monitor, not a post-mortem.
- **Three-way classification** — up (2xx/3xx), HTTP error (4xx/5xx:
  reachable, the endpoint is failing), down (timeout/connection error:
  nothing answered). Uptime counts only the first; the report keeps all
  three separate.
- **User-perceived latency** — wall time of the whole request (DNS,
  connect, TLS, wait), not just time-to-first-byte.
- **Downtime intervals** — runs of consecutive failed checks, with
  offsets and counts (`12s – 27s (4 checks)`), plus recommendations
  pointing at [Server Timing](../server-timing) and
  [TLS Audit](../tls-audit) for the diagnosis.
- **Exact pacing** — a check's own time counts inside the interval, so
  5 s means 5 s, not 5 s + response time.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **URL** — press **Run** (⌘↩) and watch the chart grow.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --url https://example.com
python3 main.py --url https://example.com --duration 300 --interval 10
python3 main.py --url https://api.example.com/health --duration 60 --interval 2 --timeout 3
```

## Result

- **Results tab** — the live chart, then the summary table and the
  report with intervals.
- **Artifacts** — `uptime_samples.json` (every check), `report.md`.

## Exit codes

- `0` — the monitoring completed; downtime is a result, not a failure
  (an all-404 run is a successful monitoring of a broken endpoint).
- `1` — the target never answered anything: there was nothing to
  monitor.
- `2` — bad arguments.

## Layout

```
uptime-monitor/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: the monitoring loop, stats, report
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
