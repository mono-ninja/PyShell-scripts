# HAR Analyze

**What is actually heavy on this page** — the DevTools `.har` read
offline, as a diagnosis (not a viewer). The perf line closed from
the browser side: Server Timing times one URL live, Cache Check
watches the cache layer, Load Test degrades under load — this reads
the recording the browser itself made. Stdlib `json`, **zero
network**.

- **Waterfall by phases** — dns / connect / ssl / send / wait
  (TTFB) / receive per request, aggregated: where the page's
  milliseconds went.
- **Render-blocking** — stylesheets by definition; the scripts the
  saved document loads without `async`/`defer`. Without the response
  content in the HAR the report says so honestly instead of
  guessing.
- **Third parties** — requests to other registrable domains with
  counts and bytes: the "whose weight is this" answer (subdomains
  of the page's domain are not third parties).
- **Size by type** — html / script / css / image / font / media /
  data buckets (bar chart event).
- **From cache** — memory/disk hits and 304 revalidations: the
  bytes that never left the origin.
- **Redirects** — every hop with its target.
- **The worst 10** — slowest requests with their phase breakdown.

## Using with PyShell

1. In DevTools → Network: load the page, right-click → *Save all as
   HAR with content* (the content unlocks the blocking analysis).
2. Pick the **HAR file**, press **Run** (⌘↩).

## Running standalone

```bash
python3 main.py --har-file page.har
python3 main.py --har-file page.har --max-entries 1000
```

## Result

- **Results tab** — the worst-10 table, the size-by-type chart, and
  the report: phases, weight by type, third parties, render-
  blocking, cache, redirects, the worst 10.
- **Artifacts** — `report.md`, `har_findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the diagnosis |
| 1 | not a HAR / not JSON / no entries |
| 2 | bad arguments (missing file) |

## Layout

```
har-analyze/
├── pyshell.yaml      # manifest
├── main.py           # HAR in · phases · blocking · third parties · report
├── docs/             # EN + UA docs
└── tests/            # 14 tests over synthetic HARs
```

## License

MIT — see the root [LICENSE](../LICENSE).
