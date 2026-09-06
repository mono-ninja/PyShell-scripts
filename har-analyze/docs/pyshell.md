# HAR Analyze

What is actually heavy on this page — the DevTools `.har` read
**offline** with the stdlib, as a diagnosis: the waterfall by phases
(dns/connect/ssl/wait/receive, aggregated), render-blocking
resources (stylesheets by definition; scripts the saved document
loads without async/defer — honestly "cannot tell" when the content
wasn't saved), the third-party inventory by registrable domain with
bytes, size by type, what was served from cache (memory/disk/304),
redirect chains, and the worst 10 requests with their phase
breakdown.

The perf line closed from the browser side: Server Timing (one URL,
live) · Cache Check (the cache layer) · Load Test (degradation) ·
**this** (what the browser actually loaded).

---

## Before running

1. In DevTools → Network: load the page, then *Save all as HAR with
   content* — the response content is what unlocks the
   render-blocking analysis.
2. Pick the **HAR file**.
3. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **HAR file** — the export from DevTools (any browser; the format
  is the shared one).
- **Max entries** — safety cap (100–50000, default 5000); a bigger
  HAR is truncated with a note in the report.

---

## Result

- **Results tab** — the worst-10 table (url · ms · type · size ·
  ttfb · receive), the size-by-type bar chart, and the report:
  - **Where the milliseconds went** — every phase summed and
    averaged over the requests that have it.
  - **Weight by type** — the buckets with counts and shares.
  - **Third parties** — the share of the page that comes from other
    registrable domains, top 10 by bytes; subdomains of the page's
    domain don't count.
  - **Render-blocking** — stylesheets count; the synchronously
    loaded scripts named (from the saved document); without content
    — the honest note.
  - **Served from cache** — memory × / disk × / revalidated × with
    the bytes that never left the origin.
  - **Redirects** and **the worst 10**.
- **Artifacts** — `report.md`, `har_findings.json` (everything,
  machine-readable).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the diagnosis |
| 1 | not a HAR (no `log`), invalid JSON, or zero entries |
| 2 | bad arguments: missing file |

## Related

- **Server Timing** — the same phase math, live, for one URL.
- **Cache Check** — the cache layer this report counts hits from.
- **Tech Stack** — the third-party inventory from the technology
  side; this report shows its byte cost.
