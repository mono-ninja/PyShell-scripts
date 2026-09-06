# Cache Check

**Is caching actually working?** Several requests to one URL watch
`Age` grow and the HIT/MISS status flip; `Cache-Control` is decoded
into a TTL; a conditional request checks revalidation; the classic
cache-busters (`Set-Cookie`, `Vary: Cookie`, `private`, `no-store`)
are called out by name.

The perf line of the collection: **Server Timing** (why slow) ·
**Load Test** (how it degrades) · **this script** (is the cache doing
its job). No cache-status headers exposed — the report says so
instead of guessing, and falls back to the Age/TTL evidence.

---

## Before running

1. Enter the **URL** of the page or asset to watch.
2. **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the page or asset whose cache story you want. Redirects
  are followed; the report shows the final URL.

### Probe

- **Requests** — how many plain requests (2–10, default 3): enough to
  see MISS→HIT settle and Age grow.
- **Interval (s)** — pause between requests, so Age has time to grow
  (default 1).
- **Per-request timeout (s)** — 3–60, default 15.

---

## Result

- **Results tab** — the table (request # · status · Age · cache
  status · size · ms; the conditional request appears as row `cond`)
  and the report:
  - **Policy** — Cache-Control decoded: `never cached` / `stored,
    always revalidated` / `browser-only` / `cacheable, TTL Ns` /
    `no TTL directives`.
  - **Cache layer** — the HIT/MISS story, or the honest "no
    cache-status headers exposed — cannot see the cache layer from
    here" with the Age-growth fallback.
  - **Freshness** — TTL minus the observed Age: the seconds of
    freshness that remained at first request.
  - **Revalidation** — 304 on the conditional request means
    ETag/Last-Modified work; a full 200 means they don't.
  - **Cache-busters** — `Set-Cookie` (the classic WordPress
    "every visitor misses" cause), `Vary: Cookie`.
  - **What to do** — page-cache plugin rules, CDN rules, far-future
    `max-age` for static assets.
- **Artifacts** — `report.md`, `cache_results.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report describes the cache story |
| 1 | unreachable — connection failed |
| 2 | bad arguments: no http(s) URL, requests out of 2–10 |

## Related

- **Server Timing** — where the milliseconds go, phase by phase.
- **Load Test** — degradation under load; re-run Cache Check when it
  finds degradation.
- **SEO Checks** — the crawler pass that finds slow pages site-wide.
