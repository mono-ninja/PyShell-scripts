# Load Test

Phased load against **a site you own**, at a rate you set — with a
live latency/throughput chart and a degradation report against the
baseline. The collection's one deliberate exception to the passive
philosophy, and therefore the one script with a contract.

> **The ownership contract:** without the *I own this target*
> confirmation the run refuses to start. Loading a site you don't
> control is an attack, whatever the intent. Even on your own site,
> tell your host/CDN what you're doing — a real load test looks
> exactly like a small DDoS from the outside.

---

## Before running

1. **Target URL** — the site you're about to load. Only this host
   receives traffic.
2. Tick **I own this target or have permission to load-test it**.
3. Pick the phases, the rate and the duration, press **Run** (⌘↩).

A pre-flight GET checks the target answers (and isn't already
5xx-ing) before a single unit of load is generated.

## Fields

### Target

- **Target URL** — scheme + host.
- **I own this target** — the contract; the run refuses without it.

### Plan

- **Phases** — repeatable:
  - **Baseline** — homepage GETs; the reference every other phase is
    graded against. Include it when you want the thresholds.
  - **Search** — `/?s=<random term>` per request — defeats caching,
    reaches the database.
  - **REST API** — `/wp-json/wp/v2/posts`.
  - **Login page** — GET `wp-login.php`; never submitted, no
    credentials ever sent.
  - **XML-RPC** — one minimal `system.listMethods` POST per request;
    no amplification payloads.
  - **Custom paths** — your paths, round-robin (set them in the
    Custom paths field).
- **Custom paths** — one path per line, starting with `/`.

### Load

- **Target rate (req/s)** — 1–100, held steady by the pacer. The
  target rate is a ceiling: the achieved rate (reported per phase)
  can only undershoot — workers or the site can't keep up.
- **Phase duration (s)** — 5–300 per phase; the whole plan must fit
  1500 s (the manifest timeout has headroom).
- **Per-request timeout (s)** — a request slower than this counts as
  an error, not a latency.

---

## Result

- **Results tab** — the live chart while the run lasts (per-second
  average latency + requests per second; a 120-second rolling window
  on long runs), then the per-phase table and the degradation report:
  - **p95 over 3× the baseline p95** → flagged;
  - **error rate over 5%** → flagged;
  - no baseline phase in the plan → the numbers stand alone, no
    thresholds (said so, not hidden).
- **Artifacts** — `loadtest_results.json` (every request with its
  latency and status), `report.md`.

### Reading it honestly

- Achieved RPS below target = the site (or the workers) saturated —
  that saturation point is the finding.
- 429/503 answers are the site's protection shedding load — a
  *healthy* answer under a flood, visible in the error column.
- The before/after of a caching change is the whole point: measure
  with [Server Timing](../../server-timing) unloaded, load here, fix,
  repeat. What the load looks like from the site's side is
  [Log Attack Checker](../../log-attack-checker) territory.

## Exit codes

- `0` — the plan ran; degradation flags are findings.
- `1` — the target never answered, or is already 5xx-ing.
- `2` — bad arguments (no ownership confirmation, plan over the cap,
  unknown phases, custom without paths).
