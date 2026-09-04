# Server Timing

Measures server response time with a series of requests and reports
percentiles instead of the mean. Changes nothing on the target — read-only.

## Before you run

- **Cache-bust** — adds `?_cb=<uuid>` and bypasses CDN/page cache straight to
  the application. Without it, cached delivery is measured — that is a
  different number.
- **Count / Delay** — the defaults of 20 requests with a 0.2s pause are chosen
  so the series does not look like an attack on targets with basic rate
  limiting.
- **Reuse** — measures keep-alive; with it DNS/TCP/TLS will be zero from the
  second request, and the phase breakdown becomes uninformative for the first
  three phases.

## Result

Phase table (p50/p95/max) and a chart in the Results tab; JSON/CSV/Prometheus —
in the artifacts tab, if the corresponding format is selected.

## How to read the results

Every request is split into phases; the table shows p50/p95/max/mean per
phase, in milliseconds.

| Phase | What it measures |
|---|---|
| `dns` | Resolving the hostname to an IP address. Usually near zero — the OS caches lookups, and the warmup requests warm that cache too. |
| `connect` | TCP handshake — one round trip to the server. Zero from the second request on with **Reuse** enabled. |
| `tls` | TLS handshake, HTTPS only — the row is absent for `http://`. |
| `server` | Application time: from "request sent" to "response headers received", minus `dns`/`connect`/`tls`. Includes roughly one network round trip (the request travelling there and the headers travelling back), so it is truly *pure* server time only on localhost. |
| `transfer` | Reading the response body after the headers. Grows with body size and drops with bandwidth; `--gzip` shrinks it, but that is deliberately a different measurement. |
| `total` | The whole request: `dns + connect + tls + server + transfer`. This is the number the user feels. |

What to look for:

- big `connect`/`tls` → the problem is the network distance, not the app;
- big `server` → the application (or its database/cache) is slow;
- big `transfer` → heavy payload or thin bandwidth, not a slow server.

### Percentiles

Every measured request (default 20; the 3 warmup requests are not counted)
feeds the statistics. Failed requests are excluded from the phases but counted
in `statuses` and the success rate.

- **p50** (median) — half of the requests were faster. The "typical" request.
- **p95** — 95% of requests were faster, the slowest 5% were slower. This is
  the tail: set thresholds and SLAs against p95, not p50. p90/p99 are
  available in the JSON output.
- **max** — the single worst request of the series.
- **mean** — shown dimmed on purpose: the average hides the tail, so trust the
  percentiles first.

Percentiles are nearest-rank without interpolation: p50 of two measurements is
the smaller value, not an invented midpoint. With fewer than 10 successful
requests the script warns that the percentiles are not representative.

### Server-Timing

If the server returns a `Server-Timing` header (W3C spec), its metrics are
printed on a separate line. That is the server's *own* internal timing — more
honest than the `server` phase, which always carries the network round trip.

## Optional pycurl backend

The default backend uses the stdlib (`socket`/`ssl`/`http.client`). For a
byte-for-byte comparison with `curl`, you can install `pycurl` manually:

```bash
pip install pycurl
```

`pycurl` is deliberately **not** included in `requirements.txt` — PyShell
installs every dependency from that file on each Prepare Env, and pycurl
requires the system libcurl library and may fail to build on some platforms.
The `--backend pycurl` flag will arrive in v2.
