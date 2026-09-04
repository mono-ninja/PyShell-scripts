# Server Timing

A Python CLI utility that measures HTTP(S) server response time broken down
by phase (DNS → TCP → TLS → TTFB → full download), runs a series of requests
and reports **percentiles** instead of the average. Works as a regular CLI
(`python -m srvtime`) and as a [PyShell](https://github.com/mono-ninja/PyShell) script (form,
progress, tables, charts — see the `pyshell.yaml` manifest). It changes
nothing on the target, read-only.

Key differences from `curl -w`: series aggregation, separation of "pure
server time" from network overhead, parsing of the `Server-Timing` header,
machine-readable output for CI/cron.

## Requirements

- Python 3.11+ (the `pyshell.yaml` manifest constrains it to `>=3.11,<3.15`)
- stdlib only (`socket`, `ssl`, `http.client`) — zero dependencies.
  `requirements.txt` is empty; `pycurl` is an optional backend (v2), not in
  `requirements.txt`.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O) — the manifest is `pyshell.yaml`.
2. Press **Prepare Env** — nothing to install, standard library only.
3. Fill in the form and press **Run** (⌘↩): progress, the phase table and the
   chart stream into the Results tab; artifacts land in `PYSHELL_OUTPUT_DIR`.

Field-by-field documentation lives in
[`docs/pyshell.md`](docs/pyshell.md) — the same text is shown in PyShell's
**Docs** panel (⌘D).

## Running standalone

```bash
python main.py https://example.com/
python main.py https://example.com/ -n 50 --cache-bust --format json

# Multiple targets in a single run:
python main.py https://a.example/ https://b.example/ -n 30

# Artifacts (json/csv/prom) are written to PYSHELL_OUTPUT_DIR, fallback — current folder:
PYSHELL_OUTPUT_DIR=./out python main.py https://example.com/ --format prometheus
```

## CLI

```
srvtime URL [URL ...]
  -n, --count N          number of measurements (default 20)
  -w, --warmup K         warmup requests, not counted (default 3)
      --delay SEC        pause between requests (default 0.2)
      --cache-bust       append a random query parameter
      --reuse            keep-alive instead of a new connection
      --gzip             allow response compression (default Accept-Encoding: identity)
      --method GET|HEAD|POST
      --header 'K: V'    repeatable
      --headers-file FILE   same thing, one header per line
      --urls-file FILE   additional URLs, one per line
      --data FILE        request body from a file (no curl-style `@`)
      --timeout SEC      (default 10)
      --insecure         do not verify the TLS certificate
      --ipv4 / --ipv6    force a version (mutually exclusive)
      --format human|json|csv|prometheus
      --threshold-p95 MS exit code 1 if p95 is exceeded (for CI/cron)
```

`--headers-file` and `--urls-file` are not an alternative syntax for the
sake of it: the PyShell form has no "arbitrary list of strings" field type,
so a repeatable `--header` and positional `URL ...` cannot be expressed
there directly. Both flags accept the same content that would come via
repetition and merge with `--header`/positional `URL` into a single
structure inside the script.

## Example output (human)

```
https://example.com/  (n=20, cache-bust: on, keep-alive: off)

phase        p50      p95      max
dns          1.2ms    3.4ms    4.1ms
connect     11.8ms   14.2ms   19.0ms
tls         38.1ms   45.9ms   61.2ms
server     124.6ms  310.2ms  402.7ms   ← pure server time
transfer     8.9ms   12.1ms   15.3ms
total      184.6ms  372.8ms  480.3ms

Server-Timing:  db 42.1ms p95 · app 118.4ms p95
statuses: 200×20 · size: 48.2 KB
```

## Phases

| Phase | What it is |
|---|---|
| `dns` | name resolution (may be cached by the OS) |
| `connect` | TCP handshake |
| `tls` | TLS handshake (`—` for `http://`) |
| `server` | **pure server time** = `ttfb − (dns + connect + tls)` |
| `transfer` | body delivery = `total − ttfb` |
| `total` | from start to the last byte |

`--no-reuse` (default behavior): a new connection per request, so the phase
breakdown is meaningful for every measurement. `--reuse` measures
keep-alive — then DNS/TCP/TLS are zero from the second request on.

`Accept-Encoding: identity` by default; `--gzip` enables compression
explicitly — that is a different measurement dimension (compressed
`transfer` is not comparable with uncompressed).

## Output formats

- **human** (default) — phase table p50/p95/max, ANSI colors (disabled when
  not in a terminal, under `NO_COLOR`, or under PyShell).
- **json** — all percentiles, time in seconds, `server_timing` in
  milliseconds.
- **csv** — one summary row per URL; append-safe for accumulating a time
  series in cron (`>> srvtime.csv`).
- **prometheus** — text exposition for the `node_exporter` textfile
  collector.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | OK |
| `1` | `--threshold-p95` exceeded |
| `2` | all requests failed |
| `3` | argument error |

A single failed request does not abort the series: it lands in the report
as `error`, and the summary shows `success_rate`. Aborting happens only if
the first 3 requests all fail (a typical sign of a wrong URL or an
unreachable host).

## Request identification

`srvtime` sends `User-Agent: srvtime/<version>` — the target server can
recognize the series and tell it apart from a load test. The conservative
default `--count 20 --delay 0.2` and this header together reduce the risk
of the series being perceived as an attack.

## Cross-checking with `curl`

`srvtime` uses the stdlib TLS stack (CPython/OpenSSL), while `curl`
usually uses LibreSSL/GnuTLS, so absolute `tls` phase values may differ by
a few milliseconds. The `dns`/`connect`/`server`/`total` phases match
within noise. For a byte-for-byte cross-check use `--backend pycurl`
(planned for v2).

## Layout

```
main.py          # entry point, argparse; PyShell invokes this file
src/
├── probe.py     # single measurement: connection phases + Server-Timing parser
├── stats.py     # percentiles (nearest rank), series aggregation
├── output.py    # human/json/csv/prometheus + emit() for PyShell
└── errors.py
pyshell.yaml     # PyShell form manifest
docs/pyshell.md  # description for the Docs panel in PyShell
```

`main.py` imports the package absolutely (`from src import ...`) because it
lives in the project root — PyShell runs exactly `python main.py`.

## License

[MIT](../LICENSE), same as the repository.
