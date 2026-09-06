# Load Test

A [PyShell](https://github.com/mono-ninja/PyShell) script that runs
**phased load against a site you own**, at a rate you set — the
collection's one deliberate exception to the passive philosophy, and
therefore the one script with a contract: **without the "I own this
target" confirmation the run refuses to start.**

Each phase holds a steady requests-per-second while the Results tab
redraws a **live chart** (per-second latency and throughput — the
uptime-monitor pattern), and the final report grades every phase
against the baseline: achieved rate, p50/p95/max latency, error rate,
and the **degradation thresholds** — p95 over 3× baseline or errors
over 5% are flagged.

The phases are WordPress-shaped (a port of the NinjaLoadTest idea)
but load-shaped, not attack-shaped:

- **Baseline** — homepage GETs; the reference.
- **Search** — `/?s=<random term>` — cache-busting, reaches the DB.
- **REST API** — `/wp-json/wp/v2/posts`.
- **Login page** — GET `wp-login.php` (sessions and nonces make it
  expensive). **Never submitted — no credentials are sent, ever.**
- **XML-RPC** — one minimal `system.listMethods` POST. No
  amplification payloads, no credential lists.
- **Custom** — your paths, round-robin.

No locust, no heavy framework: `requests` in a paced worker pool —
the target rate is a ceiling, the achieved rate is a measurement.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. Fill the target, tick **I own this target**, pick phases and the
   rate, press **Run** (⌘↩) — and watch the chart.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --url https://my-site.example --i-own-this-target
python3 main.py --url https://my-site.example --i-own-this-target \
    --phase baseline --phase search --phase rest
python3 main.py --url https://my-site.example --i-own-this-target \
    --rps 20 --duration 60 --phase baseline --phase custom \
    --custom-paths "/
/shop
/blog/hello-world"
```

## Result

- **Results tab** — the live latency/throughput chart while the run
  lasts; at the end, the per-phase table (requests · achieved/target
  RPS · p50 · p95 · errors) and the degradation report.
- **Artifacts** — `loadtest_results.json` (every request,
  machine-readable), `report.md`.

## Exit codes

- `0` — the plan ran. Degradation flags are findings, not failures.
- `1` — the target never answered the pre-flight GET, or it's already
  5xx-ing (loading a down site is not a test).
- `2` — bad arguments: **no ownership confirmation**, an impossible
  plan (over the 1500 s cap), unknown phases, the custom phase
  without paths.

## Layout

```
load-test/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # thin entry point: contract, plan, phases
├── requirements.txt     # requests
├── src/
│   ├── phases.py        # the phase presets (pure)
│   ├── engine.py        # paced worker pool, live results
│   └── report.py        # chart, table, degradation, artifacts
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
