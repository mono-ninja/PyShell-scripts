# CORS Check

**Is the CORS policy actually strict?** Security Headers grades CORS
by presence; this is the deep dive — a short series of GET/OPTIONS
requests with a **spoofed Origin**, ported from the NinjaChek CORS
security lab's matrix:

1. **Reflection** — an unrelated attacker origin echoed back in
   `Access-Control-Allow-Origin`; with credentials it's the critical
   shape (any site reads authenticated responses).
2. **The null origin** — `Origin: null` accepted means sandboxed
   iframes and `file://` pages are inside the trust boundary.
3. **Wildcard + credentials** — `*` with
   `Allow-Credentials: true`: browsers ignore the combo, but it's
   the signature of a config one refactor away from reflection.
4. **Prefix/suffix/substring traps** — the `indexOf`/unanchored-
   regex bugs: `api.example.com.attacker.io` and
   `not-really-example.com` accepted against a whitelist that meant
   `example.com`.
5. **Preflight** — OPTIONS with a request method: does the echo
   allow `*`?
6. **Vary: Origin** — a per-origin answer without it is cache-
   poisoning food.

No ownership gate (unlike Load Test / Port Check): these are a
handful of ordinary requests with one custom header — the traffic
any browser produces. Nothing is fuzzed, no payloads are sent.

## Using with PyShell

1. Enter the **URL** to probe (an API endpoint or page).
2. Press **Prepare Env** (installs `requests`), then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --url https://api.example.com/v1/data
```

## Result

- **Results tab** — a table (check · result · severity · detail) and
  the report with the baseline (what the endpoint says unprompted),
  every probe's outcome, and how a strict setup answers.
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

🔴 reflected + credentials · 🟠 misconfigured (plain reflection,
wildcard+credentials, trap accepted) · 🟡 loose but guarded
(wildcard on public data, preflight echo) · 🟢 strict.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | unreachable |
| 2 | bad arguments (no http(s) URL) |

## Layout

```
cors-check/
├── pyshell.yaml      # manifest
├── main.py           # probe series · verdicts · report
├── requirements.txt  # requests
├── docs/             # EN + UA docs
└── tests/            # 13 tests against a local CORS lab
```

## License

MIT — see the root [LICENSE](../LICENSE).
