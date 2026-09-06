# CORS Check

Is the CORS policy actually strict — a series of GET/OPTIONS
requests with a **spoofed Origin** watches for: reflection of the
attacker origin (critical with credentials), the accepted null
origin, wildcard-plus-credentials, prefix/suffix/substring matching
traps (`indexOf`/unanchored-regex bugs), the preflight echo, and the
missing `Vary: Origin` that cache poisoning feeds on.

The deep dive behind Security Headers' CORS line. No ownership gate:
a handful of ordinary requests with one custom header — the traffic
any browser produces; nothing is fuzzed, no payloads are sent.

---

## Before running

1. Enter the **URL** of the endpoint to probe.
2. **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the API endpoint or page. The confusable-origin traps
  are built from this host: `host.attacker.io`,
  `not-really-domain.com`, `domainattacker.io`.
- **Per-request timeout (s)** — 3–60, default 15.

---

## Result

- **Results tab** — the table (check · result · severity · detail)
  and the report:
  - **Baseline** — what the endpoint answers without an Origin at
    all (ACAO, credentials, Vary).
  - **reflection** — the attacker origin (`attacker.example`)
    reflected? With credentials → critical; plain → high.
  - **null origin** — `Origin: null` accepted (sandboxed iframes,
    `file://` pages in the trust boundary).
  - **wildcard(+credentials)** — `*` is fine for public data,
    wrong for anything per-user; `*` + credentials is the broken
    config signature.
  - **suffix / prefix / substring traps** — confusable origins
    built from the target's own host; an accepted trap means the
    whitelist matches by string, not by domain.
  - **preflight** — OPTIONS + `Access-Control-Request-Method`:
    `*` methods = the gate is open to every verb.
  - **vary** — a reflecting answer without `Vary: Origin` = a
    shared cache can pin one visitor's ACAO onto everyone's copy.
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

🔴 reflected + credentials · 🟠 misconfigured · 🟡 loose but
guarded · 🟢 strict. Severity per check is in the table; the report
ends with how a strict CORS setup answers (exact-origin whitelist,
credentials never with `*`, domain matching by parsed host).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | unreachable — connection failed |
| 2 | bad arguments: no http(s) URL |

## Related

- **Security Headers** — the header-presence grades (its CORS line
  is what this script deep-dives).
- **CSP Audit** — the same deep-dive shape for the
  Content-Security-Policy header.
- **Cache Check** — the Vary/origin side of cache behavior.
