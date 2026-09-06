# CSP Audit

**How strong the Content-Security-Policy really is** — the whole
dive behind Security Headers' one-line CSP grade, in the Google CSP
Evaluator shape:

- **unsafe-inline / unsafe-eval** — in script-src directly or via
  default-src inheritance, with the nonce nuance: alongside a
  nonce/hash, modern browsers ignore `unsafe-inline` in script-src —
  that pairing is reported as transitional, not as the hole it
  would otherwise be.
- **Wildcards** — `*`, `http:`, `https:`, `*.subdomain` in
  script-src: the planet (or the subdomain's tenants) is inside.
- **Bypass hosts** — the allowlist entries that can serve
  attacker-controlled or arbitrary script: unpkg, jsdelivr,
  raw.githubusercontent, the JSONP family, public buckets — a
  curated YAML (`bypass_hosts.yaml`), each entry with its reason.
- **Foundational directives** — `base-uri` (missing = injected
  `<base>` hijacks every relative URL), `object-src`, 
  `frame-ancestors` (cross-checked against X-Frame-Options from the
  same response), `form-action`, `upgrade-insecure-requests`.
- **strict-dynamic** — recognized and praised.
- **Report-Only twin** — the same fetch's
  `Content-Security-Policy-Report-Only` diffed against the enforced
  policy: what is reported but tolerated, what is enforced but
  never reported.

One fetch; every finding names the directive and the source.

## Using with PyShell

1. Enter the **URL** of the page.
2. Press **Prepare Env** (installs `requests` + `pyyaml`), then
   **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --url https://example.com/
```

## Result

- **Results tab** — a table (severity · check · detail) and the
  report: every finding with its reason, the Report-Only diff, and
  the shape to aim for (`script-src 'nonce-…' 'strict-dynamic'`,
  the one-liner foundations).
- **Artifacts** — `report.md`, `findings.json` (the parsed policy
  included).

### Verdicts

🔴 script-src wide open (unsafe-inline without nonce, unsafe-eval,
scheme wildcards) · 🟠 holes to close (bypass hosts, missing
base-uri/frame-ancestors, subdomain wildcards) · 🟢 strict · 🟡
present, plain.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | unreachable, or no CSP header at all |
| 2 | bad arguments (no http(s) URL) |

## Layout

```
csp-audit/
├── pyshell.yaml        # manifest
├── main.py             # parse · analyze · diff · report
├── bypass_hosts.yaml   # the curated bypass list (YAML data)
├── requirements.txt    # requests, pyyaml
├── docs/               # EN + UA docs
└── tests/              # 20 tests: pure analysis + a local CSP server
```

## License

MIT — see the root [LICENSE](../LICENSE).
