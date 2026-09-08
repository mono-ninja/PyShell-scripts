# CSP Audit

**How strong the Content-Security-Policy really is** — the whole
dive behind Security Headers' one-line CSP grade, in the Google CSP
Evaluator shape:

- **unsafe-inline / unsafe-eval** — in script-src directly or via
  default-src inheritance, with the nonce nuance: alongside a
  nonce/hash, modern browsers ignore `unsafe-inline` in script-src —
  that pairing is reported as transitional, not as the hole it
  would otherwise be.
- **Wildcards and scheme sources** — `*`, `http:`, `https:`,
  `*.subdomain`, `data:` (an injected data: URL is script the
  policy blessed), `blob:`/`filesystem:` in script-src: the planet
  (or the subdomain's tenants, or anything the page builds at
  runtime) is inside.
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
  never reported, and what the report restricts while the enforced
  policy doesn't mention it at all. A page carrying *only* a
  Report-Only header gets its own verdict — a trial, not a defense.
- **Both deliveries** — the headers *and*
  `<meta http-equiv="Content-Security-Policy">` in the document
  head. A meta policy is analyzed like any other, with what that
  delivery costs named: it only covers what the parser reads after
  the tag, `frame-ancestors`/`report-uri`/`sandbox` are dropped
  there, and a meta *Report-Only* policy is ignored by browsers
  outright.
- **The policy as browsers read it** — several policies in one
  response (repeated headers or commas) are each enforced on their
  own, so only the holes *every* policy leaves open are reported;
  keyword sources match case-insensitively; a directive repeated
  inside one policy keeps its first occurrence, and the rest is
  flagged as dead text.

One fetch; every finding names the directive and the source.
Redirects are followed and the final response is the one audited. A
page with no policy at all gets a report too — the absence is a
result, not a failed run.

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
- **Artifacts** — `report.md`, `findings.json` (the parsed
  policies, the merged view, the raw `<meta>` policies, the
  Report-Only policy, and the requested vs. final URL).

### Verdicts

🔴 script-src wide open (unsafe-inline without nonce, unsafe-eval,
scheme wildcards, `data:` script) · 🔴 no CSP at all (no header and
no `<meta>` policy) · 🟠 holes to close (bypass hosts,
missing base-uri/frame-ancestors, subdomain wildcards) · 🟠
report-only — nothing is enforced (a Report-Only header and no
enforced policy) · 🟢 strict (nonce/hash or `strict-dynamic` in
script-src, no holes) · 🟡 present, plain (a policy with no holes
and no script-src strength — a plain host allowlist).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture — “no CSP at all” included |
| 1 | unreachable |
| 2 | bad arguments (no http(s) URL, or a timeout below 1s) |

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
