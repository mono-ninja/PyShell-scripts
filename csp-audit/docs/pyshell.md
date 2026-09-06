# CSP Audit

How strong the Content-Security-Policy really is — the deep dive
behind Security Headers' presence line: **unsafe-inline/unsafe-eval**
in script-src (directly or inherited from default-src) with the
nonce nuance (alongside a nonce, modern browsers ignore
unsafe-inline — reported as transitional), **wildcards** (`*`,
schemes, `*.sub`), **bypass hosts** — the allowlist entries that can
serve attacker-controlled or arbitrary script (unpkg, jsdelivr,
raw.githubusercontent, the JSONP family, public buckets) from a
curated YAML with reasons — the missing **foundations**
(base-uri, object-src, frame-ancestors cross-checked against
X-Frame-Options, form-action, upgrade-insecure-requests),
**strict-dynamic**, and the **Report-Only twin** diffed against the
enforced policy.

One fetch; every finding names the directive and the source.

---

## Before running

1. Enter the **URL** of the page whose CSP to dissect.
2. **Prepare Env** — installs `requests` and `pyyaml`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the page. Both headers are read from the same response:
  the enforced `Content-Security-Policy` and the
  `Content-Security-Policy-Report-Only` twin, when present.
- **Per-request timeout (s)** — 3–60, default 15.

---

## Result

- **Results tab** — the table (severity · check · detail) and the
  report:
  - **unsafe-inline / unsafe-eval / wildcard / bypass-host /
    base-uri / object-src / frame-ancestors / form-action /
    upgrade-insecure-requests / strict-dynamic / nonce** — every
    check with its reason and the directive it belongs to;
    inheritance from default-src is named (`default-src→script-src`).
  - **Report-Only twin** — the diff: sources tolerated under
    Report-Only but blocked enforced (the "reporting what you
    already prevent" or "eyeing a loosening" shape), and sources
    enforced but absent from the report.
  - **The shape to aim for** — nonce + strict-dynamic, the
    one-liner foundations, Report-Only as a trial state, never a
    resting one.
- **Artifacts** — `report.md`, `findings.json` (the parsed policy
  included, machine-readable).

### Verdicts

🔴 script-src wide open · 🟠 holes to close · 🟢 strict · 🟡 present,
plain. When the page carries no CSP at all: exit 1 with the pointer
to Security Headers (which grades the absence).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | unreachable, or no CSP header at all |
| 2 | bad arguments: no http(s) URL |

## Related

- **Security Headers** — the presence grades; this script is the
  deep dive behind its CSP line.
- **CORS Check** — the other deep-dive sibling (the Access-Control
  family).
- **Web Conf Audit** — the config side: where the add_header lives.
