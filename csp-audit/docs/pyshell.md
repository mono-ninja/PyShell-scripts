# CSP Audit

How strong the Content-Security-Policy really is — the deep dive
behind Security Headers' presence line: **unsafe-inline/unsafe-eval**
in script-src (directly or inherited from default-src) with the
nonce nuance (alongside a nonce, modern browsers ignore
unsafe-inline — reported as transitional), **wildcards and scheme
sources** (`*`, `http:`/`https:`, `*.sub`, `data:`), **bypass
hosts** — the allowlist entries that can serve attacker-controlled
or arbitrary script (unpkg, jsdelivr,
raw.githubusercontent, the JSONP family, public buckets) from a
curated YAML with reasons — the missing **foundations**
(base-uri, object-src, frame-ancestors cross-checked against
X-Frame-Options, form-action, upgrade-insecure-requests),
**strict-dynamic**, and the **Report-Only twin** diffed against the
enforced policy.

Both deliveries are read: the **headers** and the
`<meta http-equiv="Content-Security-Policy">` in the document head —
a page whose only policy lives in a meta tag is audited like any
other, with the costs of that delivery named.

One fetch; every finding names the directive and the source. When
the URL redirects, the final response is the one audited — its
address is what the report names. A page with no policy at all still
gets a report (verdict 🔴 no CSP at all), not just an error line.

---

## Before running

1. Enter the **URL** of the page whose CSP to dissect.
2. **Prepare Env** — installs `requests` and `pyyaml`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the page. Both headers are read from the same response:
  the enforced `Content-Security-Policy` and the
  `Content-Security-Policy-Report-Only` twin, when present. A
  response may carry several policies (repeated headers, or one
  header with commas) — each is enforced on its own, so a hole is
  only reported when *every* policy leaves it open. A `<meta>`
  policy counts as one of them; a `<meta>` **Report-Only** policy
  does not (browsers ignore that one).
- **Per-request timeout (s)** — 3–60, default 15.

---

## Result

- **Results tab** — the table (severity · check · detail) and the
  report:
  - **unsafe-inline / unsafe-eval / unsafe-hashes / wildcard /
    scheme-source / bypass-host / base-uri / object-src /
    frame-ancestors / form-action / upgrade-insecure-requests /
    strict-dynamic / nonce / duplicate-directive /
    multiple-policies / meta-policy / meta-ignored-directive /
    meta-report-only / no-csp** — every check with its reason and the
    directive it belongs to; inheritance from default-src is named
    (`default-src→script-src`). Keyword sources are matched
    case-insensitively (`'NONE'` is `'none'`), and a directive
    repeated inside one policy is reported as dead text — browsers
    keep the first occurrence.
  - **Report-Only twin** — the diff, in three shapes: sources
    tolerated under Report-Only but blocked enforced (the
    "reporting what you already prevent" or "eyeing a loosening"
    shape), directives enforced but absent from the report, and
    directives the report restricts while the enforced policy
    doesn't mention them at all (a restriction still in trial).
  - **Report-Only only** — a page with no enforced policy is
    called out as exactly that: the findings then describe the
    trial policy, and nothing on the page is blocked.
  - **Delivered by `<meta>`** — a meta policy only covers what the
    parser reads *after* the tag, and `frame-ancestors`,
    `report-uri` and `sandbox` are dropped there; both facts are
    findings, and a dropped `frame-ancestors` still leaves the
    clickjacking warning standing.
  - **No policy at all** — the report says so, names what is left
    (X-Frame-Options, if any) and points at Security Headers, which
    grades the absence.
  - **The shape to aim for** — nonce + strict-dynamic, the
    one-liner foundations, Report-Only as a trial state, never a
    resting one.
- **Artifacts** — `report.md`, `findings.json` (the parsed
  policies, the merged view, the raw `<meta>` policies, the
  Report-Only policy, the requested and final URL, plus
  `present: false` when there is no policy at all and
  `enforced: false` when only a Report-Only header was found —
  machine-readable).

### Verdicts

🔴 script-src wide open · 🔴 no CSP at all (no header and no
`<meta>` policy) · 🟠 holes to close · 🟠 report-only — nothing is
enforced (only a Report-Only header) · 🟢 strict (a nonce/hash or
`strict-dynamic` in script-src and no holes; a plain host allowlist
without them stays 🟡) · 🟡 present, plain.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture — including “this page has no CSP” |
| 1 | unreachable |
| 2 | bad arguments: no http(s) URL, or a timeout below 1s |

## Related

- **Security Headers** — the presence grades; this script is the
  deep dive behind its CSP line.
- **CORS Check** — the other deep-dive sibling (the Access-Control
  family).
- **Web Conf Audit** — the config side: where the add_header lives.
