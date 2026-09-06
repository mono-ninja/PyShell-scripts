# SRI Check

Whose code runs on your page, and is it pinned. CSP Audit reads the
policy; this reads the `<script>` and `<link rel=stylesheet>` tags
themselves — the **supply-chain view** of one page:

- **Third-party resources without integrity** — what the CDN serves
  is what runs on your page. Polyfill.io served malware to half a
  million sites in June 2024; none of them needed a new
  vulnerability — the delivery channel *was* the vulnerability.
- **Integrity without crossorigin** — a cross-origin hash is only
  checked in CORS mode; without the attribute the browser refuses
  the subresource entirely. A broken tag, not a soft warning.
- **The same-origin mistake** — integrity on your own files is
  redundant *and* blocks the resource the day a deploy rewrites it.
  SRI is for resources you don't control.
- **Hash verification** — every declared integrity hash is checked
  against the bytes served *right now*: match, mismatch (the file
  changed — deploy drift or tampering), or honestly unverified.
- **Ready-to-paste tags** — for each unpinned third-party resource
  a complete `integrity="sha384-…" crossorigin="anonymous"` line,
  computed from today's response.

One page fetch + one fetch per unique resource (skippable with
**Attributes only** for a one-request pass).

---

## Before running

1. Know the page you want to inspect (one URL — like Page SEO
   Audit, no crawling).
2. Press **Run** (⌘↩). **Prepare Env** installs `requests` once.

## Fields

### Target

- **Page URL** — the page whose script and stylesheet tags are
  inspected. Each unique resource is then fetched once to verify
  its declared hash or compute a new one.
- **Per-request timeout (s)** — per-fetch deadline, 3–60
  (default 15).

### Mode

- **Attributes only (no resource fetches)** — read the tags without
  downloading any resource: exactly one request in total, no hash
  verification and no ready-to-paste tags. Attribute-level findings
  (unpinned, missing crossorigin, invalid hashes) still work.

---

## Result

- **Results tab** — the resources table (resource · kind · side ·
  integrity · verdict) and the report:
  - **Host inventory** — every host behind the tags: your origin /
    same site, other origin / third-party, with pin coverage.
  - **Red — fix these** — unpinned third parties, integrity without
    crossorigin, invalid hashes, hash mismatches.
  - **Yellow — judgment calls** — same-origin integrity,
    `use-credentials` on a CDN.
  - **Ready-to-paste tags** — complete tags with today's sha384, and
    the pinning tradeoff said aloud: a pinned CDN file that changes
    breaks the page. Pin versioned URLs.
- **Artifacts** — `report.md`, `findings.json` (every resource with
  its attributes, findings, hash state, snippet).

The honesty line: a hash that matches means *matches right now* —
not "safe forever". And a hash pins the file as served at this
moment; when the CDN updates it, the page breaks by design.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | page unreachable / answered non-200 |
| 2 | bad arguments (not a full http(s) URL) |

## Related

- **CSP Audit** — the policy side of the same page: what the
  allowlist permits.
- **Tech Stack** — the full third-party inventory behind these
  hosts.
- **Page SEO Audit** — the rest of the page.
