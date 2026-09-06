# Takeover Check

Which of your subdomains can be hijacked — the CNAMEs pointing at
unclaimed cloud resources (S3, GitHub Pages, Heroku, Azure,
Shopify, Tumblr, Pantheon, GCS…), checked against a curated
fingerprint list: **NXDOMAIN on the target** (the strongest
dangling hint), the provider's **unclaimed-marker page** (one GET),
and the **closed-vs-open nuance** (Fastly, Vercel, Netlify,
WordPress.com closed the hole — their matches are reported as
exposed-but-not-claimable, never silently skipped).

**The passivity contract:** DNS + one GET per candidate, a marker
comparison — nothing else. Nothing is registered, nothing claimed;
the signs and the provider's docs are the output. The difference
between diagnosing a hole and exploiting it is the line this
script does not cross.

---

## Before running

1. Enter the **Domain** — candidates are collected from the crt.sh
   transparency feed (capped by **Max subdomains**); or point
   **Subdomains file** at an existing list (Subdomain Search
   output, a hosts file) — then only the ownership filter applies.
2. **Prepare Env** — installs `requests`, `dnspython`, `pyyaml`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **Domain (or subdomains file)** — the registrable domain for the
  feed collection.
- **Subdomains file (optional)** — one hostname per line; skips the
  feed. Foreign hosts are filtered by the domain.
- **Per-probe timeout (s)** — each DNS query and each GET.
- **Max subdomains** — cap on feed candidates (10–5000, default
  500).

---

## Result

- **Results tab** — the table (host · cname · service · verdict)
  and the report:
  - **🔴 dangling — target is NXDOMAIN** — the CNAME target does
    not resolve at all: the resource is gone; whoever recreates it
    owns your subdomain.
  - **🔴 marker matches — likely claimable** — the provider's
    unclaimed page answered on your subdomain.
  - **🟠 marker matches — service closed the hole** — the dangling
    shape is exposed, the takeover is not (domain verification).
  - **⚪ fingerprint target, no marker** — points at the service,
    but the resource exists and is served.
  - The fix list for the red ones: remove the CNAME or recreate
    the resource in your account; parked delegations are exactly
    what this report finds.
- **Artifacts** — `report.md`, `findings.json` (per-finding docs
  links to the provider's own domain pages).

### The aging data

The takeover flags reflect the providers' current verification
requirements and will age — when a service adds verification, the
flip is a YAML edit (`takeover_fingerprints.yaml`), not a code
change.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | feed unreachable, or no candidates found |
| 2 | bad arguments: not a domain, missing file |

## Related

- **Subdomain Search** — the passive inventory; feed its output
  into `--subdomains-file`.
- **CT Log Check** — the historical names: a cert for a gone
  subdomain often means a gone CNAME.
- **Port Check / FW Audit** — the exposure side of the same
  hygiene.
