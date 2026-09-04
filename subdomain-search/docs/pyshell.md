# Subdomain Search

Enumerates a domain's subdomains from passive OSINT sources — **crt.sh**
(certificate transparency, the broadest), **HackerTarget** (host search),
**RapidDNS** (passive DNS) and **Shodan** (DNS domain lookup, API key) —
then confirms every candidate with parallel forward-DNS resolution. The
inverse of [IP → Domains](../../ip-domains): that one asks "who else
lives on this IP", this one asks "what lives under this domain".

Each subdomain in the result carries the source(s) that named it — one
API echoing another's data is common, and *who saw this* is part of the
result.

**Wildcard-aware.** A domain with a `*.example.com` record resolves
*anything* — a naive resolver fan-out would report every candidate as
alive. Before verification, two random probes are resolved; when they
answer, their IPs mark the wildcard, and candidates resolving *only* to
those IPs are reported as `wildcard` — visible, not silent, and never
counted as finds.

---

## Before running

1. **Domain** — the registrable domain: `example.com`, no scheme, no
   `www.` (subdomains are what gets searched, so give the parent).
2. Click **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩).

The OSINT queries are passive (they ask the sources, not the target);
the verification phase sends ordinary DNS lookups for each candidate —
the same queries any visitor's resolver would make.

---

## Fields

### Target

- **Domain** — the registrable domain to enumerate. Validated as a DNS
  name; IP literals, schemes and paths are refused with an explanation.

### Sources

- **Sources** — any subset, re-run as often as you like:
  - *crt.sh (certificate transparency)* — every hostname ever issued a
    certificate under the domain. The broadest source, also the
    slowest (up to ~30 s on a busy domain) and the one most likely to
    name subdomains that no longer exist.
  - *HackerTarget (host search)* — forward-DNS derived; free tier is
    rate-limited, so it sometimes returns nothing on a busy day.
  - *RapidDNS (passive DNS)* — passive records seen in the wild.
  - *Shodan (DNS domain lookup)* — needs the API key below.
- **Shodan API Key** — required only when Shodan is selected; stored in
  the Keychain, never on the command line. Without it, Shodan is
  skipped with a status note and the other sources carry the run.

### Output

- **Skip DNS verification** — list raw candidates without resolving
  them. Faster, but a stale or wrong record looks exactly like a live
  one; leave verification on for anything that matters.
- **Verification threads** — parallel DNS lookups during verification.
  50 is polite and quick; the resolver, not this number, is usually the
  bottleneck.
- **Max subdomains to verify** — cap on candidates sent to DNS. Larger
  sets are truncated with a status note so the run stays in bounds.

---

## Result

- **Results tab** — a table: subdomain, resolved IPs, status
  (`alive` / `unresolved` / `wildcard`), and the sources that named it.
  Sorted alive first; truncated past 2000 rows with a note.
- **Artifacts** — `subdomains.csv` (every candidate with its status and
  sources — the complete result), `subdomains_raw.json` (the raw
  candidate-to-sources map before verification).

### Reading the statuses

- **alive** — resolves, to IPs beyond the wildcard (or there is no
  wildcard). A real, reachable name.
- **unresolved** — no DNS answer today. Often a stale certificate
  transparency entry; sometimes a record that only exists internally.
- **wildcard** — resolves *only* to the IPs a random probe also
  answered on: the `*` record, not the subdomain. The name probably
  doesn't exist.

A `wildcard` status means the domain has a catch-all record — treat
`alive` rows on such a domain with extra care, and don't trust any
third-party subdomain list blindly.

---

## Exit codes

- `0` — the search ran, however many subdomains turned up (zero is a
  result, not a failure).
- `1` — the domain input is not a registrable domain, or every
  selected source failed.
- `2` — bad arguments.
