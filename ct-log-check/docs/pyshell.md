# CT Log Check

Every certificate ever issued for a domain — the certificate
transparency logs via the crt.sh feed: the issuance **timeline** (per
month, as a chart), the **issuers grouped by CA** (your main CA and
everyone else who ever issued — the headline), **wildcards**, every
**name** the certs cover with the still-valid ones separated, and the
**burst flag** (recent pace vs the last year's monthly average).

Two counting rules keep the numbers honest. A precertificate and its
final certificate are two crt.sh rows with different ids and the same
serial — **one** issuance, folded on `(issuer_ca_id, serial_number)`;
without that every count roughly doubles. And issuances are grouped by
**CA**, not by the intermediate that signed them: `CN=R3`, `CN=E5` and
`CN=X3` are one Let's Encrypt (isc.org: 48 intermediates, 10 CAs).

Plus the **CAA comparison**: the domain's CAA records (who is *allowed*
to issue — fetched via DNS-over-HTTPS, parents climbed the way a CA
does, stopping at the registrable domain) against the CAs holding
*live* certificates — allowed ✅ · outside the list 🔴 · unrecognized ⚪
(the curated mapping doesn't know every CA; never guessed into a
verdict).

The historical twin of TLS Audit's live certificate. Passive: one feed
fetch plus a couple of DNS-over-HTTPS lookups.

---

## Before running

1. Enter the **Domain** — a registrable domain; every certificate
   for it and any subdomain is in scope (the `%.domain` feed). An
   internationalised name is converted to punycode for you.
2. **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩). The feed can be slow on big domains — two
   retries with backoff are built in, and they cover the transient
   404 crt.sh answers under load.

## Fields

### Target

- **Domain** — the registrable domain (e.g. `example.com`, not
  `www.example.com`).
- **crt.sh timeout (s)** — 10–120, default 45.
- **Skip the CAA comparison** — off by default: the CAA policy is
  fetched over DNS-over-HTTPS (the domain and its parents, the
  RFC 8659 climb) and compared with the live issuers. Skip for a
  crt.sh-only pass with no DNS lookups.

---

## Result

- **Results tab** — the CA table (CA · certificates · intermediates,
  top 15), the issuance-per-month bar chart, and the report:
  - **Issuers** — the main CA, then *everyone else*: a CA you don't
    recognize is either history (a rotation) or a question
    (cross-check ACME accounts and the DNS provider's API log). The
    per-intermediate census stays in `findings.json`.
  - **Timeline** — first and latest issuance, the last-30-days count,
    the burst warning, and — when the newest issuance is months old —
    either the crt.sh cap or a dormant domain (see below).
  - **Wildcards** — the `*.domain` certificates.
  - **Names** — the still-valid coverage; which names still exist is a
    DNS question → **Subdomain Search** / **Fleet Check**.
  - **CAA — who is allowed vs who actually issued** — the policy line,
    then every live-certificate CA: allowed, outside the list (issued
    before the policy or a gap in it), or unrecognized. A domain with
    **no** CAA record has no list to be outside of: its CAs are
    reported as unconstrained under the plain statement that any CA in
    the world may issue — never as violations. A lookup that failed on
    both resolvers is reported as **not checked**, never as "no
    policy". The nuance is said aloud: CAA governs from publication —
    a live certificate may legitimately predate your own policy; the
    rotation schedule is yours.
- **Artifacts** — `report.md`, `findings.json` (every record: cert id,
  the certificate identity key, name, issuer, not_before, not_after;
  the per-CA and per-intermediate censuses; plus the CAA policy and
  verdicts).

### An old feed: the cap, or a dormant domain

crt.sh caps its JSON at roughly the oldest 5000 rows for very large
domains, so the newest issuance in the answer can be years old. A small
feed whose newest issuance is old means something entirely different —
nobody has issued for that domain in a while. Only the feed size tells
them apart, so the report never guesses:

- **large feed** → the cap is named, and every "valid now" count is
  withheld rather than shown as a misleading zero;
- **small feed** → reported as a dormant domain, with the counts
  intact because they are complete.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the history |
| 1 | crt.sh unreachable / non-JSON answer, or no records found |
| 2 | bad arguments: not a domain |

## Related

- **TLS Audit** — the live certificate this history feeds.
- **Subdomain Search** — the names, from the same crt.sh feed plus
  passive sources.
- **Fleet Check** — the whole portfolio's live TLS in one table.
