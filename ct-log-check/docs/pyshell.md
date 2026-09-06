# CT Log Check

Every certificate ever issued for a domain — the certificate
transparency logs via the crt.sh feed: the issuance **timeline**
(per month, as a chart), the **issuers** (your main CA and everyone
else who ever issued — the headline), **wildcards**, every **name**
the certs cover with the still-valid ones separated, the **burst
flag** (recent pace vs the last year's average), and — when crt.sh's
JSON cap for very large domains hits (the feed's newest issuance is
months old) — the honest note naming it, instead of a misleading
"valid now: 0".

Plus the **CAA comparison**: the domain's CAA records (who is
*allowed* to issue — fetched via DNS-over-HTTPS, parents climbed the
way a CA does) against the CAs holding *live* certificates —
allowed ✅ · outside the list 🔴 · unrecognized ⚪ (the curated
mapping doesn't know every CA; never guessed into a verdict).

The historical twin of TLS Audit's live certificate. Passive: one
feed fetch plus a couple of DNS-over-HTTPS lookups.

---

## Before running

1. Enter the **Domain** — a registrable domain; every certificate
   for it and any subdomain is in scope (the `%.domain` feed).
2. **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩). The feed can be slow on big domains — two
   retries with backoff are built in.

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

- **Results tab** — the issuers table (top 15 by count), the
  issuance-per-month bar chart, and the report:
  - **Issuers** — the main CA, then *everyone else*: a CA you don't
    recognize is either history (a rotation) or a question
    (cross-check ACME accounts and the DNS provider's API log).
  - **Timeline** — first and latest issuance, the last-30-days
    count, the burst warning, the crt.sh-cap note when it applies.
  - **Wildcards** — the `*.domain` certificates.
  - **Names** — the still-valid coverage; which names still exist
    is a DNS question → **Subdomain Search** / **Fleet Check**.
  - **CAA — who is allowed vs who actually issued** — the policy
    line (or the honest "no CAA record — any CA may issue"), then
    every live-certificate CA: allowed, outside the list (issued
    before the policy or a gap in it), or unrecognized. The nuance
    is said aloud: CAA governs from publication — a live
    certificate may legitimately predate your own policy; the
    rotation schedule is yours.
- **Artifacts** — `report.md`, `findings.json` (every record:
  cert id, name, issuer, not_before, not_after; plus the CAA
  policy and verdicts).

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
