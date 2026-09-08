# CT Log Check — Report

Domain: **isc.org** · 4574 issuance record(s) over 117 name(s) · 313 valid right now

Certificate transparency is public by law of the ecosystem: every public CA reports every issuance. This is what the logs say about your domain — nobody was probed.

## Issuers

- main: **C=US, O=Let's Encrypt, CN=R3** (1202 record(s))
- everyone else who ever issued for `isc.org`:
  - C=US, O=Let's Encrypt, CN=R11: 462
  - C=US, O=Let's Encrypt, CN=R10: 458
  - C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3: 424
  - C=US, O=Let's Encrypt, CN=R13: 338
  - C=US, O=Let's Encrypt, CN=R12: 272
  - C=BE, O=GlobalSign nv-sa, CN=GlobalSign CloudSSL CA - SHA256 - G3: 225
  - C=US, O=Let's Encrypt, CN=E5: 196
  - C=US, O=Let's Encrypt, CN=E6: 156
  - C=US, O=Let's Encrypt, CN=E8: 128
  - C=US, O=Let's Encrypt, CN=YR1: 119

A CA you don't recognize in this list is either history (an old rotation) or a question — who ordered that certificate? Cross-check with your ACME accounts and your DNS provider's API log.

## Timeline

- first issuance in the feed: **2004-08**, latest: **2026-09**
- last 30 days: 107 issuance(s)

## Wildcards

- `*.gitlab-pages.aws.isc.org` — covers everything below it
- `*.gitlab-pages.isc.org` — covers everything below it
- `*.isc.org` — covers everything below it

## Names

- 117 distinct name(s) in the certs; 79 still covered by a valid certificate.
  - valid now: `*.gitlab-pages.isc.org`
  - valid now: `*.isc.org`
  - valid now: `acme.aws.isc.org`
  - valid now: `altops.isc.org`
  - valid now: `asteriskbsd.isc.org`
  - valid now: `atlas-vis.isc.org`
  - valid now: `bikeshed.isc.org`
  - valid now: `bind.isc.org`
  - valid now: `bugs.isc.org`
  - valid now: `cloak.isc.org`
  - valid now: `clock.isc.org`
  - valid now: `crowsnest-oak1.isc.org`
  - valid now: `crowsnest.isc.org`
  - valid now: `dagger.isc.org`
  - valid now: `demo.stork.isc.org`
  - … +64 more
- Which of these names still *exist* is a DNS question — **Subdomain Search** answers it from the same feed plus DNS; **Fleet Check** tests them over HTTP.

## Related

- **TLS Audit** — the live certificate this history feeds: grade, chain, expiry of what's served now.
- **Subdomain Search** — the names, from the same crt.sh feed plus passive sources.
- **Fleet Check** — the whole portfolio's live TLS in one table.