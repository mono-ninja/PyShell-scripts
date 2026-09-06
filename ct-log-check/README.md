# CT Log Check

**Every certificate ever issued for a domain** — the certificate
transparency logs (via the crt.sh feed, the same client as Subdomain
Search — which found *names* there; this finds *issuances*). TLS
Audit inspects the **live** certificate; this reads the **history**:

- **The timeline** — issuances per month (a bar chart): the renewal
  rhythm, accelerations and silences at a glance.
- **The issuers** — grouped by CA: your main issuer and *everyone
  else who ever issued for the domain* — the headline. An unfamiliar
  CA in that list is either history (a rotation) or a question (who
  ordered that cert?).
- **Wildcards** — the `*.domain` certificates, each covering
  everything below it.
- **Names** — every name the certs cover, the ones still covered by
  a valid certificate separated from the expired history. Which
  names still *exist* is a DNS question — the report says so and
  points at Subdomain Search instead of guessing.
- **The burst flag** — the recent pace against the last year's
  monthly average.
- **CAA vs the actual issuers** — the policy half nobody reads: the
  domain's CAA records (who is *allowed* to issue, via
  DNS-over-HTTPS, parents climbed the way a CA does — RFC 8659)
  compared with the CAs holding **live** certificates: allowed ✅ ·
  outside the list 🔴 (issued before the policy or a gap in it) ·
  unrecognized ⚪ (the curated issuer→CAA mapping doesn't know every
  CA — never guessed into a verdict). The nuance is said aloud:
  CAA governs from publication; a live certificate may legitimately
  predate your own policy.
- **The crt.sh cap, honestly** — for very large domains the feed
  returns only the oldest ~5000 rows; when detected (the newest
  issuance in the feed is months old), the report names it instead
  of showing a misleading "valid now: 0".

Passive: one feed fetch plus a couple of DNS-over-HTTPS lookups.

## Using with PyShell

1. Enter the **Domain** (a registrable domain — every cert for it
   and any subdomain).
2. Press **Prepare Env** (installs `requests`), then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --domain example.com
```

## Result

- **Results tab** — the issuers table, the timeline chart, and the
  report.
- **Artifacts** — `report.md`, `findings.json` (every record:
  cert id, name, issuer, validity).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the history |
| 1 | crt.sh unreachable / non-JSON, or no records for the domain |
| 2 | bad arguments (not a domain) |

## Layout

```
ct-log-check/
├── pyshell.yaml      # manifest
├── main.py           # feed · parse · analyze · report
├── requirements.txt  # requests
├── docs/             # EN + UA docs
└── tests/            # 10 tests over canned crt.sh rows
```

## License

MIT — see the root [LICENSE](../LICENSE).
