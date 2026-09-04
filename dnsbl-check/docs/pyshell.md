# DNSBL Check

Checks an IP address — or a domain and the IPs behind it — against the
**major public DNS blocklists** (DNSBLs): Spamhaus ZEN and DBL,
SpamCop, Barracuda, SORBS, blocklist.de, PSBL, GBUDb, SpamRats,
Mailspike, SURBL, UCEPROTECT. Pure DNS queries against the blocklist
zones; the target itself is never contacted beyond resolving its A
records.

The reputation half of the email story: [Email DNS
Audit](../../email-dns-audit) grades what your DNS *says* (SPF, DMARC,
DKIM), this one grades what the world *thinks* of what you send from.
Run both before wondering why mail lands in spam.

Twelve curated, alive zones — no dead zones, no padding. Every zone
row carries what it lists and a link to its lookup/delisting page.

---

## Before running

1. **IP or domain** — a sending IP (`198.51.100.25`) or a domain. A
   domain is resolved first: its A records (up to 8) go to the IP
   lists, the domain itself to the domain lists (Spamhaus DBL, SURBL).
2. Click **Prepare Env** — installs `dnspython`.
3. Press **Run** (⌘↩). A full run is a dozen-plus DNS queries — seconds.

**The resolver matters for Spamhaus.** The free tier of `zen.spamhaus.org`
and `dbl.spamhaus.org` does not serve big public resolvers (1.1.1.1,
8.8.8.8, …). Some of them get a refusal the script reports as
`blocked`; others get a **silent not-listed** — a "clean" that is not a
verdict, which the report calls out explicitly. Leave the resolver
blank (system) or use your own recursive resolver for trustworthy
Spamhaus rows.

---

## Fields

### Target

- **IP or domain** — what gets checked. A bare IP is checked against
  the ten IP lists only; a domain adds its A records to the IP checks
  and the domain itself to the two domain lists.
- **Custom resolver (optional)** — query through this nameserver
  instead of the system one. Must be an IP address.
- **Per-query timeout (s)** — each blocklist query gets this long
  (default 5 s; a slow or dead zone times out and reports `error`,
  never a false verdict).
- **Parallel queries** — how many zones are asked at once (default 10).

---

## Result

- **Results tab** — the markdown report: listings first (zone, decoded
  return code, the TXT reason when the zone serves one, delisting
  link), then the full zone table, then notes on blocked queries and
  zone errors.
- **Artifacts** — `dnsbl_raw.json` (every query's outcome, machine
  readable), `report.md`.

### Reading the statuses

- **listed** — the zone answered with a 127.x code. The decoded meaning
  is shown per zone; for Spamhaus ZEN, note that `PBL`
  (127.0.0.10/11) is a *policy* listing — normal for residential
  lines, not a spam verdict.
- **clean** — NXDOMAIN: not on this list.
- **blocked** — the zone refused *you* (public-resolver policy, rate
  limit). Not a verdict about the target.
- **error** — the zone couldn't be queried (timeout, SERVFAIL). Says
  nothing about the target.

UCEPROTECT level 1 is marked **aggressive** in listings — a single
report can list an IP there; weigh it accordingly.

---

## Exit codes

- `0` — the checks ran. Listings are results, not failures: a fully
  blacklisted IP is a successful check that found a bad reputation.
- `1` — the target is unusable (no A records and nothing to query), or
  every single query failed (DNS unusable from here).
- `2` — bad arguments (not an IP or domain, bad nameserver).
