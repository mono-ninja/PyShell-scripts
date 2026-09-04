# DNS Propagation

"I just changed the record — is it live everywhere yet?" One query to
your system resolver answers for exactly one cache. This script asks
**~20 public resolvers from different operators** — Google, Cloudflare,
Quad9, OpenDNS, Level3, DNS.Watch, Yandex, Comodo, SafeDNS, Freenom,
Neustar, CIRA — plus your system resolver, and lays the answers side by
side: who serves which value, what TTLs they report, and whether the
answers agree at all.

Give the **Expected value** and every resolver is classified — serving
the new value, or something else — that's the propagation progress bar.
Leave it empty and the script answers the consistency question: how
many distinct answers are out there and which resolver serves which.

Pure DNS queries to the resolvers' addresses — the authoritative
nameservers are never contacted, nothing is changed anywhere.

---

## Before running

1. **Record name** — the name you changed: `example.com`,
   `www.example.com`, `_dmarc.example.com`…
2. Click **Prepare Env** — installs `dnspython`.
3. Press **Run** (⌘↩). Twenty-ish queries in parallel — seconds.

**Anycast is not geography.** Most big resolvers are anycast — the same
address answered from edges worldwide. What differs between them is
the *cache* and the *view*: each operator runs its own recursion, so
one can hold the old record while another already serves the new one.
That is exactly the difference this check exposes — it is not a "which
country sees my site" tool.

## Fields

### Query

- **Record name** — the DNS name being checked.
- **Record type** — A (default), AAAA, CNAME, MX, TXT, NS, SOA, CAA.
- **Expected (new) value** — what you changed the record to. Comma-
  separate round-robin sets (`104.21.44.149, 172.64.80.1`) — a resolver
  counts as updated when it serves any of them. Comparison is
  normalized per type: TXT strips quotes, MX compares the host part,
  CNAME/NS fold case and the trailing dot; A/AAAA compare exactly.
- **Per-resolver timeout (s)** — default 4; a resolver slower than this
  reports an error row, never a guess.
- **Parallel queries** — default 8.

---

## Result

- **Results tab** — the propagation summary (with an expected value:
  who serves it, who doesn't, with a bar chart) or the agreement view
  (distinct answers and their resolvers), plus the per-resolver table
  with TTLs.
- **Artifacts** — `dns_propagation.json` (every resolver's outcome,
  machine-readable), `report.md`.

### Reading the statuses

- **updated** — serves at least one of the expected values.
- **differs** — answered, but not with the expected value: the old
  record still cached, or a different view (a Cloudflare round-robin
  pair with a single expected value shows up here — give both).
- **NXDOMAIN** — the name doesn't exist on that resolver at all.
- **no records** — the name exists but has no records of this type.
- **error** — timeout or SERVFAIL: that resolver said nothing.

A resolver still on the old value isn't broken — its cache holds the
record until the TTL runs out. The TTL column shows how long each one
may keep its answer.

## Exit codes

- `0` — the check ran. Disagreement, NXDOMAIN everywhere, zero
  propagation — all results, not failures.
- `1` — every resolver failed to answer (DNS unusable from here).
- `2` — bad arguments.
