# IP Search

A [PyShell](https://github.com/mono-ninja/PyShell) script that resolves a
website's IP address through **every available method at once** — the
system resolver, dnspython, DNS-over-HTTPS, DNS-over-TLS, real TCP/HTTP
connections, and the `dig`/`host`/`nslookup` binaries — then cross-checks
the answers against each other. Divergence between methods is the
*signal*: it means CDN, load balancing, or a lying local resolver.

Alongside resolution it can identify the hosting provider (RDAP
organization/ASN/country + reverse DNS + an optional SSH banner read),
pull extra DNS records (NS, MX, TXT, SOA, CAA), query domain WHOIS,
detect the CDN/WAF in front of the site, and run a traceroute. All
methods run in parallel, so a full run takes roughly as long as the
slowest single method — usually traceroute.

Passive reconnaissance by design: DNS queries, one `HEAD` request, a
traceroute, and an optional unauthenticated SSH banner read. Nothing is
probed, scanned, or written to the target.

## Methods

| Group | Methods |
|---|---|
| Resolution → records table | `system`, `dnspython`, `doh`, `dot`, `connect` (reads the IP actually connected to), `tools` (dig/host/nslookup) |
| Analysis → markdown summary | `hosting` (RDAP + PTR + optional SSH banner), `dnsrecs` (NS/MX/TXT/SOA/CAA at the registrable domain), `whois` (registrar, dates, DNSSEC via RDAP), `cdn` (headers + TLS certificate), `traceroute` |

A method that cannot run (no `dig` installed, no dnspython for DoT) is
marked `SKIPPED` — not an error. One broken resolver never aborts the
other ten.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `dnspython`.
3. **Site URL** — `https://example.com` or just `example.com`. Press
   **Run** (⌘↩); with no methods picked, all 11 run.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 main.py --url https://example.com

# pick method groups (repeatable flag)
python3 main.py --url example.com --method system --method doh --method cdn

# hosting lookup with SSH banner read
python3 main.py --url example.com --method hosting --ssh-banner

# artifacts somewhere else (default: current directory)
PYSHELL_OUTPUT_DIR=./out python3 main.py --url example.com
```

## Result

- **Table** — every record obtained: method, source, address (IP or
  CNAME), type, TTL, status, time, hosting.
- **Markdown summary** — unique IPs with the number of **independent
  sources** that confirmed them (local resolver / Google / Cloudflare /
  DNS.SB / observed peer — not just a method count), a **divergence**
  section (IPs seen only by the local resolver are a sign of split-horizon
  DNS or interception), then hosting details, DNS records, WHOIS,
  CDN/WAF detection, and the traceroute.
- **Artifacts** — `results.csv` (always 10 columns, including `hosting`),
  `results.json` (full data), `dns_records.csv` (with `dnsrecs`),
  `traceroute.csv` (with `traceroute`).

## Exit codes

- `0` — the run finished, even when every method failed: failures are
  rows in the table, not process errors, so probing a dead host does not
  light up red in History.
- `1` — the hostname could not be parsed.

## Layout

```
ip-search/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # everything: methods → pipeline → events + artifacts
├── requirements.txt     # dnspython
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
