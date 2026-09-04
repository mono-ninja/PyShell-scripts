# IP Search

Resolves the specified website's IP address using **every available method**
and cross-checks the results against each other. The script sends nothing to
the target except ordinary DNS queries and a single TCP/HTTP connection — this
is passive reconnaissance.

All resolution methods, per-IP hosting lookups, and analysis methods run
**in parallel**, so a full run takes roughly as long as the slowest single
method (usually traceroute), not the sum of all of them.

## Before running

- **Site URL** — a full address (`https://example.com`) or just a domain
  (`example.com`). The scheme can be omitted.
- **Timeout** — wait time for a single operation, in seconds.
- **IPv6 (AAAA)** — whether to include IPv6 addresses in the result.
- **Resolution methods** — which methods to use. All are enabled by default:
  - `system` — system resolver via `socket.getaddrinfo` / `gethostbyname(_ex)`;
  - `dnspython` — library resolver plus direct UDP queries to `8.8.8.8` and
    `1.1.1.1`;
  - `doh` — DNS-over-HTTPS (Google, Cloudflare, DNS.SB);
  - `dot` — DNS-over-TLS (Google, Cloudflare);
  - `connect` — a direct TCP/HTTP(S) connection that reads the IP of the node
    actually connected to (`socket` + `http.client`);
  - `tools` — the system utilities `dig`, `host`, `nslookup` (if installed);
  - `hosting` — hosting provider identification for the found IPs: an RDAP
    query (organization, network, ASN, country, CIDR), reverse DNS (PTR), and
    optionally an SSH banner. RDAP data is cached per network (CIDR), so IPs
    from the same block (typical for CDNs) are not queried repeatedly;
  - `dnsrecs` — additional DNS records for the domain: NS, MX, TXT, SOA, CAA
    (these reveal the DNS provider, mail hosting, SPF/DKIM, certificate
    policy). Queries go to the **registrable domain** (apex), not the `www.`
    subdomain;
  - `whois` — domain WHOIS via RDAP: registrar, creation/update/expiration
    dates, nameservers, status, DNSSEC. The query goes to the registrable
    domain;
  - `cdn` — CDN/WAF detection: analysis of HTTP headers (Server, CF-Ray,
    X-Fastly, X-Amz-Cf-Id, etc.) and the TLS certificate (issuer, SANs);
  - `traceroute` — network path to the host via the system `traceroute`
    utility (shows transit providers and hops). On timeout, the partial result
    is kept.

- **SSH banner** — when enabled (together with the `hosting` method), the
  script connects to port 22 of each unique IP and reads the SSH greeting
  line (e.g. `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`). No authentication is
  performed — only passive banner reading. If the RDAP organization belongs
  to a known CDN (Cloudflare, Fastly, AWS CloudFront, etc.), the banner is
  skipped because a CDN-edge IP never responds over SSH — this is noted in
  the report.
- **Artifacts folder** — where to write output files. Defaults to the PyShell
  folder (`$PYSHELL_OUTPUT_DIR`) or the current directory in CLI mode.
  Artifacts that this run does not produce (e.g. `traceroute.csv` without the
  `traceroute` method) are deleted so they do not linger from a previous run.

## Result

- **A table** of all obtained records: method, source, address (IP or CNAME),
  type (A/AAAA/CNAME), TTL, status, time, hosting. The "hosting" column is
  always present (empty if the `hosting` method did not run).
- **A markdown summary** with:
  - a list of unique IPs and the number of **independent sources** that
    confirmed them (local resolver / Google / Cloudflare / DNS.SB / observed
    peer) — not just a count of methods, since several methods may use the
    same resolver;
  - a **divergence** section: IPs seen only by the local resolver but by no
    public one — a sign of split-horizon DNS or interception;
  - hosting details (provider, ASN, country, PTR, SSH banner), DNS records,
    domain WHOIS, CDN/WAF detection, and traceroute.
- Artifacts: `results.csv` (always 10 columns, including `hosting`),
  `results.json` (full data), `dns_records.csv` (only with the `dnsrecs`
  method), `traceroute.csv` (only with the `traceroute` method).

Methods that depend on missing tools (e.g. `tools` without `dig` installed,
or DoT without `dnspython`) are marked with the `SKIPPED` status — this is not
an error. Different methods may return the same IPs — this is normal mutual
cross-checking (consensus). Divergences between methods point to a CDN, load
balancing, or local resolver tampering.
