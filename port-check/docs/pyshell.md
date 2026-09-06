# Port Check

A TCP port scan of **a host you own** — which ports answer, what
greeted, and what the exposure means. The second deliberate
active-traffic exception in the collection (after
[Load Test](../../load-test)), under the same contract.

> **The ownership contract:** without the *I own this target*
> confirmation the run refuses to start. A port scan of a host you
> don't control is reconnaissance for an attack, whatever the intent.
> Even on your own server, expect your host/ISP to notice — a scan
> looks exactly like the first minutes of a real intrusion, and some
> providers auto-block the source IP.

---

## Before running

1. **Host or URL** — a bare host, a URL, or an IP. It resolves to up
   to 4 IPv4 addresses and scans each. **For a CDN-fronted site,
   scan your origin IP instead** — the CDN's ports are not yours.
2. Tick **I own this target or have permission to scan it**.
3. Pick the port set and press **Run** (⌘↩).

## Fields

### Target

- **Host or URL** — the server to scan.
- **I own this target** — the contract; the run refuses without it.

### Scan

- **Port set** —
  - **Common services (~110 ports)**: web and hosting panels, mail,
    remote access, file sharing, databases and caches, admin/dev
    tooling (Docker, Redis, Mongo, Elasticsearch, Kubernetes, Kibana…);
  - **Custom spec**: your `80,443,8000-8100`;
  - **Full range 1–65535**: minutes, not seconds — the per-port
    timeout is what a *dropping* firewall costs on every closed port.
- **Grab banners** — on every open port: read the greeting, send a
  minimal HTTP HEAD where nothing greets, guess the service
  (best-effort — an unrecognized banner shows as the raw bytes, never
  an invention). Turn off for a pure connect scan.
- **Per-port timeout (s)** — the connect (and banner) wait. 2 s is a
  good internet default; 0.5–1 s is plenty on a LAN.
- **Concurrency** — ports probed in parallel (default 300).

---

## Result

- **Results tab** — the open-port table (IP · port · service · banner
  · exposure group) and the report: the risky families called out
  with the follow-up each one wants.
- **Artifacts** — `findings.json` (every open port per IP),
  `report.md`.

### Reading the findings honestly

- **Closed vs filtered**: *closed* got an honest RST (nothing
  listens); *filtered* got no answer at all (a firewall drops — the
  normal good case, and the reason scans are slow).
- **Exposure groups** are the story: databases & caches, remote
  access, admin/dev tooling and file sharing have no business facing
  the public internet — bind them to localhost/private networks and
  let the firewall say no. Mail and web ports are expected; their
  *quality* is other scripts' job — [Mail Probe](../../mail-probe)
  for the wire, [TLS Audit](../../tls-audit) and
  [Security Headers](../../security-headers) for the web, [SSH Log
  Check](../../ssh-log-check) for what port 22 is absorbing.
- **TCP only, connect-only**: no UDP (unreliable to scan honestly),
  no exploit payloads, nothing beyond the banner. TLS ports show
  "TLS? (no plain banner)".

## Exit codes

- `0` — the scan ran; open ports are findings.
- `1` — the target doesn't resolve.
- `2` — bad arguments (no ownership confirmation, an invalid custom
  port spec, an empty target).
