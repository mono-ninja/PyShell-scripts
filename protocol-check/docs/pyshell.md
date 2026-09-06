# Protocol Check

Which protocols the site actually speaks — the protocol layer
around TLS Audit's certificate grades: **ALPN** (h2 or http/1.1 on
a real handshake), the **HTTP/3 Alt-Svc announcement** (honestly an
announcement — no QUIC stack), **compression actually served** on
Accept-Encoding (br/gzip/zstd with the byte win and the
Vary-correctness note), **IPv6 with a real connection** (not just
the AAAA record — a published record behind a closed path is the
classic silent breakage), **keep-alive** (two requests, one
connection), and **TLS session resumption** (0-RTT stated as not
visible to the standard client, never guessed).

Standard library only: ssl, socket, http.client, urllib.

---

## Before running

1. Enter the **URL** — https:// is required (the ALPN layer lives
   inside TLS; for a plain-http site there is nothing to negotiate).
2. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the https:// site. The handshake, the announcements
  and the wire behavior are read from it.
- **Per-probe timeout (s)** — 3–60, default 15.

---

## Result

- **Results tab** — the table (check · result · detail) and the
  report, every line with why it matters:
  - **ALPN** — the negotiated protocol, TLS version and cipher; the
    http/1.1 case gets the every-request-pays-the-connection note.
  - **HTTP/3** — announced (port, via Alt-Svc) or not advertised;
    the announcement/confirmation distinction stated verbatim.
  - **Compression** — the encoding served, the byte win, the
    missing-`Vary` note.
  - **IPv6** — connected over the v6 address; or the AAAA-but-broken
    note naming the observed failure; or no AAAA.
  - **Keep-alive / TLS resumption** — the connection-reuse story;
    probes that fail are listed as failed, the rest still reports.
- **Artifacts** — `report.md`, `findings.json` (every probe's raw
  result).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the protocol picture |
| 1 | the TLS/HTTP probes could not reach the host |
| 2 | bad arguments: not an https:// URL |

## Related

- **TLS Audit** — the certificate and the handshake grades; this
  script is the protocol layer around it.
- **Server Timing / Cache Check / HAR Analyze** — what the
  protocols cost and save in practice.
- **DNS Propagation / DNSSEC Check** — the other layers of the
  stack's plumbing.
