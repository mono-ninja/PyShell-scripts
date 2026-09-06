# Protocol Check

**Which protocols the site actually speaks** — the protocol layer
around TLS Audit's certificate grades, read with the standard
library only (ssl, socket, http.client, urllib — no QUIC stack, and
the report says so where that matters):

- **ALPN** — the negotiated application protocol on a real
  handshake: `h2` or `http/1.1` (with the connection-cost note when
  it's the latter).
- **HTTP/3** — the `Alt-Svc` announcement (`h3=":443"`), reported
  honestly as **an announcement**: the difference between "the site
  tells browsers HTTP/3 exists" and "HTTP/3 works" is exactly the
  line this script draws without a QUIC client.
- **Compression** — what the server actually serves on
  `Accept-Encoding: br, gzip, zstd`, with the byte win and the
  `Vary: Accept-Encoding` cache-correctness note.
- **IPv6** — not just the AAAA record: a real TCP+TLS connection to
  the v6 address (with the hostname for SNI). A published AAAA
  behind a closed v6 path is the classic silent breakage — and a
  local no-route shows up as what it is: the observed path.
- **Keep-alive** — two requests over one connection.
- **TLS resumption** — a second handshake offering the first's
  session; 0-RTT is not visible to the standard client — stated,
  not guessed.

## Using with PyShell

1. Enter the **URL** (https:// — the ALPN layer lives inside TLS).
2. Press **Run** (⌘↩) — no Prepare Env, stdlib only.

## Running standalone

```bash
python3 main.py --url https://example.com/
```

## Result

- **Results tab** — a table (check · result · detail) and the
  report: every protocol line with why it matters, the honesty
  notes (QUIC, 0-RTT), and the related scripts.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the protocol picture |
| 1 | the TLS/HTTP probes could not reach the host |
| 2 | bad arguments (not an https:// URL) |

## Layout

```
protocol-check/
├── pyshell.yaml      # manifest
├── main.py           # alpn · alt-svc · compression · ipv6 · keep-alive · resumption
├── docs/             # EN + UA docs
└── tests/            # 11 tests against a local ALPN HTTPS server (openssl fixture)
```

## License

MIT — see the root [LICENSE](../LICENSE).
