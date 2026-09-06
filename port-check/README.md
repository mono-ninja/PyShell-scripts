# Port Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that runs a
**TCP port scan of a host you own** — the second deliberate exception
to the collection's passive philosophy (after [Load Test](../load-test)),
under the same contract: **without the "I own this target"
confirmation the run refuses to start.** A port scan of a host you
don't control is reconnaissance for an attack, whatever the intent.

What it does:

- **Common set** (default): ~110 well-known service ports — web,
  mail, databases, remote access, admin panels, the dev-tooling
  classics (Docker API, Redis, Mongo, Elasticsearch, Kubernetes…);
- **Custom spec** — `80,443,8000-8100`;
- **Full range** 1–65535 (minutes, not seconds);
- resolves the target to its IPv4 addresses (up to 4) and scans each;
- on every open port: **banner grab** (the service greeting, plus a
  minimal HTTP HEAD where nothing greets) and a best-effort service
  guess — SSH, HTTP, SMTP, FTP, MySQL, RDP, VNC…;
- the report groups findings by **exposure**: remote access,
  databases & caches, admin/dev tooling, file sharing, mail, web —
  the families that have no business facing the public internet.

Honest limits: **TCP only, connect-only** — no UDP (unreliable to scan
honestly), no exploit payloads, nothing beyond the banner. TLS ports
show "TLS? (no plain banner)" — the certificate is
[TLS Audit](../tls-audit)'s job. Stdlib only.

The attack-surface sibling of [SSH Log Check](../ssh-log-check)
(what port 22 is absorbing), [Mail Probe](../mail-probe) (the mail
ports' wire behavior) and [WP Exposure Check](../wp-exposure-check)
(the HTTP surface's open doors).

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O). No dependencies —
   **Prepare Env** has nothing to install.
2. Fill the host, tick **I own this target**, pick the port set,
   press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 main.py --target my-server.example --i-own-this-target
python3 main.py --target my-server.example --i-own-this-target --port-set full
python3 main.py --target my-server.example --i-own-this-target \
    --port-set custom --custom-ports "80,443,8000-8100"
python3 main.py --target my-server.example --i-own-this-target --no-banners
```

## Result

- **Results tab** — the open-port table (IP · port · service · banner
  · exposure group) and the report with the risky families called
  out.
- **Artifacts** — `findings.json` (every open port per IP,
  machine-readable), `report.md`.

## Exit codes

- `0` — the scan ran. Open ports are findings, not failures.
- `1` — the target doesn't resolve (nothing to scan).
- `2` — bad arguments — including **a missing ownership
  confirmation**, an empty/invalid custom port spec.

## Layout

```
port-check/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # port sets, spec parsing, the scan, banners
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
