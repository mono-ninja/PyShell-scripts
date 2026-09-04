# cURL

A [PyShell](https://github.com/mono-ninja/PyShell) script that wraps the
system `curl` binary: a form collects the flags, the script builds the
command, runs it and renders a report — the exact command, exit code, timing,
response status, headers and body.

It drives the real `curl` found on `PATH` (macOS ships one out of the box), so
every flag the installed curl supports is available. **No Python
dependencies** — standard library only.

## Features

- **Request** — method (GET…OPTIONS), body with raw / binary / JSON /
  URL-encoded encoding, headers, User-Agent, Referer
- **Connection** — connect and total timeouts, redirects, retries with delay,
  compression, HTTP version 1.0–3, IPv4/IPv6, interface binding
- **TLS** — skip verify, client certificate + key, CA bundle, ciphers, max
  TLS version
- **Auth** — Basic / NTLM / Negotiate / Anyauth, plus an independent Bearer
  token
- **Proxy** — HTTP/SOCKS proxy with credentials and a no-proxy list
- **Cookies** — send (`-b`) and save (`-c`) cookies
- **Advanced** — `--resolve`, `--connect-to`, DNS servers, DNS-over-HTTPS,
  Unix socket, keep-alive tuning

Secrets (passwords, tokens) are stored in the macOS Keychain and **never
appear on the command line**: they are passed to curl through a config fed
via stdin (`curl -K -`), so `ps` never sees them. In the report and in the
saved `command.sh` they are masked as `***`.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Run** (⌘↩) — there is nothing to install, no `requirements.txt`.
3. The report lands in the **Results** tab; artifacts include `command.sh`
   (the exact command, ready for a terminal), `headers.txt` and
   `response.txt`.

Field-by-field documentation lives in
[`docs/pyshell.md`](docs/pyshell.md) — the same text is shown in PyShell's
**Docs** panel (⌘D).

## Running standalone

```bash
python3 main.py --url https://example.com --method GET \
  --silent --show-error --save-body
```

All form fields map 1:1 to argparse flags (`--url`, `--method`, `--data`,
`--headers`, `--retry`, …; see `main.py`). Credentials come from environment
variables rather than flags: `AUTH_PASSWORD`, `BEARER_TOKEN`,
`PROXY_PASSWORD`. When `PYSHELL_OUTPUT_DIR` is not set, artifacts are written
to the current directory.

## Exit codes

- `0` — the command ran. curl's own exit code is a **result**, not a failure:
  it is shown in the report (`curl exited with code N`) together with timing,
  status, headers and body.
- `1` — could not start or was cut short: the `curl` binary is missing from
  `PATH`, or curl exceeded the configured timeout.

## Layout

```
curl/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py               # entry point — builds and runs the curl command
└── docs/
    ├── pyshell.md         # operator docs (Docs panel)
    └── pyshell_ua.md       # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
