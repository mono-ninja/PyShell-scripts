# HTTP Request

A [PyShell](https://github.com/mono-ninja/PyShell) script that sends one
HTTP request and shows the response: status, headers (with duplicates),
body (JSON is formatted, binary is saved as a file), timing with
TTFB/download breakdown, cookies, the redirect chain, and an equivalent
`curl` command. An interactive "send and inspect" tool — the form-driven
counterpart of a quick `curl` or Postman check.

Network script: PyShell does not sandbox the process, so the request goes
out directly, with your IP address.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`. One time only.
3. Fill in the form and press **Run** (⌘↩). Quick start: **Method** `GET`,
   **URL** `https://jsonplaceholder.typicode.com/posts/1`.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## What the form covers

- **Request** — method (GET…DELETE, HEAD, OPTIONS), URL, query params and
  headers (JSON object or one `key=value` / `Key: Value` per line), body
  (valid JSON is sent as JSON, anything else as raw text).
- **Auth** — Bearer token and Basic-auth password are Keychain secrets
  passed via environment variables; they never appear in `argv`, `ps`, or
  the report.
- **Options** — timeout (1–90 s), max body bytes (default 5 MB, larger
  bodies truncated), follow redirects, skip TLS verification, redact
  secrets in the report (`Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key`), and repeat 1–50× with min/median/max timing.

## Running standalone

```bash
python3 -m pip install -r requirements.txt

PYSHELL_OUTPUT_DIR=/tmp/out python3 main.py --url https://example.com
PYSHELL_OUTPUT_DIR=/tmp/out python3 main.py --method POST \
  --url https://jsonplaceholder.typicode.com/posts \
  --headers '{"Content-Type": "application/json"}' \
  --body '{"title": "hello"}'
```

Without `PYSHELL_OUTPUT_DIR` the script still runs; it just skips writing
artifacts. Secrets come from the environment (`AUTH_TOKEN`,
`AUTH_PASSWORD`), never from flags. Note that **follow redirects** is on
by default in the form but off in a bare terminal run — pass
`--follow-redirects` explicitly.

## Result

- **Results tab** — a markdown report: status with reason phrase, timing
  (total + TTFB + download), size, redirect chain, the equivalent `curl`
  command, headers and cookies tables, and the body (JSON pretty-printed;
  binary replaced with a note about type and size).
- **Artifacts** — `request.json` (the request exactly as sent, for
  replay), `response.json` (machine-readable record), `response.txt` /
  `response.bin` (the raw body, text or binary).

## Exit codes

- `0` — a response was received. Even `4xx`/`5xx` counts as a successful
  run — a bad status shows in the report, not in the exit code.
- `1` — network error (timeout, connection refused, DNS) — no response.
- `2` — headers, query params, or the request body couldn't be parsed.

A red row in History means "the request never made it", not "the server
returned an error" — those are different things.

## Layout

```
http-request/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
