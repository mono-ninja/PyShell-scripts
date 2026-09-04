# Security Headers

A [PyShell](https://github.com/mono-ninja/PyShell) script that grades a
URL's HTTP security headers — HSTS, CSP, `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP,
cookie flags, version leaks — and hands back a 0–100 score, a letter
grade (A+ … F), and concrete fixes ready to paste into a server config.

Passive by design: **one GET request** (or a bounded redirect chain, max
10 hops), nothing sent that a normal browser visit wouldn't already
trigger. No scanning, no fuzzing. A `GET` is used rather than `HEAD`
because some origins only attach CSP/HSTS to real document responses.

The header set is recorded **at every redirect hop**: a header present at
the origin but dropped after a redirect to a CDN edge is surfaced as its
own finding, which a final-response-only tool would never see.

## What gets checked

| Header | Pass condition |
|---|---|
| `Strict-Transport-Security` | present, `max-age` ≥ ~6 months (`15768000`) |
| `Content-Security-Policy` | present, `default-src` or a full set of `-src` directives; no bare `unsafe-inline`/`unsafe-eval` |
| `X-Content-Type-Options` | exactly `nosniff` |
| `X-Frame-Options` | `DENY`/`SAMEORIGIN` — or CSP `frame-ancestors`, which supersedes it |
| `Referrer-Policy` | present, not `unsafe-url` |
| `Permissions-Policy` | present (informational weight) |
| `Cross-Origin-Opener-Policy` | `same-origin` (informational weight) |
| `Cross-Origin-Resource-Policy` | `same-origin` / `same-site` (informational weight) |
| `Set-Cookie` | per cookie: `Secure` + `HttpOnly` + `SameSite` all set |
| `Server` / `X-Powered-By` | absent or version-free — a leaked version is informational, not scored |

`X-XSS-Protection` gets a note, never a score: the modern guidance is to
omit it entirely.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **URL** — the page to audit, with scheme (`https://…`). Press
   **Run** (⌘↩).

**Extra request headers** (one `Key: Value` per line) lets you audit
pages behind auth — a session `Cookie` header. It goes into the
*request*, never the grading.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --url https://example.com/
python3 main.py --url https://example.com/ --follow-redirects \
  --headers "Cookie: session=abc123"
```

Note: **follow redirects** is on by default in the form but off in a bare
terminal run — pass `--follow-redirects` explicitly.

## Result

- **Results tab** — a markdown report: the grade headline, the top 3
  fixes, the full findings table (Header / Status / Detail / Fix), and
  the redirect chain.
- **Artifacts** — `headers_raw.json` (every header at every hop,
  verbatim — the raw evidence), `findings.json` (machine-readable, for
  CI), `report.md`.

## Exit codes

- `0` — a response arrived, whatever the grade. An `F` is a successful
  audit that found a bad result, not a script failure.
- `1` — no response at all (timeout, connection refused, DNS failure).
- `2` — the extra-headers block couldn't be parsed.

A red row in History means "the request never landed", not "the site
scored poorly".

## Layout

```
security-headers/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
