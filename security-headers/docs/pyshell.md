# Security Headers

Grades a URL's HTTP security headers — HSTS, CSP, `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP, CORP, cookie
flags, version leaks — and hands back a 0–100 score, a letter grade
(A+ … F), and concrete fixes ready to paste into a server config.

Passive by design: **one GET request** (or a bounded redirect chain, max 10
hops), nothing sent that a normal browser visit wouldn't already trigger. No
scanning, no fuzzing.

---

## Before running

1. Click **Prepare Env** — installs `requests`.
2. **URL** — the page to audit, with scheme (`https://…`).
   A `GET` is used (not `HEAD`): some origins only attach CSP/HSTS to real
   document responses, and `HEAD` would under-report.

---

## Fields

### Request

- **URL** — the target page.
- **Follow redirects** (on by default) — audit the whole chain. The header set
  is recorded **at every hop**: a header present at the origin but dropped
  after a redirect to a CDN edge is surfaced as its own finding, which a
  final-response-only tool would never see. Turn it off to audit exactly the
  one response the URL returns.
- **Timeout (s)** — per request; each redirect hop gets its own budget.
- **User-Agent** — defaults to a PyShell audit identity. Some WAFs silently
  drop bare `python-requests`, which would look like a timeout.
- **Extra request headers** — one `Key: Value` per line. Use this to audit
  pages behind auth (a session `Cookie` header); the header goes into the
  *request*, never the grading.
- **Skip TLS verification** — for internal/staging hosts with self-signed
  certificates.

---

## What gets checked

| Header | Pass condition |
|---|---|
| `Strict-Transport-Security` | present, `max-age` ≥ ~6 months (`15768000`) |
| `Content-Security-Policy` | present, `default-src` or a full set of `-src` directives; no bare `unsafe-inline`/`unsafe-eval` |
| `X-Content-Type-Options` | exactly `nosniff` |
| `X-Frame-Options` | `DENY`/`SAMEORIGIN` — or CSP `frame-ancestors`, which supersedes it |
| `Referrer-Policy` | present, not `unsafe-url` |
| `Permissions-Policy` | present (informational weight — most sites still don't send it) |
| `Cross-Origin-Opener-Policy` | `same-origin` (informational weight — newer than Permissions-Policy, adoption is lower still) |
| `Cross-Origin-Resource-Policy` | `same-origin` / `same-site` (informational weight, same reasoning) |
| `Set-Cookie` | per cookie: `Secure` + `HttpOnly` + `SameSite` all set |
| `Server` / `X-Powered-By` | absent or version-free — a leaked version is informational, not scored |

`X-XSS-Protection` gets a note, never a score: the modern guidance is to omit
it entirely (deprecated, and on old IE it could itself introduce an XSS
vector).

## Result

- **Results tab** — markdown report: the grade headline, the top 3 fixes, the
  full findings table (Header / Status / Detail / Fix), and the redirect chain.
- **Artifacts** — `headers_raw.json` (every header at every hop, verbatim —
  the raw evidence), `findings.json` (machine-readable, for CI), `report.md`.

## Exit code

- `0` — a response arrived, whatever the grade. An `F` is a successful audit
  that found a bad result, not a script failure.
- `1` — no response at all (timeout, connection refused, DNS failure).
- `2` — the extra-headers block couldn't be parsed.

A red row in History means "the request never landed", not "the site scored
poorly".
