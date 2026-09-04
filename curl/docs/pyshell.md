# cURL

A wrapper around the system `curl`: a form collects flags, the script builds
the command, runs it and shows a report — the command, status, response
headers and body.

It uses the real `curl` binary from `PATH` (on macOS it ships out of the box).
**No Python dependencies** — standard library only. No `requirements.txt`
is needed.

## Field groups

| Group | What it contains |
| --- | --- |
| **Request** | URL, method, body (with raw/binary/json/urlencoded encoding), headers, User-Agent, Referer, `-i`/`-I`/`-f` |
| **Connection** | Timeouts, redirects, retries, compression, HTTP version (1.0–3), IPv4/IPv6, interface |
| **TLS** | `-k`, client certificate + key, CA, ciphers, max TLS version |
| **Auth** | Basic / NTLM / Negotiate / Anyauth + a separate Bearer token. Passwords are `secret` type → Keychain |
| **Proxy** | `--proxy`, username + password (`secret`), `--noproxy` |
| **Cookies** | `-b` (send), `-c` (save) |
| **Output** | `-s`/`-S`/`-v`, `-w`, `--dump-header`, save body as an artifact |
| **Advanced** | `--resolve`, `--connect-to`, DNS servers, DNS-over-HTTPS, Unix socket, keep-alive |

## Secrets

The **Password**, **Bearer token** and **Proxy password** fields are of type
`secret` — the value is stored in the macOS Keychain and passed to the script
through an environment variable.

The script then **never puts them on the command line at all**. Instead of
`-u user:pass` it builds a curl config and feeds it via stdin
(`curl -K -`), so `ps` never sees the credentials even at the moment of
launch. In the report and in `command.sh` they are shown as `***`:

```sh
curl -s -K - 'https://api.example.com/' <<'CURLRC'
user = "admin:***"
header = "Authorization: Bearer ***"
CURLRC
```

Substitute the real values for `***` and the command can be run in a terminal
as is.

**The Bearer token is independent of the Auth method.** It is simply an
`Authorization` header, so the field is always visible and works both on its
own and on top of the chosen method.

Also masked: cookie values in `-b` (names stay visible) and the headers
`Authorization`, `Proxy-Authorization`, `X-Api-Key`, `Api-Key`,
`X-Auth-Token`, `X-Csrf-Token` if you typed them by hand into the **Headers**
field.

## Response headers

For the report to contain headers, curl has to save them separately. If you
did not pick `-i`, `-I` or `--dump-header`, the script automatically adds
`--dump-header` to a temporary file — headers are always present in the
report. This helper flag is not shown in the report, because you did not ask
for it.

When **Follow redirects** is on, the report gets the **last** response of the
chain, not the first 301 — and this works the same for `-i` and for
`--dump-header`.

## Things worth knowing about individual fields

- **Method: HEAD** is sent as `-I`. A bare `-X HEAD` makes curl wait for a
  body the server will never send — the request would simply hang until the
  timeout.
- **HTTP version** expands into real curl flags (`--http1.1`, `--http2`,
  `--http2-prior-knowledge`, `--http3`). HTTP/3 works only if your curl was
  built with its support.
- **DNS servers** requires libcurl built with c-ares. The system curl on macOS
  is not — in that case the field is skipped and a note appears in the report.
  For the same tasks there is **DNS-over-HTTPS** and `--resolve`.
- **Write-out** (`-w`) goes to a separate section of the report instead of
  being mixed into the body, so the `response.txt` artifact stays an exact
  copy of the response.
- **Body encoding: Raw** sends the body with the `-d` flag, and from a file
  body curl strips line breaks — multi-line text would go as a single line.
  The script notices this and adds a note; to send the body byte for byte,
  choose **Binary** or **JSON**.
- **Body encoding: URL-encoded** encodes the entire field content. Earlier the
  text up to the first `=` was treated as a field name and left unencoded.
- **Verbose** (`-v`) shows the curl trace in the report even when the request
  succeeds.

## Notes in the report

If the script changed something in your command or skipped an unsupported
field, it does not do so silently: a **Notes** block appears above the result
with a list of exactly what happened and why.

## Result

The **Results** tab holds a markdown report: the command, exit code, timing,
notes, curl diagnostics, status line, header table, write-out and body
(truncated to ~50 KB; a binary one shows the size). Artifacts:

- `command.sh` — the exact command (with secrets masked) that you can copy
  into a terminal.
- `headers.txt` — the full response headers.
- `response.txt` — the full body (if **Save body** is on).

## Exit code and timeout

The script exits with `0` even when curl finished with an error. The HTTP
status and curl's exit code are always in the report — so a run does not light
up red in History when you are simply probing an unreachable server. The
exceptions are `1`, if the `curl` binary is missing from `PATH` or the process
timed out; in both cases the reason also lands in the report.

There is no application-side time limit — the deadline is computed by the
script itself, by the formula **Max time × (Retries + 1) + delays between
attempts + 10 s**. This is done because curl's `--max-time` applies to each
attempt separately, so with retries a request legitimately takes longer, and
a fixed application limit would kill it halfway through.

**Retry delay = 0** does not mean “no pause” but “curl's default backoff”:
1 s doubling on every attempt (up to 10 min). The script budgets exactly this
backoff into the deadline — otherwise it would kill curl mid-series.

## Preview

Press **Preview** in the header — you will see the Python command line that
PyShell runs. Look at the curl command itself in the report after the run, or
in `command.sh`.
