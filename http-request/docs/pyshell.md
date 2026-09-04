# HTTP Request

Sends a single HTTP request and shows the response: status, headers (with
duplicates), body (JSON is formatted, binary is saved as `response.bin`),
timing (with TTFB / download breakdown), cookies, and an equivalent `curl`
command. An interactive "send and inspect" tool.

Network script: PyShell does not sandbox the process, so the request goes out
directly, with your IP address.

---

## Quick start

1. Click **Prepare Env** — PyShell will install `requests`. One time only.
2. **Method** = `GET`, **URL** = `https://jsonplaceholder.typicode.com/posts/1`.
3. Click **Run**. The response will appear in the **Results** tab: status `200`,
   headers, and the body as JSON.

---

## Fields

### Request

- **Method** — HTTP method. Defaults to `GET`.
- **URL** — full address with scheme (`https://…`). Required.
- **Query params** — optional. Query string parameters, merged with whatever
  is already in the URL. Two formats:
  - JSON object: `{"page": "1", "size": "20"}`. A list value repeats the key:
    `{"tag": ["a", "b"]}` → `?tag=a&tag=b`.
  - One `key=value` per line. Lines with `#` are ignored.
- **Headers** — optional. Two formats:
  - JSON object: `{"Content-Type": "application/json", "Accept": "*/*"}`
  - One `Key: Value` per line. Lines with `#` are ignored.
- **Body** — request body. If it is valid JSON it is sent as JSON (with the
  appropriate `Content-Type`), otherwise as raw text (gets
  `text/plain; charset=utf-8` by default, unless you set your own). Ignored for
  `GET`, `HEAD`, `OPTIONS`. A body that looks like JSON (starts with `{` or
  `[`) but fails to parse is a run error (exit code 2).

### Auth

- **Bearer token** — a secret (stored in Keychain, passed via env, never
  appears in argv or logs). Injected as `Authorization: Bearer <token>`, unless
  you set your own `Authorization`.
- **Basic-auth user** — username for HTTP Basic auth.
- **Basic-auth password** — password (a secret, Keychain → env). Only works
  together with **user**.

### Options

- **Timeout** — how long to wait for the response, 1–90 s. Capped at 90 so the
  script has time to write artifacts before the overall PyShell timeout
  (120 s).
- **Max body bytes** — how many bytes of the response body to read into memory
  (default 5 MB). Larger responses are truncated and marked `truncated`.
- **Follow redirects** — automatically follow `3xx`. Enabled by default.
- **Skip TLS verification** — do not verify the server certificate. For
  staging and self-signed certs. A warning appears in the report.
- **Redact secrets** — mask `Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key` in the report and artifacts (the value is replaced with
  `•••• (N chars, redacted)`). The Keychain token never gets into argv anyway;
  this toggle also hides secrets coming from the response.
- **Repeat** — repeat the request N times (1–50) and show the minimum / median
  / maximum timing. Useful for assessing latency stability.
- **Verbose** — print request details (headers, body) to the log.

---

## Example: POST request

1. **Method** = `POST`
2. **URL** = `https://jsonplaceholder.typicode.com/posts`
3. **Headers** = `{"Content-Type": "application/json"}`
4. **Body** =
   ```json
   {"title": "hello", "body": "world", "userId": 1}
   ```
5. **Run** → status `201 Created`, response with an assigned `id`.

---

## Results

- **Markdown** in the Results tab — status with reason phrase (`200 OK`),
  timing (total + TTFB + download), size (decoded and wire, if they differ),
  redirect chain (if any), the equivalent `curl` command, a headers table
  (duplicates on separate rows), a cookies table, and the body. JSON bodies
  are pretty-printed; binary bodies are replaced with a note about the type
  and size; large responses (over 20,000 characters) are truncated with a
  note.
- **Artifacts** in the Files tab:
  - `request.json` — the request exactly as sent (method, URL, headers, body,
    auth) — for replay;
  - `response.json` — a machine-readable record: status, timing, size, headers
    (a flat dict + `headers_multi` with duplicates), cookies, encoding, body;
  - `response.txt` — the raw response body as text (for text responses);
  - `response.bin` — the raw response body as bytes (for binary ones: images,
    PDFs, etc.).

  On a network error (no response) `response.txt`/`response.bin` are not
  created.

---

## Exit code

- `0` — a response was received (even `4xx`/`5xx` counts as a successful run —
  there is a response). A bad status is visible in the report, not in the code.
- `1` — network error (timeout, connection refused, DNS) — no response.
- `2` — failed to parse headers, query params, or the request body.

So a red row in History means "the request never made it", not "the server
returned an error" — those are different things.
