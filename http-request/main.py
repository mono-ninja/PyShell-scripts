#!/usr/bin/env python3
"""http-request/main.py — HTTP Request.

Sends one HTTP request and inspects the response: status, headers (with
duplicates preserved), body (pretty-printed when JSON, raw bytes saved for
binary), timing split, cookies, and a curl equivalent. A request inspector —
one request, one response, every detail.

Structured events are emitted on stderr so PyShell renders them natively.
Artifacts are written to PYSHELL_OUTPUT_DIR: ``response.json`` (the full
response record), ``response.txt`` (raw text body) or ``response.bin`` (raw
binary body), and ``request.json`` (the request as sent, for reproduction).

Run from a terminal too — the events degrade to plain JSON log lines.
"""
import argparse
import json
import os
import re
import shlex
import statistics
import sys
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ

BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Reason phrases for common status codes. Used only as a fallback when the
# server's response gives no reason phrase (rare over HTTP/1.1, where
# resp.reason is essentially always populated). Unknown codes fall back to an
# empty reason.
REASON_PHRASES = {
    200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
    418: "I'm a teapot", 422: "Unprocessable Entity", 429: "Too Many Requests",
    500: "Internal Server Error", 501: "Not Implemented",
    502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
}

# Header names whose values are secrets — masked in the report and artifacts
# when --redact is on.
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}

DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB cap on the response body we read

EVENTS: dict[str, int] = {"status": 0, "markdown": 0}


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    EVENTS[event["type"]] = EVENTS.get(event["type"], 0) + 1
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def parse_headers(raw: str | None) -> dict[str, str]:
    """Parse a headers block into a dict.

    Accepts either a JSON object (``{"Content-Type": "application/json"}``)
    or one ``Key: Value`` pair per line. Comments (``#``) and blank lines are
    ignored in the line format.
    """
    if not raw or not raw.strip():
        return {}

    text = raw.strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Headers are not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError("Headers JSON must be an object {\"Key\": \"Value\"}")
        return {str(k): str(v) for k, v in obj.items()}

    headers: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Header line {lineno} has no ':' separator: {line!r}")
        key, _, val = line.partition(":")
        headers[key.strip()] = val.strip()
    return headers


def parse_query(raw: str | None) -> list[tuple[str, str]]:
    """Parse a query-params block into a list of (key, value) pairs.

    Accepts a JSON object (a list value repeats the key) or one ``key=value``
    pair per line. Comments (``#``) and blank lines are ignored.
    """
    if not raw or not raw.strip():
        return []

    text = raw.strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Query params are not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError("Query params JSON must be an object {\"key\": \"value\"}")
        pairs: list[tuple[str, str]] = []
        for k, v in obj.items():
            if isinstance(v, list):
                for item in v:
                    pairs.append((str(k), str(item)))
            else:
                pairs.append((str(k), str(v)))
        return pairs

    pairs = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Query line {lineno} has no '=' separator: {line!r}")
        key, _, val = line.partition("=")
        pairs.append((key.strip(), val.strip()))
    return pairs


def apply_query(url: str, pairs: list[tuple[str, str]]) -> str:
    """Merge query pairs into the URL's existing query string."""
    if not pairs:
        return url
    parts = urlsplit(url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    merged = existing + pairs
    return urlunsplit(parts._replace(query=urlencode(merged)))


def parse_body(raw: str | None) -> tuple[Any, bool]:
    """Parse the request body.

    Returns ``(body, is_json)``: if the text is valid JSON, the parsed value is
    returned with ``is_json=True``; otherwise the raw string is returned with
    ``is_json=False``.

    A body that *looks* like intended JSON (starts with ``{`` or ``[``) but
    fails to parse is treated as a user error and raises ``ValueError`` — the
    most common mistake when hand-editing JSON bodies.
    """
    if not raw or not raw.strip():
        return None, False
    text = raw.strip()
    try:
        return json.loads(text), True
    except json.JSONDecodeError as exc:
        if text[0] in "{[":
            raise ValueError(f"Body looks like JSON but failed to parse: {exc}") from exc
        return text, False


# ---------------------------------------------------------------------------
# Request execution
# ---------------------------------------------------------------------------

def classify_error(exc: BaseException) -> str:
    """Map a requests exception to a short kind for the one-line status."""
    if isinstance(exc, requests.Timeout):
        return "timeout"
    if isinstance(exc, requests.ConnectionError):
        low = str(exc).lower()
        if ("nameresolution" in low or "failed to resolve" in low
                or "nodename" in low or "name or service not known" in low):
            return "dns"
        if "ssl" in low or "certificate" in low:
            return "tls"
        if "refused" in low:
            return "connection refused"
        return "connection error"
    if isinstance(exc, requests.RequestException):
        return "request error"
    return "invalid request"


def is_text_content(content_type: str, sample: bytes) -> bool:
    """Heuristically decide whether a response body is text."""
    ct = content_type.lower()
    text_prefixes = (
        "text/", "application/json", "application/xml",
        "application/javascript", "application/x-www-form-urlencoded",
        "application/atom+xml", "application/rss+xml", "image/svg+xml",
    )
    if any(ct.startswith(p) for p in text_prefixes):
        return True
    if ct.startswith(("image/", "video/", "audio/", "application/octet-stream")):
        return False
    # No usable content-type: sniff for NUL bytes — present in binary, not text.
    return b"\x00" not in sample


def send(method: str, url: str, headers: dict[str, str], body: Any, is_json: bool,
         timeout: int, follow_redirects: bool, max_bytes: int, insecure: bool,
         auth: tuple[str, str] | None) -> dict:
    """Execute the request and return a result record.

    The record has a fixed shape whether the request succeeded or failed, so
    every downstream stage reads this one dict and never branches on success.
    """
    record: dict[str, Any] = {
        "method": method,
        "url": url,
        "status": None,
        "reason": None,
        "responded": False,
        "headers": {},
        "headers_multi": [],
        "body_text": "",
        "body_json": None,
        "body_bytes": b"",
        "is_binary": False,
        "encoding": None,
        "content_type": "",
        "time_ms": 0,
        "ttfb_ms": 0,
        "download_ms": 0,
        "size_bytes": 0,
        "wire_bytes": None,
        "truncated": False,
        "error": None,
        "error_kind": None,
        "redirected": False,
        "history": [],
        "cookies": [],
        "insecure": insecure,
    }

    kwargs: dict[str, Any] = {
        "headers": headers,
        "timeout": timeout,
        "allow_redirects": follow_redirects,
        "stream": True,
        "verify": not insecure,
    }
    if auth is not None:
        kwargs["auth"] = auth
    if body is not None and method in BODY_METHODS:
        if is_json:
            kwargs["json"] = body
        else:
            kwargs["data"] = body

    try:
        start = time.monotonic()
        resp = requests.request(method, url, **kwargs)
        # resp.elapsed covers send -> headers received (time to first byte).
        ttfb_ms = round(resp.elapsed.total_seconds() * 1000)

        content_type = resp.headers.get("Content-Type", "")

        # Read the body with a hard cap so a huge response can't exhaust RAM.
        body_bytes = b""
        truncated = False
        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            if len(body_bytes) + len(chunk) > max_bytes:
                body_bytes += chunk[: max_bytes - len(body_bytes)]
                truncated = True
                break
            body_bytes += chunk
        # Best-effort: we already hold the bytes, so a close failure must not
        # turn a successful response into an error record.
        try:
            resp.close()
        except (OSError, requests.RequestException):
            pass

        # Let requests' helpers (text/json) operate on exactly the bytes we
        # kept, so truncation is reflected everywhere consistently.
        resp._content = body_bytes

        download_ms = round((time.monotonic() - start) * 1000) - ttfb_ms

        # Encoding: requests follows RFC 2616 and falls back to ISO-8859-1 for
        # text/* responses with no charset, which mojibakes most UTF-8 pages.
        # Promote to the sniffed encoding when the server did not state one.
        encoding = resp.encoding
        if encoding is None or (
            encoding.lower() == "iso-8859-1"
            and "charset" not in content_type.lower()
        ):
            encoding = resp.apparent_encoding or "utf-8"
            resp.encoding = encoding

        is_binary = not is_text_content(content_type, body_bytes[:1024])

        wire_len = resp.headers.get("Content-Length")
        try:
            wire_bytes = int(wire_len) if wire_len is not None else None
        except ValueError:
            wire_bytes = None

        record.update(
            status=resp.status_code,
            reason=resp.reason or REASON_PHRASES.get(resp.status_code, ""),
            responded=True,
            time_ms=ttfb_ms + max(download_ms, 0),
            ttfb_ms=ttfb_ms,
            download_ms=max(download_ms, 0),
            headers=dict(resp.headers),
            headers_multi=[[k, v] for k, v in resp.raw.headers.items()],
            content_type=content_type,
            is_binary=is_binary,
            encoding=encoding,
            size_bytes=len(body_bytes),
            wire_bytes=wire_bytes,
            truncated=truncated,
            redirected=bool(resp.history),
            history=[f"{r.status_code} → {r.url}" for r in resp.history],
            body_bytes=body_bytes,
        )

        # Cookies (redaction is applied later in the report/artifact stage).
        record["cookies"] = [
            {"name": c.name, "value": c.value or "",
             "domain": c.domain or "", "path": c.path or ""}
            for c in resp.cookies
        ]

        if is_binary:
            record["body_text"] = ""
            record["body_json"] = None
        else:
            record["body_text"] = resp.text
            try:
                record["body_json"] = resp.json()
            except (json.JSONDecodeError, ValueError):
                record["body_json"] = None

    except requests.Timeout as exc:
        record["error"] = f"timeout after {timeout}s"
        record["error_kind"] = classify_error(exc)
    except requests.ConnectionError as exc:
        record["error"] = f"connection error: {exc}"
        record["error_kind"] = classify_error(exc)
    except requests.RequestException as exc:
        record["error"] = str(exc)
        record["error_kind"] = classify_error(exc)
    except Exception as exc:  # noqa: BLE001 - required by design, see 1.3
        # e.g. requests raises ValueError for a method with non-token chars
        # before any network call — keep the fixed-shape record contract.
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["error_kind"] = classify_error(exc)

    return record


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def format_size(n: int) -> str:
    """Human-readable byte size."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def redact_value(val: str) -> str:
    """Mask a secret value, keeping its length visible for debugging."""
    if val is None:
        return ""
    return f"•••• ({len(val)} chars, redacted)"


def redact_pairs(pairs: list[list[str]], redact: bool) -> list[list[str]]:
    if not redact:
        return pairs
    return [[k, redact_value(v) if k.lower() in SENSITIVE_HEADERS else v]
            for k, v in pairs]


def esc_cell(val: Any, max_len: int = 200) -> str:
    """Escape a value for a markdown table cell.

    A ``|`` would split the row; a newline would end the table. Long values
    are truncated so one header doesn't dominate the view.
    """
    s = str(val).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s


def pick_fence(text: str) -> str:
    """A backtick fence longer than the longest backtick run in the body."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def pretty_body(record: dict, max_len: int = 20000) -> str:
    """Pretty-print the body: JSON gets indented, binary is summarised, else raw.

    Bodies longer than ``max_len`` are truncated with a note — a 5 MB response
    in a markdown view helps no one.
    """
    if record["is_binary"]:
        ct = record["content_type"] or "unknown"
        note = f"_(binary body — {esc_cell(ct)}, {format_size(record['size_bytes'])}"
        if record["truncated"]:
            note += ", truncated"
        return note + "; see response.bin)_"

    body = record["body_text"]
    if not body:
        return "_(empty body)_"

    if record["body_json"] is not None:
        pretty = json.dumps(record["body_json"], indent=2, ensure_ascii=False)
    else:
        pretty = body

    fence = pick_fence(pretty)
    if len(pretty) > max_len:
        return (f"{fence}\n{pretty[:max_len]}\n"
                f"… ({len(pretty):,} chars total, truncated)\n{fence}")

    lang = "json" if record["body_json"] is not None else ""
    return f"{fence}{lang}\n{pretty}\n{fence}"


def build_report(record: dict, *, redact: bool = False, repeat_stats: dict | None = None,
                 curl_line: str | None = None) -> str:
    """Build the markdown report — emitted once, complete."""
    if record["error"]:
        lines = [
            "## Request failed",
            "",
            f"`{record['method']} {record['url']}`",
            "",
            f"❌ **{record['error']}**"
            + (f" · _{record['error_kind']}_" if record["error_kind"] else ""),
        ]
        if record["insecure"]:
            lines += ["", "⚠️ TLS verification was **off** (insecure)."]
        return "\n".join(lines)

    status_code = record["status"]
    reason = record["reason"] or ""
    icon = "✅" if status_code is not None and status_code < 400 else "❌"

    size_line = format_size(record["size_bytes"])
    if record["wire_bytes"] is not None and record["wire_bytes"] != record["size_bytes"]:
        size_line += f" (wire {format_size(record['wire_bytes'])})"

    lines = [
        "## Response",
        "",
        (f"{icon} **{status_code} {reason}** · {record['time_ms']} ms "
         f"(TTFB {record['ttfb_ms']}, download {record['download_ms']}) · {size_line}"
         + (" · truncated" if record["truncated"] else "")),
        "",
        f"`{record['method']} {record['url']}`",
    ]

    if record["encoding"]:
        lines.append(f"_(decoded as `{record['encoding']}`)_")

    if record["insecure"]:
        lines += ["", "⚠️ **TLS verification off** — connection not checked against CAs."]

    if record["history"]:
        lines += ["", "**Redirect chain:**"]
        for hop in record["history"]:
            lines.append(f"- {hop}")

    if repeat_stats:
        lines += [
            "",
            "### Repeat timing",
            "",
            (f"{repeat_stats['count']} runs · total min **{repeat_stats['min']} ms** · "
             f"median **{repeat_stats['median']} ms** · max **{repeat_stats['max']} ms**"),
            (f"TTFB min **{repeat_stats['ttfb_min']} ms** · "
             f"median **{repeat_stats['ttfb_median']} ms** · "
             f"max **{repeat_stats['ttfb_max']} ms**"),
        ]

    if curl_line:
        lines += ["", "### Equivalent command", "", "```bash", curl_line, "```"]

    lines += ["", "### Headers", "",
              "| Header | Value |", "| --- | --- |"]
    for key, val in redact_pairs(record["headers_multi"], redact):
        lines.append(f"| `{esc_cell(key)}` | {esc_cell(val)} |")

    if record["cookies"]:
        lines += ["", "### Cookies", "",
                  "| Name | Value | Domain | Path |", "| --- | --- | --- | --- |"]
        for c in record["cookies"]:
            val = redact_value(c["value"]) if redact else c["value"]
            lines.append(f"| `{esc_cell(c['name'])}` | {esc_cell(val)} | "
                         f"{esc_cell(c['domain'])} | {esc_cell(c['path'])} |")

    lines += ["", "### Body", "", pretty_body(record)]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Request reproduction (curl + request.json)
# ---------------------------------------------------------------------------

def build_curl(method: str, url: str, headers: dict[str, str], body: Any,
               is_json: bool, redact: bool, insecure: bool,
               auth: tuple[str, str] | None) -> str:
    """Build a curl command equivalent to the request being sent."""
    parts = ["curl", "-X", method]
    if insecure:
        parts.append("-k")
    for k, v in headers.items():
        if redact and k.lower() in SENSITIVE_HEADERS:
            v = redact_value(v)
        parts += ["-H", f"{k}: {v}"]
    if auth is not None:
        user, pw = auth
        cred = f"{user}:{redact_value(pw) if redact else pw}"
        parts += ["-u", cred]
    if body is not None and method in BODY_METHODS:
        data = json.dumps(body, ensure_ascii=False) if is_json else str(body)
        parts += ["--data", data]
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


def build_request_record(method: str, url: str, headers: dict[str, str], body: Any,
                         is_json: bool, auth: tuple[str, str] | None, insecure: bool,
                         follow_redirects: bool, timeout: int, max_bytes: int,
                         redact: bool) -> dict:
    """Capture the request as sent, for the request.json artifact."""
    req_headers = dict(headers)
    if redact:
        req_headers = {k: (redact_value(v) if k.lower() in SENSITIVE_HEADERS else v)
                       for k, v in req_headers.items()}
    rec: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": req_headers,
        "body": body,
        "is_json": is_json,
        "insecure": insecure,
        "follow_redirects": follow_redirects,
        "timeout": timeout,
        "max_bytes": max_bytes,
    }
    if auth is not None:
        user, pw = auth
        rec["auth"] = {"user": user, "password": redact_value(pw) if redact else pw}
    return rec


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

def write_artifacts(record: dict, request_record: dict, *, redact: bool
                    ) -> tuple[str | None, str | None, str | None]:
    """Write request.json, response.json and the body artifact to PYSHELL_OUTPUT_DIR.

    ``response.json`` is a machine-readable record. The body artifact is
    ``response.txt`` for text bodies or ``response.bin`` for binary, and is
    skipped on network failure (no body arrived).
    """
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        print("PYSHELL_OUTPUT_DIR not set — skipping artifacts", flush=True)
        return None, None, None

    # --- request.json (always) ----------------------------------------------
    req_path = os.path.join(out_dir, "request.json")
    with open(req_path, "w", encoding="utf-8") as fh:
        json.dump(request_record, fh, indent=2, ensure_ascii=False, default=str)

    # --- response.json (always — carries the error on failure too) ----------
    headers_multi = redact_pairs(record["headers_multi"], redact)
    cookies = record["cookies"]
    if redact:
        cookies = [{**c, "value": redact_value(c["value"])} for c in cookies]

    json_record: dict[str, Any] = {
        "method": record["method"],
        "url": record["url"],
        "status": record["status"],
        "reason": record["reason"],
        "responded": record["responded"],
        "time_ms": record["time_ms"],
        "ttfb_ms": record["ttfb_ms"],
        "download_ms": record["download_ms"],
        "size_bytes": record["size_bytes"],
        "wire_bytes": record["wire_bytes"],
        "truncated": record["truncated"],
        "redirected": record["redirected"],
        "history": record["history"],
        "encoding": record["encoding"],
        "content_type": record["content_type"],
        "is_binary": record["is_binary"],
        "headers": record["headers"],
        "headers_multi": headers_multi,
        "cookies": cookies,
        "error": record["error"],
        "error_kind": record["error_kind"],
        "insecure": record["insecure"],
    }
    if record["is_binary"]:
        json_record["body"] = f"<{format_size(record['size_bytes'])} binary, see response.bin>"
    else:
        json_record["body"] = (record["body_json"] if record["body_json"] is not None
                               else record["body_text"])

    json_path = os.path.join(out_dir, "response.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(json_record, fh, indent=2, ensure_ascii=False, default=str)

    # --- body artifact (skipped on network failure) -------------------------
    body_path = None
    if not record["error"]:
        if record["is_binary"]:
            body_path = os.path.join(out_dir, "response.bin")
            with open(body_path, "wb") as fh:
                fh.write(record["body_bytes"])
        else:
            body_path = os.path.join(out_dir, "response.txt")
            with open(body_path, "w", encoding="utf-8") as fh:
                fh.write(record["body_text"])

    return req_path, json_path, body_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _input_error(message: str) -> int:
    """Report an input-parse failure to Results (not just the log) and exit 2."""
    print(message, file=sys.stderr, flush=True)
    emit({"type": "markdown", "content": f"## Input error\n\n❌ {message}"})
    status("Input error")
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="HTTP Request — request inspector")
    parser.add_argument("--method", type=str, default="GET", help="HTTP method")
    parser.add_argument("--url", type=str, required=True, help="Request URL")
    parser.add_argument("--query", type=str, default=None,
                        help="Query params: JSON object or 'key=value' per line")
    parser.add_argument("--headers", type=str, default=None,
                        help="Headers: JSON object or 'Key: Value' per line")
    parser.add_argument("--body", type=str, default=None,
                        help="Request body (JSON or raw text)")
    parser.add_argument("--auth-user", type=str, default=None,
                        help="Basic-auth username (pair with AUTH_PASSWORD env)")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout in seconds")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help="Max response body bytes to read into memory")
    parser.add_argument("--follow-redirects", action=argparse.BooleanOptionalAction,
                        default=False, help="Follow 3xx redirects (PyShell passes "
                                            "the flag only when the toggle is on)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification")
    parser.add_argument("--redact", action="store_true",
                        help="Mask sensitive headers/cookies in output and artifacts")
    parser.add_argument("--repeat", type=int, default=1,
                        help="Repeat the request N times and report timing")
    parser.add_argument("--verbose", action="store_true",
                        help="Print the request being sent")
    args = parser.parse_args()

    # Introspection builds the form from argparse; no request should be sent.
    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no request sent", flush=True)
        return 0

    method = args.method.upper()
    url = args.url
    auth_token = os.environ.get("AUTH_TOKEN")
    auth_password = os.environ.get("AUTH_PASSWORD")
    redact = args.redact
    insecure = args.insecure
    repeat = max(1, args.repeat)

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"PyShell detected: {UNDER_PYSHELL}", flush=True)

    # --- parse query params -------------------------------------------------
    try:
        query_pairs = parse_query(args.query)
    except ValueError as exc:
        return _input_error(f"Cannot parse query params: {exc}")

    # --- parse headers ------------------------------------------------------
    try:
        headers = parse_headers(args.headers)
    except ValueError as exc:
        return _input_error(f"Cannot parse headers: {exc}")

    # Bearer token comes from env (Keychain), never argv.
    if auth_token:
        headers.setdefault("Authorization", f"Bearer {auth_token}")

    # --- parse body ---------------------------------------------------------
    try:
        body, is_json = parse_body(args.body)
    except ValueError as exc:
        return _input_error(f"Cannot parse body: {exc}")

    if body is not None and method not in BODY_METHODS:
        print(f"Note: body ignored for {method} (no body allowed)", flush=True)
        body = None

    # A raw-text body with no Content-Type often 415s; default to text/plain.
    if body is not None and not is_json and method in BODY_METHODS:
        has_ct = any(k.lower() == "content-type" for k in headers)
        if not has_ct:
            headers["Content-Type"] = "text/plain; charset=utf-8"
            print("Note: no Content-Type set for raw body — "
                  "defaulting to text/plain; charset=utf-8", flush=True)

    # --- basic auth ---------------------------------------------------------
    auth = (args.auth_user, auth_password or "") if args.auth_user else None

    # --- url + query --------------------------------------------------------
    url = apply_query(url, query_pairs)

    print(f"{method} {url}", flush=True)
    if args.verbose:
        display_headers = headers
        if redact:
            display_headers = {k: (redact_value(v) if k.lower() in SENSITIVE_HEADERS else v)
                               for k, v in headers.items()}
        print(f"  headers: {json.dumps(display_headers) if display_headers else '(none)'}",
              flush=True)
        if body is not None:
            preview = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
            print(f"  body: {preview[:200]}", flush=True)
        print(f"  follow_redirects: {args.follow_redirects}", flush=True)
        if insecure:
            print("  ⚠️ TLS verification OFF", flush=True)
        if auth:
            print(f"  auth: basic as {args.auth_user}", flush=True)

    # --- send (with optional repeat) ----------------------------------------
    status(f"Sending {method} {url}…")
    records: list[dict] = []
    for i in range(repeat):
        rec = send(method, url, headers, body, is_json, args.timeout,
                   args.follow_redirects, args.max_bytes, insecure, auth)
        records.append(rec)
        if rec["error"]:
            break
        if repeat > 1:
            status(f"Run {i + 1}/{repeat}: {rec['status']} · {rec['time_ms']} ms")

    final = records[-1]

    repeat_stats = None
    if repeat > 1 and not final["error"]:
        times = [r["time_ms"] for r in records]
        ttfbs = [r["ttfb_ms"] for r in records]
        repeat_stats = {
            "count": len(records),
            "min": min(times), "max": max(times),
            "median": int(statistics.median(times)),
            "ttfb_min": min(ttfbs), "ttfb_max": max(ttfbs),
            "ttfb_median": int(statistics.median(ttfbs)),
        }

    if final["error"]:
        print(f"✗ {final['error']}", flush=True)
    else:
        print(f"← {final['status']} {final['reason']} "
              f"({final['time_ms']} ms, {format_size(final['size_bytes'])})",
              flush=True)

    # --- report & artifacts -------------------------------------------------
    curl_line = build_curl(method, url, headers, body, is_json, redact, insecure, auth)
    request_record = build_request_record(method, url, headers, body, is_json, auth,
                                          insecure, args.follow_redirects, args.timeout,
                                          args.max_bytes, redact)
    report = build_report(final, redact=redact, repeat_stats=repeat_stats,
                          curl_line=curl_line)
    emit({"type": "markdown", "content": report})

    req_path, json_path, body_path = write_artifacts(final, request_record, redact=redact)
    if req_path:
        print(f"Wrote {req_path}", flush=True)
    if json_path:
        print(f"Wrote {json_path}", flush=True)
    if body_path:
        print(f"Wrote {body_path}", flush=True)

    if final["error"]:
        status(f"Failed: {final['error_kind'] or 'error'}")
    else:
        status(f"{final['status']} {final['reason']} · {final['time_ms']} ms")

    print(
        f"\n{EVENTS['status']} status, {EVENTS['markdown']} markdown events",
        flush=True,
    )

    # Exit codes: a 4xx/5xx response is a successful *run* (we got an answer),
    # so exit 0. A network error or bad input is a real failure.
    if final["error"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
