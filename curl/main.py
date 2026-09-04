#!/usr/bin/env python3
"""curl/main.py — PyShell wrapper around the system curl binary.

Builds a curl command line from form inputs, executes it, and renders a
markdown report (command, status, headers, body) as a structured event.
No third-party dependencies: only the standard library plus the `curl`
binary on PATH.

Credentials never reach curl's argv: they go into a curl config file fed
through stdin (`curl -K -`), so `ps` never sees them at all.
"""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple

EVENTS = {"progress": 0, "status": 0, "markdown": 0}

MASK = "***"

# curl has no `--http-version`; each version is its own flag.
HTTP_VERSION_FLAGS = {
    "1.0": "--http1.0",
    "1.1": "--http1.1",
    "2": "--http2",
    "2-prior-knowledge": "--http2-prior-knowledge",
    "3": "--http3",
}

# Values masked in the report and in command.sh when typed into Headers.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
}

STATUS_LINE_RE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+\d{3}")

# `--json` landed in curl 7.82, `%output{}` in --write-out in curl 8.3.
JSON_FLAG_SINCE = (7, 82)
WRITE_OUT_FILE_SINCE = (8, 3)

# curl's own pause between retries when --retry-delay is absent or zero:
# one second, doubling each attempt, capped at ten minutes.
RETRY_BACKOFF_CAP = 600

_curl_version: tuple[int, int, int] | None = None


def emit(event: dict) -> None:
    event["pyshell"] = True
    EVENTS[event["type"]] = EVENTS.get(event["type"], 0) + 1
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def read_lines(path: str | None) -> list[str]:
    if not path or not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f.read().splitlines() if ln.strip()]


def has_line_breaks(path: str) -> bool:
    """Whether a body file holds the CR/LF that `-d @file` would strip."""
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                if b"\n" in chunk or b"\r" in chunk:
                    return True
    except OSError:
        pass
    return False


def retry_budget(retries: int, retry_delay: int | None) -> int:
    """Seconds curl may spend sleeping between attempts.

    `--retry-delay` pins the pause only when it is non-zero — both zero and
    absent mean curl's default backoff instead. Budgeting `retry_delay *
    retries` for those cuts the process off in the middle of the series.
    """
    if retry_delay:
        return retry_delay * retries
    return sum(min(2 ** i, RETRY_BACKOFF_CAP) for i in range(retries))


def curl_version() -> tuple[int, int, int]:
    """Version of the curl on PATH, or (0, 0, 0) if it cannot be read."""
    global _curl_version
    if _curl_version is not None:
        return _curl_version
    _curl_version = (0, 0, 0)
    try:
        out = subprocess.run(
            ["curl", "--version"], capture_output=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return _curl_version
    m = re.search(rb"curl\s+(\d+)\.(\d+)(?:\.(\d+))?", out)
    if m:
        _curl_version = (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    return _curl_version


def curl_at_least(minimum: tuple[int, int]) -> bool:
    return curl_version() >= minimum


def curl_accepts(*option: str) -> bool:
    """Whether this libcurl build accepts an option.

    Some options exist in the parser but are refused by the build behind it —
    `--dns-servers` needs c-ares, which the curl shipped with macOS lacks. A
    no-op `file://` transfer answers the question without touching the network.
    """
    if not os.path.exists(os.devnull):
        return True
    try:
        probe = subprocess.run(
            ["curl", *option, "-s", "-o", os.devnull, f"file://{os.devnull}"],
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def _split_at_blank_line(buf: bytes) -> tuple[bytes, bytes] | None:
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = buf.find(sep)
        if i != -1:
            return buf[:i], buf[i + len(sep):]
    return None


def last_header_block(raw: bytes) -> tuple[bytes, bytes]:
    """Split a header stream into (final header block, whatever follows).

    curl writes one block per response, so a redirect chain or a `100 Continue`
    leaves several stacked up — with `-L` the interesting one is the last. The
    status-line check keeps a body that happens to start with `HTTP/` from
    being mistaken for another block.
    """
    block = b""
    rest = raw
    for _ in range(64):
        if not STATUS_LINE_RE.match(rest):
            break
        split = _split_at_blank_line(rest)
        if split is None:
            block, rest = rest, b""
            break
        block, rest = split
    return block, rest


def parse_header_block(block: bytes) -> tuple[str, list[tuple[str, str]]]:
    lines = block.decode("utf-8", errors="replace").splitlines()
    status_line = lines[0].strip() if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return status_line, headers


def body_preview(
    body_bytes: bytes, saved: bool, max_chars: int = 50000
) -> tuple[str | None, str | None]:
    where = "full body saved to response.txt" if saved else "enable Save body to keep it"
    if b"\x00" in body_bytes:
        return None, f"[Binary content — {len(body_bytes)} bytes; {where}]"
    text = body_bytes.decode("utf-8", errors="replace")
    if len(text) > max_chars:
        text = text[:max_chars] + (
            f"\n\n… [truncated — {len(body_bytes)} bytes total; {where}]"
        )
    return text, None


def fence_lang(headers: list[tuple[str, str]]) -> str:
    ct = ""
    for k, v in headers:
        if k.lower() == "content-type":
            ct = v.lower()
            break
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    return ""


def md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def mask_header(line: str) -> str:
    if ":" not in line:
        return line
    name, _ = line.split(":", 1)
    if name.strip().lower() in SENSITIVE_HEADERS:
        return f"{name}: {MASK}"
    return line


def mask_cookie(raw: str) -> str:
    """Keep cookie names visible, hide the values."""
    if os.path.isfile(raw):  # -b also accepts a cookie file
        return raw
    parts = []
    for chunk in raw.split(";"):
        name, sep, _ = chunk.partition("=")
        parts.append(f"{name}{sep}{MASK}" if sep else chunk)
    return ";".join(parts)


def config_line(option: str, value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\t", "\\t")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )
    return f'{option} = "{escaped}"'


def render_config(entries: list[tuple[str, str, str]], mask: bool) -> str:
    return "\n".join(config_line(opt, shown if mask else real) for opt, real, shown in entries)


def is_head(args) -> bool:
    return args.head or args.method.upper() == "HEAD"


class Plan(NamedTuple):
    cmd: list[str]           # what actually runs
    shown: list[str]         # what the report and command.sh display
    config: list[tuple[str, str, str]]  # (curl option, real value, masked value)
    header_file: str | None  # auto --dump-header target, when we added one
    write_out_file: str | None
    temps: list[str]
    head_mode: bool


def build_command(args, warnings: list[str]) -> Plan:
    cmd: list[str] = ["curl"]
    shown: list[str] = ["curl"]
    config: list[tuple[str, str, str]] = []
    temps: list[str] = []

    def add(*parts: str, display: list[str] | None = None) -> None:
        cmd.extend(parts)
        shown.extend(parts if display is None else display)

    def add_internal(*parts: str) -> None:
        """Plumbing the operator did not ask for — kept out of the shown command."""
        cmd.extend(parts)

    def new_temp(suffix: str) -> str:
        fh = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        fh.close()
        temps.append(fh.name)
        return fh.name

    if args.silent:
        add("-s")
    if args.show_error:
        add("-S")
    if args.verbose:
        add("-v")
    if args.fail:
        add("-f")
    if args.compressed:
        add("--compressed")

    head_mode = is_head(args)
    if head_mode:
        add("-I")
        if not args.head:
            warnings.append(
                "Method `HEAD` was sent as `-I`. `-X HEAD` makes curl wait for a "
                "response body that never arrives, so it hangs until the timeout."
            )
    elif args.method != "GET":
        add("-X", args.method)

    if args.data:
        # Under PyShell this is a temp file (binding: temp_file); from the CLI it
        # may well be the body itself, which used to be dropped without a word.
        ref = f"@{args.data}" if os.path.isfile(args.data) else args.data
        if args.data_mode == "json":
            if curl_at_least(JSON_FLAG_SINCE):
                add("--json", ref)
            else:
                warnings.append(
                    "`--json` needs curl 7.82+; sent as a raw body with explicit "
                    "Content-Type and Accept headers instead."
                )
                add("-H", "Content-Type: application/json")
                add("-H", "Accept: application/json")
                add("-d", ref)
        elif args.data_mode == "binary":
            add("--data-binary", ref)
        elif args.data_mode == "urlencoded":
            # `@file` makes curl encode the whole file. Passing the contents
            # instead would make curl read everything up to the first `=` as a
            # field name and leave it unencoded.
            add("--data-urlencode", ref)
        else:
            if ref.startswith("@") and has_line_breaks(args.data):
                warnings.append(
                    "Body encoding `Raw` sends the body with `-d`, and curl strips "
                    "carriage returns and newlines out of a file body — it went out "
                    "as a single line. Use `Binary` or `JSON` to send it verbatim."
                )
            add("-d", ref)

    for line in read_lines(args.headers):
        add("-H", line, display=["-H", mask_header(line)])

    if args.user_agent:
        add("-A", args.user_agent)
    if args.referer:
        add("-e", args.referer)
    if args.include:
        add("-i")

    if args.connect_timeout is not None:
        add("--connect-timeout", str(args.connect_timeout))
    if args.max_time is not None:
        add("--max-time", str(args.max_time))
    if args.location:
        add("-L")
    if args.max_redirs is not None:
        add("--max-redirs", str(args.max_redirs))
    if args.retry is not None:
        add("--retry", str(args.retry))
    if args.retry_delay is not None:
        add("--retry-delay", str(args.retry_delay))
    if args.http_version != "default":
        flag = HTTP_VERSION_FLAGS.get(args.http_version)
        if flag:
            add(flag)
        else:
            warnings.append(f"Unknown HTTP version `{args.http_version}` — ignored.")
    if args.ipv4:
        add("-4")
    if args.ipv6:
        add("-6")
    if args.interface:
        add("--interface", args.interface)

    if args.insecure:
        add("-k")
    if args.cert:
        add("--cert", args.cert)
    if args.key:
        add("--key", args.key)
    if args.cacert:
        add("--cacert", args.cacert)
    if args.ciphers:
        add("--ciphers", args.ciphers)
    if args.tls_max != "default":
        add("--tls-max", args.tls_max)

    token = os.environ.get("BEARER_TOKEN", "")
    if token:
        config.append(
            ("header", f"Authorization: Bearer {token}", f"Authorization: Bearer {MASK}")
        )

    if args.auth_method != "none":
        if args.auth_method == "ntlm":
            add("--ntlm")
        elif args.auth_method == "negotiate":
            add("--negotiate")
        elif args.auth_method == "anyauth":
            add("--anyauth")
        user = args.auth_user or ""
        pwd = os.environ.get("AUTH_PASSWORD", "")
        # `-u :` is the documented idiom for the GSS-API methods, which take the
        # credentials from the ticket cache. For Basic it just sends an empty
        # Authorization header, so skip it.
        if user or pwd or args.auth_method in ("ntlm", "negotiate", "anyauth"):
            config.append(("user", f"{user}:{pwd}", f"{user}:{MASK}"))
        else:
            warnings.append(
                f"Auth method `{args.auth_method}` selected with no username and no "
                "password — no credentials were sent."
            )

    if args.proxy:
        add("--proxy", args.proxy)
    if args.proxy_user:
        proxy_pwd = os.environ.get("PROXY_PASSWORD", "")
        config.append(
            ("proxy-user", f"{args.proxy_user}:{proxy_pwd}", f"{args.proxy_user}:{MASK}")
        )
    if args.noproxy:
        add("--noproxy", args.noproxy)

    if args.cookie:
        add("-b", args.cookie, display=["-b", mask_cookie(args.cookie)])
    if args.cookie_jar:
        add("-c", args.cookie_jar)

    write_out_file = None
    if args.write_out:
        if curl_at_least(WRITE_OUT_FILE_SINCE):
            # Without %output{} the write-out text lands in stdout, glued to the
            # response body — which also corrupts the response.txt artifact.
            write_out_file = new_temp(".writeout")
            add(
                "-w",
                "%output{" + write_out_file + "}" + args.write_out,
                display=["-w", args.write_out],
            )
        else:
            warnings.append(
                "`--write-out` needs curl 8.3+ to write to its own file; on this "
                "version its output is appended to the response body."
            )
            add("-w", args.write_out)

    if args.dump_header:
        add("--dump-header", args.dump_header)

    for line in read_lines(args.resolve):
        add("--resolve", line)
    for line in read_lines(args.connect_to):
        add("--connect-to", line)
    if args.dns_servers:
        if curl_accepts("--dns-servers", "1.1.1.1"):
            add("--dns-servers", args.dns_servers)
        else:
            warnings.append(
                "`--dns-servers` needs a libcurl built with c-ares, which the curl "
                "shipped with macOS is not — the field was ignored. Use "
                "DNS-over-HTTPS or `--resolve` instead."
            )
    if args.doh_url:
        add("--doh-url", args.doh_url)
    if args.unix_socket:
        add("--unix-socket", args.unix_socket)
    if args.no_keepalive:
        add("--no-keepalive")
    if args.keepalive_time is not None:
        add("--keepalive-time", str(args.keepalive_time))

    if config:
        add("-K", "-")

    header_file = None
    if not (head_mode or args.include or args.dump_header):
        header_file = new_temp(".hdr")
        add_internal("--dump-header", header_file)

    add(args.url)
    return Plan(cmd, shown, config, header_file, write_out_file, temps, head_mode)


def render_command(plan: Plan) -> str:
    """The command as the operator should see it — secrets masked, plumbing gone."""
    line = shlex.join(plan.shown)
    if not plan.config:
        return line
    return f"{line} <<'CURLRC'\n{render_config(plan.config, mask=True)}\nCURLRC"


def main() -> int:
    parser = argparse.ArgumentParser(description="curl wrapper for PyShell")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--data", default=None)
    parser.add_argument("--data-mode", default="raw")
    parser.add_argument("--headers", default=None)
    parser.add_argument("--user-agent", default=None)
    parser.add_argument("--referer", default=None)
    parser.add_argument("--include", action="store_true")
    parser.add_argument("--head", action="store_true")
    parser.add_argument("--fail", action="store_true")
    parser.add_argument("--connect-timeout", type=int, default=None)
    parser.add_argument("--max-time", type=int, default=None)
    parser.add_argument("--location", action="store_true")
    parser.add_argument("--max-redirs", type=int, default=None)
    parser.add_argument("--retry", type=int, default=None)
    parser.add_argument("--retry-delay", type=int, default=None)
    parser.add_argument("--compressed", action="store_true")
    parser.add_argument("--http-version", default="default")
    parser.add_argument("--ipv4", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--interface", default=None)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--cert", default=None)
    parser.add_argument("--key", default=None)
    parser.add_argument("--cacert", default=None)
    parser.add_argument("--ciphers", default=None)
    parser.add_argument("--tls-max", default="default")
    parser.add_argument("--auth-method", default="none")
    parser.add_argument("--auth-user", default=None)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--proxy-user", default=None)
    parser.add_argument("--noproxy", default=None)
    parser.add_argument("--cookie", default=None)
    parser.add_argument("--cookie-jar", default=None)
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--show-error", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--write-out", default=None)
    parser.add_argument("--dump-header", default=None)
    parser.add_argument("--resolve", default=None)
    parser.add_argument("--connect-to", default=None)
    parser.add_argument("--dns-servers", default=None)
    parser.add_argument("--doh-url", default=None)
    parser.add_argument("--unix-socket", default=None)
    parser.add_argument("--no-keepalive", action="store_true")
    parser.add_argument("--keepalive-time", type=int, default=None)
    parser.add_argument("--save-body", action="store_true")

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode, skipping real work", flush=True)
        sys.exit(0)

    args = parser.parse_args()

    if not shutil.which("curl"):
        msg = "`curl` binary not found in PATH"
        print(f"Error: {msg}", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content": f"## curl\n\n**Error:** {msg}\n"})
        emit({"type": "progress", "pct": 100, "message": "curl not found"})
        return 1

    status("Building curl command…")
    warnings: list[str] = []
    plan = build_command(args, warnings)

    try:
        emit({"type": "progress", "pct": 10, "message": "Executing curl…"})
        status("Executing curl…")
        start = time.monotonic()

        # curl applies --max-time per attempt, so retries legitimately run past
        # it; the outer guard has to allow for all of them plus the sleeping in
        # between, which is curl's backoff unless --retry-delay pins it.
        retries = args.retry or 0
        py_timeout = (
            (args.max_time or 300) * (retries + 1)
            + retry_budget(retries, args.retry_delay)
            + 10
        )

        config_text = render_config(plan.config, mask=False)
        try:
            proc = subprocess.run(
                plan.cmd,
                input=config_text.encode("utf-8"),
                capture_output=True,
                timeout=py_timeout,
            )
        except subprocess.TimeoutExpired:
            msg = f"curl timed out after {py_timeout}s"
            print(f"Error: {msg}", file=sys.stderr, flush=True)
            emit({"type": "markdown", "content": f"## curl\n\n**Error:** {msg}\n"})
            emit({"type": "progress", "pct": 100, "message": "Timed out"})
            return 1
        elapsed = time.monotonic() - start

        emit({"type": "progress", "pct": 80, "message": "Parsing response…"})
        stdout = proc.stdout or b""
        stderr = proc.stderr or b""
        rc = proc.returncode

        if plan.head_mode:
            block, _ = last_header_block(stdout)
            status_line, headers = parse_header_block(block)
            body_bytes = b""
        elif args.include:
            block, body_bytes = last_header_block(stdout)
            status_line, headers = parse_header_block(block)
        else:
            status_line, headers = "", []
            hdr_path = args.dump_header or plan.header_file
            if hdr_path:
                try:
                    with open(hdr_path, "rb") as f:
                        block, _ = last_header_block(f.read())
                    status_line, headers = parse_header_block(block)
                except OSError:
                    pass
            body_bytes = stdout

        write_out_text = ""
        if plan.write_out_file:
            try:
                with open(plan.write_out_file, "r", encoding="utf-8", errors="replace") as f:
                    write_out_text = f.read()
            except OSError:
                pass

        out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, "command.sh"), "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
                if plan.config:
                    f.write(f"# Secrets are masked as {MASK} — fill them in before running.\n")
                f.write(render_command(plan) + "\n")
            with open(os.path.join(out_dir, "headers.txt"), "w", encoding="utf-8") as f:
                f.write(status_line + "\n")
                for k, v in headers:
                    f.write(f"{k}: {v}\n")
            if args.save_body:
                with open(os.path.join(out_dir, "response.txt"), "wb") as f:
                    f.write(body_bytes)

        lines = ["## curl", "", "```sh", render_command(plan), "```", ""]
        lines.append(f"**Exit code:** `{rc}`  ·  **Elapsed:** `{elapsed:.2f}s`")
        lines.append("")

        if warnings:
            lines.append("**Notes:**")
            lines.extend(f"- {w}" for w in warnings)
            lines.append("")

        if stderr.strip() and (rc != 0 or args.verbose):
            diag = stderr.decode("utf-8", errors="replace").strip().splitlines()
            if args.verbose:
                # A -v trace is only useful from the top, where the handshake is.
                head, tail = diag[:400], []
                note = [f"… [trace truncated — {len(diag)} lines total]"] if len(diag) > 400 else []
            else:
                head, tail, note = diag[-12:], [], []
            lines.append("**curl diagnostics:**")
            lines.append("```")
            lines.extend(head + tail + note)
            lines.append("```")
            lines.append("")

        lines += ["### Response", ""]
        if status_line:
            lines.append(f"**Status:** `{status_line}`")
            lines.append("")
        if headers:
            lines += ["| Header | Value |", "| --- | --- |"]
            for k, v in headers:
                lines.append(f"| `{md_escape(k)}` | {md_escape(v)} |")
            lines.append("")
        else:
            lines += ["_No headers captured._", ""]

        if write_out_text.strip():
            lines += ["### Write-out", "", "```", write_out_text.rstrip("\n"), "```", ""]

        lines += ["### Body", ""]
        preview, binary_note = body_preview(body_bytes, args.save_body)
        if binary_note:
            lines.append(binary_note)
        elif preview:
            lines.append(f"```{fence_lang(headers)}")
            lines.append(preview)
            lines.append("```")
        else:
            lines.append("_Empty body._")
        lines.append("")

        emit({"type": "markdown", "content": "\n".join(lines)})
        emit({"type": "progress", "pct": 100, "message": "Done"})

        status_msg = f"Done — exit {rc}"
        if status_line:
            status_msg += f", {status_line}"
        status(status_msg)

        print(f"curl exited with code {rc} in {elapsed:.2f}s", flush=True)
        print(f"Events sent: {EVENTS}", flush=True)
        return 0
    finally:
        for path in plan.temps:
            try:
                os.unlink(path)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
