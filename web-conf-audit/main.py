#!/usr/bin/env python3
"""web-conf-audit/main.py — what the web server config actually allows.

The fw-audit shape, applied to the web server: **Security Headers**
sees what reaches the browser, **this script** reads *why* it is
that way — the saved config that produced it.  nginx (main config,
site configs, vhosts), Apache (apache2.conf, vhosts) and
`.htaccess` files are recognized automatically and reviewed
passively: nothing runs as root, nothing is reloaded.

The checks, per format:

- **Directory listings** — `autoindex on` (nginx), `+Indexes`
  (apache): every path without an index file becomes a file browser.
- **Version banners** — `server_tokens` (nginx defaults **on** when
  absent — the absent case is flagged, not just the explicit one),
  `ServerTokens`/`ServerSignature` (apache defaults Full/On).
- **TLS** — `ssl_protocols`/`SSLProtocol` and
  `ssl_ciphers`/`SSLCipherSuite` graded on the tls-audit scale:
  TLSv1/TLSv1.1 are red, TLSv1.2 the floor, TLSv1.3 the good case;
  3DES/RC4/NULL/EXPORT/aNULL ciphers are red.
- **PHP inside uploads** — a `location ~ \\.php$` (or apache
  `FilesMatch`) that executes anywhere it finds a file, while
  nothing keeps `uploads/` out of it — the classic upload-a-shell
  path.  The safe shapes (an uploads location with `deny`/engine
  off) are recognized and praised.
- **Security headers** — which of the core six are actually
  `add_header`'d / `Header set`: the same list Security Headers
  grades; here it explains its zeroes.
- **Upload size** — `client_max_body_size`/`LimitRequestBody`
  absent (nginx: 1m default; apache: unlimited) or huge.
- **Compression** — no `gzip`/`brotli` left on the table.
- **Proxy Host** — `proxy_pass` without
  `proxy_set_header Host` in the same block: the backend sees the
  wrong vhost.

Unrecognized files are reported as such, never interpreted.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field

SECURITY_HEADERS = ["Strict-Transport-Security", "X-Content-Type-Options",
                    "X-Frame-Options", "Content-Security-Policy",
                    "Referrer-Policy", "Permissions-Policy"]

WEAK_CIPHERS = ("3DES", "RC4", "NULL", "EXPORT", "aNULL", "MD5",
                "DES-CBC")
WEAK_TLS = ("TLSv1 ", "TLSv1.1", "SSLv2", "SSLv3", "TLSv1\t",
            "TLSv1;")

GOOD_TLS = ("TLSv1.3",)
FLOOR_TLS = ("TLSv1.2",)


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# -------------------------------------------------------------------- model

@dataclass
class Flag:
    severity: str        # critical | warning | info | good
    check: str
    detail: str
    where: str = ""


@dataclass
class WebConfig:
    path: str
    fmt: str = "unknown"    # nginx | apache | htaccess | unknown
    flags: list[Flag] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    verdict: str = ""


# ---------------------------------------------------------------- detection

def detect_format(text: str, path: str) -> str:
    if os.path.basename(path) == ".htaccess":
        return "htaccess"
    head = text[:8000]
    nginx_marks = sum(bool(re.search(p, head, re.M)) for p in
                      (r"^\s*server\s*\{", r"^\s*location\s", r"^\s*server_name\s",
                       r"^\s*ssl_protocols\s", r"^\s*fastcgi_pass\s",
                       r"^\s*proxy_pass\s", r"^\s*http\s*\{"))
    apache_marks = sum(bool(re.search(p, head, re.M)) for p in
                       (r"<VirtualHost", r"<Directory", r"^\s*ServerTokens\s",
                        r"^\s*SSLEngine\s", r"^\s*DocumentRoot\s",
                        r"^\s*Options\s+[+-]?Indexes", r"<IfModule",
                        r"^\s*php_(?:value|flag|admin_value|admin_flag)\s"))
    if nginx_marks >= apache_marks and nginx_marks >= 2:
        return "nginx"
    if apache_marks >= 2:
        return "apache"
    return "unknown"


# ------------------------------------------------------------------ parsers

def tls_flags(protocols: str, ciphers: str, prefix: str) -> list[Flag]:
    flags: list[Flag] = []
    if protocols:
        # apache syntax: "all -SSLv3 -TLSv1" — a minus token DISABLES
        tokens = protocols.split()
        disabled = [t for t in tokens if t.startswith("-")]
        enabled = " ".join(t for t in tokens if not t.startswith("-"))
        weak_hits = [t for t in enabled.split()
                     if t in ("SSLv2", "SSLv3", "TLSv1.1", "TLSv1")]
        if weak_hits:
            flags.append(Flag("critical", "tls",
                              f"{prefix} enables "
                              f"{', '.join(weak_hits)} — the tls-audit "
                              "scale puts these in the red band; "
                              "browsers reject them since 2020"))
        elif "all" in enabled and disabled:
            flags.append(Flag("good", "tls",
                              f"{prefix}: {protocols.strip()} — "
                              "everything except the old protocols "
                              "(modern on any current build)"))
        elif any(g in enabled for g in GOOD_TLS) \
                or any(f in enabled for f in FLOOR_TLS):
            flags.append(Flag("good", "tls",
                              f"{prefix}: {enabled.strip()} — modern "
                              "protocols only"))
        else:
            flags.append(Flag("info", "tls",
                              f"{prefix}: {protocols.strip()}"))
    else:
        flags.append(Flag("info", "tls",
                          f"no {prefix} directive — the enabled "
                          "protocols depend on the server version and "
                          "its defaults"))
    if ciphers:
        # "!3DES" in a cipher list EXCLUDES it — negations are the
        # point; only non-negated tokens count
        active = ":".join(t for t in re.split(r"[:,\s]+", ciphers)
                          if not t.startswith("!"))
        weak = [c for c in WEAK_CIPHERS if c in active]
        if weak:
            flags.append(Flag("critical", "tls",
                              f"{prefix} cipher list contains "
                              f"{', '.join(weak)} — broken primitives, "
                              "red on every scale"))
    return flags


def header_coverage(text: str, add_pat: str) -> tuple[list[str], list[str]]:
    """(present, missing) of the core security headers, given the
    format's add-header syntax."""
    present = []
    for h in SECURITY_HEADERS:
        if re.search(add_pat.format(header=re.escape(h)), text, re.I):
            present.append(h)
    return present, [h for h in SECURITY_HEADERS if h not in present]


def parse_nginx(text: str, cfg: WebConfig) -> None:
    if re.search(r"^\s*autoindex\s+on\s*;", text, re.M):
        where = " ; ".join(m.group(0).strip()
                           for m in
                           re.finditer(r"^\s*location[^\n]*\{?[^;]*"
                                       r"autoindex\s+on", text))[:120]
        cfg.flags.append(Flag(
            "warning", "listings",
            "autoindex on — paths without an index file become "
            "directory browsers" + (f" ({where})" if where else ""),
            ))
    if re.search(r"^\s*server_tokens\s+on\s*;", text, re.M):
        cfg.flags.append(Flag("warning", "banners",
                              "server_tokens on — the version banner "
                              "ships with every response and every "
                              "error page"))
    elif not re.search(r"^\s*server_tokens\s+off\s*;", text, re.M):
        cfg.notes.append("server_tokens not set — nginx defaults to "
                         "**on** (the version banner) unless the "
                         "distro turned it off in nginx.conf")
    protocols = ""
    m = re.search(r"^\s*ssl_protocols\s+([^;]+);", text, re.M)
    if m:
        protocols = m.group(1)
    m = re.search(r"^\s*ssl_ciphers\s+([^;]+);", text, re.M)
    ciphers = m.group(1) if m else ""
    cfg.flags.extend(tls_flags(protocols, ciphers, "ssl_protocols"))

    # php execution vs uploads
    php_blocks = re.findall(r"location\s+[^{\n]*\\?\.php[^{\n]*\{",
                            text)
    uploads_guard = re.search(r"location\s+\S*uploads\S*\s*\{", text) \
        and re.search(r"uploads[^\n]*\n(?:(?!location)[^\n]*\n)*?"
                      r"\s*(deny|return\s+403)", text)
    if php_blocks:
        if uploads_guard:
            cfg.flags.append(Flag("good", "php-uploads",
                                  "PHP handler present and uploads/ "
                                  "explicitly denied — the safe shape"))
        else:
            cfg.flags.append(Flag(
                "warning", "php-uploads",
                f"PHP executes wherever a *.php file is found "
                f"({len(php_blocks)} handler location(s)) and nothing "
                "keeps uploads/ out of it — an uploaded shell runs; "
                "deny php in the uploads location or serve it from "
                "another root"))
    m = re.search(r"^\s*client_max_body_size\s+(\d+)([kKmMgG]?)\s*;",
                  text, re.M)
    if m:
        size = int(m.group(1)) * {"": 1, "k": 1024, "m": 1024 ** 2,
                                  "g": 1024 ** 3}.get(
            m.group(2).lower(), 1)
        if size > 64 * 1024 * 1024:
            cfg.flags.append(Flag(
                "warning", "uploads",
                f"client_max_body_size {m.group(1)}{m.group(2)} — a very "
                "generous upload ceiling"))
    else:
        cfg.notes.append("client_max_body_size not set — nginx "
                         "default is 1m (fine for most, surprising "
                         "the first time a big upload 413s)")
    if not re.search(r"^\s*gzip\s+on\s*;", text, re.M) \
            and not re.search(r"^\s*brotli\s+on\s*;", text, re.M):
        cfg.notes.append("no gzip/brotli directive — compression is "
                         "left off (check the distro snippets before "
                         "trusting this)")
    present, missing = header_coverage(
        text, r"add_header\s+{header}")
    if missing:
        cfg.flags.append(Flag(
            "warning", "headers",
            f"security headers not added in this file: "
            f"{', '.join(missing)} — the Security Headers report "
            "grades exactly these; its zeroes are explained here"))
    elif present:
        cfg.flags.append(Flag("good", "headers",
                              f"all core headers added "
                              f"({len(present)} of {len(SECURITY_HEADERS)})"))
    for m in re.finditer(r"location\s+\S+\s*\{([^{}]*)\}", text, re.S):
        block = m.group(1)
        if "proxy_pass" in block \
                and "proxy_set_header Host" not in block \
                and "proxy_set_header X-Forwarded-Host" not in block:
            cfg.flags.append(Flag(
                "warning", "proxy",
                "proxy_pass without proxy_set_header Host — the "
                "backend routes by the wrong vhost and often answers "
                "with its default site",
                where=m.group(0)[:80].replace("\n", " ")))


def parse_apache(text: str, cfg: WebConfig) -> None:
    m = re.search(r"^\s*ServerTokens\s+(\w+)", text, re.M | re.I)
    if m:
        if m.group(1).lower() in ("os", "full", "minor", "major"):
            cfg.flags.append(Flag("warning", "banners",
                                  f"ServerTokens {m.group(1)} — the "
                                  "server version ships in every "
                                  "response header"))
        else:
            cfg.flags.append(Flag("good", "banners",
                                  f"ServerTokens {m.group(1)}"))
    else:
        cfg.notes.append("ServerTokens not set — apache defaults to "
                         "**Full** (version + modules in the banner)")
    if re.search(r"^\s*ServerSignature\s+On", text, re.M | re.I):
        cfg.flags.append(Flag("warning", "banners",
                              "ServerSignature On — the version sits "
                              "on every error page"))
    if re.search(r"^\s*Options\s+[^\n]*(?<!-)Indexes\b", text, re.M):
        cfg.flags.append(Flag("warning", "listings",
                              "Options Indexes/+Indexes — directory "
                              "browsing on"))
    protocols = ""
    m = re.search(r"^\s*SSLProtocol\s+([^\n]+)", text, re.M)
    if m:
        protocols = m.group(1)
    m = re.search(r"^\s*SSLCipherSuite\s+([^\n]+)", text, re.M)
    ciphers = m.group(1) if m else ""
    cfg.flags.extend(tls_flags(protocols, ciphers, "SSLProtocol"))
    # php in uploads: engine off inside a Directory with uploads?
    uploads_off = re.search(r"<Directory[^>]*uploads[^>]*>[\s\S]*?"
                            r"php_admin_flag\s+engine\s+off", text)
    php_handler = re.search(r"FilesMatch\s+\\?\.php", text) \
        or re.search(r"SetHandler\s+.*php", text)
    if php_handler and not uploads_off \
            and "uploads" not in text.lower():
        cfg.flags.append(Flag("warning", "php-uploads",
                              "PHP handler present; nothing in this "
                              "file restricts uploads/ — the safe "
                              "shape is a Directory block with "
                              "php_admin_flag engine off"))
    elif uploads_off:
        cfg.flags.append(Flag("good", "php-uploads",
                              "PHP engine explicitly off inside "
                              "uploads/ — the safe shape"))
    if not re.search(r"^\s*LimitRequestBody", text, re.M):
        cfg.notes.append("LimitRequestBody not set — apache accepts "
                         "request bodies of any size")
    present, missing = header_coverage(
        text, r"Header\s+(?:always\s+)?set\s+{header}")
    if missing:
        cfg.flags.append(Flag("warning", "headers",
                              f"security headers not set in this file: "
                              f"{', '.join(missing)}"))
    elif present:
        cfg.flags.append(Flag("good", "headers",
                              f"all core headers set "
                              f"({len(present)} of "
                              f"{len(SECURITY_HEADERS)})"))


PARSERS = {"nginx": parse_nginx, "apache": parse_apache,
           "htaccess": parse_apache}


def read_config(path: str) -> WebConfig:
    cfg = WebConfig(path=path)
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        cfg.verdict = "⚫ unreadable"
        cfg.notes.append(str(exc))
        return cfg
    cfg.fmt = detect_format(text, path)
    if cfg.fmt == "unknown":
        cfg.verdict = "⚫ unrecognized format"
        cfg.notes.append("matches neither nginx nor apache/.htaccess "
                         "shapes")
        return cfg
    if cfg.fmt == "htaccess":
        cfg.notes.append(".htaccess — the rules apply to its folder "
                         "and below; the main config still owns "
                         "TLS and banners")
    PARSERS[cfg.fmt](text, cfg)
    finalize(cfg)
    return cfg


def finalize(cfg: WebConfig) -> None:
    if cfg.verdict:
        return
    if any(f.severity == "critical" for f in cfg.flags):
        cfg.verdict = "🔴 critical flags"
    elif any(f.severity == "warning" for f in cfg.flags):
        cfg.verdict = "🟠 to tighten"
    elif any(f.severity == "good" for f in cfg.flags):
        cfg.verdict = "🟢 sane"
    else:
        cfg.verdict = "🟡 see notes"


# -------------------------------------------------------------------- report

ICON = {"critical": "🔴", "warning": "🟠", "info": "ℹ️", "good": "🟢"}


def build_table_event(configs: list[WebConfig]) -> dict:
    rows = []
    for cfg in configs:
        counts = {}
        for f in cfg.flags:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        rows.append([
            os.path.basename(cfg.path),
            cfg.fmt,
            counts.get("critical", 0),
            counts.get("warning", 0),
            counts.get("good", 0),
            cfg.verdict,
        ])
    return {"type": "table",
            "columns": ["file", "format", "critical", "warnings",
                        "good", "verdict"],
            "rows": rows}


def build_markdown(configs: list[WebConfig]) -> str:
    red = sum(1 for c in configs if "🔴" in c.verdict)
    out = [f"# Web Conf Audit — Report\n",
           f"{len(configs)} config file(s): {red} with critical "
           f"flags.\n",
           "The config is read, not tested — *why* the responses "
           "look the way they do. For what actually reaches the "
           "browser run **Security Headers**; the two reports are "
           "designed to be read together.\n"]
    for cfg in configs:
        rel = os.path.basename(cfg.path)
        out.append(f"\n## {rel}\n")
        out.append(f"- Format: **{cfg.fmt}** · verdict: "
                   f"**{cfg.verdict}**")
        for note in cfg.notes:
            out.append(f"- ℹ️ {note}")
        if cfg.flags:
            out.append("")
            for f in cfg.flags:
                out.append(f"- {ICON[f.severity]} **{f.check}** — "
                           f"{f.detail}"
                           + (f" (`{f.where}`…)" if f.where else ""))
    out.append("\n## What good looks like\n")
    out.append("- `server_tokens off` / `ServerTokens Prod`; "
               "`autoindex`/`Indexes` off.")
    out.append("- `ssl_protocols TLSv1.2 TLSv1.3` and a modern "
               "cipher list — the tls-audit scale in config form.")
    out.append("- PHP denied inside uploads (`deny` in the nginx "
               "location, `php_admin_flag engine off` in the apache "
               "Directory).")
    out.append("- The core security headers `add_header`'d / "
               "`Header set` — exactly what Security Headers grades.")
    out.append("\n## Related\n")
    out.append("- **Security Headers** — what reaches the browser; "
               "this script explains its zeroes.")
    out.append("- **TLS Audit** — the live handshake; here the "
               "protocol list is the config-side truth.")
    out.append("- **FW Audit** — the same passive-config review for "
               "the firewall; **Docker Audit** for the compose file.")
    return "\n".join(out)


def write_artifacts(configs: list[WebConfig], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {"configs": [{
        "file": os.path.basename(c.path),
        "format": c.fmt,
        "verdict": c.verdict,
        "flags": [{"severity": f.severity, "check": f.check,
                   "detail": f.detail} for f in c.flags],
        "notes": c.notes,
    } for c in configs]}
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- input

def collect_inputs(args) -> list[str]:
    if args.mode == "single":
        if not args.single_file:
            raise ValueError("--single-file is required in single mode")
        if not os.path.isfile(args.single_file):
            raise ValueError(f"{args.single_file}: file not found")
        return [args.single_file]
    if args.mode == "multiple":
        if not args.input_file:
            raise ValueError("select at least one config "
                             "(--input-file, repeatable)")
        for path in args.input_file:
            if not os.path.isfile(path):
                raise ValueError(f"{path}: file not found")
        return list(args.input_file)
    if not args.input_folder:
        raise ValueError("--input-folder is required in folder mode")
    if not os.path.isdir(args.input_folder):
        raise ValueError(f"{args.input_folder}: folder not found")
    found: list[str] = []
    skipped = 0
    walker = os.walk(args.input_folder) if args.recursive else [
        (args.input_folder, [], sorted(os.listdir(args.input_folder)))]
    for root, _dirs, files in walker:
        for name in sorted(files):
            full = os.path.join(root, name)
            try:
                text = open(full, encoding="utf-8",
                            errors="replace").read(8000)
            except OSError:
                skipped += 1
                continue
            if detect_format(text, full) != "unknown":
                found.append(full)
            else:
                skipped += 1
    if skipped:
        log(f"  ⚫ {skipped} file(s) not in a web-server format, "
            "skipped")
    if not found:
        raise ValueError(f"{args.input_folder}: no web-server configs "
                         "recognized")
    return found


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web Conf Audit — nginx/apache/.htaccess configs "
                    "reviewed passively: listings, banners, TLS, "
                    "php-in-uploads, headers, limits")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-file", help="the config to review")
    parser.add_argument("--input-file", action="append", default=[],
                        help="a config file; repeatable")
    parser.add_argument("--input-folder", help="folder of configs")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no configs are read", flush=True)
        return 0

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    total = len(sources)
    log(f"Reviewing {total} web-server config(s)")
    status(f"{total} config(s)")

    configs: list[WebConfig] = []
    for i, src in enumerate(sources, 1):
        cfg = read_config(src)
        configs.append(cfg)
        rel = os.path.basename(src)
        if cfg.fmt == "unknown":
            log(f"  ⚫ {rel}: unrecognized")
        else:
            crit = sum(1 for f in cfg.flags if f.severity == "critical")
            warn = sum(1 for f in cfg.flags if f.severity == "warning")
            log(f"  {cfg.verdict} {rel} ({cfg.fmt}, {crit} critical, "
                f"{warn} warning(s))")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    recognized = [c for c in configs if c.fmt != "unknown"]
    if not recognized:
        print("✗ no config matched a web-server format",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(configs)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(configs))
    emit({"type": "markdown", "content": report})
    write_artifacts(configs, report)

    red = sum(1 for c in configs if "🔴" in c.verdict)
    orange = sum(1 for c in configs if "🟠" in c.verdict)
    summary = f"{len(recognized)} reviewed · {red} critical · " \
              f"{orange} to tighten"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
