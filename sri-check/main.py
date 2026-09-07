#!/usr/bin/env python3
"""sri-check/main.py — whose code runs on your page, and is it pinned.

CSP Audit reads the policy; this reads the `<script>` and
`<link rel=stylesheet>` tags themselves — the **supply-chain view**
of one page:

- **third-party resources without integrity** — what the CDN serves
  is what runs on your page. Polyfill.io served malware to half a
  million sites in June 2024; none of them needed a new
  vulnerability — the delivery channel *was* the vulnerability.
- **integrity without crossorigin** — a cross-origin hash is only
  checked in CORS mode; without the attribute the browser refuses
  the subresource entirely. A broken tag, not a soft warning.
- **the same-origin mistake** — integrity on your own files is
  redundant *and* blocks the resource the day a deploy rewrites it.
  SRI is for resources you don't control.
- **hash verification** — every declared integrity hash is checked
  against the bytes served *right now*: match, mismatch (the file
  changed — deploy drift or tampering), or honestly unverified.
- **ready-to-paste tags** — for each unpinned third-party resource
  a complete `integrity="sha384-…" crossorigin="anonymous"` line,
  computed from today's response — with the pinning tradeoff said
  aloud: when the CDN updates the file, the page breaks. Pin
  versioned URLs.

One page fetch + one fetch per unique resource (skippable with
--skip-fetch for an attributes-only pass).

Exit codes: 0 = ran, 1 = page unreachable, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html as html_mod
import json
import os
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests

USER_AGENT = "PyShell-sri-check/1 (+subresource integrity audit)"

MAX_RESOURCE_BYTES = 10 * 1024 * 1024     # politeness cap per resource

TAG_RE = re.compile(r"<(script|link)\b([^>]*)>", re.I)
ATTR_RE = re.compile(
    r"([a-zA-Z_][-\w]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))")
HASH_OPTION_RE = re.compile(
    r"^(sha(256|384|512))-[A-Za-z0-9+/]+={0,2}$")

# Registrable-domain heuristic for the *inventory label* only (own /
# same-site / third-party) — the findings themselves use strict
# origin comparison, never this list.
SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "com.ar",
    "com.ua", "net.ua", "org.ua",
    "co.in", "co.nz", "co.za", "com.sg", "com.tr", "com.cn",
    "com.tw", "com.hk", "com.pl", "co.kr",
}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ parsing

@dataclass
class Resource:
    url: str
    kind: str                       # script | stylesheet
    integrity: str = ""
    crossorigin: str | None = None  # None = attribute absent
    cross_origin: bool = True
    site: str = "third-party"       # own | same-site | third-party
    findings: list[dict] = field(default_factory=list)
    hash_state: str = "not checked"  # verified| mismatch | invalid |
                                     # unverified | skipped | ok-less
    note: str = ""
    snippet: str = ""


def parse_attrs(tag_body: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for m in ATTR_RE.finditer(tag_body):
        name = m.group(1).lower()
        value = m.group(2)
        if value is None:
            value = m.group(3)
        if value is None:
            value = m.group(4) or ""
        attrs.setdefault(name, html_mod.unescape(value))
    return attrs


def parse_tags(page_html: str, page_url: str) -> tuple[list[Resource],
                                                        int]:
    """Resources + the count of inline scripts (SRI never applies)."""
    page = urlsplit(page_url)
    page_origin = (page.scheme, (page.hostname or "").lower(),
                   page.port or (443 if page.scheme == "https" else 80))
    base_reg = registrable(page.hostname or "")
    out: list[Resource] = []
    inline = 0
    for m in TAG_RE.finditer(page_html):
        tag, body = m.group(1).lower(), m.group(2)
        attrs = parse_attrs(body)
        if tag == "script":
            src = attrs.get("src")
            if not src:
                inline += 1
                continue
            kind = "script"
        else:
            rel = {t.lower() for t in attrs.get("rel", "").split()}
            if "stylesheet" not in rel or not attrs.get("href"):
                continue
            src, kind = attrs["href"], "stylesheet"
        url = urljoin(page_url, src)
        u = urlsplit(url)
        origin = (u.scheme, (u.hostname or "").lower(),
                  u.port or (443 if u.scheme == "https" else 80))
        res = Resource(url=url, kind=kind,
                       integrity=attrs.get("integrity", ""),
                       crossorigin=attrs.get("crossorigin"),
                       cross_origin=origin != page_origin)
        host = (u.hostname or "").lower()
        if not res.cross_origin:
            res.site = "own"
        elif host == page.hostname or host.endswith(
                f".{page.hostname or ''}") \
                or registrable(host) == base_reg:
            res.site = "same-site"
        else:
            res.site = "third-party"
        out.append(res)
    return out, inline


def registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


# ---------------------------------------------------------------- analysis

def integrity_options(integrity: str) -> list[str]:
    """The whitespace-separated hash options of an integrity value."""
    return [opt for opt in (integrity or "").split() if opt]


def analyze_tag(res: Resource) -> None:
    """Attribute-level findings — no fetching needed."""
    opts = integrity_options(res.integrity)
    bad = [o for o in opts if not HASH_OPTION_RE.match(o)]
    if res.integrity and bad:
        res.findings.append({
            "severity": "red", "code": "invalid-hash",
            "message": f"integrity {bad[0][:44]!r} is not a valid "
                       "sha256/384/512 hash — it can never pass"})
    if res.cross_origin:
        if not res.integrity:
            res.findings.append({
                "severity": "red", "code": "no-integrity",
                "message": "no integrity attribute — this host "
                           "decides what runs on your page (the "
                           "Polyfill.io lesson)"})
        elif res.crossorigin is None:
            res.findings.append({
                "severity": "red", "code": "no-crossorigin",
                "message": "integrity without crossorigin: the hash "
                           "is only checked in CORS mode — the "
                           "browser refuses the resource"})
        if res.crossorigin is not None and \
                res.crossorigin.strip().lower() == "use-credentials":
            res.findings.append({
                "severity": "yellow", "code": "credentials",
                "message": "crossorigin=use-credentials sends your "
                           "cookies to this host and needs "
                           "Access-Control-Allow-Credentials in "
                           "reply — almost never what a public "
                           "CDN wants"})
    elif res.integrity:
        res.findings.append({
            "severity": "yellow", "code": "same-origin-integrity",
            "message": "integrity on a same-origin resource is "
                       "redundant — and blocks the resource the day "
                       "a deploy rewrites the file"})


def hash_option_for(data: bytes, option: str) -> str:
    algo = option.split("-", 1)[0]
    digest = hashlib.new(algo, data).digest()
    return f"{algo}-{base64.b64encode(digest).decode()}"


def verify_hashes(res: Resource, data: bytes) -> None:
    """The declared options against the bytes just fetched."""
    opts = integrity_options(res.integrity)
    if any(not HASH_OPTION_RE.match(o) for o in opts):
        res.hash_state = "invalid"
        return
    if any(hash_option_for(data, o) == o for o in opts):
        res.hash_state = "verified"
    else:
        res.hash_state = "mismatch"
        res.findings.append({
            "severity": "red", "code": "hash-mismatch",
            "message": "the served bytes do not match the declared "
                       "hash — the file changed since the tag was "
                       "written (deploy drift or tampering)"})


def build_snippet(res: Resource, data: bytes) -> None:
    digest = hashlib.sha384(data).digest()
    integrity = "sha384-" + base64.b64encode(digest).decode()
    if res.kind == "script":
        res.snippet = (f'<script src="{res.url}" '
                       f'integrity="{integrity}" '
                       f'crossorigin="anonymous"></script>')
    else:
        res.snippet = (f'<link rel="stylesheet" href="{res.url}" '
                       f'integrity="{integrity}" '
                       f'crossorigin="anonymous">')


# ----------------------------------------------------------------- fetching

def fetch_bytes(url: str, timeout: int) -> tuple[bytes | None, str]:
    """(body, note) — body None means 'no hash from this'."""
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": USER_AGENT},
                         stream=True)
        if r.status_code != 200:
            return None, f"HTTP {r.status_code} — not pinned: " \
                         "an error page must never be hashed in"
        chunks: list[bytes] = []
        size = 0
        for chunk in r.iter_content(65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_RESOURCE_BYTES:
                return None, "larger than 10 MB — skipped"
        return b"".join(chunks), ""
    except requests.RequestException as exc:
        return None, f"unreachable: {exc}"


# ------------------------------------------------------------------ report

def worst(res: Resource) -> str:
    if any(f["severity"] == "red" for f in res.findings):
        return "🔴 " + ", ".join(sorted({f["code"] for f
                                         in res.findings}))
    if res.findings:
        return "🟡 " + ", ".join(sorted({f["code"] for f
                                         in res.findings}))
    if res.cross_origin:
        return "✅ pinned"
    return "· own origin"


def short(url: str, width: int = 64) -> str:
    if len(url) <= width:
        return url
    return url[:width - 1] + "…"


def build_table_event(resources: list[Resource]) -> dict:
    rows = [[short(r.url), r.kind,
             r.site,
             r.hash_state if r.integrity
             else ("—" if not r.cross_origin else "none"),
             worst(r)]
            for r in resources]
    if not rows:
        rows = [["—", "—", "—", "—",
                 "no external scripts or stylesheets"]]
    return {"type": "table",
            "columns": ["resource", "kind", "side", "integrity",
                        "verdict"],
            "rows": rows}


def build_markdown(url: str, resources: list[Resource], inline: int,
                   skipped_fetch: bool) -> str:
    third = [r for r in resources if r.cross_origin]
    unpinned = [r for r in third if not r.integrity]
    reds = [r for r in resources
            if any(f["severity"] == "red" for f in r.findings)]
    yellows = [r for r in resources
               if not any(f["severity"] == "red" for f in r.findings)
               and r.findings]
    out = [f"# SRI Check — Report\n",
           f"Page: `{url}` · **{len(resources)} external "
           f"resource(s)** ({len(third)} cross-origin, {inline} "
           f"inline — SRI never applies to inline) · "
           f"**{len(unpinned)} unpinned third-party** · "
           f"{len(reds)} red, {len(yellows)} yellow\n"]

    # inventory
    hosts: dict[str, dict] = {}
    for r in resources:
        h = urlsplit(r.url).hostname or "?"
        entry = hosts.setdefault(h, {"n": 0, "pinned": 0,
                                     "site": r.site})
        entry["n"] += 1
        entry["pinned"] += 1 if r.integrity else 0
    if hosts:
        out.append("## Host inventory\n")
        for h, e in sorted(hosts.items(),
                           key=lambda kv: (-kv[1]["n"], kv[0])):
            label = {"own": "your origin",
                     "same-site": "same site, other origin",
                     "third-party": "third-party"}[e["site"]]
            out.append(f"- `{h}` — {e['n']} resource(s), "
                       f"{e['pinned']} pinned · {label}")
        out.append("")

    for title, group in (("Red — fix these", reds),
                         ("Yellow — judgment calls", yellows)):
        if group:
            out.append(f"## {title}\n")
            for r in group:
                for f in r.findings:
                    mark = {"red": "🔴",
                            "yellow": "🟡"}[f["severity"]]
                    out.append(f"- {mark} **{f['code']}** · "
                               f"`{short(r.url)}` — {f['message']}")
            out.append("")

    if unpinned and not skipped_fetch:
        made = [r for r in unpinned if r.snippet]
        out.append("## Ready-to-paste tags\n")
        out.append("Hashes computed from the bytes served *right "
                   "now*. The tradeoff, said aloud: **a pinned CDN "
                   "file that changes breaks the page** — pin "
                   "versioned URLs (`lib@1.2.3.js`), not floating "
                   "ones.\n")
        for r in made:
            out.append(f"**{short(r.url)}**\n")
            out.append(f"```html\n{r.snippet}\n```")
            out.append("")
        could_not = [r for r in unpinned if not r.snippet]
        for r in could_not:
            out.append(f"- ⚫ `{short(r.url)}` — not pinned: "
                       f"{r.note}")
        if could_not:
            out.append("")

    if skipped_fetch:
        out.append("⚫ Attributes-only pass (`--skip-fetch`): the "
                   "tags were read but no resource downloaded — "
                   "declared hashes are **not verified** and no "
                   "ready-to-paste tags were computed.\n")

    verified = [r for r in resources
                if r.integrity and r.hash_state == "verified"]
    if verified:
        out.append("## Verified against the bytes served now\n")
        for r in verified:
            out.append(f"- ✅ `{short(r.url)}` — the declared hash "
                       "matches the current response. A match means "
                       "*matches right now*, not safe forever.")
        out.append("")

    if not reds and not yellows and not unpinned:
        out.append("Every cross-origin resource is pinned and every "
                   "pinned hash matches the bytes served right now. "
                   "This is what the Polyfill.io survivors wished "
                   "they had.")

    out.append("\n## Related\n")
    out.append("- **CSP Audit** — the policy side of the same page "
               "(what the allowlist permits).")
    out.append("- **Tech Stack** — the full third-party inventory "
               "behind these hosts.")
    out.append("- **Page SEO Audit** — the rest of the page.")
    return "\n".join(out)


def write_artifacts(url: str, resources: list[Resource], inline: int,
                    skipped_fetch: bool, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "url": url,
        "inline_scripts": inline,
        "resources": [{
            "url": r.url, "kind": r.kind, "site": r.site,
            "cross_origin": r.cross_origin,
            "integrity": r.integrity, "crossorigin": r.crossorigin,
            "hash_state": r.hash_state, "note": r.note,
            "snippet": r.snippet,
            "findings": r.findings} for r in resources],
        "skipped_fetch": skipped_fetch,
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SRI Check — the supply-chain view of a page's "
                    "script/stylesheet tags: unpinned third parties, "
                    "broken integrity attributes, hash verification, "
                    "ready-to-paste tags")
    parser.add_argument("--url", required=True,
                        help="the page to inspect")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds "
                             "(default 15)")
    parser.add_argument("--skip-fetch", action="store_true",
                        help="attributes only: read the tags, never "
                             "download resources (no verification, "
                             "no snippets)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — nothing is fetched",
              flush=True)
        return 0

    u = urlsplit(args.url)
    if u.scheme not in ("http", "https") or not u.hostname:
        print("✗ --url must be a full http(s) URL", file=sys.stderr,
              flush=True)
        return 2

    try:
        page = requests.get(args.url, timeout=args.timeout,
                            headers={"User-Agent": USER_AGENT})
    except requests.RequestException as exc:
        print(f"✗ page unreachable: {exc}", file=sys.stderr,
              flush=True)
        return 1
    if page.status_code != 200:
        print(f"✗ page answered HTTP {page.status_code}",
              file=sys.stderr, flush=True)
        return 1

    resources, inline = parse_tags(page.text, args.url)
    for res in resources:
        analyze_tag(res)
    log(f"{len(resources)} external resource(s), {inline} inline "
        f"script(s)")
    status(f"{len(resources)} resources · {inline} inline")

    if not resources:
        report = build_markdown(args.url, resources, inline,
                                args.skip_fetch)
        emit({"type": "progress", "pct": 100, "message": "Done"})
        emit(build_table_event(resources))
        emit({"type": "markdown", "content": report})
        write_artifacts(args.url, resources, inline,
                        args.skip_fetch, report)
        log("← no external resources — nothing to pin")
        return 0

    if args.skip_fetch:
        for res in resources:
            res.hash_state = "skipped" if res.integrity else "—"
        log("  ⚫ attributes only — no resource fetched")
    else:
        unique = {r.url for r in resources if (
            r.integrity or r.cross_origin)}
        fetched: dict[str, tuple[bytes | None, str]] = {}
        for i, url in enumerate(sorted(unique), 1):
            fetched[url] = fetch_bytes(url, args.timeout)
            emit({"type": "progress",
                  "pct": int(100 * i / len(unique)),
                  "message": urlsplit(url).hostname or url})
        for res in resources:
            if res.url not in fetched:
                continue
            data, note = fetched[res.url]
            if data is None:
                res.note = note
                if res.integrity:
                    res.hash_state = "unverified"
                    res.note = note
                continue
            if res.integrity:
                verify_hashes(res, data)
            elif res.cross_origin:
                build_snippet(res, data)

    report = build_markdown(args.url, resources, inline,
                            args.skip_fetch)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(resources))
    emit({"type": "markdown", "content": report})
    write_artifacts(args.url, resources, inline, args.skip_fetch,
                    report)

    unpinned = sum(1 for r in resources
                   if r.cross_origin and not r.integrity)
    reds = sum(1 for r in resources
               if any(f["severity"] == "red" for f in r.findings))
    summary = (f"{len(resources)} resources · {unpinned} unpinned "
               f"third-party · {reds} red")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
