#!/usr/bin/env python3
"""tls-rpt-report/main.py — which receivers could not raise TLS
to your MX.

The sixth act of the mail story and dmarc-report's twin: Email DNS
Audit publishes the MTA-STS policy and the TLS-RPT address
(`_smtp._tls`), Mail Probe walks your own TLS wire — and this
script reads the **feedback loop**: the RFC 8460 reports receivers
mail to that address when they could not deliver mail to you over
TLS.  Nobody is probed; the internet already reported.

Why this is not a dead script: fewer than 1% of the top million
domains publish MTA-STS — but those who did are exactly the ones
left blind without reading these reports, and the collection
itself leads users there (email-dns-audit sets up `_smtp._tls`).

The merged picture:

- **failure types** — `starttls-not-supported` (the receiver's MX
  never offered TLS), `certificate-expired`,
  `certificate-not-trusted`, `validation-failure`,
  `sts-policy-invalid` (your own policy is broken!),
  `tls-version-insufficient`, and friends — each with its counts
  and its meaning spelled out.
- **the sending MTAs** — which IPs failed, against which of your
  MX hosts.
- **successes vs failures** — the delivery rate over TLS.
- **the policy read** — in `testing` mode failures are
  observations; in `enforce` mode every failure is **mail that did
  not land**.  The report says which world you are in.

Offline, stdlib only (`json`, `gzip`, `zipfile`) — like
dmarc-report.

Exit codes: 0 = ran, 1 = no report parsed, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, field

REPORT_EXTENSIONS = {".json", ".gz", ".zip"}

FAILURE_MEANINGS = {
    "starttls-not-supported":
        "the receiving MX never offered STARTTLS — plain SMTP only",
    "certificate-expired":
        "your (or a relay's) certificate was past its validity",
    "certificate-not-trusted":
        "the certificate did not chain to a trusted root",
    "validation-failure":
        "the hostname in the certificate did not match the MX",
    "sts-policy-invalid":
        "your MTA-STS policy itself failed to parse/validate — "
        "the fault is on your side",
    "tls-version-insufficient":
        "the TLS version offered was below the policy floor",
    "sts-policy-fetch-error":
        "the receiver could not fetch /.well-known/mta-sts.txt",
    "sts-policy-change-error":
        "the policy changed incompatibly mid-flight",
    "bad-envelope": "the message envelope was malformed",
}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ----------------------------------------------------------------- parsing

@dataclass
class Report:
    file: str
    org: str = ""
    policy_domain: str = ""
    policy_type: str = ""          # sts | tlsa
    policy_mode: str = ""          # testing | enforce (from strings)
    successes: int = 0
    failures: int = 0
    failure_types: Counter = field(default_factory=Counter)
    failure_ips: Counter = field(default_factory=Counter)
    failing_mx: Counter = field(default_factory=Counter)
    details: list[dict] = field(default_factory=list)
    status: str = "ok"
    note: str = ""


def parse_tlsrpt(data: dict, file_label: str) -> Report:
    rep = Report(file=file_label)
    if not isinstance(data, dict) or "policies" not in data:
        rep.status = "unreadable"
        rep.note = "no 'policies' array — not a TLS-RPT report"
        return rep
    rep.org = data.get("organization-name", "")
    total_s = total_f = 0
    for pol in data.get("policies") or []:
        policy = pol.get("policy") or {}
        rep.policy_domain = policy.get("policy-domain",
                                       rep.policy_domain)
        rep.policy_type = policy.get("policy-type",
                                     rep.policy_type)
        strings = policy.get("policy-string") or []
        if isinstance(strings, list):
            for s in strings:
                if isinstance(s, str) and s.lower().startswith(
                        "mode:"):
                    rep.policy_mode = s.split(":", 1)[1].strip()
        summary = pol.get("summary") or {}
        total_s += int(summary.get("total-successful-session-count",
                                   0))
        total_f += int(summary.get("total-failure-session-count", 0))
        for detail in pol.get("failure-details") or []:
            rtype = detail.get("result-type", "?")
            count = int(detail.get("failed-session-count", 0))
            ip = detail.get("sending-mta-ip", "?")
            mx = detail.get("receiving-mx-hostname", "?")
            rep.failure_types[rtype] += count
            rep.failure_ips[ip] += count
            rep.failing_mx[mx] += count
            rep.details.append({"result-type": rtype, "count": count,
                                "sending-mta-ip": ip,
                                "receiving-mx-hostname": mx})
    rep.successes = total_s
    rep.failures = total_f
    return rep


def iter_report_files(path: str):
    """(label, parsed-json) from .json / .json.gz / .zip."""
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path)
    if ext == ".json":
        with open(path, "rb") as fh:
            yield base, json.load(fh)
    elif ext == ".gz":
        with gzip.open(path, "rb") as fh:
            yield base, json.load(fh)
    elif ext == ".zip":
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.lower().endswith(".json") and not \
                        name.endswith("/"):
                    yield f"{base}:{name}", json.loads(
                        zf.read(name).decode("utf-8",
                                             "replace"))


# ----------------------------------------------------------------- analysis

def merge(reports: list[Report]) -> dict:
    ok = [r for r in reports if r.status == "ok"]
    failure_types: Counter = Counter()
    failure_ips: Counter = Counter()
    failing_mx: Counter = Counter()
    for r in ok:
        failure_types.update(r.failure_types)
        failure_ips.update(r.failure_ips)
        failing_mx.update(r.failing_mx)
    successes = sum(r.successes for r in ok)
    failures = sum(r.failures for r in ok)
    modes = {r.policy_mode for r in ok if r.policy_mode}
    domains = {r.policy_domain for r in ok if r.policy_domain}
    return {
        "reports": len(ok),
        "orgs": sorted({r.org for r in ok if r.org}),
        "policy_domain": sorted(domains),
        "mode": sorted(modes),
        "successes": successes,
        "failures": failures,
        "failure_types": dict(failure_types),
        "failure_ips": dict(failure_ips),
        "failing_mx": dict(failing_mx),
        "details": [d for r in ok for d in r.details],
    }


# -------------------------------------------------------------------- report

def build_table_event(a: dict) -> dict:
    rows = [{"failure type": t, "count": c,
             "what it means": FAILURE_MEANINGS.get(
                 t, "— see RFC 8460 §3.4")}
            for t, c in sorted(a["failure_types"].items(),
                               key=lambda kv: -kv[1])]
    if not rows:
        rows = [{"failure type": "—", "count": 0,
                 "what it means": "no failures reported"}]
    return {"type": "table",
            "columns": ["failure type", "count", "what it means"],
            "rows": rows}


def build_markdown(a: dict, unreadable: list[str]) -> str:
    domain = a["policy_domain"][0] if a["policy_domain"] else "?"
    rate = (100 * a["successes"] /
            max(1, a["successes"] + a["failures"]))
    out = [f"# TLS RPT Report — Report\n",
           f"Policy domain: **{domain}** · mode: "
           f"**{', '.join(a['mode']) or 'unknown'}** · "
           f"{a['reports']} report(s) from "
           f"{len(a['orgs'])} receiver(s)\n",
           f"**{a['successes']} successful TLS sessions · "
           f"{a['failures']} failures** "
           f"({rate:.1f}% success rate)\n"]
    if not a["failure_types"]:
        out.append("Every reported session negotiated TLS "
                   "successfully. Nothing to fix — this is what a "
                   "healthy MTA-STS deployment reports.")
        if unreadable:
            out.append("")
            for u in unreadable:
                out.append(f"- ⚫ {u}")
        return "\n".join(out)

    out.append("## Failure types\n")
    for t, c in sorted(a["failure_types"].items(),
                       key=lambda kv: -kv[1]):
        out.append(f"- **{t}** × {c} — "
                   + FAILURE_MEANINGS.get(
                       t, "see RFC 8460 §3.4 for this type"))
    out.append("")
    if a["failing_mx"]:
        out.append("## Your MX hosts the failures hit\n")
        for mx, c in sorted(a["failing_mx"].items(),
                            key=lambda kv: -kv[1])[:8]:
            out.append(f"- `{mx}` — {c} failed session(s)")
        out.append("")
    if a["failure_ips"]:
        out.append("## Sending MTAs behind the failures\n")
        for ip, c in sorted(a["failure_ips"].items(),
                            key=lambda kv: -kv[1])[:10]:
            out.append(f"- `{ip}` — {c} session(s)")
        out.append("")
    out.append("## What the mode means\n")
    if "enforce" in a["mode"]:
        out.append("🔴 the policy is in **enforce** mode: every "
                   "failure above is **mail that did not land** — "
                   "the sender gave up rather than deliver in "
                   "plain. Fix the certificate/policy side or "
                   "expect bounces.")
    elif "testing" in a["mode"]:
        out.append("🟡 the policy is in **testing** mode: the "
                   "failures are observations — mail still lands "
                   "in plain SMTP. Fix them *before* switching to "
                   "enforce, or the bounces start.")
    else:
        out.append("⚫ the mode is not stated in the reports — "
                   "check the MTA-STS record with Email DNS "
                   "Audit.")
    if any(t == "sts-policy-invalid" or
           t.startswith("sts-policy") for t in a["failure_types"]):
        out.append("\n⚠️ **sts-policy-* failures point at your own "
                   "policy** — the fault is on your side of the "
                   "wire (the record, the well-known file, or the "
                   "cert). Email DNS Audit validates both ends.")
    if unreadable:
        out.append("")
        for u in unreadable:
            out.append(f"- ⚫ {u}")
    out.append("\n## Related\n")
    out.append("- **Email DNS Audit** — the MTA-STS record and the "
               "`_smtp._tls` address these reports arrive at.")
    out.append("- **Mail Probe** — your own MX's TLS wire.")
    out.append("- **DMARC Report** — the twin feedback loop for "
               "sender authenticity.")
    return "\n".join(out)


def write_artifacts(a: dict, unreadable: list[str],
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump({**a, "unreadable": unreadable}, fh,
                  ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- input

def collect_inputs(args) -> list[str]:
    if args.mode == "single":
        if not args.single_file:
            raise ValueError("--single-file is required in single "
                             "mode")
        if os.path.splitext(args.single_file)[1].lower() \
                not in REPORT_EXTENSIONS:
            raise ValueError(f"{args.single_file}: expected .json, "
                             ".json.gz or .zip")
        if not os.path.isfile(args.single_file):
            raise ValueError(f"{args.single_file}: file not found")
        return [args.single_file]
    if args.mode == "multiple":
        if not args.input_file:
            raise ValueError("select at least one report "
                             "(--input-file, repeatable)")
        for path in args.input_file:
            if os.path.splitext(path)[1].lower() \
                    not in REPORT_EXTENSIONS:
                raise ValueError(f"{path}: expected .json/.gz/.zip")
            if not os.path.isfile(path):
                raise ValueError(f"{path}: file not found")
        return list(args.input_file)
    if not args.input_folder:
        raise ValueError("--input-folder is required in folder mode")
    if not os.path.isdir(args.input_folder):
        raise ValueError(f"{args.input_folder}: folder not found")
    found, skipped = [], 0
    walker = os.walk(args.input_folder) if args.recursive else [
        (args.input_folder, [], sorted(os.listdir(args.input_folder)))]
    for root, _dirs, files in walker:
        for name in sorted(files):
            full = os.path.join(root, name)
            if os.path.splitext(name)[1].lower() in \
                    REPORT_EXTENSIONS:
                found.append(full)
            else:
                skipped += 1
    if skipped:
        log(f"  ⚫ {skipped} non-report file(s) skipped")
    if not found:
        raise ValueError(f"{args.input_folder}: no report files "
                         "found (json, gz, zip)")
    return found


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="TLS RPT Report — RFC 8460 SMTP TLS reports "
                    "merged: failure types, sending MTAs, the "
                    "enforce-vs-testing read")
    parser.add_argument("--mode", choices=["single", "multiple",
                                           "folder"],
                        default="single",
                        help="input mode (default single)")
    parser.add_argument("--single-file", help="the report to read")
    parser.add_argument("--input-file", action="append", default=[],
                        help="a report file; repeatable")
    parser.add_argument("--input-folder", help="folder of reports")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no reports are read",
              flush=True)
        return 0

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    log(f"Reading {len(sources)} TLS-RPT file(s)")
    status(f"{len(sources)} file(s)")
    reports: list[Report] = []
    unreadable: list[str] = []
    for i, path in enumerate(sources, 1):
        try:
            for label, data in iter_report_files(path):
                rep = parse_tlsrpt(data, label)
                reports.append(rep)
                if rep.status == "ok":
                    log(f"  ✓ {label}: {rep.org} · "
                        f"{rep.successes} ok / {rep.failures} fail")
                else:
                    unreadable.append(f"{label}: {rep.note}")
        except (OSError, ValueError, json.JSONDecodeError,
                zipfile.BadZipFile, gzip.BadGzipFile,
                UnicodeDecodeError) as exc:
            unreadable.append(f"{os.path.basename(path)}: {exc}")
        emit({"type": "progress", "pct": int(100 * i / len(sources)),
              "message": os.path.basename(path)})

    if not any(r.status == "ok" for r in reports):
        print("✗ no report parsed — nothing to analyze",
              file=sys.stderr, flush=True)
        return 1
    a = merge(reports)
    report = build_markdown(a, unreadable)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(a))
    emit({"type": "markdown", "content": report})
    write_artifacts(a, unreadable, report)

    summary = (f"{a['successes']} ok · {a['failures']} fail · "
               f"{len(a['failure_types'])} failure type(s)")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
