#!/usr/bin/env python3
"""dmarc-report/main.py — what the whole internet sees in your mail.

The fifth act of the mail story: **Email DNS Audit** reads the policy
you published, **Mail Probe** walks your servers' wire, **DNSBL
Check** asks the reputation lists, **Mail Header Check** dissects one
saved message — and this script reads the **feedback loop**: the
aggregate RUA reports every receiver mails to the address in your
DMARC record.  Nobody has to be probed: the internet already tells
you, daily, who sent mail claiming to be your domain and how the
authentication went.

Inputs are what the mailbox already holds — `.xml`, `.xml.gz`, and
the `.zip` bundles some providers send (several reports inside one
archive, all unpacked).  Several files merge into one picture.

The analysis, per source IP: volume, SPF/DKIM results as the
receiver evaluated them against your policy (alignment included),
dispositions taken (none / quarantine / reject), and the
forwarder-vs-spoof split — a record whose SPF domain differs from
your header_from but whose DKIM still aligns is mail **forwarded**
with your signature intact: a failure that is not a threat.  The
headline: the aligned-pass rate and what still blocks moving the
policy from `p=none` toward quarantine and reject.

Offline by default (the one opt-in network action is PTR resolution
for the source IPs); stdlib only.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import socket
import sys
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

REPORT_EXTENSIONS = {".xml", ".gz", ".zip"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ----------------------------------------------------------------- parsing

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(elem, name: str):
    for c in elem:
        if _local(c.tag) == name:
            return c
    return None


def _text(elem, name: str, default: str = "") -> str:
    c = _child(elem, name)
    return (c.text or "").strip() if c is not None else default


@dataclass
class Record:
    source_ip: str = ""
    count: int = 0
    disposition: str = ""       # none | quarantine | reject
    spf_aligned: bool = False   # policy_evaluated/spf == pass
    dkim_aligned: bool = False  # policy_evaluated/dkim == pass
    header_from: str = ""
    envelope_from: str = ""     # auth_results/spf domain
    dkim_domains: list[str] = field(default_factory=list)
    spf_result: str = ""        # raw spf result for envelope domain
    dkim_result: str = ""


@dataclass
class Report:
    file: str
    org: str = ""
    domain: str = ""            # policy_published/domain
    policy: str = ""            # p=
    date_begin: str = ""
    date_end: str = ""
    records: list[Record] = field(default_factory=list)
    status: str = "ok"          # ok | unreadable
    note: str = ""


def parse_report_xml(data: bytes, file_label: str) -> Report:
    rep = Report(file=file_label)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        rep.status = "unreadable"
        rep.note = f"XML parse error: {exc}"
        return rep
    if _local(root.tag) != "feedback":
        rep.status = "unreadable"
        rep.note = "root element is not <feedback> — not a RUA report"
        return rep
    meta = _child(root, "report_metadata")
    if meta is not None:
        rep.org = _text(meta, "org_name")
        rep.date_begin = _text(meta, "date_begin")
        rep.date_end = _text(meta, "date_end")
    policy_pub = _child(root, "policy_published")
    if policy_pub is not None:
        rep.domain = _text(policy_pub, "domain").lower()
        rep.policy = _text(policy_pub, "p")
    for rec_el in root:
        if _local(rec_el.tag) != "record":
            continue
        rec = Record()
        row = _child(rec_el, "row")
        if row is None:
            continue
        rec.source_ip = _text(row, "source_ip")
        try:
            rec.count = int(_text(row, "count", "0"))
        except ValueError:
            rec.count = 0
        pol_eval = _child(row, "policy_evaluated")
        if pol_eval is not None:
            rec.disposition = _text(pol_eval, "disposition", "none")
            rec.spf_aligned = _text(pol_eval, "spf") == "pass"
            rec.dkim_aligned = _text(pol_eval, "dkim") == "pass"
        ident = _child(rec_el, "identifiers")
        if ident is not None:
            rec.header_from = _text(ident, "header_from").lower()
        auth = _child(rec_el, "auth_results")
        if auth is not None:
            for res in auth:
                if _local(res.tag) == "spf":
                    rec.envelope_from = _text(res, "domain").lower()
                    rec.spf_result = _text(res, "result")
                elif _local(res.tag) == "dkim":
                    dom = _text(res, "domain").lower()
                    if dom:
                        rec.dkim_domains.append(dom)
                    if _text(res, "result") == "pass":
                        rec.dkim_result = "pass"
        if rec.source_ip and rec.count:
            rep.records.append(rec)
    return rep


def iter_report_files(path: str):
    """Yield (label, xml_bytes) from .xml / .xml.gz / .zip — a zip
    may hold several reports; each entry is yielded separately."""
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path)
    if ext == ".xml":
        with open(path, "rb") as fh:
            yield base, fh.read()
    elif ext == ".gz":
        with gzip.open(path, "rb") as fh:
            yield base, fh.read()
    elif ext == ".zip":
        with zipfile.ZipFile(path) as zf:
            names = [n for n in zf.namelist()
                     if n.lower().endswith(".xml")
                     and not n.endswith("/")]
            if not names:
                yield base + " (empty zip)", b"<notxml/>"
            for name in names:
                yield f"{base}:{name}", zf.read(name)
    else:
        raise ValueError(f"{path}: unsupported extension")


# ---------------------------------------------------------------- analysis

@dataclass
class Source:
    ip: str
    messages: int = 0
    dmarc_pass: int = 0          # aligned spf OR dkim
    spf_aligned: int = 0
    dkim_aligned: int = 0
    dispositions: dict = field(default_factory=dict)
    envelope_domains: set = field(default_factory=set)
    aligned_dkim: int = 0        # dkim pass for the header_from domain
    ptr: str = ""


def analyze(reports: list[Report]) -> dict:
    sources: dict[str, Source] = {}
    total_msgs = 0
    total_pass = 0
    policy_domains: set[str] = set()
    orgs: set[str] = set()
    for rep in reports:
        if rep.status != "ok":
            continue
        if rep.domain:
            policy_domains.add(rep.domain)
        if rep.org:
            orgs.add(rep.org)
        for rec in rep.records:
            s = sources.setdefault(rec.source_ip,
                                   Source(ip=rec.source_ip))
            s.messages += rec.count
            total_msgs += rec.count
            if rec.envelope_from:
                s.envelope_domains.add(rec.envelope_from)
            # policy_evaluated IS the receiver's aligned verdict —
            # second-guessing it from raw auth_results would be
            # guessing; the report already did the alignment math
            aligned_spf = rec.spf_aligned
            aligned_dkim = rec.dkim_aligned
            if aligned_spf:
                s.spf_aligned += rec.count
            if aligned_dkim:
                s.dkim_aligned += rec.count
            passed = aligned_spf or aligned_dkim
            if passed:
                s.dmarc_pass += rec.count
                total_pass += rec.count
            if aligned_dkim and not aligned_spf:
                s.aligned_dkim += rec.count
            s.dispositions[rec.disposition or "none"] = \
                s.dispositions.get(rec.disposition or "none", 0) \
                + rec.count

    # forwarder shape: volume from an IP whose envelope domain is
    # NOT the policy domain, but whose DKIM still aligns with it —
    # the signature survived a hop, so this is forwarded legit mail
    forwarders = []
    domain_list = {d for d in policy_domains if d}
    for s in sources.values():
        foreign_env = s.envelope_domains - domain_list \
            if domain_list else set()
        if foreign_env and s.aligned_dkim > 0 \
                and s.dmarc_pass >= s.messages * 0.9:
            forwarders.append((s, sorted(foreign_env)))

    spoof_candidates = [s for s in sources.values()
                        if s.dmarc_pass == 0 and s.messages > 0]
    pass_rate = (100.0 * total_pass / total_msgs) if total_msgs else None
    return {
        "sources": sources,
        "total_messages": total_msgs,
        "total_pass": total_pass,
        "pass_rate": pass_rate,
        "policy_domains": sorted(policy_domains),
        "orgs": sorted(orgs),
        "forwarders": forwarders,
        "spoof_candidates": spoof_candidates,
    }


def readiness(analysis: dict) -> tuple[str, str]:
    """(verdict, what blocks) — the p=none → quarantine → reject
    ladder."""
    rate = analysis["pass_rate"]
    if rate is None:
        return ("no data", "no records parsed — nothing to conclude")
    failing = analysis["total_messages"] - analysis["total_pass"]
    if rate >= 99.0:
        return ("ready for p=reject",
                f"{rate:.1f}% aligned pass — the remaining {failing} "
                "message(s) should be inspected, then the policy can "
                "go to reject (watch quarantine first if nervous)")
    if rate >= 95.0:
        return ("ready for p=quarantine",
                f"{rate:.1f}% aligned pass; {failing} message(s) fail "
                "alignment — identify them (forwarders? a forgotten "
                "sender?) before reject")
    return ("stay at p=none",
            f"only {rate:.1f}% aligned pass — {failing} of "
            f"{analysis['total_messages']} message(s) would be hurt "
            "by a stricter policy; fix alignment first")


# --------------------------------------------------------------------- input

def collect_inputs(args) -> list[str]:
    if args.mode == "single":
        if not args.single_file:
            raise ValueError("--single-file is required in single mode")
        if os.path.splitext(args.single_file)[1].lower() \
                not in REPORT_EXTENSIONS:
            raise ValueError(f"{args.single_file}: expected .xml, "
                             ".xml.gz or .zip")
        if not os.path.isfile(args.single_file):
            raise ValueError(f"{args.single_file}: file not found")
        return [args.single_file]
    if args.mode == "multiple":
        if not args.input_file:
            raise ValueError("select at least one report "
                             "(--input-file, repeatable)")
        for path in args.input_file:
            if os.path.splitext(path)[1].lower() not in REPORT_EXTENSIONS:
                raise ValueError(f"{path}: expected .xml, .xml.gz or "
                                 ".zip")
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
            if os.path.splitext(name)[1].lower() in REPORT_EXTENSIONS:
                found.append(full)
            else:
                skipped += 1
    if skipped:
        log(f"  ⚫ {skipped} non-report file(s) skipped")
    if not found:
        raise ValueError(f"{args.input_folder}: no report files found "
                         "(xml, xml.gz, zip)")
    return found


# -------------------------------------------------------------------- report

def build_table_event(analysis: dict) -> dict:
    rows = []
    for s in sorted(analysis["sources"].values(),
                    key=lambda x: -x.messages):
        rows.append([
            s.ip + (f" ({s.ptr})" if s.ptr else ""),
            s.messages,
            f"{100 * s.dmarc_pass / s.messages:.0f}%"
            if s.messages else "—",
            s.spf_aligned,
            s.dkim_aligned,
            ", ".join(f"{k}:{v}" for k, v
                      in sorted(s.dispositions.items())),
        ])
    return {"type": "table",
            "columns": ["source ip", "messages", "dmarc pass",
                        "spf aligned", "dkim aligned", "disposition"],
            "rows": rows}


def build_markdown(reports: list[Report], analysis: dict) -> str:
    domain = analysis["policy_domains"][0] \
        if analysis["policy_domains"] else "?"
    verdict, blocker = readiness(analysis)
    rate = analysis["pass_rate"]
    out = [f"# DMARC Report — Report\n",
           f"Domain: **{domain}** · "
           f"{len(reports)} report(s) from "
           f"{len(analysis['orgs'])} receiver(s): "
           + ", ".join(analysis["orgs"][:6])
           + (f" +{len(analysis['orgs']) - 6} more"
              if len(analysis["orgs"]) > 6 else "") + "\n"]
    total = analysis["total_messages"]
    if not total:
        out.append("No records parsed — the reports are empty or "
                   "unreadable. Nothing to conclude.\n")
        return "\n".join(out)
    out.append(f"**{total} message(s)** claimed to be from "
               f"`{domain}` · "
               f"**{analysis['total_pass']} passed DMARC "
               f"({rate:.1f}%)**\n")
    out.append(f"## Readiness: {verdict}\n")
    out.append(blocker + "\n")

    out.append("## Sources\n")
    for s in sorted(analysis["sources"].values(),
                    key=lambda x: -x.messages):
        ptr = f" ({s.ptr})" if s.ptr else ""
        out.append(f"- `{s.ip}`{ptr} — {s.messages} msg · "
                   f"{100 * s.dmarc_pass / s.messages:.0f}% DMARC "
                   f"pass · SPF aligned {s.spf_aligned}, DKIM aligned "
                   f"{s.dkim_aligned} · disposition: "
                   + ", ".join(f"{k}×{v}" for k, v in
                               sorted(s.dispositions.items())))
    out.append("")

    if analysis["forwarders"]:
        out.append("## Forwarders — failures that are not spoofing\n")
        for s, envs in analysis["forwarders"]:
            out.append(f"- `{s.ip}` sends from envelope domain(s) "
                       f"{', '.join(f'`{e}`' for e in envs)} but the "
                       "DKIM signature of your domain survives — "
                       "classic forwarding (a mailing list, a "
                       "filter service). These pass; they are the "
                       "reason arc-sealing exists, not a threat.")
        out.append("")
    if analysis["spoof_candidates"]:
        out.append("## Spoof candidates — zero aligned pass\n")
        for s in analysis["spoof_candidates"]:
            out.append(f"- `{s.ip}` — {s.messages} msg, **none** of "
                       "them aligned: neither your SPF nor your DKIM. "
                       "With p=none the receiver did what its local "
                       "policy said; with p=reject these would not "
                       "land.")
        out.append("")

    out.append("## How to read this\n")
    out.append("- **Aligned pass** is the DMARC verdict: SPF or DKIM "
               "matching the visible From domain. That is what the "
               "policy ladder cares about.")
    out.append("- Before moving `p=`, whitelist nothing — fix the "
               "senders: more selectors for the legit services, "
               "ARC for the forwarders.")
    out.append("- The reports came to you because receivers already "
               "evaluate your mail; **Email DNS Audit** shows the "
               "record they evaluate, **Mail Header Check** dissects "
               "a single message, **Mail Probe** checks the wire your "
               "servers speak.")
    return "\n".join(out)


def write_artifacts(reports: list[Report], analysis: dict,
                    report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "domain": analysis["policy_domains"][0]
        if analysis["policy_domains"] else None,
        "receivers": analysis["orgs"],
        "total_messages": analysis["total_messages"],
        "dmarc_pass": analysis["total_pass"],
        "pass_rate": analysis["pass_rate"],
        "readiness": readiness(analysis)[0],
        "readiness_blocker": readiness(analysis)[1],
        "sources": [{
            "ip": s.ip, "messages": s.messages,
            "dmarc_pass": s.dmarc_pass,
            "spf_aligned": s.spf_aligned,
            "dkim_aligned": s.dkim_aligned,
            "dispositions": s.dispositions,
            "envelope_domains": sorted(s.envelope_domains),
            "ptr": s.ptr,
        } for s in analysis["sources"].values()],
        "forwarders": [{"ip": s.ip, "envelope_domains": envs}
                       for s, envs in analysis["forwarders"]],
        "spoof_candidates": [s.ip for s in
                             analysis["spoof_candidates"]],
        "reports": [{"file": r.file, "org": r.org, "status": r.status,
                     "records": len(r.records)} for r in reports],
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="DMARC Report — aggregate RUA reports merged: "
                    "sources, alignment, forwarders, policy readiness")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-file", help="the report file to read")
    parser.add_argument("--input-file", action="append", default=[],
                        help="a report file; repeatable")
    parser.add_argument("--input-folder", help="folder of reports")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    parser.add_argument("--resolve-ptr", action="store_true",
                        help="resolve source IP hostnames (the only "
                             "network this script does)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no reports are read", flush=True)
        return 0

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    total = len(sources)
    log(f"Reading {total} DMARC report file(s)")
    status(f"{total} file(s)")

    reports: list[Report] = []
    for i, path in enumerate(sources, 1):
        try:
            for label, xml_bytes in iter_report_files(path):
                rep = parse_report_xml(xml_bytes, label)
                reports.append(rep)
                if rep.status == "ok":
                    log(f"  ✓ {label}: {rep.org} · "
                        f"{len(rep.records)} record(s) · "
                        f"policy p={rep.policy}")
                else:
                    log(f"  ⚫ {label}: {rep.note}")
        except (OSError, ValueError, zipfile.BadZipFile,
                gzip.BadGzipFile, ET.ParseError) as exc:
            reports.append(Report(file=os.path.basename(path),
                                  status="unreadable", note=str(exc)))
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {os.path.basename(path)}"})

    parsed = [r for r in reports if r.status == "ok"]
    if not parsed:
        print("✗ no report parsed — nothing to analyze",
              file=sys.stderr, flush=True)
        return 1

    if args.resolve_ptr:
        analysis_raw = analyze(parsed)
        for s in analysis_raw["sources"].values():
            try:
                s.ptr = socket.gethostbyaddr(s.ip)[0]
            except (socket.herror, socket.gaierror, OSError):
                s.ptr = ""
    else:
        analysis_raw = analyze(parsed)

    report = build_markdown(reports, analysis_raw)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(analysis_raw))
    emit({"type": "markdown", "content": report})
    write_artifacts(reports, analysis_raw, report)

    verdict, _ = readiness(analysis_raw)
    summary = (f"{analysis_raw['total_messages']} msg · "
               f"{analysis_raw['pass_rate']:.1f}% aligned pass · "
               f"{verdict}")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
