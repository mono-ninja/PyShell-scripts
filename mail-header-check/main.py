#!/usr/bin/env python3
"""mail-header-check/main.py — why a mail landed where it did.

The fourth act of the mail story: Email DNS Audit reads the *policy*
(SPF/DKIM/DMARC records), Mail Probe walks the *wire* (MX, STARTTLS,
cert), DNSBL Check asks the *reputation* lists — and this script reads
**the message itself**, the .eml file your mail client saved: what the
receivers recorded about SPF/DKIM/DMARC in `Authentication-Results`,
whether the domains actually align with the visible From, the Received
hop chain with per-hop delays and TLS markers, and the small signals
that make filters nervous (Reply-To mismatch, bulk markers, executable
attachments).

Reads a local file with the standard library — nothing is sent, no DNS
is queried, no network at all. When the header lacks verdicts, that is
reported honestly instead of guessed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import email
import email.errors
import email.parser
import email.policy
import email.utils
import json
import os
import re
import sys
from dataclasses import dataclass, field

EML_EXTENSION = ".eml"

EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".com", ".js",
                         ".vbs", ".vbe", ".ps1", ".hta", ".jar", ".msi",
                         ".docm", ".xlsm", ".pptm", ".apk"}

VERDICT_GOOD = {"pass"}
VERDICT_NEUTRAL = {"none", "neutral", "temperror", "softfail"}
VERDICT_BAD = {"fail", "permerror", "hardfail"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ parsing

@dataclass
class AuthResults:
    """One Authentication-Results header, parsed."""
    authserv: str = ""
    spf: str = ""                # pass/fail/none/…
    spf_domain: str = ""         # smtp.mailfrom=
    dkim: str = ""
    dkim_domain: str = ""        # header.d=
    dkim_selector: str = ""      # header.s=
    dmarc: str = ""
    dmarc_domain: str = ""       # header.from=
    raw: str = ""


@dataclass
class Hop:
    """One Received header, parsed."""
    from_host: str = ""
    ip: str = ""
    by_host: str = ""
    protocol: str = ""           # ESMTP / ESMTPS / ESMTPSA / SMTP…
    date: dt.datetime | None = None
    raw: str = ""


@dataclass
class MailDoc:
    path: str
    status: str = "ok"           # ok | unreadable
    from_addr: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addr: str = ""
    subject: str = ""
    date_hdr: dt.datetime | None = None
    message_id: str = ""
    auth: AuthResults | None = None
    auth_all: list[AuthResults] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)   # newest first
    delays: list[float] = field(default_factory=list)  # s per hop (index 0 = newest)
    total_delay: float = 0.0
    spam_headers: dict = field(default_factory=dict)
    is_bulk: bool = False
    attachments: list[dict] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    red_flags: list[str] = field(default_factory=list)
    verdict: str = ""            # 🟢/🟠/🔴 label
    note: str = ""


def parse_auth_results(value: str) -> AuthResults:
    """'mx.google.com; spf=pass smtp.mailfrom=x.com; dkim=pass header.d=x.com'"""
    ar = AuthResults(raw=value)
    parts = [p.strip() for p in value.split(";") if p.strip()]
    if parts:
        ar.authserv = parts[0].split()[0] if parts[0] else ""
    for part in parts[1:]:
        m = re.match(r"(spf|dkim|dmarc|arc)\s*=\s*(\w+)", part)
        if not m:
            continue
        kind, verdict = m.group(1).lower(), m.group(2).lower()
        if kind == "spf":
            ar.spf = verdict
            d = re.search(r"smtp\.mailfrom[= ]([^\s;]+)", part)
            ar.spf_domain = d.group(1).strip("<>") if d else ""
        elif kind == "dkim":
            ar.dkim = verdict
            d = re.search(r"header\.d[= ]([^\s;]+)", part)
            ar.dkim_domain = d.group(1) if d else ""
            s = re.search(r"header\.s[= ]([^\s;]+)", part)
            ar.dkim_selector = s.group(1) if s else ""
        elif kind == "dmarc":
            ar.dmarc = verdict
            d = re.search(r"header\.from[= ]([^\s;]+)", part)
            ar.dmarc_domain = d.group(1).strip("<>") if d else ""
    return ar


RECEIVED_RE = re.compile(
    r"from\s+(?P<from>\S+)"
    r"(?:\s*\((?P<comment>[^)]*)\))?"
    r"\s+by\s+(?P<by>\S+)"
    r"(?:.*?\bwith\s+(?P<with>\S+))?"
    r"(?:.*?;\s*(?P<date>.+))?$",
    re.DOTALL)


def parse_received(value: str) -> Hop:
    hop = Hop(raw=value)
    m = RECEIVED_RE.search(value)
    if m:
        hop.from_host = m.group("from") or ""
        hop.by_host = (m.group("by") or "").rstrip(";")
        hop.protocol = m.group("with") or ""
        comment = m.group("comment") or ""
        ipm = re.search(r"\[([0-9a-fA-F.:]+)\]", comment)
        if ipm:
            hop.ip = ipm.group(1)
        else:
            ipm = re.search(r"\[([0-9a-fA-F.:]+)\]", value)
            hop.ip = ipm.group(1) if ipm else ""
        date_raw = m.group("date")
        if date_raw:
            try:
                hop.date = email.utils.parsedate_to_datetime(
                    date_raw.strip())
            except (TypeError, ValueError):
                hop.date = None
    return hop


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip().lower().rstrip(">") \
        if "@" in addr else ""


def aligned(header_domain: str, auth_domain: str) -> str:
    """Relaxed alignment: same domain or one is the other's subdomain."""
    if not header_domain or not auth_domain:
        return "unknown"
    if header_domain == auth_domain:
        return "aligned"
    if header_domain.endswith("." + auth_domain) \
            or auth_domain.endswith("." + header_domain):
        return "aligned (subdomain)"
    return "MISALIGNED"


def hop_has_tls(protocol: str) -> bool:
    p = protocol.upper()
    return p.startswith("ESMTPS") or "SMTPS" in p or p.endswith("TLS")


def analyze(mail: MailDoc, msg) -> None:
    """Fill verdicts, signals and red flags of a parsed message."""
    mail.from_addr = str(msg.get("From", "")).strip()
    mail.from_domain = domain_of(re.sub(r".*<([^>]+)>.*", r"\1",
                                        mail.from_addr) if "<" in
                                 mail.from_addr else mail.from_addr)
    mail.reply_to = str(msg.get("Reply-To", "")).strip()
    mail.return_path = str(msg.get("Return-Path", "")).strip()
    mail.to_addr = str(msg.get("To", "")).strip()
    mail.subject = str(msg.get("Subject", "")).strip()
    mail.message_id = str(msg.get("Message-ID", "")).strip()
    date_raw = msg.get("Date")
    if date_raw:
        try:
            mail.date_hdr = email.utils.parsedate_to_datetime(str(date_raw))
        except (TypeError, ValueError):
            mail.date_hdr = None

    # Authentication-Results: all of them, topmost (final receiver) wins
    raw_ar = msg.get_all("Authentication-Results") or []
    mail.auth_all = [parse_auth_results(str(v)) for v in raw_ar]
    mail.auth = mail.auth_all[0] if mail.auth_all else None

    # Received chain (newest first as they appear in the file)
    mail.hops = [parse_received(str(v))
                 for v in (msg.get_all("Received") or [])]
    dated = [h.date for h in mail.hops if h.date]
    if len(mail.hops) >= 2:
        # hops[0] is newest; delay at hop i = hops[i].date - hops[i+1].date
        for i in range(len(mail.hops) - 1):
            a, b = mail.hops[i].date, mail.hops[i + 1].date
            mail.delays.append(max(0.0, (a - b).total_seconds())
                               if a and b else 0.0)
    if len(dated) >= 2:
        mail.total_delay = sum(
            (a - b).total_seconds()
            for a, b in zip(dated, dated[1:]))

    # spam / bulk markers
    for key in ("X-Spam-Status", "X-Spam-Score", "X-Spam-Flag",
                "X-Spam-Report"):
        vals = msg.get_all(key)
        if vals:
            mail.spam_headers[key] = "; ".join(str(v) for v in vals)
    if msg.get("List-Unsubscribe") \
            or str(msg.get("Precedence", "")).lower() == "bulk":
        mail.is_bulk = True

    # attachments
    for part in msg.walk():
        name = part.get_filename()
        if name:
            size = 0
            try:
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
            except Exception:
                pass
            ext = os.path.splitext(name)[1].lower()
            mail.attachments.append({
                "name": name, "type": part.get_content_type(),
                "size": size, "executable": ext in EXECUTABLE_EXTENSIONS,
            })

    # signals & red flags
    ar = mail.auth
    if ar:
        for kind, verdict, dom in (("SPF", ar.spf, ar.spf_domain),
                                   ("DKIM", ar.dkim, ar.dkim_domain),
                                   ("DMARC", ar.dmarc, ar.dmarc_domain)):
            if not verdict:
                continue
            if verdict in VERDICT_BAD:
                mail.red_flags.append(f"{kind} {verdict} ({dom or '—'})")
            elif verdict in VERDICT_GOOD:
                mail.signals.append(f"{kind} pass")
            else:
                mail.signals.append(f"{kind} {verdict}")
        if ar.spf and ar.spf_domain:
            a = aligned(mail.from_domain, ar.spf_domain)
            if a == "MISALIGNED":
                mail.red_flags.append(
                    f"SPF domain misaligned: mailfrom {ar.spf_domain} "
                    f"vs From {mail.from_domain}")
            elif a != "unknown":
                mail.signals.append(f"SPF {a}")
        if ar.dkim and ar.dkim_domain:
            a = aligned(mail.from_domain, ar.dkim_domain)
            if a == "MISALIGNED":
                mail.red_flags.append(
                    f"DKIM domain misaligned: signed by {ar.dkim_domain} "
                    f"vs From {mail.from_domain}")
            elif a != "unknown":
                mail.signals.append(f"DKIM {a}")
    else:
        mail.signals.append("no Authentication-Results — the receiver "
                            "recorded no verdicts")

    rp_dom = domain_of(mail.return_path)
    if rp_dom and mail.from_domain and rp_dom != mail.from_domain:
        mail.signals.append(
            f"Return-Path domain {rp_dom} differs from From "
            f"{mail.from_domain} (normal for newsletters, odd otherwise)")
    if mail.reply_to and mail.from_addr:
        rt = re.sub(r".*<([^>]+)>.*", r"\1", mail.reply_to) \
            if "<" in mail.reply_to else mail.reply_to
        if domain_of(rt) != mail.from_domain:
            mail.red_flags.append(
                f"Reply-To ({rt}) points at another domain than From — "
                "classic phishing shape")
    if mail.date_hdr:
        now = dt.datetime.now(dt.timezone.utc)
        if abs((now - mail.date_hdr).total_seconds()) > 7 * 86400:
            mail.red_flags.append(
                f"Date header is {abs((now - mail.date_hdr).days)} days "
                "away from now")
    mid_dom = domain_of(mail.message_id)
    if mail.message_id and mid_dom and mail.from_domain \
            and mid_dom != mail.from_domain:
        mail.signals.append(
            f"Message-ID domain {mid_dom} differs from From — often a "
            "mailer service, sometimes a forgery")
    for att in mail.attachments:
        if att["executable"]:
            mail.red_flags.append(
                f"attachment {att['name']} is executable/macro — do not "
                "open unless expected")
    if mail.is_bulk:
        mail.signals.append("bulk/list markers present")

    # plain-ESMTP public hops (hop 0 is the final receiver side)
    public_plain = [h for h in mail.hops[:3]
                    if h.protocol.upper().startswith(("SMTP", "ESMTP"))
                    and not hop_has_tls(h.protocol)]
    if public_plain:
        mail.signals.append(
            f"{len(public_plain)} of the last hops without TLS marker")

    if mail.red_flags:
        mail.verdict = "🔴 suspicious"
    elif ar and ar.spf in VERDICT_GOOD and ar.dkim in VERDICT_GOOD \
            and ar.dmarc in VERDICT_GOOD:
        mail.verdict = "🟢 authenticated"
    elif ar and (ar.spf in VERDICT_BAD or ar.dkim in VERDICT_BAD
                 or ar.dmarc in VERDICT_BAD):
        mail.verdict = "🔴 authentication failed"
    else:
        mail.verdict = "🟠 partial"


def read_eml(path: str) -> MailDoc:
    mail = MailDoc(path=path)
    try:
        with open(path, "rb") as fh:
            msg = email.parser.BytesParser(
                policy=email.policy.default).parse(fh)
        if not msg.items():
            raise ValueError("no headers found — not an RFC 5322 message")
    except (OSError, ValueError, email.errors.MessageParseError) as exc:
        mail.status = "unreadable"
        mail.note = str(exc) or "cannot parse"
        return mail
    analyze(mail, msg)
    return mail


# --------------------------------------------------------------------- input

def collect_inputs(args) -> list[str]:
    if args.mode == "single":
        if not args.single_file:
            raise ValueError("--single-file is required in single mode")
        if os.path.splitext(args.single_file)[1].lower() != EML_EXTENSION:
            raise ValueError(f"{args.single_file}: not an .eml file "
                             "(Outlook's binary .msg is a different "
                             "format)")
        if not os.path.isfile(args.single_file):
            raise ValueError(f"{args.single_file}: file not found")
        return [args.single_file]
    if args.mode == "multiple":
        if not args.input_file:
            raise ValueError("select at least one message (--input-file, "
                             "repeatable)")
        for path in args.input_file:
            if os.path.splitext(path)[1].lower() != EML_EXTENSION:
                raise ValueError(f"{path}: not an .eml file")
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
            if os.path.splitext(name)[1].lower() == EML_EXTENSION:
                found.append(full)
            else:
                skipped += 1
    if skipped:
        log(f"  ⚫ {skipped} non-eml file(s) skipped")
    if not found:
        raise ValueError(f"{args.input_folder}: no .eml files found")
    return found


# -------------------------------------------------------------------- report

def build_table_event(mails: list[MailDoc]) -> dict:
    rows = []
    for m in mails:
        if m.status == "unreadable":
            spf = dkim = dmarc = "—"
        elif m.auth:
            spf = m.auth.spf or "—"
            dkim = m.auth.dkim or "—"
            dmarc = m.auth.dmarc or "—"
        else:
            spf = dkim = dmarc = "none"
        rows.append({
            "file": os.path.basename(m.path),
            "from": m.from_addr or "—",
            "spf": spf, "dkim": dkim, "dmarc": dmarc,
            "verdict": m.verdict if m.status == "ok" else "unreadable",
        })
    return {"type": "table",
            "columns": ["file", "from", "spf", "dkim", "dmarc", "verdict"],
            "rows": rows}


def _fmt_delay(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


def build_markdown(mails: list[MailDoc]) -> str:
    red = sum(1 for m in mails if m.red_flags)
    green = sum(1 for m in mails if m.verdict == "🟢 authenticated")
    out = [f"# Mail Header Check — Report\n",
           f"{len(mails)} message(s): {green} fully authenticated, "
           f"{red} with red flags.\n",
           "The receiver's verdicts are read from the message itself — "
           "nothing was queried, nothing was sent.\n"]

    for m in mails:
        rel = os.path.basename(m.path)
        out.append(f"\n## {rel}\n")
        if m.status == "unreadable":
            out.append(f"⚫ **unreadable** — {m.note}\n")
            continue
        out.append(f"- From: **{m.from_addr or '—'}**")
        if m.to_addr:
            out.append(f"- To: {m.to_addr}")
        out.append(f"- Subject: {m.subject or '—'}")
        if m.date_hdr:
            out.append(f"- Date: {m.date_hdr.strftime('%Y-%m-%d %H:%M UTC')}")
        if m.message_id:
            out.append(f"- Message-ID: `{m.message_id}`")
        out.append(f"- Verdict: **{m.verdict}**\n")

        out.append("### Authentication (receiver's verdicts)\n")
        ar = m.auth
        if not ar:
            out.append("No `Authentication-Results` header — the receiver "
                       "did not record SPF/DKIM/DMARC verdicts. Check the "
                       "domain's setup with **Email DNS Audit**.\n")
        else:
            out.append(f"- authserv-id: `{ar.authserv}`")
            out.append(f"- SPF: **{ar.spf or '—'}**"
                       + (f" · mailfrom `{ar.spf_domain}`" if ar.spf_domain
                          else "")
                       + (f" · {aligned(m.from_domain, ar.spf_domain)}"
                          if ar.spf_domain else ""))
            out.append(f"- DKIM: **{ar.dkim or '—'}**"
                       + (f" · signed by `{ar.dkim_domain}`"
                          f" (selector `{ar.dkim_selector}`)"
                          if ar.dkim_domain else "")
                       + (f" · {aligned(m.from_domain, ar.dkim_domain)}"
                          if ar.dkim_domain else ""))
            out.append(f"- DMARC: **{ar.dmarc or '—'}**"
                       + (f" · from `{ar.dmarc_domain}`" if ar.dmarc_domain
                          else ""))
            if len(m.auth_all) > 1:
                out.append(f"- ({len(m.auth_all)} A-R headers found — "
                           "the top one, added by the final receiver, is "
                           "used; intermediaries add their own below)")
            out.append("")

        if m.hops:
            out.append("### Received chain (newest first)\n")
            for i, hop in enumerate(m.hops):
                delay = _fmt_delay(m.delays[i]) \
                    if i < len(m.delays) and m.delays[i] > 0 else ""
                tls = "🔒" if hop_has_tls(hop.protocol) else "○"
                when = hop.date.strftime("%H:%M:%S") if hop.date else "—"
                out.append(f"{i + 1}. {tls} from `{hop.from_host}`"
                           + (f" [{hop.ip}]" if hop.ip else "")
                           + f" by `{hop.by_host}`"
                           + (f" with {hop.protocol}" if hop.protocol
                              else "")
                           + f" at {when}"
                           + (f" · waited {delay}" if delay else ""))
            if m.total_delay:
                out.append(f"\nTotal transit time: "
                           f"**{_fmt_delay(m.total_delay)}**")
            out.append("")

        if m.spam_headers:
            out.append("### Filter verdicts found\n")
            for key, val in m.spam_headers.items():
                out.append(f"- `{key}`: {val[:160]}")
            out.append("")

        if m.signals:
            out.append("### Signals\n")
            for s in m.signals:
                out.append(f"- ℹ️ {s}")
            out.append("")
        if m.red_flags:
            out.append("### Red flags\n")
            for s in m.red_flags:
                out.append(f"- 🚩 {s}")
            out.append("")

        if m.attachments:
            out.append("### Attachments\n")
            for att in m.attachments:
                warn = " 🚩 executable/macro" if att["executable"] else ""
                out.append(f"- {att['name']} — {att['type']}, "
                           f"{att['size']} B{warn}")
            out.append("")

    out.append("\n## What to do\n")
    out.append("- 🚩 flags first: failed SPF/DKIM/DMARC with misalignment "
               "or a Reply-To to another domain is the phishing shape — "
               "verify through a second channel before trusting the mail.")
    out.append("- For your own domain's mail landing in spam: check the "
               "DNS side with **Email DNS Audit**, the wire with "
               "**Mail Probe**, reputation with **DNSBL Check**.")
    return "\n".join(out)


def write_artifacts(mails: list[MailDoc], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    findings = []
    for m in mails:
        findings.append({
            "file": os.path.basename(m.path),
            "status": m.status,
            "from": m.from_addr,
            "subject": m.subject,
            "auth": ({"spf": m.auth.spf, "spf_domain": m.auth.spf_domain,
                      "dkim": m.auth.dkim, "dkim_domain": m.auth.dkim_domain,
                      "dmarc": m.auth.dmarc}
                     if m.auth else None),
            "hops": [{"from": h.from_host, "ip": h.ip, "by": h.by_host,
                      "protocol": h.protocol,
                      "date": h.date.isoformat() if h.date else None}
                     for h in m.hops],
            "delays_s": m.delays,
            "attachments": m.attachments,
            "signals": m.signals,
            "red_flags": m.red_flags,
            "verdict": m.verdict,
        })
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(findings, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mail Header Check — SPF/DKIM/DMARC verdicts, the "
                    "Received chain and phishing signals, read from "
                    ".eml files")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-file", help="the .eml message to analyze")
    parser.add_argument("--input-file", action="append", default=[],
                        help="an .eml message to analyze; repeatable")
    parser.add_argument("--input-folder", help="folder of .eml messages")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no messages are read", flush=True)
        return 0

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    total = len(sources)
    log(f"Analyzing {total} message header(s)")
    status(f"{total} message(s)")

    mails: list[MailDoc] = []
    for i, src in enumerate(sources, 1):
        m = read_eml(src)
        mails.append(m)
        rel = os.path.basename(src)
        if m.status == "ok":
            log(f"  {m.verdict} {rel}: "
                + ("; ".join(m.red_flags) if m.red_flags
                   else "; ".join(m.signals) or "no signals"))
        else:
            log(f"  ⚫ {rel}: {m.note}")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    if mails and all(m.status == "unreadable" for m in mails):
        print("✗ every message was unreadable — nothing to analyze",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(mails)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(mails))
    emit({"type": "markdown", "content": report})
    write_artifacts(mails, report)

    red = sum(1 for m in mails if m.red_flags)
    green = sum(1 for m in mails if m.verdict == "🟢 authenticated")
    summary = (f"{sum(1 for m in mails if m.status == 'ok')} read · "
               f"{green} authenticated · {red} with red flags")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
