"""src/report.py — table, markdown, artifacts."""
from __future__ import annotations

import json
import os
from dataclasses import asdict

from .smtp_probe import HostResult, RelayVerdict


def build_table_event(results: list[HostResult]) -> dict:
    rows = []
    for r in results:
        tls = ""
        if r.tls and not r.tls.error:
            tls = f"{r.tls.version}"
            if r.tls.days_left is not None:
                tls += f" · {r.tls.days_left}d"
            if not r.tls.verified:
                tls += " ⚠️ unverified"
        elif r.tls and r.tls.error:
            tls = f"broken ({r.tls.error})"
        relay = {"accepted": "🔴 accepted", "rejected": "🟢 rejected",
                 "unclear": "🟡 unclear",
                 "not tested": "—"}.get(r.relay_verdict.value, "—")
        rows.append([
            r.host,
            "✗ " + r.connect_error if r.connect_error else "✓",
            "✓" if r.starttls_offered else "—",
            tls or "—",
            " ".join(r.auth_mechs) or "—",
            ("✓ " if r.ptr_confirmed else "— ") + (r.ptr or "no PTR"),
            relay,
        ])
    return {
        "type": "table",
        "columns": ["MX host", "Connect", "STARTTLS", "TLS",
                    "AUTH", "PTR", "Relay"],
        "rows": rows,
    }


def build_markdown(domain: str, mx_note: str,
                   results: list[HostResult], relay_tested: bool) -> str:
    connected = [r for r in results if not r.connect_error]
    open_relays = [r for r in results
                   if r.relay_verdict == RelayVerdict.ACCEPTED]
    no_tls = [r for r in connected if not r.starttls_offered]
    broken_tls = [r for r in connected if r.tls and r.tls.error]
    unverified = [r for r in connected if r.tls and not r.tls.error
                  and not r.tls.verified]
    expiring = [r for r in connected if r.tls and r.tls.days_left is not None
                and r.tls.days_left < 21]
    no_ptr = [r for r in connected if not r.ptr]

    if open_relays:
        head = f"## 🔴 Open-relay flag on {len(open_relays)} host(s)"
    elif no_tls or broken_tls:
        head = f"## 🟠 TLS gaps on {len(no_tls) + len(broken_tls)} host(s)"
    else:
        head = f"## 🟢 {len(connected)} MX host(s) probed"
    lines = [head, "", f"`{domain}` · {mx_note}", ""]

    lines.append(f"- Connected: **{len(connected)}/{len(results)}** · "
                 f"STARTTLS offered: {sum(1 for r in connected if r.starttls_offered)}"
                 f" · AUTH advertised: {sum(1 for r in connected if r.auth_mechs)}")
    lines.append("")

    for r in results:
        lines.append(f"### {r.host}" + (f" (pref {r.preference})"
                                         if r.preference else ""))
        lines.append("")
        if r.connect_error:
            lines.append(f"- ✗ connection failed: `{r.connect_error}`")
            lines.append("")
            continue
        banner = r.banner[:120] + ("…" if len(r.banner) > 120 else "")
        lines.append(f"- Banner: `{banner or '—'}`")
        lines.append(f"- STARTTLS: {'✓ offered' if r.starttls_offered else '— not offered'}")
        if r.tls and not r.tls.error:
            cert = (f"{r.tls.subject_cn or '—'} · issued by "
                    f"{r.tls.issuer_cn or '—'} · "
                    f"{r.tls.days_left} day(s) left")
            lines.append(f"- TLS: {r.tls.version} · {r.tls.cipher}")
            lines.append(f"- Certificate: {cert}"
                         + ("" if r.tls.verified
                            else f" · ⚠️ **verification failed** "
                                 f"({r.tls.verify_error})"))
        elif r.tls:
            lines.append(f"- TLS: ⚠️ handshake broken ({r.tls.error})")
        if r.auth_mechs:
            lines.append(f"- AUTH mechanisms: {', '.join(r.auth_mechs)}"
                         " — advertising them in EHLO is normal; the "
                         "risk is what an unauthenticated session is "
                         "then allowed to do (see the relay probe)")
        lines.append(f"- PTR: {'`' + r.ptr + '`' if r.ptr else '— none'}"
                     + (" ✓ forward-confirmed" if r.ptr_confirmed
                        else " ⚠️ not forward-confirmed" if r.ptr else ""))
        if r.relay_verdict != RelayVerdict.NOT_TESTED:
            icon = {"accepted": "🔴", "rejected": "🟢",
                    "unclear": "🟡"}[r.relay_verdict.value]
            lines.append(f"- Relay probe: {icon} **{r.relay_verdict.value}**"
                         f" — `{r.relay_detail}`")
        lines.append("")

    if open_relays:
        lines += ["**Shut the relay down now.** An MX host accepting "
                  "third-party recipients from unauthenticated "
                  "connections will be found by spammers within days "
                  "and blacklisted within weeks — check "
                  "[DNSBL Check](../dnsbl-check) for the damage "
                  "already done.", ""]
    if no_tls:
        lines += [f"- ⚠️ {len(no_tls)} host(s) offer no STARTTLS — mail "
                  "to them crosses the internet in plaintext.", ""]
    if broken_tls:
        lines += [f"- ⚠️ {len(broken_tls)} host(s) offer STARTTLS but "
                  "the handshake fails — worse than none when clients "
                  "require it.", ""]
    if unverified:
        lines += [f"- ⚠️ {len(unverified)} host(s) present a "
                  "certificate that fails verification — check the "
                  "chain and the names ([TLS Audit](../tls-audit) "
                  "grades the HTTPS side).", ""]
    if expiring:
        names = ", ".join(f"{r.host} ({r.tls.days_left}d)" for r in expiring)
        lines += [f"- ⏰ certificate expiring within 21 days: {names}.", ""]
    if no_ptr:
        lines += [f"- ℹ️ {len(no_ptr)} host(s) have no PTR record — "
                  "many receivers weigh it in spam scoring.", ""]

    lines.append("_One connection per MX host on port 25; EHLO "
                 "capabilities read; STARTTLS handshaked; the relay "
                 "probe (if on) stopped before DATA — **no mail was "
                 "sent**. The DNS side of this domain (SPF/DMARC/DKIM) "
                 "belongs to [Email DNS Audit](../email-dns-audit)._")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(domain: str, mx_note: str,
                    results: list[HostResult]) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "domain": domain,
        "mx_note": mx_note,
        "hosts": [
            {**asdict(r), "tls": asdict(r.tls) if r.tls else None}
            for r in results
        ],
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    # The markdown is rebuilt here (report.md is an artifact too) from
    # the same results — same content the Results tab saw.
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(build_markdown(domain, mx_note, results,
                                any(r.relay_verdict != RelayVerdict.NOT_TESTED
                                    for r in results)) + "\n")
