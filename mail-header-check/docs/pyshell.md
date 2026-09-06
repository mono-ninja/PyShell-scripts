# Mail Header Check

Diagnoses **why a mail landed where it did**: the SPF/DKIM/DMARC
verdicts from `Authentication-Results` with alignment analysis, the
Received hop chain with per-hop delays and TLS markers, phishing
signals and attachment flags — read from a saved `.eml file, nothing
sent anywhere.

The fourth act of the mail story: **Email DNS Audit** (policy) ·
**Mail Probe** (wire) · **DNSBL Check** (reputation) · **this script**
(the message itself). Local file, standard library, zero network.

---

## Before running

1. Save the message as `.eml` (Apple Mail: *File → Save As…*;
   Thunderbird: native; Gmail: *Show original* → download). Outlook's
   binary `.msg` is a different format and is not supported.
2. Pick a **Source** — one message, several, or a folder.
3. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **Source** — single / multiple / folder; `.eml` only.
  `--recursive` descends into subfolders in folder mode; non-eml
  files are noted as skipped.
- A message with no `Authentication-Results` is analyzed for the
  chain and signals and reported honestly: the receiver recorded no
  verdicts.

---

## Result

- **Results tab** — the table (file · from · SPF · DKIM · DMARC ·
  verdict) and the per-message report:
  - **Authentication** — the receiver's verdicts (topmost A-R header,
    the one the final receiver added; intermediaries' own A-R lines
    are counted and noted), plus the alignment analysis: does
    `smtp.mailfrom` / `header.d` match the visible From domain —
    exact, subdomain, or **misaligned**.
  - **Received chain** — newest first, each hop with 🔒/○ TLS marker,
    hosts, IP, protocol, timestamp and the wait at that hop; total
    transit time.
  - **Filter verdicts** — `X-Spam-*` headers when present.
  - **Signals** — bulk markers, Return-Path ≠ From, Message-ID from
    another domain (mailer service or forgery), plain-ESMTP hops.
  - **Red flags** — failed SPF/DKIM/DMARC, misaligned domains,
    Reply-To pointing at another domain (the phishing shape),
    executable/macro attachments, a Date header far from now.
  - **Attachments** — name, type, size, executable warning.
- **Artifacts** — `report.md`, `findings.json` (everything the report
  shows, machine-readable).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report lists what was found |
| 1 | every message was unreadable (no headers / not RFC 5322) |
| 2 | bad arguments: not `.eml`, missing file, empty folder |

## Related

- **Email DNS Audit** — the DNS side of the same story (SPF/DKIM/DMARC
  records, MTA-STS) for your own domain.
- **Mail Probe** — MX hosts, STARTTLS and certificates on the wire.
- **DNSBL Check** — the reputation lists.
