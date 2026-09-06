# DMARC Report

What the whole internet sees in your mail: aggregate **RUA reports**
(`.xml`, `.xml.gz`, `.zip` bundles — several reports inside one
archive, all unpacked) from every receiver merged into one picture.
Per source IP: volume and the receiver's own DMARC verdict
(`policy_evaluated` — never re-guessed), SPF/DKIM aligned counts,
dispositions. The forwarder-vs-spoof split: envelope domain ≠ your
domain while your DKIM survived = forwarded legit mail; zero aligned
pass = spoof candidates. The headline — the aligned-pass rate and
whether the domain is ready for `p=none → quarantine → reject`.

Offline by default; `--resolve-ptr` is the only network action, and
it is opt-in.

---

## Before running

1. Save the report attachments from the mailbox (they arrive at the
   `rua=` address of your DMARC record).
2. Pick a **Source** — one file, several, or a folder (recursive for
   subfolders).
3. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **Source** — single / multiple / folder. Extensions: `.xml`,
  `.xml.gz`, `.zip`. A zip with several reports inside is unpacked
  entry by entry — every report joins the merged picture. Files in
  another format are noted as skipped.
- **Recursive (with subfolders)** — folder mode: descend into
  subfolders.

### Analysis

- **Resolve source hostnames (PTR)** — off by default. When on:
  each source IP gets a reverse-DNS lookup — the only network this
  script ever does; without it everything stays offline.

---

## Result

- **Results tab** — the sources table (source ip · messages · DMARC
  pass % · spf aligned · dkim aligned · disposition) and the report:
  - **Readiness** — ≥99% aligned pass → ready for p=reject; ≥95% →
    ready for p=quarantine; below → stay at p=none, with the failing
    volume named and what to fix (selectors, ARC for forwarders).
  - **Sources** — every sending IP with its verdicts.
  - **Forwarders — failures that are not spoofing** — envelope
    domain differs, DKIM signature survived: mailing lists and
    filter services; the reason arc-sealing exists.
  - **Spoof candidates — zero aligned pass** — what p=reject would
    block.
- **Artifacts** — `report.md`, `findings.json` (sources, forwarders,
  spoof candidates, per-report status).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | no report parsed (all unreadable) |
| 2 | bad arguments: wrong extension, missing file, empty folder |

## Related

- **Email DNS Audit** — the record the receivers evaluate
  (SPF/DKIM/DMARC as published).
- **Mail Header Check** — one saved message dissected (why *this*
  letter landed in spam).
- **Mail Probe** — the wire your own servers speak.
- **DNSBL Check** — the reputation lists.
