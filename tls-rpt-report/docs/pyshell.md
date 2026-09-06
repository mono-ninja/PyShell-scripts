# TLS RPT Report

Which receivers could not raise TLS to your MX. The sixth act of the
mail story and DMARC Report's twin: Email DNS Audit publishes the
MTA-STS policy and the TLS-RPT address (`_smtp._tls`), Mail Probe
walks your own TLS wire — and this script reads the **feedback
loop**: the RFC 8460 reports receivers mail to that address when
they could not deliver to you over TLS. Nobody is probed; the
internet already reported.

Inputs are what the mailbox already holds: `.json`, `.json.gz`, and
`.zip` (several reports inside one archive — all unpacked). Files
merge into one picture:

- **Failure types** — `starttls-not-supported` (the receiver's MX
  never offered TLS), `certificate-expired`,
  `certificate-not-trusted`, `validation-failure`,
  `sts-policy-invalid` (**your own policy is broken**),
  `tls-version-insufficient`, and friends — each with its counts
  and its meaning spelled out.
- **Your MX hosts the failures hit** — which of your MX names the
  failing sessions aimed at.
- **The sending MTAs** — which IPs failed, with per-type counts.
- **The mode read** — in `testing` mode failures are observations;
  in `enforce` mode every failure is **mail that did not land**.
  The report says which world you are in.

Offline, stdlib only, zero network — like DMARC Report.

---

## Before running

1. Save the report attachments from the mailbox (they arrive at the
   `_smtp._tls` TLS-RPT address of your domain — the one Email DNS
   Audit sets up).
2. Pick a **Source** — one file, several, or a folder (recursive for
   subfolders).
3. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **Source** — single / multiple / folder. Extensions: `.json`,
  `.json.gz`, `.zip`. A zip with several reports inside is unpacked
  entry by entry — every report joins the merged picture. Files in
  another format are noted as skipped.
- **Report file** — the single report (single mode).
- **Report files** — the reports to merge (multiple mode).
- **Report folder** — every report-like file in this folder is read
  (folder mode).
- **Recursive (with subfolders)** — folder mode: descend into
  subfolders.

---

## Result

- **Results tab** — the failure-types table (type · count · what it
  means) and the report:
  - **Successes vs failures** — the delivery rate over TLS.
  - **Failure types** — each RFC 8460 `result-type` with its count
    and a plain-language meaning; unknown types point at
    RFC 8460 §3.4 instead of guessing.
  - **Your MX hosts** — the receiving hostnames behind the failures.
  - **Sending MTAs** — the IPs behind the failures.
  - **What the mode means** — testing vs enforce, spelled out;
    `sts-policy-*` failures are flagged as **your side of the wire**.
- **Artifacts** — `report.md`, `findings.json` (per-type/IP/MX
  counts, mode, per-report details, unreadable files).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | no report parsed (all unreadable) |
| 2 | bad arguments: wrong extension, missing file, empty folder |

## Related

- **Email DNS Audit** — the MTA-STS record and the `_smtp._tls`
  address these reports arrive at.
- **Mail Probe** — your own MX's TLS wire, from your side.
- **DMARC Report** — the twin feedback loop for sender
  authenticity.
