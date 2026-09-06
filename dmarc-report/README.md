# DMARC Report

**What the whole internet sees when it gets mail from your domain.**
The fifth act of the mail story: Email DNS Audit reads the policy,
Mail Probe walks the wire, DNSBL Check asks the reputation lists,
Mail Header Check dissects one message — and this script reads the
**feedback loop**: the aggregate RUA reports receivers mail to the
address in your DMARC record, daily, for free. Nobody is probed; the
internet already tells you who sent mail claiming your domain and
how authentication went.

Inputs are what the mailbox already holds: `.xml`, `.xml.gz`, and
the `.zip` bundles some providers send (several reports inside one
archive — all unpacked). Several files merge into one picture:

- **Sources** — per sending IP: volume, the DMARC verdict the
  receiver computed (alignment included), SPF/DKIM aligned counts,
  the dispositions taken.
- **Forwarders** — records whose envelope domain differs from yours
  while your DKIM signature survived the hop: the classic "failures
  that are not spoofing" (mailing lists, filter services).
- **Spoof candidates** — sources with zero aligned pass: what a
  `p=reject` would actually block.
- **Readiness** — the headline: the aligned-pass rate and whether
  the domain is ready to move `p=none → quarantine → reject`, with
  the blocker named.

Offline by default — the one opt-in network action is PTR resolution
for source IPs (`--resolve-ptr`). Stdlib only.

## Using with PyShell

1. Save the reports from the mailbox (the attachments of the
   messages your DMARC record's `rua=` receives).
2. Pick a **Source** — one file, several, or a folder.
3. Press **Run** (⌘↩).

## Running standalone

```bash
python3 main.py --single-file google.com!example.com!172...xml
python3 main.py --mode folder --input-folder ./reports --recursive
python3 main.py --mode folder --input-folder ./reports --resolve-ptr
```

## Result

- **Results tab** — the sources table (IP · messages · DMARC pass %
  · aligned counts · dispositions) and the report: readiness verdict
  with its blocker, per-source lines, forwarders, spoof candidates,
  how to read it.
- **Artifacts** — `report.md`, `findings.json`.

### The readiness ladder

≥99% aligned pass → **ready for p=reject** · ≥95% → **ready for
p=quarantine** · below → **stay at p=none**, with the failing volume
named. The verdict respects `policy_evaluated` — the receiver's own
alignment math, never re-guessed from raw auth results.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the picture |
| 1 | no report parsed |
| 2 | bad arguments (wrong extension, missing file, empty folder) |

## Layout

```
dmarc-report/
├── pyshell.yaml      # manifest
├── main.py           # xml/gz/zip in · merge · forwarder split · readiness
├── docs/             # EN + UA docs
└── tests/            # 12 tests: fixtures in all three container formats
```

## License

MIT — see the root [LICENSE](../LICENSE).
