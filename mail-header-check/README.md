# Mail Header Check

**Why a mail landed where it did** — the diagnosis of a saved `.eml`
message: the SPF/DKIM/DMARC verdicts the receiver recorded in
`Authentication-Results`, an alignment analysis (does the signed
domain match the visible From?), the `Received` hop chain with
per-hop delays and TLS markers, and the small signals that make
filters nervous — Reply-To pointing at another domain, bulk markers,
executable attachments, SpamAssassin verdicts.

The fourth act of the mail story: **Email DNS Audit** reads the
policy, **Mail Probe** walks the wire, **DNSBL Check** asks the
reputation lists — this reads **the message itself**. A local file,
the standard library, no network at all: nothing is queried, nothing
is sent.

## Using with PyShell

1. Save the message as `.eml` (in Apple Mail: select → *File → Save
   As…*; in Thunderbird it's the native format; Gmail: *Show
   original* → download).
2. Pick a **Source** — one message, several, or a folder (recursive
   for subfolders).
3. Press **Run** (⌘↩).

## Running standalone

```bash
python3 main.py --single-file spam.eml
python3 main.py --mode multiple --input-file a.eml --input-file b.eml
python3 main.py --mode folder --input-folder ./inbox --recursive
```

## Result

- **Results tab** — a table (file · from · SPF · DKIM · DMARC ·
  verdict) and a per-message report: authentication verdicts with
  alignment, the hop chain (`🔒` TLS / `○` plain) with per-hop waits
  and total transit time, filter verdicts when present, signals,
  red flags, attachments.
- **Artifacts** — `report.md`, `findings.json`.

### The verdicts

- 🟢 **authenticated** — SPF+DKIM+DMARC all pass and domains align.
- 🟠 **partial** — some verdicts missing or neutral.
- 🔴 **suspicious** — any red flag: a failed verdict, a misaligned
  domain, a Reply-To to another domain, an executable/macro
  attachment, a Date header far from now.

When the header carries no `Authentication-Results`, that is reported
honestly — the receiver recorded no verdicts; guessing is not
diagnosis.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report lists what was found |
| 1 | every message was unreadable |
| 2 | bad arguments (not an `.eml`, missing file, empty folder) |

## Layout

```
mail-header-check/
├── pyshell.yaml      # manifest
├── main.py           # parse · align · chain · signals · report
├── docs/
│   ├── pyshell.md    # EN docs
│   └── pyshell_ua.md # UA docs
└── tests/            # 17 tests, dynamic-date .eml fixtures
```

## License

MIT — see the root [LICENSE](../LICENSE).
