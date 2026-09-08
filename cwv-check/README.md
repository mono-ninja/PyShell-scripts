# CWV Check

**What real Chrome users experience.** Everything else in the
collection's perf line is laboratory — Server Timing times one URL
from here, HAR Analyze reads the browser's recording, Load Test
degrades it, Cache Check watches the cache. The **field** — what
actual Chrome visitors measured — was nowhere. This script reads
it from the Chrome UX Report (CrUX):

- **LCP / INP / CLS p75** per form factor — phone and desktop
  separately, each assessed against the official bands (LCP ≤ 2.5
  s, INP ≤ 200 ms, CLS ≤ 0.10).
- **URL with the origin fallback** — CrUX needs a few hundred
  visits per URL; thin pages have no record, and the honest
  fallback is the **origin**, reported as exactly what it is
  (site-wide numbers, said aloud in the header and the notes).
- **The 25-week trend** — the history API as a line chart: is the
  p75 improving or rotting.
- **The lab-vs-field headline** — lab green + field red means the
  lab missed the visitors' network, device or real payload; that
  divergence is the actionable conclusion, and the report ends on
  it.

The API key is **free** (150 req/s — Google Cloud Console → enable
the Chrome UX Report API → create a key); without it the script
exits with instructions, never an imitated number.

## Using with PyShell

1. Enter the **URL** (a page, or a site root for the origin
   record).
2. Put the **CrUX API key** in the field (stored in the Keychain,
   sent via `CRUX_API_KEY`).
3. Press **Prepare Env** (installs `requests`), then **Run** (⌘↩).

## Running standalone

```bash
export CRUX_API_KEY=…   # free key from Google Cloud Console
python3 main.py --url https://example.com/
```

## Result

- **Results tab** — a table (form factor · metric · p75 ·
  assessment), the 25-week trend chart, and the report with the
  lab-vs-field headline.
- **Artifacts** — `report.md` (the same report, the trend
  included as prose), `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the field picture |
| 1 | no API key, or no CrUX data for the URL nor the origin |
| 2 | bad arguments (no http(s) URL) |

## Layout

```
cwv-check/
├── pyshell.yaml      # manifest
├── main.py           # CrUX queries · bands · trend · headline
├── requirements.txt  # requests
└── docs/             # EN + UA docs
```

## License

MIT — see the root [LICENSE](../LICENSE).
