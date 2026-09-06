# SRI Check

**Whose code runs on your page, and is it pinned.** The
supply-chain view of a page's `<script>` and `<link rel=stylesheet>`
tags: what the third-party CDNs serve is what runs on your page —
and an `integrity` hash is the only thing that pins it. The
Polyfill.io incident (June 2024, half a million sites) needed no
new vulnerability anywhere: the delivery channel was the
vulnerability.

One page fetch, then one fetch per unique resource:

- **Unpinned third parties** — script/stylesheet from another origin
  with no `integrity`: named by host, with the fix ready.
- **Integrity without crossorigin** — for a cross-origin resource
  the hash is only checked in CORS mode; the browser refuses the
  subresource entirely. A broken tag, not a soft warning.
- **Same-origin integrity** — redundant *and* deploy-breaking: SRI
  is for resources you don't control.
- **Hash verification** — declared hashes checked against the bytes
  served right now: verified / mismatch (the file changed — deploy
  drift or tampering) / invalid format / honestly unverified.
- **Ready-to-paste tags** — complete
  `integrity="sha384-…" crossorigin="anonymous"` lines computed from
  today's responses, with the pinning tradeoff said aloud: a pinned
  CDN file that changes breaks the page. Pin versioned URLs.
- **Host inventory** — your origin / same-site-other-origin /
  third-party, with pin coverage per host.

**Attributes only** mode inspects the tags without downloading any
resource — exactly one request in total.

## Using with PyShell

1. Pick the page (one URL — like Page SEO Audit, no crawling).
2. Press **Run** (⌘↩).

## Running standalone

```bash
pip install -r requirements.txt
python3 main.py --url https://www.python.org/
python3 main.py --url https://example.com/page/ --skip-fetch
```

## Result

- **Results tab** — the resources table (resource · kind · side ·
  integrity · verdict) and the report: host inventory, red/yellow
  findings, ready-to-paste tags, verified hashes.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | page unreachable / answered non-200 |
| 2 | bad arguments (not a full http(s) URL) |

## Layout

```
sri-check/
├── pyshell.yaml      # manifest
├── main.py           # tag parse · findings · hash verify · snippets
├── requirements.txt  # requests
├── docs/             # EN + UA docs
└── tests/            # 11 tests: two-origin local fixture
```

## License

MIT — see the root [LICENSE](../LICENSE).
