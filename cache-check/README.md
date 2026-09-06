# Cache Check

**Is caching actually working?** Several requests to one URL watch the
`Age` header grow and the HIT/MISS status flip; `Cache-Control` is
decoded into a TTL (with the freshness that remains); a conditional
request checks that `ETag`/`Last-Modified` revalidation works; and the
classic cache-busters — `Set-Cookie` on the response, `Vary: Cookie`,
`private`, `no-store` — are called out by name.

The perf line of the collection: **Server Timing** shows why a page is
slow, **Load Test** shows how it degrades under load — this answers
the follow-up: *is the cache layer doing its job?* When the server
does not expose cache-status headers (`X-Cache`,
`CF-Cache-Status`, …), the report says so instead of guessing and
falls back to the Age/TTL evidence.

## Using with PyShell

1. Enter the **URL** of the page or asset to watch.
2. Press **Prepare Env** (installs `requests`), then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --url https://example.com/
python3 main.py --url https://example.com/ --requests 5 --interval 2
```

## Result

- **Results tab** — a table (request # · status · Age · cache status ·
  size · ms) plus the report: the Cache-Control policy in plain words,
  the HIT/MISS story, freshness remaining, whether revalidation
  works, cache-busters, and what to do about them.
- **Artifacts** — `report.md`, `cache_results.json` (every request,
  every header, machine-readable).

### What the report answers

- **Is it cached?** — HIT/MISS sequence, or Age growing when status
  headers are absent.
- **For how long?** — `max-age`/`s-maxage` TTL minus the observed Age.
- **Can it refresh cheaply?** — the conditional request: 304 means
  validators are honored.
- **What breaks it?** — `Set-Cookie` (the classic "cache plugin says
  it caches but every visitor misses"), `Vary: Cookie`, `private`,
  `no-store`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report describes the cache story |
| 1 | unreachable — connection failed (check the URL / your link) |
| 2 | bad arguments (no http(s) URL, requests out of 2–10) |

## Layout

```
cache-check/
├── pyshell.yaml      # manifest
├── main.py           # probe · decode · verdicts · report
├── requirements.txt  # requests
├── docs/
│   ├── pyshell.md    # EN docs
│   └── pyshell_ua.md # UA docs
└── tests/            # 12 tests against a local fake-CDN server
```

## License

MIT — see the root [LICENSE](../LICENSE).
