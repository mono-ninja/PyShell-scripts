# AI Crawler Check

**What your site gives AI crawlers** — the policy side of the AI
question. Bot Hunter classifies who already *visited* (the log
side); this reads what the site *tells* them:

- **robots.txt — the AI crawler census** — GPTBot, OAI-SearchBot,
  ChatGPT-User, ClaudeBot, Claude-Web, CCBot, Google-Extended,
  PerplexityBot, Amazonbot, Applebot-Extended, meta-externalagent,
  Bytespider, YouBot, cohere-ai: blocked, partial, allowed — or
  **not mentioned**, which robots.txt means as *allowed by default*.
  The `*` group is read too, with its trap named: a blanket
  Disallow hits normal search engines just as hard.
- **llms.txt** — the `/llms.txt` and `/llms-full.txt` convention: a
  markdown brief of the site for LLM consumption. A **convention,
  not a standard** — the report treats it exactly as that:
  presence, reachability and shape, no invented normativity.
- **noai markers** — `X-Robots-Tag: noai, noimageai` headers and
  the `<meta name="robots">` family on the page.

Three fetches, plain words. The script doesn't judge the choice to
allow or block — that's editorial; it makes the current state
visible.

## Using with PyShell

1. Enter the **URL** of the site.
2. Press **Prepare Env** (installs `requests`), then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --url https://example.com/
```

## Result

- **Results tab** — the census table (crawler · operator ·
  robots.txt verdict) and the report: every crawler's status with
  its detail, the llms.txt state, the noai markers, and how to read
  it all (the Google-Extended nuance, the Bytespider
  non-compliance, robots.txt as a request, not a fence).
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the policy picture |
| 1 | unreachable |
| 2 | bad arguments (no http(s) URL) |

## Layout

```
ai-crawler-check/
├── pyshell.yaml      # manifest
├── main.py           # robots census · llms.txt · noai · report
├── requirements.txt  # requests
├── docs/             # EN + UA docs
└── tests/            # 7 tests: parsing pure + a local site
```

## License

MIT — see the root [LICENSE](../LICENSE).
