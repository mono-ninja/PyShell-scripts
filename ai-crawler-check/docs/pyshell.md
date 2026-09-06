# AI Crawler Check

What your site gives AI crawlers — the **policy** side: the
robots.txt census of the 14 known AI crawlers (GPTBot, ClaudeBot,
PerplexityBot, CCBot, Google-Extended, Bytespider… — blocked /
partial / allowed / **not mentioned = allowed by default**), the
`/llms.txt` and `/llms-full.txt` **convention** (presence and shape,
honestly "not a standard"), and the noai/noimageai markers
(X-Robots-Tag header + meta robots on the page).

Bot Hunter is the log side (who actually came); this is what the
site told them beforehand. The script makes the state visible —
the allow/block choice itself is editorial.

---

## Before running

1. Enter the **URL** of the site.
2. **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the site. robots.txt and llms.txt are read from the
  origin; the noai markers from this exact page.
- **Per-request timeout (s)** — 3–60, default 15.

---

## Result

- **Results tab** — the census table (crawler · operator ·
  robots.txt) and the report:
  - **The census** — every crawler with 🚫 blocked / ◐ partial /
    ✅ allowed / ⚪ not mentioned; the `*`-group inheritance named
    ("partial via *"), with the trap spelled out: a bare
    `Disallow: /` under `*` also hits normal search engines.
  - **llms.txt** — present / absent / 200-but-wrong-shape; absent
    is reported as a fact, not a failure ("a convention several AI
    tooling vendors read, not a standard").
  - **noai markers** — the header and meta values found (or their
    absence as a fact).
  - **Reading it** — the Google-Extended nuance (Gemini-only, does
    not touch Search), the reverse shape (welcoming AI while
    unindexed), and robots.txt-as-a-request: Bytespider is the
    famous non-complier; enforcement is a firewall job (**Port
    Check**, **FW Audit**).
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the policy picture |
| 1 | unreachable |
| 2 | bad arguments: no http(s) URL |

## Related

- **Robots Audit** — the robots.txt validator (syntax and sanity);
  this script adds the AI-crawler reading of the same file.
- **Bot Hunter** — the log side: who actually crawled, classified
  by agent.
- **Tech Stack** — the classic third-party inventory; the AI
  crawlers are the new neighbors.
