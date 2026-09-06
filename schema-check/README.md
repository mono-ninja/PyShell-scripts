# Schema Check

**Is the structured data valid — and is it worth anything?** Page
SEO Audit **extracts** the JSON-LD (presence as a signal); this
script **validates** it and adds the verdict no official validator
gives: **valid but no rich result**. Google renders rich results
for a bounded list of types (31 as of March 2026; the FAQ listing
left the SERP in May 2026) — a perfectly valid `WebPage` block
earns nothing in Google and still feeds Bing, Perplexity and every
other consumer. Valid ≠ valuable, and the report says which.

- **JSON-LD parses** — invalid JSON in a ld+json script is the
  most common failure in the wild; `@graph` walked, `@type` arrays
  flattened.
- **Types against curated schema.org shapes** (YAML data):
  required and recommended properties per type, nesting
  understood (`Product` → `offers` → `Offer` with its own
  requireds), URL-shaped and date-shaped property checks.
- **Microdata and RDFa alongside** — spotted and counted; mixing
  three syntaxes is a maintenance smell, said as such.
- **The schema-vs-page cross-check** — the `Product.offers.price`
  that appears nowhere in the visible text: markup and page must
  agree.

## Using with PyShell

1. Enter the **URL** of the page.
2. Press **Prepare Env** (installs `requests`, `lxml`, `pyyaml`),
   then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --url https://example.com/product
```

## Result

- **Results tab** — a table (severity · check · entity · detail)
  and the report: the rich-result verdict per type, the findings
  grouped by check, the other-syntaxes note.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | unreachable, or no structured data on the page |
| 2 | bad arguments (no http(s) URL) |

## Layout

```
schema-check/
├── pyshell.yaml       # manifest
├── main.py            # extract · validate · cross-check · report
├── schema_types.yaml  # the curated shapes + Google's list (data)
├── requirements.txt   # requests, lxml, pyyaml
├── docs/              # EN + UA docs
└── tests/             # 12 tests over HTML fixtures
```

## License

MIT — see the root [LICENSE](../LICENSE).
