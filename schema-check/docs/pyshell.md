# Schema Check

Is the structured data valid — and is it worth anything: JSON-LD
parsed (`@graph` walked, `@type` arrays flattened) and validated
against **curated schema.org shapes** (YAML data: required and
recommended properties per type, nesting understood — Product →
offers → Offer with its own requireds; URL-shaped and date-shaped
checks), microdata and RDFa spotted alongside, the
**schema-vs-page cross-check** (the markup price that appears
nowhere in the visible text), and the verdict no validator gives:
**valid but no rich result** — Google's bounded supported list
(31 types as of March 2026), a type outside it is not an error but
"for Bing/Perplexity, not for Google".

Page SEO Audit extracts the JSON-LD as a presence signal; this
script is its validation sibling.

---

## Before running

1. Enter the **URL** of the page.
2. **Prepare Env** — installs `requests`, `lxml`, `pyyaml`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the page; one fetch, everything else offline.
- **Per-request timeout (s)** — 3–60, default 15.

---

## Result

- **Results tab** — the table (severity · check · entity · detail)
  and the report:
  - **The verdict validators don't give** — per top-level type:
    🟢 in Google's rich-result list, or ⚪ valid-but-no-rich-result
    with the Bing/Perplexity note.
  - **jsonld** — invalid JSON, named by script block.
  - **required / recommended / shape** — the curated shape
    findings per entity.
  - **vs-page** — the price/name contradictions.
  - **Other syntaxes** — microdata/RDFa counts and the
    one-syntax-per-page smell note.
- **Artifacts** — `report.md`, `findings.json` (entities with
  their keys, machine-readable).

### The data file

`schema_types.yaml` carries Google's supported list and the
per-type shapes — both age (Google drops types, schema.org grows
properties); updating is a data edit, not a code change.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | unreachable, or no structured data found |
| 2 | bad arguments: no http(s) URL |

## Related

- **Page SEO Audit** — extracts the same JSON-LD as a signal;
  mutual pointers in both READMEs.
- **AI Crawler Check** — the policy side; good schema is what AI
  answers cite.
- **Site Crawler → SEO Checks** — the whole-site pass.
