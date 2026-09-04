# Page SEO Audit

A [PyShell](https://github.com/mono-ninja/PyShell) script that runs a
full on-page SEO audit of **one URL**: response status, meta tags and
indexability, heading structure, image `alt` text, Open Graph / Twitter
Card tags, hreflang, structured data (JSON-LD, microdata, RDFa), word
count, and mixed content. One fetch, one parse pass, a report in seconds.
No crawling.

This is the one-shot counterpart to the
[Site Crawler](../site-crawler) + [SEO Checks](../seo-checks) pair: those
two need a whole crawl to say anything useful (duplicates, redirect
reliance and indexability all compare *across* pages); this one answers
"is this single page any good?" from a bare URL. HTTP security headers
have their own script ([Security Headers](../security-headers)) and are
deliberately **not** re-checked here.

## What gets checked

| Category | Checks |
|---|---|
| Response | audited status (2xx = pass, 4xx/5xx = fail), https scheme, redirect chain length, truncated body |
| Meta | `<title>` and meta description (missing/duplicate/length), **canonical** (duplicate, unresolvable, cross-domain), **indexability** — `noindex` from meta robots, `X-Robots-Tag`, or robots.txt, naming every source that said so; viewport, charset, favicon, `lang` |
| Headings | zero/multiple `h1`, empty headings, skipped levels, heading before the first `h1` |
| Images | missing `alt` attribute (aggregate warn; `alt=""` is correct for decorative images and never flagged), whitespace-only alt, filename-only alt, missing `width`/`height`, lazy-loaded first image |
| Social | Open Graph completeness, relative `og:image`/`twitter:image`, `og:url` vs canonical, Twitter card type |
| Hreflang | invalid codes, duplicates, non-absolute targets, missing self-reference, `x-default` |
| Structured Data | JSON-LD parsed and validated (`@context`, `@type`); microdata and RDFa read too |
| Content | word count vs threshold, text-to-markup ratio, landmarks, unfollowable anchors (`javascript:…`, `#`) |
| Mixed Content | any subresource loaded over bare `http://` on an https page |
| Links | *off by default*: per-link verification (HEAD + GET fallback) and canonical-target verification |

**No single score.** The deliverable is a per-category status table
(pass/warn/fail/info) plus the findings, worst first — "Images: warn,
Structured Data: pass" is more actionable than a single 74/100.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests` and `lxml`.
3. **URL** — the page to audit, with scheme (`https://…`). Press
   **Run** (⌘↩).

**Verify links on the page** is off by default — it is the one option
that sends requests beyond the page itself. **Fail the run on** wires a
severity threshold into the exit code for pipeline gating.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --url https://example.com/
python3 main.py --url https://example.com/ --check-links --link-scope internal
python3 main.py --url https://example.com/ --fail-on warn
```

## Result

- **Results tab** — a markdown report: response status and redirect
  summary, the per-category status table, then all findings (Category /
  Status / Detail / Fix), highest severity first.
- **Artifacts** — `page_facts.json` (every raw extracted fact — the
  evidence), `findings.json` (machine-readable; every finding carries a
  stable `code` for CI rules), `report.md`.

## Exit codes

- `0` — the page was fetched and audited, and nothing crossed **Fail the
  run on**. A page failing every check is still a successful audit by
  default.
- `1` — no usable response: timeout, connection refused, DNS failure, a
  non-HTML response, or an unparseable body.
- `2` — the audit ran to completion, but a finding at or above the **Fail
  the run on** severity was present.

## Layout

```
page-seo-audit/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point
├── requirements.txt     # requests, lxml
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
