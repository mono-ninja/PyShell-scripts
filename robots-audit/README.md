# Robots Audit

A [PyShell](https://github.com/mono-ninja/PyShell) script that validates
a robots.txt against **RFC 9309** and the classic indexing-killers —
live (fetched from a site) or as a local draft before deploying it.
Reads one robots.txt (plus one request per `Sitemap:` line when
verification is on); no crawling, no writes.

The third member of the crawl pipeline: [Site Crawler](../site-crawler)
respects robots.txt, [Bot Hunter](../bot-hunter) drafts one from your
access logs — this script tells you whether the file actually says what
you think it says.

## What it does

- **RFC 9309 syntax** — invalid lines, unknown fields, orphan rules,
  non-numeric `Crawl-delay`: everything crawlers silently ignore becomes
  a finding, because an ignored line is a rule you think you have but
  don't.
- **The classic traps** — a whole-site `Disallow: /` on `*` (`fail`,
  with the exact rule named); **duplicate user-agent groups**, whose
  second block crawlers never run; silent truncation past 500 KiB.
- **URL testing** — paste your key pages, get each one's verdict with
  the deciding rule, against any user-agent token or the `*` group.
  Evaluation follows Google's implementation of RFC 9309 §2.2.2: longest
  rule wins, ties go to `Allow`, `*`/`$` wildcards supported.
- **Sitemap directives** — absolute-URL enforcement per the RFC,
  cross-host sitemaps noted, optional 200-verification of each line.
- **Honest HTTP semantics** — 404 is "unrestricted" per the RFC (an
  info, not an error); 401/403 and 5xx get the crawler-divergence
  nuance spelled out.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **Site URL** or **a local robots.txt** — exactly one. Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --site-url https://example.com
python3 main.py --site-url https://example.com --test-urls "https://example.com/
https://example.com/private/" --user-agent Googlebot
python3 main.py --robots-file robots.draft.txt --verify-sitemaps
```

## Result

- **Results tab** — findings table (severity / check / detail / fix),
  URL-test verdicts, sitemap checks, and the groups as parsed.
- **Artifacts** — `findings.json` (machine-readable), `robots_parsed.json`
  (the parsed structure), `report.md`.

## Exit codes

- `0` — the audit ran; findings are results, not failures.
- `1` — the robots.txt could not be obtained (network error, missing
  file).
- `2` — bad arguments (neither or both sources, unusable URL).

## Layout

```
robots-audit/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: source selection, tests, events
├── requirements.txt     # requests
├── docs/
│   ├── pyshell.md       # operator docs (Docs panel)
│   └── pyshell_ua.md    # Ukrainian translation
└── src/
    ├── robotsio.py      # fetch / read (the only I/O)
    ├── parser.py        # RFC 9309 parser — groups, rules, notes
    ├── evaluate.py      # Google-style longest-match evaluation
    ├── checks.py        # the findings — pure over parsed facts
    └── report.py        # findings.json / robots_parsed.json / report.md
```

## License

[MIT](../LICENSE), same as the repository.
