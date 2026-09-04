# Bot Hunter

A [PyShell](https://github.com/mono-ninja/PyShell) script that analyzes
Apache/Nginx access logs from an SEO point of view: which bots visit the
site, where the crawl budget goes, and which scrapers should be blocked.
Sends nothing over the network — it only reads local log files and writes
reports.

Reads `combined` and `vhost_combined` (cPanel-style) log formats, including
`.gz` and `.bz2` archives, scanned recursively. Multi-gigabyte logs are
expected: the parse phase is a single pass and everything downstream works
on the aggregated stats.

## What it detects

- **Known bots** — Googlebot, Bingbot, Yandex, GPTBot, Claude-Web,
  AhrefsBot and more (46 signatures), each marked legitimate or not.
- **Disguised bots** — IPs with a browser User-Agent but systematic
  scanning (`/wp-json/`, `/plugins/`, high URL diversity). Most tools count
  these as human; Bot Hunter does not.
- **Suspicious subnets** — /24 (IPv4) or /64 (IPv6) ranges with 3+ IP
  addresses or high traffic: a botnet or a distributed scraper. Legitimate
  bots (Google, Bing) are excluded, so their ranges are never flagged.
- **Crawl-budget waste** — top 404 URLs and top 301 redirects burning the
  indexer's budget.
- **Google rate limiting** — 429-response share for Google bots, peak
  hours, recommendations.
- **Parser diagnostics** — which log formats were recognized and how the
  non-matching lines classify (`php-fpm`, `vhost-combined`, `no-match`), so
  the parse rate is a meaningful parser-health signal.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `pyyaml` (needed only for the optional
   config file; the analysis itself is standard library).
3. Fill in the form and press **Run** (⌘↩).

The **Results** tab shows bot-activity tables (top 20, disguised bots,
blocking rules), charts by bot category and status code, and a full
markdown report. Field-by-field documentation lives in
[`docs/pyshell.md`](docs/pyshell.md) — the same text is shown in PyShell's
**Docs** panel (⌘D).

Artifacts (dated per run, named after the domain):

- `YYYY-MM-DD_domain.html` — full HTML report
- `YYYY-MM-DD_domain.json` — raw data (when selected)
- `YYYY-MM-DD_domain.nginx.conf` / `.htaccess` — ready-to-paste blocking
  rules
- `YYYY-MM-DD_domain.robots.txt` — recommended robots.txt

## Running standalone

```bash
python3 main.py --domain example.com
python3 main.py --domain example.com --format json --verbose
python3 main.py --logs-dir /var/log/nginx --domain example.com
```

- Reports go to `reports/`; `--output` redirects every artifact (report,
  robots.txt, blocking rules) next to the given file.
- `--format` decides the report content (`html` | `json` | `both`); an
  extension that contradicts `--format` triggers a warning instead of
  being silently followed.
- `--max-lines` caps lines per file (`0` = unlimited) for a quick pass
  over huge logs; `--no-blocking` skips the blocking configs.
- `botHunter_config.yaml` supplies defaults (this is what needs `pyyaml`).
  A missing default config is a soft fallback to CLI flags only; a missing
  user-supplied `--config` path is a hard error.

## Exit codes

- `0` — the analysis ran. Found bots and threats are results, not errors.
- `1` — the run could not start: no domain given, logs directory missing,
  or a user-supplied `--config` file not found.

## Layout

```
bot-hunter/
├── pyshell.yaml            # manifest: form fields, bindings, artifacts
├── main.py                 # orchestration entry point
├── src/                    # parser, analyzer, classifier, blocking, robots, reports
├── botHunter_config.yaml   # optional defaults
├── requirements.txt        # pyyaml (config loading only)
└── docs/
    ├── pyshell.md          # operator docs (Docs panel)
    └── pyshell_ua.md       # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
