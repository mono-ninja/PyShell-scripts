# Bot Hunter

Web-server log analyzer for SEO: detects bots, optimizes crawl budget,
generates scraper-blocking rules. Sends nothing over the network — it only
reads local log files and writes reports.

## Fields

- **Logs directory** — folder with Apache/Nginx logs (combined or
  vhost_combined format). Supports `.log`, `.txt`, `.gz`, `.bz2`, scanned
  recursively. Drop your server's `access.log*` files here.
- **Domain** — the site's domain for the report (e.g. `example.com`). Used
  only for the report title and file names; the logs themselves are not
  filtered by domain.
- **Max lines per file** — per-file line cap. `0` = unlimited. Handy for a
  quick pass over huge logs.
- **Skip blocking rules** — don't generate `nginx.conf` / `.htaccess`
  blocking configs. By default the rules are always generated.
- **Report format** — `HTML` for viewing and sharing with clients, `JSON`
  for programmatic use, `HTML + JSON` for archival.
- **Verbose** — print the list of found files and detailed progress.

## What you get

- **Progress bar** — log parsing (0–80%), bot detection (80–85%), report
  generation (85–100%).
- **Tables** — bot activity (top 20), disguised bots (IPs with a browser UA
  but bot-like behavior), blocking rules.
- **Charts** — request distribution by bot category (search, scraper,
  AI…), HTTP status-code distribution.
- **Markdown report** — full report in the Results tab: summary, bot
  table, detected threats, blocking rules, robots.txt recommendations.
- **Artifacts** — files in the artifacts tab:
  - `YYYY-MM-DD_domain.html` — full HTML report
  - `YYYY-MM-DD_domain.json` — raw data (if selected)
  - `YYYY-MM-DD_domain.nginx.conf` — nginx blocking rules
  - `YYYY-MM-DD_domain.htaccess` — Apache blocking rules
  - `YYYY-MM-DD_domain.robots.txt` — recommended robots.txt

## What it detects

1. **Known bots** — Googlebot, Bingbot, Yandex, GPTBot, Claude-Web,
   AhrefsBot and more (46 signatures). Each is marked legitimate or not.
2. **Disguised bots** — IPs with a browser User-Agent but systematic
   scanning (`/wp-json/`, `/plugins/`, high URL diversity). These requests
   count as human in most tools, but they are bots.
3. **Suspicious subnets** — /24 (IPv4) or /64 (IPv6) ranges with 3+ IP
   addresses or high traffic, indicating a botnet or distributed scraper.
   Legitimate bots (Google, Bing) are excluded.
4. **Crawl budget waste** — top 404 URLs and top 301 redirects burning the
   indexer's budget.
5. **Google rate limiting** — 429 response share for Google bots, peak
   hours, recommendations.
6. **Skip & format diagnostics** — the report shows which log formats were
   recognized (`combined` / `vhost_combined`) and classifies the lines that
   matched neither (`php-fpm`, `vhost-combined`, `no-match`), so the parse
   rate is a meaningful parser-health signal.

## Exit code

`0` on success: found bots and threats are the analysis result, not a script
error. The data lives in the tables and the report. `1` means the run could
not start at all — no domain given, logs directory missing, or a user-supplied
`--config` file not found.

## Running locally

Outside PyShell the script works as a plain CLI:

```bash
python main.py --domain example.com
python main.py --domain example.com --format json --verbose
python main.py --logs-dir /var/log/nginx --domain example.com
```

Reports are written to `reports/`. With `--output`, all artifacts (report,
robots.txt, blocking rules) are saved next to the given file; `--format`
decides the report content — `both` writes the HTML and JSON reports side by
side, and an extension that contradicts `--format` triggers a warning instead
of being silently followed. Log read errors go to stderr.
