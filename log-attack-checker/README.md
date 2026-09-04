# Log Attack Checker

Apache/Nginx access log security analyzer for WordPress sites. Parses raw HTTP logs, classifies attack patterns, detects coordinated threats, and produces actionable hardening recommendations with ready-to-paste Nginx/Apache config snippets and cURL verification commands.

## Quick Start

```bash
# Install dependencies (any venv works)
python3 -m venv .venv && source .venv/bin/activate
pip install rich requests

# Analyse a logs directory
python3 main.py -d /path/to/logs -o /path/to/output

# With site domain and IP whitelist
python3 main.py -d /path/to/logs -s example.com -w 1.2.3.4 5.6.7.8
```

## Using with PyShell

This project ships a `pyshell.yaml` manifest, so it can be imported as a folder
into [PyShell](https://github.com/mono-ninja/PyShell) and run from a generated
form (no CLI needed). Under PyShell:

- The form exposes all options grouped into **Source**, **Detection** and
  **GeoIP** (advanced thresholds are pre-filled with sane defaults).
- Progress, status, a summary table, an hourly chart and a markdown verdict are
  streamed as structured events to the Results tab.
- The three reports are written as **artifacts** to `PYSHELL_OUTPUT_DIR`
  (shown with **Show** / **Save** buttons), not next to the script.
- Heavy analysis is skipped during introspection (`PYSHELL_INTROSPECT=1`).

From a plain terminal it renders full `rich` tables and writes the reports to
`--output-dir` (default: the current directory).

Place `.log` files (or rotated `.log.1`, `.log.2`) in the `logs/` directory, then run.

## Output

**Terminal** — Rich-formatted tables rendered in the shell:

| Section | What it shows |
|---|---|
| Site / Server IP | Domain, auto-resolved IP, whitelist hint (if `-s` provided) |
| Sensitive Files Under Attack | Specific file paths targeted, with total and successful hit counts |
| Main Attack Stats | All detected attack types with SUCCESS / Blocked / Vulnerable counts |
| Top Attacked Endpoints | Most-hit URLs |
| Brute Force / Rate Limit / Flood IPs | IPs that exceeded thresholds |
| Coordinated Attack Chains | IPs using 3+ distinct WP attack vectors (≥1 hostile, non-2xx majority) |
| Geo / Proxy / Hosting Detection | Country distribution + Proxy/VPN + Hosting/Datacenter classification |
| Server Hardening Plan | Priority-ordered table: attack type → first Nginx fix line |
| Verdict | Severity-colored summary panel |

**`report.html`** — Self-contained dark-themed HTML report (no external dependencies):
- Collapsible sections, bar chart attack timeline
- Sensitive Files Under Attack table
- Server Hardening Plan with three-tab code blocks per attack vector: **Nginx** / **Apache** / **cURL — verify**
- cURL commands are copy-paste ready — substituted with the real domain when `-s` is provided

**`report.md`** — Full markdown report with:
- Sensitive Files Under Attack table
- Complete Server Hardening Plan — Nginx and Apache config blocks per attack vector, ordered CRITICAL → LOW
- All statistics, IP lists, timelines, attack vector URLs

**`report.json`** — Machine-readable output for SIEM/Grafana/scripting.

> `site` and `resolved_ip` are intentionally excluded from `report.md` and `report.json` — they appear in the terminal and inside `report.html` (header and cURL commands) only.

## CLI Options

```
-d, --logs-dir DIR          Directory with .log files (default: logs)
-o, --output-dir DIR        Output directory for reports (default: .)
-s, --site DOMAIN           Site domain or URL (e.g. example.com or https://example.com)
                            Substituted into the cURL commands of report.html.
                            IP is auto-resolved via DNS and shown in terminal with
                            a hint to add it to -w. Neither is written to
                            report.md / report.json.
-w, --whitelist IP [IP...]  IPs to exclude from analysis entirely

--bruteforce-threshold N        401s per window → brute force flag (default: 5)
--wp-login-post-threshold N     POSTs to wp-login.php per window (default: 10)
--notfound-flood-threshold N    404s per window → scanner flag (default: 50)
--wp-cron-flood-threshold N     wp-cron.php hits per window (default: 20)
--attack-chain-min-vectors N    Distinct WP attack types → coordinated attack (default: 3)
--time-window-minutes N         Sliding window for all detectors (default: 5)
--rate-limit-threshold N        Requests per window → rate limit flag (default: 100)
--geoip-limit N                 Max IPs sent to GeoIP API (default: 20)
--skip-geoip                    Skip GeoIP lookups entirely
--large-response-bytes N        Response size threshold for exfiltration detection (default: 100000)
--attack-burst-factor F         Multiplier over hourly avg for burst anomaly (default: 10.0)
```

## Attack Vectors

Matching runs against the request text (path + referer + user-agent, lowercased) with a single URL-decode pass appended when the line contains percent escapes — single-encoded payloads (`..%2fetc%2fpasswd`, `%24%7Bjndi:...`) are detected alongside their plain-text forms, and patterns written against encoded forms (`%27`, `%0d%0a`, `%2e%2e`) keep working. Double-encoded payloads (`%252e%252e`) are beyond a log-line matcher — put a WAF / ModSecurity layer in front of the site for those.

### General Web Attacks

| Pattern | What it detects | Risk |
|---|---|---|
| **SQL Injection** | `UNION SELECT`, `OR 1=1`, `DROP TABLE`, encoded quotes, `--` comment-out | Database extraction, auth bypass, data destruction |
| **XSS** | `<script>`, `alert(`, `javascript:`, `onerror=`, `onload=` | Session hijacking, defacement, keyloggers |
| **Malicious Script** | `shell.php`, `cmd.php`, `eval(`, `base64_decode`, `system(`, `passthru(` | Webshell drops and direct code execution |
| **Path Traversal** | `../`, `..\`, `%2e%2e` sequences | Reading files outside web root (`/etc/passwd`, configs) |
| **LFI / RFI** | `/etc/passwd`, `php://input`, `file://`, `=https?://` | Arbitrary file read or remote code execution |
| **Command Injection** | `; id`, `| cat`, backtick/`$()` execution | Full OS command execution, RCE |
| **Log4Shell** | `${jndi:ldap://`, `${jndi:rmi://` | RCE via CVE-2021-44228 in Java log pipelines |
| **XXE** | `<!ENTITY`, `SYSTEM "file://` | File read via malicious XML |
| **SSRF** | `localhost`, `127.0.0.1`, `169.254.169.254`, `metadata.google.internal` | Access to internal services, cloud metadata endpoints |
| **CRLF Injection** | `%0d%0a`, raw `\r\n` in parameters | HTTP response splitting, cache poisoning, cookie injection |
| **DNS Rebinding** | `url=` pointing to RFC-1918 addresses | Browser-mediated access to internal network |

---

### WordPress-Specific Attacks

| Pattern | What it detects | Risk |
|---|---|---|
| **WP Login Brute** | Any access to `wp-login.php` | Credential stuffing, brute force |
| **WP xmlrpc** | `xmlrpc.php` access | Multicall amplification — one request = thousands of auth attempts |
| **WP User Enum** | `?author=N`, `/wp-json/wp/v2/users`, `/author/` | Username harvesting for targeted brute force |
| **WP Email Enum** | `loggedout=true`, `action=lostpassword`, `checkemail=` | Email/username existence probing via password reset |
| **WP Config Access** | `wp-config.php` and its backups (`.bak`, `.old`, `.~`, `.swp`) | Database credentials, secret keys exposure |
| **WP Admin Scan** | `/wp-admin/` probing | Reconnaissance, targeted credential attacks |
| **WP Sensitive Files** | `readme.html`, `license.txt`, `.sql`, `.bak`, `.old` files | Version disclosure, database dumps, backup exposure |
| **WP REST API Probe** | `/wp-json/` endpoint scanning | User enumeration, private data exposure |
| **WP REST Auth Bypass** | `?context=edit` on REST endpoints | Access to private fields without authentication |
| **WP Plugin Probe** | `/wp-content/plugins/` enumeration (non-hseo) | Plugin fingerprinting, CVE targeting |
| **WP Theme Probe** | `/wp-content/themes/` enumeration | Theme fingerprinting, file exposure |
| **WP Plugin RCE** | Plugin PHP files with `cmd=`, `exec=`, `code=`, `pass=` params | Direct code execution via vulnerable plugin |
| **WP Theme RCE** | Theme PHP files with `action=`, `cmd=`, `code=` params | Direct code execution via vulnerable theme |
| **WP Webshell Upload** | `.php`, `.phtml`, `.phar` in `/wp-content/uploads/` | Full server compromise via uploaded webshell |
| **WP Admin AJAX** | `/wp-admin/admin-ajax.php` abuse | Privilege escalation, unauthenticated actions |
| **WP Vuln Plugin Probe** | `revslider`, `timthumb.php`, `wp-file-manager`, `slider-revolution`, `duplicator` | Exploitation of plugins with known public CVEs |
| **WP Version Leak** | `?ver=X.X` fingerprinting in `wp-includes`/`wp-content` | Precise version enumeration → targeted CVE exploitation |
| **WP Woo Probe** | `/wp-json/wc/`, `?add-to-cart=`, `/my-account/orders/` | WooCommerce payment logic vulnerabilities, order data extraction |
| **WP Cron Abuse** | `wp-cron.php` hits | External triggering consumes PHP workers — DoS vector |
| **WP Scanner Probe** | `wlwmanifest.xml`, `wp-links-opml.php`, `wp-app.php` | Universal WordPress confirmation fingerprint for scanners |
| **WP Trackback Spam** | `wp-trackback.php` | SEO spam, DoS via heavy DB queries |
| **WP Reg Spam** | `wp-signup.php`, `wp-register.php`, `?action=register` | Automated spam account creation |
| **WP Comment Spam** | `wp-comments-post.php` | SEO spam injection, XSS via comment fields |
| **WP Feed Scrape** | `?feed=rss`, `/feed/rss`, `/feed/atom` | Content scraping, DoS via expensive feed generation |
| **WP Debug Log** | `wp-content/debug.log`, `/upgrade/`, `/maint/` | Stack traces, credentials, and internal paths exposure |
| **WP Import/Export** | `import.php`, `export.php`, `wp-migrate-db` | Full database dump extraction |
| **WP PHP Info** | `phpinfo`, `info.php`, `php.info` | PHP version, config, and environment variable disclosure |
| **WP hseo Activation** | `action=activate.*plugin=hseo` | hseo plugin activation tracking |
| **WP hseo Install** | `plugin-install.php.*hseo`, `slug=hseo` | hseo plugin installation tracking |
| **WP hseo File Access** | `wp-content/plugins/hseo/` | Direct hseo plugin file access (shown in separate table) |

---

### Scanner / Bot Detection

Two-tier user-agent classification:

| Tier | Examples | Label |
|---|---|---|
| **Definite** | `sqlmap`, `nikto`, `nuclei`, `gobuster`, `dirbuster`, `hydra`, `nmap`, `acunetix`, `burpsuite`, `wfuzz`, `masscan`, `httpx` | Known Scanner |
| **Suspicious** | `python-requests`, `curl/`, `go-http-client`, `libwww-perl` | Suspicious Bot |

---

## Detectors

All detectors run on fully merged data after the parallel parse phase. All use O(N) sliding window (two-pointer technique).

| Detector | Trigger |
|---|---|
| **Brute Force** | N × 401 responses within time window |
| **WP Login POST Brute Force** | N × POST to `wp-login.php` within window |
| **XML-RPC Brute Force** | N × POST to `xmlrpc.php` within window |
| **404 Flood / Directory Scanner** | N × 404 responses within window |
| **WP Cron Flood / DoS** | N × `wp-cron.php` hits within window |
| **Rate Limiting** | N × total requests from one IP within window |
| **Attack Chains** | IP uses ≥ K distinct WP attack vector types |
| **Attack Bursts** | Hourly attack count > F × hourly average |
| **Compromised Accounts** | Brute force IP + POST `wp-login.php` → HTTP 302 *or* any 401 before a 302 from the same IP |
| **Data Exfiltration** | Successful attack + response size > threshold |
| **Vulnerable Endpoints** | Attack pattern match + HTTP 500 response |

## Attack Classification

Each matched request is classified as:

- **SUCCESS** — pattern matched + HTTP 2xx/3xx (server processed the request)
- **Vulnerable** — pattern matched + HTTP 500 (endpoint exists and errored — likely vulnerable)
- **Blocked** — pattern matched + any other status

## Verdict Priority

The final verdict is determined by the highest-severity finding:

1. Compromised accounts (brute force + successful login)
2. Webshell execution in uploads
3. Successful WP hseo plugin actions
4. Data exfiltration (successful attack + large response)
5. Other successful attacks
6. Vulnerable endpoints (attack → HTTP 500)
7. Coordinated attack chains
8. Active brute force

## Server Hardening Plan

For every attack vector detected in the logs, the report generates a ready-to-use config block sorted by priority:

| Priority | Vectors |
|---|---|
| **CRITICAL** | WP xmlrpc, WP Config Access, WP Webshell Upload, WP Vuln Plugin Probe, LFI/RFI, SQL Injection, Command Injection |
| **HIGH** | XSS, Path Traversal, WP Cron Abuse, WP Login Brute, WP Admin Scan, WP REST Auth Bypass, WP Debug Log, WP PHP Info, WP Sensitive Files |
| **MEDIUM** | WP Admin AJAX, WP Plugin Probe, WP Theme Probe, WP REST API Probe, WP User Enum, WP Scanner Probe |
| **LOW** | WP Version Leak |

Each entry includes:
- Risk description
- Hit counts (total and successful)
- Nginx config block
- Apache config block
- cURL verification commands (copy-paste ready; uses real domain when `-s` is set)
- Additional notes where needed (e.g., `wp-config.php` changes for WP Cron, `functions.php` snippets)

## GeoIP

Top attacker IPs are geolocated via the `ip-api.com` batch endpoint (free, no API key required). Returns country, proxy/VPN flag, and hosting/datacenter flag. Countries with ≥ 10% share of attack traffic (weighted by request volume, not IP count) are flagged for geo-blocking with instructions for Cloudflare, Nginx, and Apache. The recommendation reports its sample size and is suppressed when fewer than 10 IPs were looked up. Use `--skip-geoip` to avoid the network call (the free tier does not offer TLS).

## Requirements

- Python 3.11+ (the `pyshell.yaml` manifest constrains it to `>=3.11,<3.15`)
- `rich` — terminal rendering
- `requests` — GeoIP lookups

## Exit codes

- `0` — the analysis finished. Attacks found are a result, not a script
  failure; the findings live in the table/chart/markdown and the report files.
- `1` — fatal error: the logs directory was not found, or it contains no
  `.log` / `.log.N` files (the message names unsupported files that were
  ignored).
- `2` — invalid argument (e.g. a detection threshold below its minimum).

## Layout

```
log-attack-checker/
├── pyshell.yaml         # PyShell manifest: form fields → CLI flags
├── main.py              # thin CLI entry point (argparse only)
├── requirements.txt
├── docs/
│   ├── pyshell.md       # operator docs for PyShell's Docs panel
│   └── pyshell_ua.md    # Ukrainian translation
└── src/                 # all logic
    ├── analysis.py      # orchestration: parse → detect → enrich → report
    ├── config.py        # Config dataclass, whitelist parsing
    ├── detectors.py     # sliding-window threshold detectors
    ├── display.py       # rich terminal output
    ├── events.py        # PyShell events / progress / console
    ├── geoip.py         # ip-api.com batch lookups
    ├── hardening.py     # hardening + cURL data per attack vector
    ├── parsing.py       # log-line matcher + parallel chunk worker
    ├── patterns.py      # attack-pattern regexes
    ├── report.py        # report.md / report.json writers
    ├── report_html.py   # self-contained HTML report
    └── result.py        # AnalysisResult model, verdict, summary builders
```

## Log Format

Expects Apache/Nginx Combined Log Format:

```
IP - - [timestamp] "METHOD PATH PROTO" STATUS SIZE "REFERER" "USER-AGENT"
```

Rotated logs (`access.log.1`, `access.log.2`, etc.) are discovered and processed automatically. Processing is parallelized across CPU cores using byte-range chunks.

## License

[MIT](../LICENSE), same as the repository.
