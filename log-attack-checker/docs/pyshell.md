# Log Attack Checker

Analyses Apache/Nginx access logs for attacks targeting WordPress sites:
SQL injections, XSS, path traversal, LFI/RFI, brute force on
`wp-login.php` / `xmlrpc.php`, plugin and theme scanning, webshell attempts
in `/wp-content/uploads/`, and more. Nothing is sent to the target site —
the script only reads log files and builds reports.

## Before running

- **Logs directory** — a directory with `.log` files (or rotated `.log.1`,
  `.log.2`). Expects the Combined Log Format:
  `IP - - [date] "METHOD PATH PROTO" STATUS SIZE "REFERER" "UA"`.
  Parsing is parallelised across CPU cores via byte ranges of the files.
- **Site domain** — the site's domain (e.g. `example.com`). Used in the cURL
  commands of the HTML report; the IP is auto-resolved from it via DNS. The
  domain and IP appear in the terminal, in the header of `report.html` and
  inside its cURL commands; they never end up in `report.md` or
  `report.json`.
- **Whitelisted IPs** — IPs excluded from the analysis entirely (your own
  traffic, monitoring). Enter them comma- or space-separated:
  `1.2.3.4,5.6.7.8`.
- **Detection thresholds** — thresholds for all detectors (brute force,
  404-flood, cron-flood, rate limit, attack chains). Lower a threshold to
  catch smaller bursts; raise it to reduce false positives on a busy site.
  All detectors work in the sliding **Time window (minutes)**.
- **GeoIP** — country plus Proxy/VPN and Hosting/Datacenter flags for the
  top attacker IPs via `ip-api.com` (batch endpoint, free, no key). The
  geo-blocking recommendation is weighted by request volume, not IP count,
  and is only shown when ≥10 IPs were looked up. Enable **Skip GeoIP
  lookups** to avoid the network entirely.

## How it runs

Progress and status are streamed as structured events: log parsing →
detectors → aggregation → GeoIP → report building. At the end the **Results**
tab shows:

- a summary **table** of metrics;
- a **chart** of requests vs attacks per hour (last 48 hours, date in the
  labels);
- a **markdown verdict** with the critical findings (compromised accounts,
  successful attacks, top attacker IPs).

## Artifacts

All three reports are written to `PYSHELL_OUTPUT_DIR`:

- **report.html** — self-contained dark-themed HTML: sensitive files under
  attack, a hardening plan with ready-to-paste Nginx / Apache / cURL blocks
  (with the real domain instead of `https://SITE`), a timeline chart, IP
  tables.
- **report.md** — the full markdown report, ready to paste into an AI
  assistant.
- **report.json** — machine-readable output for SIEM / Grafana.

## Classification and verdict

Every request matching an attack pattern is classified as **SUCCESS**
(2xx/3xx), **Vulnerable** (500 — the endpoint exists and crashed) or
**Blocked**. The final verdict follows the highest severity: compromised
accounts (brute force + successful login) → webshell in uploads → successful
plugin actions → data exfiltration → successful attacks → vulnerable
endpoints → attack chains → brute force.

## Network

Only GeoIP reaches the outside network (`ip-api.com`). The site domain is
resolved locally via `socket.gethostbyname`. PyShell does not sandbox the
process — the script has the same permissions you do.

## Exit codes

- `0` — the analysis finished. Attacks found are a result, not a script
  failure; the findings are in the table/chart/markdown and the report files.
- `1` — fatal error: the logs directory was not found, or it contains no
  `.log` / `.log.N` files (the message names unsupported files that were
  ignored, e.g. compressed rotations).
- `2` — invalid argument (e.g. a detection threshold below its minimum);
  argparse prints the accepted value on stderr.
