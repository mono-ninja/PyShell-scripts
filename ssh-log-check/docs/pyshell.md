# SSH Log Check

Answers the questions an sshd log holds: who is hammering the server,
what usernames they're trying, and — the critical one — **whether any
of them got in**. The third sibling of the log-analyzer family:
[Bot Hunter](../../bot-hunter) classifies bots, [Log Attack
Checker](../../log-attack-checker) reads web attacks, this one reads
SSH.

Reads logs only. The only outbound traffic is the optional GeoIP
lookup of attacker IPs (free ip-api.com batch) — `--skip-geoip` makes
the run fully offline.

---

## Before running

1. Copy the logs off the server into one folder: `auth.log`,
   `auth.log.1`, `auth.log.2.gz`, `secure`, a `journalctl -u ssh`
   text/JSON dump, or a macOS `log show` export. The format is
   detected **per file**; whatever parses to nothing is reported as
   skipped, never silently.
2. Click **Prepare Env** — installs `requests`.
3. Point **Logs directory** at the folder, press **Run** (⌘↩).

## Fields

### Source

- **Logs directory** — one folder, non-recursive. `.gz` files are
  decompressed on the fly.
- **Whitelisted IPs** — your own addresses (the office NAT, the VPN
  gateway): a mistyped password from there is not an attack, and
  leaving them in would skew every count.

### Detection

- **Brute-force threshold** — failed attempts from one IP needed to
  flag it. Default 5 (fail2ban's window counts 3–5).
- **Top N in tables** — table rows; `findings.json` keeps everything.

### GeoIP

- **Skip GeoIP lookup** — off by default: attacker IPs get a country
  plus proxy/hosting flags via ip-api.com. On = fully offline.
- **GeoIP lookup limit** — distinct IPs to enrich, busiest first
  (the free tier is rate-limited).

---

## What gets detected

| Pattern | Meaning |
|---|---|
| `Failed password for … from IP` | a failed password attempt |
| `Invalid user … from IP` | a username that doesn't exist — probe noise, but it maps the attacker's wordlist |
| `maximum authentication attempts exceeded` | sshd gave up on that IP |
| `Disconnected/Connection closed … [preauth]` | preauth probe noise (counted, not flagged) |
| `Accepted … for user from IP` | a successful login — method (publickey/password) recorded |
| **failures → success, same IP** | the critical chain: an IP that failed and then got in. The report puts these in red — rotate those credentials before anything else |

## Result

- **Results tab** — the brute-force table (IP · failed · users tried ·
  got in? · last seen · country), then the report: the red
  success-after-failure section, the brute-force IP table, the tried
  usernames wordlist, accepted logins, and next steps.
- **Artifacts** — `report.md`; `findings.json` (every flagged IP with
  users, acceptances, timestamps, geo); `fail2ban_jail.conf` — a
  ready `/etc/fail2ban/jail.local` sshd jail with the observed
  offenders commented, plus ufw deny lines. **IPs that also logged in
  are never suggested for a raw block** — blocking your own leaked
  credentials' holder is how you lock yourself out; they're marked
  "ALSO ACCEPTED A LOGIN" instead.

### Reading the data honestly

- The success-after-failure heuristic lists every IP that both failed
  and succeeded. An IP with a handful of failures then years of
  successful key logins is probably a mistyping human — the counts are
  shown so you can judge; the section title says "may have won", not
  "did".
- Syslog timestamps carry no year — the month-rollover heuristic is
  applied (a month "in the future" means last year's log).
- Whitelisted IPs are excluded entirely, by design: the counts then
  describe everyone else.

## Exit codes

- `0` — the analysis ran. Brute force and compromised accounts are
  findings, not failures.
- `1` — no sshd events in any file (wrong folder or unsupported
  format — the log names the skipped files).
- `2` — bad arguments (the path is not a folder).
