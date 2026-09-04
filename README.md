# PyShell-scripts

Ready-made Python scripts for [**PyShell**](https://github.com/mono-ninja/PyShell) —
a desktop GUI that turns a Python script's manifest into a form, runs it in an
isolated virtual environment, and streams the output live.

This repo is the "Ready-made scripts" collection PyShell's own README points
to. Every script here ships a `pyshell.yaml` manifest, so it works right after
import — no manual setup beyond letting PyShell install the dependencies.

## Using a script

Each top-level folder (`curl/`, `image-converter/`, …) is a **complete,
independent PyShell script**. You only need the one folder for the script
you want — not the whole repository.

### Download a single script folder

Pick whichever fits how you work:

- **GitHub web UI, no tools needed** — open the script's folder on
  [github.com](https://github.com/mono-ninja/PyShell-scripts), then use the
  **···** menu at the top of the file listing → **Download directory**. Gives
  you a zip of just that folder.
- **`svn export`** — works against any public GitHub repo, no git config
  needed:
  ```bash
  svn export https://github.com/mono-ninja/PyShell-scripts/trunk/curl
  ```
- **`git sparse-checkout`** — if you want the folder as an actual git
  checkout (e.g. to track upstream changes):
  ```bash
  git clone --filter=blob:none --sparse https://github.com/mono-ninja/PyShell-scripts.git
  cd PyShell-scripts && git sparse-checkout set curl
  ```

Replace `curl` with the folder name of the script you want in any of the
above.

### Import it into PyShell

1. **+ Folder** (⇧⌘O) and pick the script's folder — or **+ File** (⌘O) for a
   single-file script that has no folder of its own.
2. Press **Prepare Env**. PyShell lists the script's dependencies (if any) and
   installs them into an isolated venv.
3. Fill in the form and press **Run** (⌘↩).

## Available scripts

| Script | Description | Dependencies |
|---|---|---|
| [`curl/`](curl) | Build and run a `curl` command from a form — wraps the system `curl` binary. Request/connection/TLS/auth/proxy/cookie/output fields, secrets go through the Keychain. | None — standard library only |
| [`http-request/`](http-request) | Send one HTTP request and inspect the response — method, query params, headers, JSON-or-raw body, cookies, timing, redirects. Bearer/Basic auth through the Keychain, secret redaction, optional repeat with min/median/max timing. | requests |
| [`email-dns-audit/`](email-dns-audit) | Check a domain's MX, SPF, DMARC and DKIM records and grade its email-spoofing protection — with a plain-language readiness summary. DNS lookups only. | dnspython |
| [`dnsbl-check/`](dnsbl-check) | Check an IP or a domain against the major public DNS blocklists (Spamhaus, SpamCop, Barracuda, SORBS, SURBL, …) — decoded return codes, TXT reasons, delisting links, and the public-resolver trap called out. DNS queries only; the reputation sibling of Email DNS Audit. | dnspython |
| [`image-converter/`](image-converter) | Convert images to AVIF, WebP, JPEG, PNG, TIFF or BMP with adjustable quality, batch/folder/recursive modes and optional resizing. | Pillow, pillow-avif-plugin |
| [`image-optimizer/`](image-optimizer) | Shrink JPEG/PNG/WebP file size without changing format — lossless recompression, metadata stripping, optional PNG quantization. Never writes a file bigger than the input. | Pillow, pyoxipng, mozjpeg-lossless-optimization |
| [`favicon-generator/`](favicon-generator) | Turn one image into the complete favicon set — multi-size ICO, classic PNGs, opaque apple-touch-icon, PWA icons, site.webmanifest and the ready-to-paste head snippet. Contained, never cropped; transparency kept where it's legal. | Pillow |
| [`page-seo-audit/`](page-seo-audit) | Full on-page SEO audit of one URL — meta & indexability (meta robots **and** `X-Robots-Tag`), headings, image alt text, social tags, JSON-LD, mixed content, optional link verification. One fetch, one report, no crawling. | requests, lxml |
| [`ip-domains/`](ip-domains) | Find all domains hosted on the same IPv4 — passive reverse-IP OSINT across crt.sh, HackerTarget, ViewDNS and Shodan (API key), then confirm the candidates with parallel forward-DNS resolution. | requests |
| [`subdomain-search/`](subdomain-search) | Enumerate a domain's subdomains via crt.sh, HackerTarget, RapidDNS and Shodan (API key), confirmed by parallel forward-DNS resolution — with wildcard-record detection so a catch-all `*.domain` can't fake the results. The inverse of IP → Domains. | requests |
| [`ip-search/`](ip-search) | Resolve a website's IP address through every method at once (system resolver, dnspython, DoH, DoT, live TCP/HTTP, dig/host/nslookup) and cross-check the answers, plus hosting/RDAP, DNS records, domain WHOIS, CDN/WAF detection, and traceroute. | dnspython |
| [`dns-propagation/`](dns-propagation) | Check one DNS record across ~20 public resolvers at once — who serves the new value, who still the old one, with TTLs, an agreement view and a propagation bar chart. The "did my change reach everyone" check a single lookup can't give. | dnspython |
| [`bot-hunter/`](bot-hunter) | SEO log analyzer — parse Apache/Nginx access logs (incl. `.gz`/`.bz2`), classify bot traffic, optimise crawl budget, and spot disguised bots, scrapers and suspicious subnets. HTML/JSON reports plus a robots.txt draft and ready-to-paste nginx/.htaccess blocking rules. | pyyaml (optional — config file only; core is stdlib) |
| [`log-attack-checker/`](log-attack-checker) | Analyse Apache/Nginx access logs for WordPress-targeted attacks — brute force, floods, attack chains, compromised accounts — with an HTML/MD/JSON report and a ready-to-paste server-hardening plan. Reads logs only, never touches the target site. | rich, requests |
| [`security-headers/`](security-headers) | Grade a URL's HTTP security headers (HSTS, CSP, cookie flags, …) with a letter score and concrete fixes. One passive GET, full redirect chain captured. | requests |
| [`tls-audit/`](tls-audit) | Grade a host's TLS layer — certificate chain, expiry, hostname, key strength, protocols, weak ciphers — from seven TLS handshakes (no HTTP requests), with a letter score. The transport-side sibling of Security Headers. | None — standard library only |
| [`seo-checks/`](seo-checks) | Run redirect/broken-link/canonical/sitemap/duplicate-content/orphan/meta checks against a Site Crawler snapshot — crawl once, re-check in seconds, no re-crawling. Optional `--baseline` diff against a previous run and a `--fail-on` CI gate. | requests (only for the optional external-link check) |
| [`robots-audit/`](robots-audit) | Validate a robots.txt against RFC 9309 — live or a local draft — with the indexing-killers caught by name: whole-site Disallow, duplicate user-agent groups, orphan rules, non-absolute sitemaps. Test your key URLs against the rules, with the deciding rule shown. The draft-checker for Bot Hunter's output. | requests |
| [`server-timing/`](server-timing) | Measure a URL's server response time with a DNS/TCP/TLS/TTFB phase breakdown, repeated over a series with percentiles. | None — standard library only |
| [`uptime-monitor/`](uptime-monitor) | Poll a URL for minutes and watch it live — a scrolling latency chart, three-way check classification (up / HTTP error / down), uptime percentage, p50/p95 latency and downtime intervals. | requests |
| [`site-crawler/`](site-crawler) | Crawl a site from a seed URL (robots.txt-respecting, politeness-tuned) and save a structured snapshot — pages, status codes, redirect chains, canonical, links — for downstream SEO checks. | requests, lxml |
| [`sitemap-generator/`](sitemap-generator) | Build `sitemap.xml` from a Site Crawler snapshot — only fetched, indexable, canonical URLs make it in, every exclusion is shown with its reason; hreflang alternates, preserved lastmod, automatic index+parts split past 50k URLs. | None — standard library only |
| [`svg-sprite-build/`](svg-sprite-build) | Bundle a folder of SVG icons into one `<symbol>` sprite. | lxml, tinycss2, jinja2 |
| [`svg-sprite-from-font/`](svg-sprite-from-font) | Convert a legacy icon font (FontAwesome 4, IcoMoon, …) into a `<symbol>` sprite. | lxml, tinycss2, jinja2, fontTools, svgpathtools |
| [`tech-stack/`](tech-stack) | Fingerprint a site's tech stack — technologies, versions, outdated libraries, and a full third-party inventory. | requests, pyyaml |
| [`cve-check/`](cve-check) | Known vulnerabilities (OSV.dev, free and keyless) for the versioned components of a Tech Stack snapshot — CVE IDs, CVSS scores and the version that fixes each one. Packages only: unmappable technologies are listed, never silently skipped. | requests |

Each script folder follows the same layout — a thin `main.py` entry point,
the logic in `src/`, one module per check:

```
<script-name>/
├── pyshell.yaml          # manifest: form fields and how they bind to the script
├── main.py               # thin entry point — argparse mirrors the manifest
├── requirements.txt      # dependencies, if any
├── README.md             # GitHub-facing docs: what it does, CLI usage, layout
├── src/                  # the logic, kept out of the entry point
│   ├── __init__.py
│   ├── snapshot.py       # shared input handling
│   ├── checks/           # one module per check
│   │   ├── redirects.py
│   │   ├── broken_links.py
│   │   ├── canonical.py
│   │   └── …
│   └── report.py         # result assembly: table/chart/markdown events, artifacts
└── docs/
    ├── pyshell.md        # operator docs shown in PyShell's Docs panel (⌘D)
    └── pyshell_ua.md     # Ukrainian translation
```

Simpler scripts (`curl/`, `ip-domains/`) keep everything in a single
`main.py` — `src/` appears as soon as the logic outgrows one file.

## Repository layout

- **Top-level folders** (`curl/`, `image-converter/`, …) — each one is a
  standalone, importable PyShell script. This is what the collection is for.
- **`_reference/`** — supporting material for script authors, not part of the
  collection: the script-authoring guide (`authoring-guide.md`, a copy of
  PyShell's own guide) plus small example scripts copied from the PyShell
  repo, each one illustrating a specific section of the guide. See
  [`_reference/README.md`](_reference/README.md) for the map.

The leading underscore keeps the reference folder sorted above the actual
scripts and signals it's supporting material, not part of the collection.

## Adding a new script

1. Create a new top-level folder named after the script.
2. Add `pyshell.yaml` — including `version`, a `description`, an `icon`
   (`lucide:<name>` from the list in the guide) and a `category` (Network,
   SEO, Recon, Security, Media, Icons) — plus `main.py`, and
   `requirements.txt` if it has dependencies.
3. Add `docs/pyshell.md` describing what the script does, what each field
   means, and what the exit codes/output mean for whoever is about to run it.
4. Add a `README.md` for GitHub: what the script does, how to run it in
   PyShell and standalone, the result, and the exit codes.
5. See [`_reference/authoring-guide.md`](_reference/authoring-guide.md) for
   the full manifest reference (field types, bindings, structured
   progress/table/chart events, secrets, artifacts).

## License

[MIT](LICENSE), matching PyShell itself.
