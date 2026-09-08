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
| [`bot-hunter/`](bot-hunter) | SEO log analyzer — parse Apache/Nginx access logs (incl. `.gz`/`.bz2`), classify bot traffic, optimise crawl budget, and spot disguised bots, scrapers and suspicious subnets. HTML/JSON reports plus a robots.txt draft and ready-to-paste nginx/.htaccess blocking rules. | pyyaml (optional — config file only; core is stdlib) |
| [`log-attack-checker/`](log-attack-checker) | Analyse Apache/Nginx access logs for WordPress-targeted attacks — brute force, floods, attack chains, compromised accounts — with an HTML/MD/JSON report and a ready-to-paste server-hardening plan. Reads logs only, never touches the target site. | rich, requests |
| [`security-headers/`](security-headers) | Grade a URL's HTTP security headers (HSTS, CSP, cookie flags, …) with a letter score and concrete fixes. One passive GET, full redirect chain captured. | requests |
| [`tls-audit/`](tls-audit) | Grade a host's TLS layer — certificate chain, expiry, hostname, key strength, protocols, weak ciphers — from seven TLS handshakes (no HTTP requests), with a letter score. The lifetime check follows the SC-081 schedule (200 days from March 2026, 100 from 2027, 47 from 2029 — keyed on the issue date, not a flat number) plus the renewal-cadence verdict ("will you manage this by hand"), and an openssl-backed probe reports the post-quantum X25519MLKEM768 hybrid: negotiated / refused / no TLS 1.3, honestly "not checked" when the local OpenSSL is older than 3.5 — never "not supported", never scored. The transport-side sibling of Security Headers. | None — standard library only |
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
| [`wp-exposure-check/`](wp-exposure-check) | Check which WordPress doors a site leaves open — REST user enumeration, XML-RPC, readme.html, debug.log, uploads listing, wp-login — one passive GET per endpoint, each with the verdict, the evidence and the fix. | requests |
| [`svg-optimize/`](svg-optimize) | Minify SVG files with scour — coordinate precision, metadata/comment/prolog stripping, opt-in ID shortening. Never writes a file bigger than the input; originals are never touched. The pre-pass before SVG Sprite — Build. | scour |
| [`password-check/`](password-check) | Check a password against known breaches via HIBP k-anonymimity — only a 5-character SHA-1 prefix ever leaves the machine — plus entropy and pattern analysis, and cryptographically strong generation. Secret field in, no artifacts out. | requests |
| [`wayback-check/`](wayback-check) | A site's history through the archive.org CDX API — first and last snapshot, a per-year activity chart, and the vanished pages (existed then, 404 now) as redirect-map candidates with a ready CSV. | requests |
| [`ssh-log-check/`](ssh-log-check) | Analyze sshd logs (auth.log, secure, journald JSON, macOS log-show, `.gz`) for brute-force IPs, the attacker username wordlist, and the critical failures-then-success chains — with a ready fail2ban jail. Reads logs only. | requests (only for the optional GeoIP lookup) |
| [`pdf-toolkit/`](pdf-toolkit) | Merge, split, extract, rotate, metadata-strip and compress PDFs — privacy-first: the report shows what the metadata would have leaked (author, producer, dates, attachments) before removing it. Originals never touched; images never re-encoded. | pypdf |
| [`color-palette/`](color-palette) | Extract a site's color palette from its CSS — backgrounds, text, borders, shadows, icons — every CSS color syntax parsed, near-identical colors grouped, delivered as a chart, a table, ready-to-paste `:root` variables and JSON. Static CSS only, honestly. | requests |
| [`asset-minify/`](asset-minify) | Minify CSS and JS through the system terser and clean-css-cli — a wrapper, like cURL — with optional vendor-prefixing via autoprefixer. Never overwrites originals; a file that won't shrink isn't written; missing binaries stop cleanly with the install line. | None — needs the system terser / clean-css-cli (npm) |
| [`mail-probe/`](mail-probe) | The SMTP wire layer of a mail domain — MX hosts, banners, EHLO capabilities, STARTTLS with the verified certificate, AUTH mechanisms, forward-confirmed PTR — plus an opt-in relay probe that stops before DATA (no mail is ever sent). The wire-side sibling of Email DNS Audit and DNSBL Check. | dnspython |
| [`exif-inspect/`](exif-inspect) | See what your photos say about you — the EXIF privacy inventory with GPS coordinates spelled out and map-linked, camera, software, dates, and the frames hidden inside multi-picture files (MPF) — plus optional EXIF-free clean copies (orientation baked in first, originals untouched). | Pillow |
| [`qr-generate/`](qr-generate) | QR codes from text or URLs — error-correction level, colors, optional center logo — one at a time or a batch from a CSV, saved as PNG artifacts. | qrcode[pil] |
| [`load-test/`](load-test) | Phased load against a site you own — controlled RPS per phase, a live latency/throughput chart, and a degradation report against the baseline. The one active-traffic script, gated by an ownership confirmation; no credentials, no amplification. | requests |
| [`wp-audit/`](wp-audit) | SAST over a WordPress site's own code — wp-content (themes and plugins) scanned against a curated 19-rule YAML rulebook: SQLi, XSS, eval-obfuscation malware signatures, object injection, SSRF, access-control gaps. Reads files only; bring your own rules in the documented schema. | pyyaml |
| [`tts-audio/`](tts-audio) | Text to speech on your machine — Kokoro neural voices through ONNX Runtime, offline and keyless, a dozen voices across languages, WAV artifact. Missing package or models is an honest exit 1 with instructions; models are opt-in downloads into a shared cache dir. | kokoro-onnx, soundfile |
| [`fleet-check/`](fleet-check) | One overview of a whole portfolio of sites — HTTP status, TLS grade and certificate days, security-headers grade, WordPress version, sitemap presence — via the sibling scripts (the needs chain, run as child processes) with labeled compact fallbacks, plus a fleet.json baseline diff. | requests, pyyaml |
| [`port-check/`](port-check) | TCP port scan of a host you own — the common-service set (~110 ports), your own spec, or the full range — with banner grabbing, best-effort service guessing and an exposure-group report. Gated by an ownership confirmation like Load Test; TCP only, nothing beyond the banner. | None — standard library only |
| [`office-metadata/`](office-metadata) | What your Word/Excel/PowerPoint files say about you — author, last editor, company, editing minutes, sheet/slide names, custom properties, the embedded thumbnail, tracked changes and macro flags, read straight from the OOXML zip — with optional clean copies (docProps dropped, content untouched). Third member of the privacy family after EXIF Inspect and PDF Toolkit; stdlib only. | None — standard library only |
| [`mail-header-check/`](mail-header-check) | Why a mail landed where it did — SPF/DKIM/DMARC verdicts from Authentication-Results with alignment analysis, the Received hop chain with per-hop delays and TLS markers, phishing signals (Reply-To to another domain, executable attachments) — read from a saved .eml with the stdlib, nothing queried, nothing sent. The message-side act of the mail story after Email DNS Audit, Mail Probe and DNSBL Check. | None — standard library only |
| [`cache-check/`](cache-check) | Is caching actually working — repeated requests watch Age grow and HIT/MISS flip, Cache-Control is decoded into a TTL, a conditional request checks ETag/Last-Modified revalidation, and the cache-busters (Set-Cookie, Vary: Cookie, private, no-store) are called out by name. Honest fallback when no cache-status headers are exposed; completes the perf line after Server Timing and Load Test. | requests |
| [`secret-scan/`](secret-scan) | Credential leaks in a codebase or config folder — AWS keys, GitHub/Slack/Stripe tokens, private keys, database URLs with passwords, committed .env files — the wp-audit rule engine (YAML rules, bring your own) with one contract on top: findings are masked at capture time, so no report or artifact ever repeats the secret it found. Two modes over the one engine: the working tree (.git and lockfiles skipped by design), or the full git history (--mode history: every line ever added via streamed git log -p, commit-attributed, re-additions deduped — the rotated key removed three commits ago still lives in every clone). | pyyaml |
| [`dnssec-check/`](dnssec-check) | Can the DNS answer be trusted — the DS/DNSKEY chain validated from the IANA root anchor (KSK-2017) through every delegation down to the zone, every signature checked locally, not taken from the resolver's word. Verdicts in plain words: secure / insecure (unsigned) / signed but no DS at the parent / bogus (the SERVFAIL shape) / indeterminate; plus key quality (algorithms, RSA sizes, KSK/ZSK), signature expiry and an NSEC/NSEC3 peek. The trust half of the DNS story next to DNS Propagation. | dnspython |
| [`fw-audit/`](fw-audit) | What the firewall rules actually allow — saved dumps of ufw, iptables, pf (including the stock macOS anchor-only ruleset) and firewalld, format detected automatically, reviewed passively: default policies, ports open to Anywhere grouped by risk like Port Check, allow-all rules, source-scoped rules praised, IPv6 parity, iptables shadowed denies. The rules-vs-reality companion to Port Check; nothing runs as root, nothing is changed. | None — standard library only |
| [`a11y-check/`](a11y-check) | The accessibility pass a page deserves — WCAG text contrast computed from static CSS with inheritance and specificity (the color-palette engine, large text at 3:1, headings at their browser defaults), forms without labels, heading skips, lang on html, ARIA roles missing their state, aria-hidden on genuinely focusable elements, dangling aria-labelledby, positive tabindex, empty and "click here" links, tables without th, iframes without a title, autoplaying media, zoom-blocking viewports, meta refresh timers, duplicate ids, landmarks and the skip link. One fetch like Page SEO Audit; what static analysis cannot see is reported as not checked, never as passed. | requests, lxml |
| [`cors-check/`](cors-check) | Is the CORS policy actually strict — a short series of GET/OPTIONS with a spoofed Origin (the NinjaChek lab matrix, browser-equivalent traffic, no payloads, no ownership gate): attacker-origin reflection with credentials, the accepted null origin, wildcard+credentials, prefix/suffix/substring whitelist traps, the preflight echo, and the missing Vary: Origin that cache poisoning feeds on. The deep dive behind Security Headers' CORS line. | requests |
| [`web-conf-audit/`](web-conf-audit) | What the web server config actually allows — saved nginx, Apache and .htaccess files, format detected automatically, reviewed passively: directory listings, version banners (absent-directive defaults included — server_tokens defaults on, ServerTokens defaults Full), TLS protocols and ciphers on the tls-audit scale (negations understood), PHP-inside-uploads with the safe shapes praised, the security-headers core six as add_header/Header set, upload limits, compression, proxy Host mistakes. The rules-vs-reality companion to Security Headers. | None — standard library only |
| [`har-analyze/`](har-analyze) | What is actually heavy on this page — the DevTools HAR read offline as a diagnosis (stdlib json, zero network): the waterfall by phases aggregated, render-blocking resources (scripts without async/defer from the saved document, honestly "cannot tell" when content wasn't exported), the third-party inventory by registrable domain with bytes, size by type, cache hits (memory/disk/304), redirect chains and the worst 10 with phase breakdowns. The perf line closed from the browser side. | None — standard library only |
| [`csp-audit/`](csp-audit) | How strong the Content-Security-Policy really is — the Google-CSP-Evaluator-style deep dive behind Security Headers' one-line grade: unsafe-inline/unsafe-eval with the nonce nuance (alongside a nonce, browsers ignore it — transitional, not broken), scheme and subdomain wildcards, the bypass hosts in your allowlist (unpkg, jsdelivr, raw.githubusercontent, the JSONP family — a curated YAML with reasons), missing base-uri/object-src/frame-ancestors, strict-dynamic, and the Report-Only twin diffed against the enforced policy. One fetch, every finding names the directive. | requests, pyyaml |
| [`ct-log-check/`](ct-log-check) | Every certificate ever issued for a domain — the crt.sh transparency feed as a timeline (issuances per month, chart), the issuer census grouped by CA rather than by the intermediate that signed, with "everyone else who ever issued" as the headline, wildcards, names still covered by a valid certificate, the burst flag — precertificates folded into their final certificate so no count is doubled, and an old feed read honestly: named as crt.sh's JSON cap when the feed is large, as a dormant domain when it is small. Plus the CAA policy (via DNS-over-HTTPS, parents climbed like a CA does, stopping at the registrable domain) compared with the CAs holding live certificates: allowed / outside the list / unrecognized — and never "outside" when the domain publishes no policy at all, with the predates-your-policy nuance said aloud. The historical twin of TLS Audit's live certificate. | requests |
| [`ai-crawler-check/`](ai-crawler-check) | What your site gives AI crawlers — the policy side next to Bot Hunter's log side: the robots.txt census of 14 known AI agents (GPTBot, ClaudeBot, PerplexityBot, CCBot, Google-Extended, Bytespider… — blocked / partial / allowed / not mentioned = allowed by default, the *-group trap named), the llms.txt convention treated honestly as a convention (not a standard), and the noai/noimageai markers in header and meta. Three fetches; the allow/block choice itself stays editorial. | requests |
| [`hreflang-check/`](hreflang-check) | The multilingual wiring under the microscope — over a Site Crawler snapshot (the needs-chain, SEO-Checks precedent): reciprocity of alternate links (Google drops one-way pairs), cluster audits with the standard shape understood (every page declaring the full set is normal — the error is one language or x-default pointing at different targets), code validity (pt-br, english, xx — each with the right spelling), alternates at non-canonical or 404 pages, outside-the-crawl marked as unverifiable. Hreflang is a cluster property; one page cannot show the broken half of it. | None — standard library only |
| [`wp-vuln-check/`](wp-vuln-check) | Known holes in the installed WordPress plugins and themes — versions read exactly from the Plugin Name/style.css headers of a wp-content folder (never guessed from the frontend), matched against the Wordfence Intelligence feed (free key via env) with PHP-style version comparison and the patched-backport nuance. The WP corner OSV cannot cover; wp-exposure-check + wp-audit + this + log-attack-checker close the WP story. | requests |
| [`takeover-check/`](takeover-check) | Which of your subdomains can be hijacked — CNAMEs pointing at unclaimed cloud resources (S3, GitHub Pages, Heroku, Azure, Shopify, Tumblr, Pantheon, GCS) checked against a curated YAML fingerprint list: NXDOMAIN on the target as the dangling hint, the provider's unclaimed-marker page via one GET, and the closed-vs-open nuance (Fastly/Vercel/Netlify/WordPress.com closed the hole — their matches are exposed-but-not-claimable, never a silent skip). The passivity contract: DNS + one GET, nothing registered, nothing claimed, nothing performed. | requests, dnspython, pyyaml |
| [`gha-audit/`](gha-audit) | What the GitHub Actions workflows allow — .github/workflows/*.yml read passively (the third passive-config audit after fw-audit and web-conf-audit): actions pinned to mutable tags instead of SHAs (the tj-actions shape that burned 23 000 repos), pull_request_target with a PR-head checkout (the exfiltration shape), event interpolation straight into run: (command injection), secrets echoed to logs, self-hosted runners on public repos, permission scopes, workflow_run. Nothing executes, nothing is sent to GitHub. | pyyaml |
| [`schema-check/`](schema-check) | Is the structured data valid — and worth anything — JSON-LD parsed (@graph walked, @type arrays flattened) and validated against curated schema.org shapes (YAML data: required/recommended properties per type, nesting understood), microdata and RDFa spotted alongside, the schema-vs-page price cross-check, and the verdict no validator gives: valid but no rich result (Google's 31-type list as of March 2026; a type outside it is for Bing/Perplexity, not an error). The validation sibling of Page SEO Audit's extraction. | requests, lxml, pyyaml |
| [`cwv-check/`](cwv-check) | What real Chrome users experience — the field side of the perf line: LCP/INP/CLS p75 per form factor (phone and desktop separately, the official bands), the URL-or-origin fallback said aloud, the 25-week trend as a chart, and the lab-vs-field headline (field red + lab green = the divergence is the finding). Free CrUX API key via env; without it the script exits with instructions, never an imitated number. | requests |
| [`protocol-check/`](protocol-check) | Which protocols the site actually speaks — the protocol layer around TLS Audit's certificate grades, stdlib only: ALPN-negotiated h2 vs http/1.1 on a real handshake, the HTTP/3 Alt-Svc announcement (honestly an announcement — no QUIC stack), compression actually served on Accept-Encoding (br/gzip/zstd with the byte win), IPv6 with a real TCP+TLS connection instead of just an AAAA record, keep-alive on one connection, TLS session resumption; 0-RTT stated as not visible, never guessed. | None — standard library only |
| [`tls-rpt-report/`](tls-rpt-report) | Which receivers could not raise TLS to your MX — the RFC 8460 SMTP TLS reports (.json, .json.gz, .zip) merged into one picture, dmarc-report's twin for the transport side: failure types with their meanings spelled out (starttls-not-supported, certificate-expired, validation-failure, sts-policy-invalid — the last one is your own policy broken), your MX hosts the failures hit, the sending MTAs behind them, and the enforce-vs-testing read (in enforce every failure is mail that did not land). Offline, stdlib, zero network — the sixth act of the mail story. | None — standard library only |
| [`sri-check/`](sri-check) | Whose code runs on your page, and is it pinned — the supply-chain view of the script/stylesheet tags (the Polyfill.io lesson: the delivery channel was the vulnerability): third-party resources without integrity, integrity without crossorigin (the browser refuses the resource — the classic copy-paste mistake), same-origin integrity (redundant and deploy-breaking), declared hashes verified against the bytes served right now, and ready-to-paste pinned tags with the tradeoff said aloud — a pinned CDN file that changes breaks the page. One page fetch + one per unique resource; attributes-only mode needs exactly one request. | requests |
| [`redirect-map/`](redirect-map) | The missing link between Wayback Check's vanished URLs and SEO Checks' chain audits — old URLs (wayback CSV, an old Site Crawler snapshot, or a plain list) matched against a fresh crawl snapshot: exact path and slug matches are confident, slug/title similarity ≥ 0.80 is needs-review (shipped commented out), nothing found is said so with the 410 suggestion — the map is proposed, never claimed. Outputs a ready nginx map $uri (query-preserving), the .htaccess twin and an editable CSV, plus a live check that each redirect lands 301 → 200 without chains or loops; 404s before install are the expected measurement. | requests |
| [`responsive-images/`](responsive-images) | One image into a delivery-ready ladder — every requested width (default 320–1920, never upscaled, skips reported) rendered as AVIF + WebP + a JPEG/PNG fallback (alpha sources keep PNG), with the ready-to-paste `<picture>` snippet (srcset, sizes, width/height, lazy, your alt text) and the measured weight table. The honest warning is part of the product: sizes describes your layout — with a wrong sizes the browser downloads the largest step anyway. The delivery link after Image Converter and Image Optimizer; a proper srcset cuts image weight 40–60% in pure HTML. | Pillow, pillow-avif-plugin |
| [`font-subset/`](font-subset) | A font cut to what the page actually serves — by Google's language subsets (one woff2 per subset with its unicode-range, so a Cyrillic page never fetches the Greek block), by a text sample, or by the glyphs really used in scanned HTML/CSS — saved as woff2 with a ready @font-face (font-display: swap, weight/style read from the font's own tables) and the measured savings; plus an inventory mode: per-language coverage and what the pages use vs what the font is missing. Zero-coverage subsets are skipped honestly, never an empty file. Montserrat-shape savings: 64.6 KB → 15 KB. | fonttools, brotli |
| [`og-image/`](og-image) | Social cards at the 1200×630 standard, produced not checked — one at a time or a batch from CSV (hundreds of pages in one run): title, subtitle, optional logo, three fixed templates (gradient / accent banner / your background image, cover-fit and darkened for legibility) in brand colors, titles wrapped and auto-shrunk to fit, plus the complete meta snippet per card (og:image, width/height, alt, twitter:card — relative or absolute with Base URL). The favicon-generator form applied to the social side; Page SEO Audit checks the tag, this makes the file it points at. | Pillow |
| [`contrast-matrix/`](contrast-matrix) | Can you write with these colors — every text/background pair of a palette (pasted hexes or Color Palette's palette.json) judged at the design stage, before the page exists: WCAG 2.2 AA/AAA for body and large text separately, APCA Lc as the second opinion that knows polarity (pairs where the models disagree are flagged as exactly the interesting ones), and for every AA failure the nearest passing shade — the text color's lightness shifted the minimum needed, offered as a hex. A fix, not a lecture. The a11y-check sibling that runs before layout; stdlib only. | None — standard library only |
| [`icon-audit/`](icon-audit) | What's wrong with the icon set, before the sprite bakes it in — the gate of the conveyor (Figma Export → this → SVG Optimize → SVG Sprite Build): viewBox diversity (the 24/20/16 mix), naming against the sprite's own slug convention (the silent renames listed, the collisions the build hard-fails on caught first), fill-vs-stroke mix, stroke-width outliers, geometry duplicates (paint-blind exact hash), embedded rasters inside SVGs, the title/aria shape — and the most valuable: unused icons, every symbol id and slug grepped against your codebase, dead weight named. | lxml |
| [`figma-export/`](figma-export) | The design tool meets the code pipeline — the front door of the icon conveyor: the components of a Figma file or frame (?node-id= scope, component sets walked to their variants) exported as SVG (optional PNG 1x/2x), names normalized by the exact slugify SVG Sprite Build applies so nothing renames twice, collisions suffixed -2 and said aloud. Personal access token via the Keychain (never argv); without it an honest exit with the where-to-get-one line. The Enterprise limit surfaced live: the Variables API 403 reads "not checked", never "no variables". | requests |

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
