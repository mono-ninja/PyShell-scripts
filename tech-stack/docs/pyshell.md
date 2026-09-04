# Tech Stack

Figures out **what a site is built on** — not just names, but versions, with
evidence and a confidence score. Paste a URL — get a stack inventory: web server,
language, CMS, JS framework, build tool, UI kit, analytics, CDN, payments, fonts,
tags — every row with a version (where one can be determined), the evidence
source, and a flag «outdated / EOL / has known vulnerabilities».

Three questions it answers:

1. **"What's running here and at which version"** — before taking a site on
   for maintenance.
2. **"What has gone stale"** — jQuery 1.12 in 2026, PHP 7.4 unsupported since
   2022. That's a talking point in a client conversation, not abstract
   "security".
3. **"Who is this site leaking data to"** — a full inventory of external hosts
   the page pulls from, grouped by purpose.

Plus a **diff mode**: `stack.json` from a previous run against today's.

## Before running

- **Target URL** — full address with `https://`. Only this host is checked.
- **Pages to sample** — how many pages to fetch in total: homepage + internal
  ones, chosen by heuristics (paths like `/product`, `/blog`, `/checkout`…).
  Range 1–10, default 3. The checkout stack ≠ the homepage stack: that's where
  payments, chat, and half the analytics live. More pages — a more accurate
  stack, but also more requests and more traces in the target's logs.
- **Extra URLs** — when you know better than the heuristics (e.g.
  `/shop/checkout`).
- **Min confidence** — display threshold. One weak signal doesn't pass; two weak
  ones give ~51%. Lower it to 30 if you want to see doubtful matches with their
  «Evidence» column.
- **JS rendering** — off by default, because it adds 5–15 s per page. Turn it on
  when you need `jQuery.fn.jquery`, `Vue.version`, or real network requests of
  an SPA: on pure React/Vue without rendering you see `<div id="root">` and
  nothing else. Without a browser Tech Stack still works — it greps the first
  ~256 KB of the main bundle.

  The browser is downloaded **once per machine** (shared cache
  `~/Library/Caches/ms-playwright`, not inside the venv). If the machine has
  already had any Playwright project, there's nothing to download. If not —
  Tech Stack won't crash; it writes a warning with `playwright install chromium`
  and finishes the scan without rendering.

## What it does NOT do

Nothing active: no brute-forcing, no port scanning, no vulnerability probing.
It fetches the homepage, up to 9 internal pages (per the «Pages to sample»
setting) and reads what a browser would receive anyway. The only "active" action
is an optional probe of `/composer.json`, `/CHANGELOG.txt`, `/readme.html` —
behind a flag, and disabled by default.

## Result

The **Results** tab — a markdown report: the stack by category, third parties,
outdated items, signature-base date, diff against the baseline. Artifacts:

- `techstack-report.md` — the same report;
- `stack.json` — snapshot for `--baseline` and for portfolio review;
- `technologies.csv` / `third-party.csv` — tabular export;
- `diff.md` — only when `--baseline` is passed.

## Exit code

Always `0` on a successful scan. A discovered EOL PHP is a finding in the
report, not a failure. A non-zero code means the target was unreachable or the
scan itself crashed.

## Notes

- The third-party inventory shows **network requests**, not consent or cookies.
  Without simulating consent mode, writing "the site violates GDPR" would be
  making things up. We write "the page contacts N external domains" — and stop
  there.
- Behind Cloudflare you get `Server: cloudflare`, and the web server isn't
  visible. The honest answer is «unknown (behind Cloudflare)», not «not
  detected».
- The signature base lives in `tech.yaml` next to the module. The downloader for
  the large GPL base (enthec/webappanalyzer) is in `scripts/update_db.py`; it
  downloads into a cache outside the repository (`~/.cache/techstack/`).
