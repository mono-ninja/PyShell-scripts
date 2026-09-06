# Fleet Check

One overview of a whole portfolio of sites: status, TLS grade,
certificate days, security-headers grade, WordPress version, sitemap
presence — plus a grade-distribution chart and a baseline diff. The
composite of the collection's Security and SEO lines.

---

## Dependencies

This script **needs** three siblings — PyShell installs them
automatically from the **Needs** chain, and runs them the *invocation*
way: their `main.py` executes as a child process per site, and their
artifacts (`findings.json`, `tls_raw.json`, `stack.json`) are parsed
for the real grades:

- [TLS Audit](../../tls-audit) (`com.pyshell.tlsaudit`) — the TLS
  letter grade and the certificate expiry;
- [Security Headers](../../security-headers)
  (`com.pyshell.securityheaders`) — the headers letter grade;
- [Tech Stack](../../tech-stack) (`com.pyshell.techstack`) — the
  technologies and the WordPress version.

**Without a sibling** (running standalone, or not installed) the same
check runs as a **compact built-in** — certificate days + verification
via the `ssl` stdlib, a five-key header-presence grade, the
generator-tag WordPress version — and every compact value is labeled
`compact*` in the table and the report. Never passed off as the full
grade, never silently skipped.

## Before running

1. **Sites** — one URL per line (bare domains get `https://`);
   `#`-comments and blank lines are skipped; up to 50 per run.
2. Press **Prepare Env** — installs `requests` + `pyyaml` (pyyaml is
   what the Tech Stack child process imports).
3. Press **Run** (⌘↩). Each site runs its checks sequentially; sites
   run in parallel (**Parallel sites**, default 3).

## Fields

### Fleet

- **Sites** — the portfolio, one URL per line.
- **Parallel sites** — 1–8; each site's checks are sequential, the
  sites themselves parallel.
- **Per-request timeout (s)** — for the inline requests (homepage,
  sitemap, compact checks). The sibling child processes get their own
  generous 240 s budget.

### Diff

- **Baseline fleet.json** — a previous run's `fleet.json`. The report
  then marks every site ↑ (improved), ↓ (slipped) or ≈ (moved but
  netted equal): grade changes, certificate expiry/renewal, HTTP
  status transitions. New and gone sites are listed.

---

## Result

- **Results tab** — the fleet table (site · HTTP · TLS · cert ·
  headers · WP · sitemap · Δ) and the bar chart of TLS / headers
  grade distribution (full grades only — compact values aren't
  grades, and the report says so).
- **Artifacts** — `fleet.json` (everything, machine-readable — feed
  it back as the next baseline), `fleet.csv` (the flat table),
  `report.md`.

### Reading it honestly

- `compact*` values are the labeled fallback — one star, one glance.
- An unreachable site lists its error class (DNS, refused, timeout) —
  [IP Search](../../ip-search) and [Server Timing](../../server-timing)
  dig into one site.
- The baseline diff compares like with like: full grades diff against
  full grades; a mode change (sibling installed since last run) shows
  as a change of value, marked in the modes of both runs' fleet.json.

## Exit codes

- `0` — the fleet ran; findings are results.
- `1` — every site unreachable.
- `2` — bad arguments (no usable URLs, over the cap, unreadable
  baseline).
