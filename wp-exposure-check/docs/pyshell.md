# WP Exposure Check

Checks which **WordPress doors a site leaves open** — the well-known
endpoints every scanner's first recon burst asks for. One **passive GET**
per endpoint, redirects followed, no POSTs and no login attempts: nothing
is sent that a thousand ordinary visitors don't send. Each endpoint comes
back with a verdict — exposed / protected / not found — the evidence that
earned it, and **the fix** when it's open.

The companion to [Log Attack Checker](../../log-attack-checker): that
script shows what attacks look like once they hit your logs, this one
tells you **which open doors let them succeed**.

---

## Before running

1. **Site URL** — the base address of a WordPress site you own or are
   responsible for (`https://example.com`). Only that host is asked;
   a deep path is trimmed to the root, because the endpoints live there.
2. Click **Prepare Env** — installs `requests`.
3. Press **Run** (⌘↩). Seven endpoints, seconds.

## Fields

### Target

- **Site URL** — `https://…`. The homepage is fetched once first: it
  proves the target answers (an unreachable site is exit 1 — there was
  nothing to check) and collects the WordPress markers.
- **Per-request timeout (s)** — one GET per endpoint, this long each.

### CI

- **Fail the run on** — `nothing` (default: exposures are findings, not
  failures) or `any` (exit code 3 when at least one endpoint is exposed —
  a CI gate).

---

## What gets checked

| Endpoint | Why it matters |
|---|---|
| `/wp-json/wp/v2/users` | User enumeration — the logins brute force tries. The `?rest_route=` spelling is retried when the pretty route is closed, because a filter can block one and not the other. |
| `/xmlrpc.php` | A live XML-RPC (405 "accepts POST only") is the pingback-DoS and credential-stuffing amplifier. |
| `/readme.html` | Ships with every install; names the exact version. |
| `/wp-content/debug.log` | Debug output left inside the webroot — served as a plain file. |
| `/wp-content/uploads/` | A browsable media directory ("Index of" page). |
| `/wp-login.php` | Informational: reachable is normal for WP; the risk is the brute force that follows, which Log Attack Checker measures. |
| homepage `<meta generator>` | The other version leak — read off the already-fetched homepage, no extra request. |

Soft-404s are handled honestly: a 200 that serves an HTML page where a
log file or a JSON list should be is **not** counted as exposed.

## Result

- **Results tab** — the endpoint table (status · check · what was seen),
  then the report: every check with evidence, and for each exposure the
  fix, ordered fix-first (high severity before medium).
- **Artifacts** — `findings.json` (every check, machine-readable),
  `report.md`.

When the homepage shows **no WordPress markers at all** (no wp-content
paths, no wp-json link, no generator), the report says so — the site may
not be WordPress; the endpoint verdicts still stand on their own.

## Exit codes

- `0` — the check ran. Exposures are findings, not failures.
- `1` — the target never answered, or the homepage itself answered an
  HTTP error: a broken site can't be exposure-checked.
- `2` — bad arguments (no scheme/host).
- `3` — the opt-in CI gate tripped (`--fail-on any`).
