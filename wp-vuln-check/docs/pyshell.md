# WP Vuln Check

Known vulnerabilities in the installed WordPress plugins and
themes — versions read **exactly** from the Plugin Name/style.css
headers of a wp-content folder (never guessed from the frontend),
matched against the Wordfence Intelligence feed with PHP-style
version comparison (`2.10` after `2.9`), affected-range operators,
and the patched-backport nuance (a patched line means the site may
already be safe on the same version number).

The WP corner OSV cannot cover — cve-check's factual gap.

---

## Before running

1. Bring the **wp-content folder** over from the server. Point at
   the WP root's parent (the folder containing `wp-content`) and
   the core version is read from `wp-includes/version.php` too.
2. Set the **Wordfence Intelligence API key** — free: register at
   wordfence.com → Account → Intelligence API → generate. Stored in
   the Keychain, sent as a Bearer token via `WORDFENCE_API_KEY`.
   The v3 feed is keyed; without the key the script exits with
   instructions instead of imitating a result.
3. **Prepare Env** — installs `requests`. Press **Run** (⌘↩).

## Fields

### Target

- **wp-content folder** — the plugins/ and themes/ subfolders are
  scanned; every plugin's main PHP file (the one carrying the
  header — folder-named first, then any header-carrying PHP file)
  and every theme's style.css. Single-file plugins are read too.
  Items without a Version header are reported honestly: every
  advisory for them is listed with the unknown-version note.

### Feed

- **Wordfence Intelligence API key** — the free key (env secret).
- **Feed timeout (s)** — 10–120, default 60; the feed is a few MB.

---

## Result

- **Results tab** — the table (software · version · vulns ·
  patched) and the report:
  - **🔴 unpatched** — the advisory covers the installed version
    and no backport exists: update.
  - **🟡 patched** — the advisory matches, but the vendor
    backported the fix to this version line: verify the patch
    level before panicking.
  - **⚪ unknown version / no range** — listed for review, said as
    such.
  - The notes section: unreadable plugin folders, a missing
    plugins/ folder, the core version when found.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | no plugins/themes, feed unreachable, or no API key |
| 2 | bad arguments: not a folder |

## Related

- **wp-exposure-check** — what the site exposes; **wp-audit** —
  your own code; this — the third party's code;
  **log-attack-checker** — what attackers already tried.
- **cve-check** — the JS/npm side and the WP core as seen from the
  frontend.
