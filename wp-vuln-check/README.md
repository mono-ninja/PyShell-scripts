# WP Vuln Check

**Known holes in the installed WordPress plugins and themes.** The
WP corner of the vulnerability line, and the biggest factual gap
cve-check has: **OSV has no WordPress ecosystem** — plugins are
invisible to it by principle. This script speaks the Wordfence
Intelligence feed (its key is free with a Wordfence account;
WPScan and Patchstack want paid tiers).

The local-folder input is the point: versions are read **exactly**
— the `Plugin Name:` / `Version:` headers of every plugin's main
PHP file, the `Theme Name:` / `Version:` of every theme's
style.css, and `wp_version` from wp-includes when the parent of
wp-content is given. Not a frontend guess in sight (the
remote-site shape stays cve-check's, with its honest scoping).

Matching is honest about WordPress version semantics: a PHP-style
version comparison (`2.10` after `2.9`), the affected-range
operators from the feed, and the **patched** flag as its own
answer — a patched backport means the site may already be safe on
the same version number.

## Using with PyShell

1. Bring the `wp-content` folder over from the server (scp, or a
   local copy). Give it the WP root's parent to include core.
2. Put the **Wordfence Intelligence API key** in the field (free:
   wordfence.com → account → Intelligence API; stored in the
   Keychain, sent as a Bearer token).
3. Press **Prepare Env** (installs `requests`), then **Run** (⌘↩).

## Running standalone

```bash
export WORDFENCE_API_KEY=…   # free key from wordfence.com
python3 main.py --wp-content ./wp-content
```

## Result

- **Results tab** — a table (software · version · vulns · patched)
  and the report: every advisory with its link, CVE, the
  patched-backport nuance, and the unknown-version honesty (no
  Version header → all advisories listed with the note).
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | no plugins/themes found, feed unreachable, or no API key |
| 2 | bad arguments (not a folder) |

## Layout

```
wp-vuln-check/
├── pyshell.yaml      # manifest
├── main.py           # headers · PHP version compare · feed · match
├── requirements.txt  # requests
├── docs/             # EN + UA docs
└── tests/            # 10 tests: fixture site + canned feed
```

## License

MIT — see the root [LICENSE](../LICENSE).
