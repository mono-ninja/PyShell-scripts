# WP Audit

SAST over a WordPress site's **own code** — themes and plugins
(`wp-content` is the default scan root when present; core is not
yours) — against a curated 19-rule rulebook: SQLi, XSS,
eval-obfuscation (the injected-malware classics), object injection,
SSRF, access-control gaps. Reads files only; nothing is executed,
nothing leaves the machine.

---

## Before running

1. **Site folder** — the site's folder on disk (a local copy, a
   mounted volume, an exported archive unpacked).
2. Click **Prepare Env** — installs `pyyaml`.
3. Press **Run** (⌘↩). A wp-content of typical size scans in under a
   minute; the file cap (20 000 by default) protects pathological
   trees, and reaching it is reported, never hidden.

## Fields

### Target

- **Site folder** — the WordPress root. When it contains
  `wp-content/`, that subfolder is the scan root (your code);
  `wp-admin` and `wp-includes` are WordPress core — shipped thousands
  of times over, not the audit's subject.
- **Scan the whole tree** — override: every PHP file under the
  folder, core included. Deliberate, not accidental.

### Rules

- **Custom rules** — an optional YAML file in the same schema as the
  built-in `rules.yaml`:

  ```yaml
  rules:
    - id: my-rule
      description: "…"
      severity: critical      # critical|high|medium|low
      vuln_type: XSS
      message: "…"
      match:
        regex: '<must hit the trigger line>'
      exclude:                # optional — suppresses when matched on the
        regex: '<pattern>'    #   trigger line or up to window_lines after
        window_lines: 0
      require_source:         # optional — needs one pattern within
        window_lines: 15      #   window_lines BEFORE the trigger
        patterns: ['<pattern>']
      file_include: ['*.php'] # optional filename globs
      file_exclude: []
  ```

- **Max files** — the safety cap.

### CI

- **Fail the run on** — `nothing` (default), `critical`, or `any`:
  the exit-3 gate for CI.

---

## Result

- **Results tab** — the findings table (severity · file:line · rule ·
  finding) and the report: counts per category, top findings with
  their trigger-line snippets, per-category advice.
- **Artifacts** — `findings.json` (every finding), `report.md`.

### Reading the findings honestly

- **A match is a lead, not a verdict.** The engine suppresses the
  common safe shapes (the escape call on the same line, prepare(),
  known directory constants) — what remains deserves a human look.
- **CODE_EXECUTION criticals in themes/plugins** are more often
  injected malware than bugs: compare against a clean copy of the
  theme/plugin, then check what the requests looked like
  ([Log Attack Checker](../../log-attack-checker)).
- The HTTP surface (open doors) is [WP Exposure
  Check](../../wp-exposure-check)'s job; the known-vulnerable versions
  of what you run is [CVE Check](../../cve-check)'s — this one reads
  the source they exploit.

## Exit codes

- `0` — the scan ran; findings are results.
- `1` — no PHP files under the scan root.
- `2` — bad arguments (not a folder; a malformed rule file — with the
  exact rule and the reason).
- `3` — the opt-in CI gate tripped.
