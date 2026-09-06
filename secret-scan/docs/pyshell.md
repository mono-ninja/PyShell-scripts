# Secret Scan

Credential leaks in a codebase or config folder: provider keys
(AWS, Google, Stripe, SendGrid), VCS and registry tokens (GitHub,
GitLab, npm), chat tokens (Slack, Telegram), private key PEMs,
credentials inside URLs and database URLs, framework `SECRET_KEY`s,
generic secret assignments, committed `.env` files — the wp-audit
rule engine (YAML rules, `--custom-rules` for your own), with the
masking contract: **every finding is masked at capture time**, so no
report or artifact ever repeats the secret it found.

Two modes, one engine and one masking contract:

- **Working tree** (default) — the files you are about to commit.
  `.git` and lockfiles are skipped by design.
- **Git history** — every line ever *added*, walked via the system
  `git log --all -p` (streamed, commit-attributed): the rotated key
  removed three commits ago still lives in every clone. Same rules,
  same masking; merge commits are not diffed, lockfile noise is
  skipped, and a leak re-added in several commits is one finding
  with a commit count. Needs the system `git` binary and a real
  repository.

---

## Before running

1. Pick the **Folder to scan** — a project or config folder.
2. Pick the **Scan mode** — working tree, or git history.
3. No **Prepare Env** needed — stdlib only (PyYAML is bundled with
   PyShell). Press **Run** (⌘↩).

## Fields

### Target

- **Folder to scan** — the project or config folder.
- **Scan mode** — *Working tree*: every text file under it is
  checked. Skipped by name: `.git`, lockfiles (`package-lock.json`
  and friends — integrity hashes, not leaks), dependency and cache
  dirs, binary-looking files, files over 5 MB — the notes section
  lists what was skipped and why. *Git history*: the commits
  themselves — every added line, attributed to the commit that
  introduced it.
- **Max commits (history mode)** — safety cap on the commit count
  (newest first, default 5000); reaching it is a note in the report,
  never a silent stop.

### Rules

- **Custom rules (optional)** — a YAML file in the documented
  schema, appended after the built-in 16. Same semantics as wp-audit
  rules (`match` / `exclude` / `require_source` / `file_include`),
  plus `mask_group` — the regex group holding the secret that gets
  masked. Malformed rule files are exit 2 with the exact rule and
  reason, never a crash.
- **Max files** (tree mode) — safety cap (default 20000); reaching
  it marks the scan as partial.

### CI gate

- **Fail on** — `none` by default (findings are results). `Exit 3 on
  critical` / `Exit 3 on any finding` turn the script into a CI
  step.

---

## Result

- **Results tab** — the table (severity · type · file · line · the
  masked finding · the commit, in history mode) and the report:
  - findings grouped by file, each with the masked trigger line and
    the rule's message (what the key grants, where to rotate it);
    in history mode each finding also names the commit that
    introduced it, with its date and subject;
  - **What to do now** — rotate first, delete second; move real
    values to env or a secrets manager; purge git history if the
    leak was pushed;
  - **By type** and **Notes** (skips, caps).
- **Artifacts** — `report.md`, `findings.json` — masked, with
  `"masked": true` recorded in the JSON (and commit attribution in
  history mode).

### The masking contract

`AKIAIOSFODNN7EXAMPLE` becomes `AKIAIO…(+14 chars)` — the first six
characters and the length only, enough to identify *which* key it
was, never enough to use it. The full value does not exist anywhere
in the output — by construction, not by filtering. The contract is
identical in both modes: the history path runs through the same
capture-time masking.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the scan ran (findings are results, masked) |
| 1 | nothing scannable under the target / the git binary is missing |
| 2 | bad arguments: unreadable folder, malformed rules file, history mode outside a git repo |
| 3 | opt-in CI gate (`--fail-on critical` / `any`) |

## Related

- **WP Audit** — the same engine over WordPress code for
  vulnerabilities; this script is its sibling for any codebase's
  credentials.
- **Password Check** — test the rotated passwords against the HIBP
  corpus before committing to them.
- **Port Check / FW Audit** — the exposure side: what answers on the
  wire vs. what the firewall allows.
