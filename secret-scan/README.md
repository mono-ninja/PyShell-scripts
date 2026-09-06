# Secret Scan

**Credential leaks in a codebase or config folder** — AWS keys,
GitHub/GitLab/npm tokens, Slack and Telegram tokens, Google and
Stripe keys, SendGrid, private key PEMs, credentials inside URLs and
database URLs, framework `SECRET_KEY`s, generic secret assignments,
committed `.env` files — against a curated rulebook. The wp-audit
engine (YAML rules, bring your own with `--custom-rules`), one
contract on top: **findings are masked at capture time** —
`AKIAIO…(+14 chars)` — so no log, table, report or artifact ever
repeats the secret it found.

Two modes, one engine, one masking contract:

- **Working tree** (default) — the files you are about to commit.
  `.git` is skipped, lockfiles are skipped (integrity hashes are
  false-positive factories, not leaks), so are dependency dirs,
  binaries and huge files.
- **Git history** (`--mode history`) — every line ever *added*,
  walked via the system `git log --all -p` (streamed,
  commit-attributed): the rotated key removed three commits ago
  still lives in every clone. Merge commits are not diffed, lockfile
  noise is skipped, a leak re-added in several commits is one
  finding with a commit count, and the cap (`--max-commits`) is a
  note in the report, never a silent stop.

## Using with PyShell

1. Pick the **Folder to scan** — a project, a config dir, anything
   with text files.
2. Pick the **Scan mode** — working tree or git history.
3. Press **Run** (⌘↩). Findings are results, not failures — the
   **Fail on** gate is opt-in for CI.

## Running standalone

```bash
python3 main.py --target ~/code/myproject
python3 main.py --target . --custom-rules my-rules.yaml --fail-on critical
python3 main.py --target ~/code/myproject --mode history
```

## Result

- **Results tab** — a table (severity · type · file · line · masked
  finding · commit, in history mode) and the report: findings
  grouped by file, every value masked, each history finding naming
  the commit that introduced it, plus the remediation order —
  **rotate first, delete second** (a key in git history stays there
  even after the file is fixed).
- **Artifacts** — `report.md`, `findings.json` (masked, with
  `"masked": true`; commit attribution in history mode).

### The rulebook

16 curated rules in `rules.yaml` — the same schema and engine as
wp-audit (`match`/`exclude`/`require_source`/`file_include`), one
new field: `mask_group` — the regex group that holds the secret and
gets masked. Placeholder lines (`changeme`, `${VAR}`,
`<your-key>`, …) are excluded by design; generic entropy scoring is
deliberately absent — without context it floods the report.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the scan ran (findings are results, masked) |
| 1 | nothing scannable under the target / the git binary is missing |
| 2 | bad arguments (unreadable folder, malformed rules file, history mode outside a git repo) |
| 3 | opt-in CI gate: `--fail-on critical` or `--fail-on any` |

## Layout

```
secret-scan/
├── pyshell.yaml      # manifest
├── main.py           # thin entry point
├── rules.yaml        # the curated rulebook (YAML data)
├── src/
│   ├── events.py     # stderr JSON events / stdout log
│   ├── rules.py      # rule model, loader, validator
│   ├── scanner.py    # discovery, engine, masking
│   ├── history.py    # git-log streaming, commit attribution, dedup
│   └── report.py     # table, markdown, artifacts
├── docs/             # EN + UA docs
└── tests/            # 28 tests: planted-leak fixtures + a real git repo
```

## License

MIT — see the root [LICENSE](../LICENSE).
