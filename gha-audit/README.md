# GHA Audit

**What the GitHub Actions workflows actually allow.** The third
"saved config, passively reviewed" after fw-audit (firewall) and
web-conf-audit (web server) — this one reads
`.github/workflows/*.yml`, the CI configuration that runs with the
repository's secrets:

- **Tag-pinned actions** — `uses: owner/repo@v3` instead of a full
  commit SHA: the tag can be retargeted at any moment — exactly the
  shape that carried tj-actions/changed-files and trivy-action over
  23 000 repositories. Local (`./…`) and docker actions are
  recognized.
- **`pull_request_target`** — runs with the repo's secrets on PR
  events; with a checkout of the PR head it's the critical
  exfiltration shape.
- **Event interpolation in `run:`** — `${{ github.event.* }}`
  pasted into a shell script is command injection with the PR
  author holding the pen.
- **Secrets echoed** — `echo ${{ secrets.X }}` and `printenv`/`env`
  dumps land in the logs.
- **Self-hosted runners** — on a public repo, code execution on
  your machine for every PR author.
- **Permission scopes** — the missing top-level `permissions`
  block, `write-all`, job-level over-grants.
- **`workflow_run`** — tokens on events you didn't type; a source-
  check note.

Nothing executes, nothing is sent to GitHub — the YAML is parsed
and the shapes that burned people are named.

## Using with PyShell

1. Pick the **Repository folder** (the repo root with
   `.github/workflows`; a folder of workflow files works too).
2. Press **Prepare Env** (installs `pyyaml`), then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --repo-dir ~/code/myrepo
```

## Result

- **Results tab** — a table (severity · check · file · job ·
  detail) and the report per workflow, with "the safe shapes".
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | no workflow files found |
| 2 | bad arguments (not a folder) |

## Layout

```
gha-audit/
├── pyshell.yaml      # manifest
├── main.py           # YAML in · the burned shapes named · report
├── requirements.txt  # pyyaml
├── docs/             # EN + UA docs
└── tests/            # 10 tests: the burned and the safe fixtures
```

## License

MIT — see the root [LICENSE](../LICENSE).
