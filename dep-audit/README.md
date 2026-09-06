# Dep Audit

**Known vulnerabilities in the project's own dependencies.** The
third look at the same source tree: secret-scan reads it for leaked
credentials, wp-audit for the operator's own code — this reads it
for **someone else's code with known holes**. cve-check covers the
live-site shape (a tech-stack snapshot → OSV); a local project was
invisible to the collection until now.

Lockfiles are the input, because they carry **pinned** versions —
the only versions a vulnerability answer can be honest about:

- **Python** — `requirements.txt` (`==` pins; `>=` ranges go to the
  honest *not pinned, not checked* list — never the worst-of-range
  guess), `poetry.lock` (tomllib).
- **JavaScript** — `package-lock.json`, `yarn.lock` (v1),
  `pnpm-lock.yaml`.
- **PHP** — `composer.lock` · **Go** — `go.mod` · **Ruby** —
  `Gemfile.lock` · **Rust** — `Cargo.lock`.

Every pinned dependency goes to OSV's `/v1/querybatch` — the
Google-run aggregation of GHSA/PyPA/Go/Rust advisories, **free and
keyless** (the same source cve-check speaks to), batches of 100;
advisory details (CVE aliases, the nearest fixed version) are
fetched in parallel, capped.

## Using with PyShell

1. Pick the **Project folder** — every supported lockfile found in
   it is audited (the top level plus one subfolder level; turn on
   **Recursive** for monorepos).
2. Press **Prepare Env** (installs `requests` + `pyyaml`), then
   **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --project-dir ~/code/myproject
python3 main.py --project-dir . --recursive
```

## Result

- **Results tab** — a table (dependency · version · advisories ·
  fix) and the report: vulnerable dependencies with advisory IDs,
  CVE aliases and the nearest fixed version; the per-lockfile
  census; the *not pinned, not checked* list.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | no supported lockfile / lockfiles parse to nothing / OSV unreachable |
| 2 | bad arguments (not a folder) |

## Layout

```
dep-audit/
├── pyshell.yaml      # manifest
├── main.py           # 9 parsers · querybatch · detail fetch · report
├── requirements.txt  # requests, pyyaml
├── docs/             # EN + UA docs
└── tests/            # 12 tests: fixtures per ecosystem + mocked OSV
```

## License

MIT — see the root [LICENSE](../LICENSE).
