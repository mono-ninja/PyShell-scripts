# GHA Audit

What the GitHub Actions workflows allow — `.github/workflows/*.yml`
read passively: **tag-pinned actions** (the tj-actions shape:
mutable refs retargetable at any moment; SHA/local/docker
recognized), **pull_request_target** (the repo's secrets on PR
events; with a PR checkout — the critical exfiltration shape),
**event interpolation in run:** (command injection with the PR
author holding the pen), **secrets echoed** (echo of `${{ secrets.* }}`,
printenv/env dumps), **self-hosted runners**, **permission scopes**
(the missing block, write-all, job-level over-grants), and
**workflow_run** (tokens on events you didn't type).

The third passive-config audit after fw-audit and web-conf-audit;
nothing executes, nothing is sent to GitHub.

---

## Before running

1. Pick the **Repository folder** — the repo root with
   `.github/workflows`, or a folder of workflow files directly;
   **Recursive** (on by default) finds more workflows folders in
   monorepos.
2. **Prepare Env** — installs `pyyaml`.
3. Press **Run** (⌘↩).

## Fields

### Input

- **Repository folder** — every `.yml`/`.yaml` in
   `.github/workflows` (plus loose workflow YAML in the folder
   itself).
- **Recursive** — walk the tree for more `.github/workflows`
   folders.

---

## Result

- **Results tab** — the table (severity · check · file · job ·
  detail) and the report grouped per workflow file:
  - **🔴 injection / pull_request_target-with-checkout** — the
    shapes that exfiltrate secrets today.
  - **🟠 pinning / permissions / self-hosted / secrets-echo /
    pull_request_target** — the conditions that make the red
    shapes possible or leak tomorrow.
  - **ℹ️ workflow_run / missing permissions / printenv** — worth a
    look.
  - **The safe shapes** — SHA pins, `read-all` + per-job widening,
    env-indirection for untrusted data.
- **Artifacts** — `report.md`, `findings.json`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | no workflow files under the folder |
| 2 | bad arguments: not a folder |

## Related

- **secret-scan** — what already leaked in the tree; **dep-audit**
  — the lockfiles beside the workflows.
- **fw-audit / web-conf-audit** — the sibling passive-config
  audits (firewall, web server).
