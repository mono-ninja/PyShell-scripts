#!/usr/bin/env python3
"""gha-audit/main.py — what the GitHub Actions workflows allow.

The third "saved config, passively reviewed" after fw-audit
(firewall) and web-conf-audit (web server) — this one reads
`.github/workflows/*.yml`, the CI configuration that runs with the
repository's secrets.  Nothing executes, nothing is sent to GitHub;
the YAML is parsed and the shapes that burned people are named:

- **Tag-pinned actions** — `uses: owner/repo@v3` instead of a full
  commit SHA: the tag can be retargeted at any moment, and it was
  exactly this shape that carried tj-actions/changed-files and
  trivy-action over 23 000 repositories in 2025.  A mutable branch
  ref is the same hole, worse.
- **`pull_request_target` with a PR checkout** — the workflow runs
  with the repo's secrets while executing untrusted PR code: the
  classic secret exfiltration shape.  `pull_request_target` alone
  is flagged (it is safe only in the right hands); with a checkout
  of the PR head it is critical.
- **Event interpolation in `run:`** — `${{ github.event.* }}`
  pasted into a shell script is command injection with the PR
  author holding the pen; the fix is an env: indirection.
- **Secrets echoed** — `echo ${{ secrets.X }}` lands in the public
  log; `printenv`/`env` dump everything at once.
- **Self-hosted runners** — on a public repo, every PR author gets
  code execution on your machine (and the runner's persistence
  beyond the job).
- **Permission scopes** — the missing top-level `permissions`
  block (the historical write-everything default), `write-all`,
  and job-level scopes wider than the job needs.
- **`workflow_run`** — runs after another workflow, with the
  repo's tokens, on events you didn't type: worth a source check
  note.

GitHub's own move toward a dependency lock for workflows (the
`dependencies:` key with SHAs) does not age this script: it reads
what lies in the repo **now**.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)
UNTRUSTED_INTERP = re.compile(
    r"\$\{\{\s*(github\.(event|head_ref|pull_request)[^}]*|"
    r"inputs\.[^}]*)\s*\}\}")
SECRET_INTERP = re.compile(r"\$\{\{\s*secrets\.[^}]+\s*\}\}")


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ----------------------------------------------------------------- findings

@dataclass
class Finding:
    severity: str       # critical | warning | info
    check: str
    detail: str
    file: str = ""
    job: str = ""


def as_jobs(doc: dict):
    """(job-name, job-dict) for the document's `jobs`."""
    jobs = doc.get("jobs") or {}
    if isinstance(jobs, dict):
        yield from jobs.items()


def uses_ref(ref: str) -> str:
    """'sha' | 'tag-or-branch' | 'local' | 'docker'."""
    if ref.startswith("./"):
        return "local"
    if ref.startswith("docker://"):
        return "docker"
    return "sha" if SHA_RE.match(ref) else "tag-or-branch"


def audit_workflow(rel: str, doc: dict) -> list[Finding]:
    findings: list[Finding] = []

    def add(sev, check, detail, job=""):
        findings.append(Finding(sev, check, detail, rel, job))

    # YAML 1.1 parses the bare key `on:` as boolean True — the
    # classic trap; check both spellings
    triggers = doc.get("on", doc.get(True))
    trigger_names = set()
    if isinstance(triggers, list):
        trigger_names = {str(t) for t in triggers}
    elif isinstance(triggers, dict):
        trigger_names = {str(k) for k in triggers}

    # permissions
    perms = doc.get("permissions")
    if perms is None:
        add("info", "permissions",
            "no top-level permissions block — the org/repo default "
            "applies (historically the write-everything token)")
    elif perms == "write-all" or perms is True:
        add("warning", "permissions",
            "permissions: write-all — every job gets every write")

    for job_name, job in as_jobs(doc):
        if not isinstance(job, dict):
            continue
        # job-level permissions
        jperms = job.get("permissions")
        if jperms == "write-all" or jperms is True:
            add("warning", "permissions",
                "permissions: write-all at the job level", job_name)
        if job.get("runs-on") in ("self-hosted",
                                  ["self-hosted"]) or \
                (isinstance(job.get("runs-on"), list)
                 and "self-hosted" in job["runs-on"]):
            add("warning", "self-hosted",
                "self-hosted runner — on a public repo every PR "
                "author gets code execution on your machine; "
                "runner persistence outlives the job", job_name)

        pr_target = "pull_request_target" in trigger_names
        checkout_pr = False
        steps = job.get("steps") or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses") or ""
            if uses:
                if not uses.startswith(("./", "docker://")):
                    ref = uses.split("@")[-1] if "@" in uses else ""
                    if uses_ref(ref) == "tag-or-branch":
                        add("warning", "pinning",
                            f"action {uses.split('@')[0]} pinned to "
                            f"mutable `{ref}` — retargetable at any "
                            "moment; pin the full commit SHA (the "
                            "tj-actions shape)", job_name)
                if uses.startswith("actions/checkout"):
                    with_block = step.get("with") or {}
                    ref_val = str(with_block.get("ref", ""))
                    if "pull_request" in ref_val \
                            or "head_ref" in str(step):
                        checkout_pr = True
            run = step.get("run")
            if isinstance(run, str):
                if UNTRUSTED_INTERP.search(run):
                    add("critical", "injection",
                        "untrusted event data interpolated straight "
                        "into run: — command injection with the PR "
                        "author holding the pen; pass it through "
                        "env: instead", job_name)
                if SECRET_INTERP.search(run) and re.search(
                        r"echo|printenv|env\s|>>", run):
                    add("warning", "secrets",
                        "secrets interpolated into a run: that "
                        "echoes/dumps — they land in the logs", job_name)
                elif re.search(r"\bprintenv\b|(^|\s)env\s*(;|&|\||$)",
                               run):
                    add("info", "secrets",
                        "printenv/env dump in run: — every secret "
                        "the job can see goes to the log at once",
                        job_name)
        if pr_target:
            if checkout_pr:
                add("critical", "pull_request_target",
                    "pull_request_target with a checkout of the PR "
                    "head — the repo's secrets run with untrusted "
                    "PR code: the exfiltration shape", job_name)
            else:
                add("warning", "pull_request_target",
                    "pull_request_target — runs with the repo's "
                    "secrets on pull request events; safe only with "
                    "deliberate care (no PR checkouts, no event "
                    "interpolation)", job_name)
    if "workflow_run" in trigger_names:
        add("info", "workflow_run",
            "workflow_run — executes after another workflow with "
            "the repo's tokens on events you didn't type; verify "
            "the triggering workflow's source (head_sha checkout, "
            "not its artifacts)")
    return findings


# ------------------------------------------------------------------ loading

def find_workflows(repo_dir: str, recursive: bool) -> list[Path]:
    root = Path(repo_dir)
    out: list[Path] = []
    if (root / ".github" / "workflows").is_dir():
        wf_dir = root / ".github" / "workflows"
        out = sorted(p for p in wf_dir.iterdir()
                     if p.suffix in (".yml", ".yaml"))
    if not out and root.is_dir():
        # a folder of workflow files directly
        out = sorted(p for p in root.iterdir()
                     if p.suffix in (".yml", ".yaml"))
    if recursive and root.is_dir():
        for p in sorted(root.rglob(".github/workflows")):
            if p.is_dir() and p != root / ".github" / "workflows":
                out.extend(sorted(q for q in p.iterdir()
                                  if q.suffix in (".yml", ".yaml")))
    return sorted(set(out))


def load_workflow(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8",
                                        errors="replace"))
    return doc if isinstance(doc, dict) else {}


# -------------------------------------------------------------------- report

ICON = {"critical": "🔴", "warning": "🟠", "info": "ℹ️"}


def build_table_event(findings: list[Finding]) -> dict:
    rows = [{"severity": ICON[f.severity] + " " + f.severity,
             "check": f.check, "file": f.file,
             "job": f.job, "detail": f.detail[:70]}
            for f in findings]
    return {"type": "table",
            "columns": ["severity", "check", "file", "job",
                        "detail"],
            "rows": rows[:60]}


def build_markdown(workflows: list[str], findings: list[Finding],
                   unparsed: list[str]) -> str:
    crit = sum(1 for f in findings if f.severity == "critical")
    warn = sum(1 for f in findings if f.severity == "warning")
    out = [f"# GHA Audit — Report\n",
           f"{len(workflows)} workflow file(s) · "
           f"**{len(findings)} finding(s)**: {crit} critical, "
           f"{warn} warnings\n",
           "The workflows are read, not run — what the CI "
           "configuration *allows*, including everything it would "
           "do with the repository's secrets.\n"]
    current = None
    for f in sorted(findings, key=lambda x: (x.file, x.check)):
        if f.file != current:
            out.append(f"\n## {f.file}\n")
            current = f.file
        out.append(f"- {ICON[f.severity]} **{f.check}**"
                   + (f" (job `{f.job}`)" if f.job else "")
                   + f": {f.detail}")
    if unparsed:
        out.append("\n⚫ unparsed: " + ", ".join(unparsed))
    out.append("\n## The safe shapes\n")
    out.append("- `uses: owner/repo@<full-sha>` — the ref that "
               "cannot be retargeted; GitHub's `dependencies:` "
               "lock is the same idea.")
    out.append("- `permissions: read-all` at the top; widen one "
               "job at a time, one scope at a time.")
    out.append("- Untrusted data → `env:` → the script reads the "
               "variable; never `${{ github.event.* }}` in `run:`.")
    out.append("- `pull_request_target` only without PR checkouts "
               "and without event interpolation — or not at all.")
    out.append("\n## Related\n")
    out.append("- **secret-scan** — what already leaked in the "
               "tree; **dep-audit** — the lockfiles beside the "
               "workflows.")
    out.append("- **fw-audit / web-conf-audit** — the sibling "
               "passive-config audits.")
    return "\n".join(out)


def write_artifacts(workflows: list[str], findings: list[Finding],
                    unparsed: list[str], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "workflows": workflows,
        "findings": [{"severity": f.severity, "check": f.check,
                      "detail": f.detail, "file": f.file,
                      "job": f.job} for f in findings],
        "unparsed": unparsed,
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GHA Audit — GitHub Actions workflows reviewed "
                    "passively: pinning, pull_request_target, "
                    "injection, secrets, permissions")
    parser.add_argument("--repo-dir", required=True,
                        help="the repo root (with .github/workflows)")
    parser.add_argument("--recursive", action="store_true",
                        default=True,
                        help="walk the tree for more workflows")
    parser.add_argument("--no-recursive", dest="recursive",
                        action="store_false")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no workflows are read",
              flush=True)
        return 0

    if not os.path.isdir(args.repo_dir):
        print(f"✗ {args.repo_dir!r} is not a folder", file=sys.stderr,
              flush=True)
        return 2

    workflows = find_workflows(args.repo_dir, args.recursive)
    if not workflows:
        print(f"✗ no workflow files under {args.repo_dir}",
              file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              "## Nothing to audit\n\nNo `.github/workflows/*.yml` "
              "and no loose workflow YAML under the given folder. "
              "Point the script at the repository root."})
        return 1
    log(f"Auditing {len(workflows)} workflow file(s)")

    findings: list[Finding] = []
    unparsed: list[str] = []
    for i, path in enumerate(workflows, 1):
        rel = os.path.relpath(path, args.repo_dir)
        try:
            doc = load_workflow(path)
        except yaml.YAMLError as exc:
            unparsed.append(f"{rel}: {exc}")
            continue
        if not doc:
            unparsed.append(f"{rel}: empty or not a mapping")
            continue
        findings.extend(audit_workflow(rel, doc))
        emit({"type": "progress", "pct": int(100 * i / len(workflows)),
              "message": rel})

    findings.sort(key=lambda f: ({"critical": 0, "warning": 1,
                                  "info": 2}[f.severity], f.file))
    report = build_markdown([str(p) for p in workflows], findings,
                            unparsed)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(findings))
    emit({"type": "markdown", "content": report})
    write_artifacts([str(p) for p in workflows], findings, unparsed,
                    report)

    crit = sum(1 for f in findings if f.severity == "critical")
    warn = sum(1 for f in findings if f.severity == "warning")
    summary = (f"{len(workflows)} workflow(s) · {crit} critical · "
               f"{warn} warning(s)")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
