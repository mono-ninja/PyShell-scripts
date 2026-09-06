"""src/history.py — the .git history scan (v2).

The same engine and the **same masking contract** as the working
tree, over every line ever *added* in the repository's history: a
rotated key that was removed three commits ago is still a leak —
it lives in every clone and in the pushbackup your hoster keeps.

Mechanics: ``git log --all -p`` streamed line by line (no giant
buffers), commit boundaries marked with a ``\\x01`` control char in
``--format`` (a marker no real commit message can start with), the
unified diff walked so every added line is checked by
:func:`src.scanner.check_line` with its new-file line number and
the commit that introduced it.

Honest limits, each visible in the report rather than hidden:

- **Merge commits are not diffed** (plain ``git log -p`` skips
  them) — content is normally introduced by its real commit;
  ``-m`` would multiply every merge into full-tree diffs.
- **Hunk context is approximate**: exclude/source windows work
  within the added lines of one hunk; a rule that excludes on a
  *context* line the diff did not carry can fire once more than it
  would on the working tree.
- **Binary files are skipped by git itself** ("Binary files …
  differ" carries no hunks).
- Dedup: one leak committed ten times is one finding with a commit
  count, not ten rows.

Requires the system ``git`` binary (the cURL/asset-minify
wrapper precedent); without it the mode exits 1 with the reason —
never an empty "no findings".
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .rules import Rule
from .scanner import SKIP_FILES, Finding, check_line

GIT_BIN = "git"
COMMIT_MARK = "\x01"          # --format=%x01… — no message starts with it
DEFAULT_MAX_COMMITS = 5000


@dataclass
class CommitInfo:
    sha: str
    date: str
    subject: str


@dataclass
class HistoryResult:
    commits: int = 0
    added_lines: int = 0
    truncated: bool = False
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class NotAGitRepo(ValueError):
    pass


class GitUnavailable(RuntimeError):
    pass


def _git(args: list[str], cwd: Path) -> subprocess.Popen:
    try:
        return subprocess.Popen(
            [GIT_BIN] + args, cwd=str(cwd), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, errors="replace")
    except FileNotFoundError as exc:
        raise GitUnavailable(
            f"the system git binary was not found: {exc}") from exc


def scan_history(root: Path, rules: list[Rule],
                 max_commits: int = DEFAULT_MAX_COMMITS
                 ) -> HistoryResult:
    """Every added line of every commit, through the same engine."""
    probe = _git(["rev-parse", "--is-inside-work-tree"], root)
    out, err = probe.communicate(timeout=30)
    if probe.returncode != 0 or out.strip() != "true":
        raise NotAGitRepo(
            f"{root} is not a git working tree (history mode needs one)")
    probe = _git(["rev-list", "--all", "--count"], root)
    out, err = probe.communicate(timeout=30)
    total_commits = int(out.strip() or "0")
    if total_commits == 0:
        raise NotAGitRepo("the repository has no commits at all")

    result = HistoryResult()
    if total_commits > max_commits:
        result.truncated = True
        result.notes.append(
            f"history capped at the {max_commits} most recent commit(s) "
            f"of {total_commits} — raise --max-commits for the full walk")

    proc = _git(
        ["log", "--all", "--full-history", "--no-color", "--text",
         f"--max-count={max_commits}",
         f"--format={COMMIT_MARK}%H%x02%ad%x02%s", "--date=short",
         "-p", "--no-ext-diff"],
        root)

    commit: CommitInfo | None = None
    file = ""
    new_line = 0
    hunk_lines: list[str] = []
    hunk_index = 0

    def flush_hunk() -> None:
        """Check the hunk's added lines as a block, so exclude and
        source windows see at least their own hunk."""
        nonlocal hunk_index
        if commit is None or not file or not hunk_lines:
            hunk_lines.clear()
            hunk_index = 0
            return
        for i in range(len(hunk_lines)):
            for f in check_line(rules, hunk_lines, i, file):
                result.findings.append(Finding(
                    rule_id=f.rule_id, severity=f.severity,
                    secret_type=f.secret_type, message=f.message,
                    file=f.file,
                    line_no=new_line - len(hunk_lines) + i + 1,
                    line_text=f.line_text,
                    commit=commit.sha, commit_date=commit.date,
                    commit_subject=commit.subject))
        result.added_lines += len(hunk_lines)
        hunk_lines.clear()
        hunk_index = 0

    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        if line.startswith(COMMIT_MARK):
            flush_hunk()
            parts = line[1:].split("\x02", 2)
            commit = CommitInfo(
                sha=parts[0],
                date=parts[1] if len(parts) > 1 else "",
                subject=parts[2] if len(parts) > 2 else "")
            result.commits += 1
            file = ""
        elif line.startswith("+++ b/"):
            flush_hunk()
            file = line[6:]
            if file.split("/")[-1] in SKIP_FILES:
                file = ""            # lockfile noise, same as tree mode
        elif line.startswith("+++"):
            flush_hunk()
            file = ""                # /dev/null and friends: no b-side
        elif line.startswith("@@"):
            flush_hunk()
            # @@ -old,count +new,count @@ — the new side starts here
            try:
                head = line.split("+", 2)[2].split(",")[0].split()[0]
                new_line = int(head)
            except (IndexError, ValueError):
                new_line = 0
        elif line.startswith("+"):
            if file:
                hunk_lines.append(line[1:])
                new_line += 1
        elif line.startswith("-"):
            pass
        else:
            # context line — counts toward the new side's numbering
            if file:
                new_line += 1
    flush_hunk()
    proc.wait(timeout=60)
    return result


def dedup_history(findings: list[Finding]) -> list[Finding]:
    """One leak committed N times is one finding with a commit
    count — the earliest commit is the finding's, the count says
    how often the line was re-added."""
    best: dict[tuple[str, str, str], Finding] = {}
    counts: dict[tuple[str, str, str], int] = {}
    order: list[tuple[str, str, str]] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line_text)
        if key not in best:
            best[key] = f
            counts[key] = 1
            order.append(key)
        else:
            counts[key] += 1
            if (f.commit_date or "9999") < \
                    (best[key].commit_date or "9999"):
                best[key] = f
    out = []
    for key in order:
        f = best[key]
        if counts[key] > 1:
            f.message += f" [re-added in {counts[key]} commit(s)]"
        out.append(f)
    return out
