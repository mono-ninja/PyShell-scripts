"""D1. Baseline comparison — what changed since the last run.

The whole point of the crawl-once/check-often split is that you re-run
this after every fix. That only pays off if a run can answer "did it get
better?", which needs the previous ``findings.json`` to compare against.

Findings are matched on a **key that ignores numbers**:
``check | page | detail with digits masked``. Without the mask, "5 page(s)
link to /old" and "4 page(s) link to /old" would read as one finding fixed
and a different one appearing, when it is the same problem getting
smaller. Same for "title is 71 characters".

A baseline path that doesn't exist yet is not an error — the first run in
a pipeline has nothing to compare to. A baseline that exists but doesn't
parse is, because that means the pipeline is comparing against garbage.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

_DIGITS = re.compile(r"\d+")


class BaselineError(Exception):
    """The baseline file exists but can't be read as findings."""


def finding_key(check: str, page: str, detail: str) -> str:
    return f"{check}|{page}|{_DIGITS.sub('#', detail)}"


def key_of(finding) -> str:
    return finding_key(finding.check, finding.page, finding.detail)


@dataclass
class Diff:
    baseline_path: str
    new: list = field(default_factory=list)
    fixed: list[dict] = field(default_factory=list)
    unchanged: int = 0
    new_keys: set[str] = field(default_factory=set)

    def is_new(self, finding) -> bool:
        return key_of(finding) in self.new_keys


def load_baseline(path: str) -> dict[str, dict] | None:
    """Findings from a previous ``findings.json``, keyed for comparison.

    Returns ``None`` when the file simply isn't there yet.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline {path!r}: {exc}") from exc

    records = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(records, list):
        raise BaselineError(
            f"baseline {path!r} has no 'findings' list — point --baseline at a "
            f"findings.json written by a previous run")

    out: dict[str, dict] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        out[finding_key(str(record.get("check", "")),
                        str(record.get("page", "")),
                        str(record.get("detail", "")))] = record
    return out


def compare(findings: list, baseline: dict[str, dict], path: str) -> Diff:
    current = {key_of(f): f for f in findings}
    new_keys = set(current) - set(baseline)
    return Diff(
        baseline_path=path,
        new=[f for f in findings if key_of(f) in new_keys],
        fixed=[record for key, record in baseline.items() if key not in current],
        unchanged=len(set(current) & set(baseline)),
        new_keys=new_keys,
    )
