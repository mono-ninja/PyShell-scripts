"""src/rules.py — the rule model, loader and validator.

The wp-audit engine, carried over: rules are YAML data (the built-in
`rules.yaml` next to main.py plus an optional `--custom-rules` file
in the same schema) — detection logic as data, versionable without
code changes.

The semantics (identical to wp-audit):

- `match.regex` must hit the trigger line;
- `exclude` suppresses the finding when its regex hits the trigger
  line **or up to `window_lines` lines after it** (a
  placeholder);
- `require_source` demands one of its patterns within
  `window_lines` lines **before** the trigger;
- `file_include`/`file_exclude` are filename globs (default: every
  file).

One field is new here: `mask_group` (default 0) — the regex group
that holds the secret. The scanner replaces exactly that span with a
mask in every finding, so **the report never repeats the leak** it
found.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

BUILTIN_RULES_PATH = Path(__file__).resolve().parent.parent / "rules.yaml"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: str
    secret_type: str
    message: str
    match_re: re.Pattern
    mask_group: int = 0
    exclude_re: re.Pattern | None = None
    exclude_window: int = 0
    source_patterns: tuple[re.Pattern, ...] = ()
    source_window: int = 0
    file_include: tuple[str, ...] = ("*",)
    file_exclude: tuple[str, ...] = ()

    def applies_to(self, filename: str) -> bool:
        import fnmatch
        base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if any(fnmatch.fnmatch(base, pat) for pat in self.file_exclude):
            return False
        return any(fnmatch.fnmatch(base, pat) for pat in self.file_include)


class RuleError(ValueError):
    """A rule file that doesn't parse or a rule that's malformed —
    surfaced as exit 2 with the file and the reason."""


def _compile(rdef: dict, source: str) -> Rule:
    where = f"{source}: rule {rdef.get('id', '<no id>')!r}"
    for key in ("id", "description", "severity", "secret_type",
                "message"):
        if not rdef.get(key):
            raise RuleError(f"{where}: missing {key}")
    severity = str(rdef["severity"]).lower()
    if severity not in VALID_SEVERITIES:
        raise RuleError(f"{where}: severity must be one of "
                        f"{sorted(VALID_SEVERITIES)}")
    match = rdef.get("match") or {}
    if "regex" not in match:
        raise RuleError(f"{where}: match.regex is required")
    try:
        match_re = re.compile(match["regex"], re.IGNORECASE)
    except re.error as exc:
        raise RuleError(f"{where}: bad match regex: {exc}")
    mask_group = int(rdef.get("mask_group", 0))
    if mask_group < 0 or mask_group > match_re.groups:
        raise RuleError(f"{where}: mask_group {mask_group} is beyond the "
                        f"regex's {match_re.groups} capturing group(s)")
    exclude_re = None
    exclude_window = 0
    exclude = rdef.get("exclude") or {}
    if "regex" in exclude:
        try:
            exclude_re = re.compile(exclude["regex"], re.IGNORECASE)
            exclude_window = int(exclude.get("window_lines", 0))
        except (re.error, ValueError, TypeError) as exc:
            raise RuleError(f"{where}: bad exclude block: {exc}")
    source_patterns: tuple[re.Pattern, ...] = ()
    source_window = 0
    src = rdef.get("require_source") or {}
    if src.get("patterns"):
        try:
            source_patterns = tuple(re.compile(p, re.IGNORECASE)
                                    for p in src["patterns"])
            source_window = int(src.get("window_lines", 0))
        except (re.error, ValueError, TypeError) as exc:
            raise RuleError(f"{where}: bad require_source block: {exc}")
    file_include = tuple(rdef.get("file_include") or ("*",))
    file_exclude = tuple(rdef.get("file_exclude") or ())
    return Rule(
        id=str(rdef["id"]), description=str(rdef["description"]),
        severity=severity, secret_type=str(rdef["secret_type"]),
        message=str(rdef["message"]), match_re=match_re,
        mask_group=mask_group,
        exclude_re=exclude_re, exclude_window=exclude_window,
        source_patterns=source_patterns, source_window=source_window,
        file_include=file_include, file_exclude=file_exclude,
    )


def load_rules(custom_path: str = "") -> list[Rule]:
    """The built-in set + an optional custom file (same schema,
    appended after the built-ins). Raises RuleError with a precise
    message on any malformed input — that's exit 2, never a crash."""
    try:
        builtin = yaml.safe_load(BUILTIN_RULES_PATH.read_text(
            encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"built-in rules.yaml unreadable: {exc}")
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for rdef in builtin.get("rules") or []:
        rule = _compile(rdef, "rules.yaml (built-in)")
        if rule.id in seen_ids:
            raise RuleError(f"built-in rules.yaml: duplicate id {rule.id!r}")
        seen_ids.add(rule.id)
        rules.append(rule)
    if custom_path:
        try:
            data = yaml.safe_load(Path(custom_path).read_text(
                encoding="utf-8")) or {}
        except OSError as exc:
            raise RuleError(f"custom rules {custom_path!r}: {exc}")
        except yaml.YAMLError as exc:
            raise RuleError(f"custom rules {custom_path!r}: YAML parse "
                            f"error: {exc}")
        if not isinstance(data, dict) or not data.get("rules"):
            raise RuleError(f"custom rules {custom_path!r}: needs a "
                            "'rules:' list")
        for rdef in data["rules"]:
            rule = _compile(rdef, f"custom {custom_path}")
            if rule.id in seen_ids:
                raise RuleError(f"custom rules {custom_path!r}: duplicate "
                                f"id {rule.id!r}")
            seen_ids.add(rule.id)
            rules.append(rule)
    return rules
