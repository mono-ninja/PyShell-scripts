"""Rule evaluation — Google's implementation of RFC 9309 §2.2.2.

The most specific rule wins: among the Allow/Disallow rules of the
selected group, the one with the **longest path** that matches the URL
decides; a tie goes to Allow; no match at all means allowed. Matching
is prefix-style with the two Google extensions the major crawlers
implement — ``*`` (any run of characters, including ``/``) and a
trailing ``$`` (end anchor). Plain-RFC crawlers that lack the
extensions treat these literally; the audit notes that separately.

An empty ``Disallow:`` value is the RFC's explicit *allow all* and is
skipped here — it can never disallow anything.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from src.parser import Group, Rule


def url_path(url: str) -> str:
    """The path an evaluation runs against — empty becomes ``/``.

    Query strings are deliberately not part of the match: RFC 9309
    defines rules over the path, and folding ``?``-handling in would
    half-implement Google's extra behavior. Sites that need query
    rules use ``*`` patterns, which the audit surfaces as a note.
    """
    try:
        path = urlsplit(url).path
    except ValueError:
        return "/"
    return path or "/"


def rule_matches(rule: Rule, path: str) -> bool:
    """Google-style match of one rule path against a URL path."""
    pattern = rule.path
    if not pattern:
        return False                       # empty Disallow = allow all
    anchored = pattern.endswith("$")
    if anchored:
        pattern = pattern[:-1]
    # Escape everything, then let the two extensions back in.
    regex = re.escape(pattern).replace(re.escape("*"), ".*")
    if anchored:
        regex += "$"
    return re.match(regex, path) is not None


def evaluate(group: Group | None, path: str) -> tuple[bool, Rule | None]:
    """(allowed, deciding rule) for one URL path under one group.

    ``group`` None means no group applies — RFC 9309's unrestricted
    crawl — and everything is allowed.
    """
    if group is None:
        return True, None
    best: Rule | None = None
    for rule in group.rules:
        if rule_matches(rule, path):
            if best is None or len(rule.path) > len(best.path):
                best = rule
            elif len(rule.path) == len(best.path) and rule.verb == "allow":
                best = rule             # tie -> allow (Google's precedence)
    if best is None:
        return True, None
    return best.verb == "allow", best


def describe_rule(rule: Rule | None) -> str:
    """Human text for the deciding rule, quoted for the report."""
    if rule is None:
        return "no rule matched — allowed by default"
    return f"{rule.verb.capitalize()}: {rule.path!r} (line {rule.lineno})"
