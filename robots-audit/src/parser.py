"""RFC 9309 robots.txt parser.

Turns raw text into a :class:`RobotsDoc`: user-agent groups with their
Allow/Disallow rules, the sitemap directives, crawl-delay values, and a
per-line commentary of everything crawlers silently ignore — invalid
lines, unknown fields, orphan rules. The parser **never rejects**: the
RFC says invalid lines are ignored, and this is an auditor — an ignored
line is a finding, not a crash.

Group semantics (RFC 9309 §2.2.1, as implemented by Google): consecutive
``User-agent`` lines accumulate into one group until the first rule
appears; the next ``User-agent`` after a rule starts a new group. Only
the **first** group matching a user-agent is ever used — later groups
for the same token are silently ignored, which is exactly the classic
"why is my Disallow not working" trap this audit exists to catch.

``Disallow:`` with an empty value is legal and means *allow all*; a
path of ``/`` means *block everything under it*. ``*`` and ``$`` in
paths are the Google/Bing/Yandex extension the RFC acknowledges but
does not require — the parser accepts them and the audit notes their
use.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Google's robots.txt size limit — content past it is ignored.
MAX_SIZE_BYTES = 500 * 1024

KNOWN_FIELDS = {"user-agent", "allow", "disallow", "sitemap", "crawl-delay"}


@dataclass
class Rule:
    verb: str            # 'allow' | 'disallow'
    path: str            # '' for the empty (allow-all) disallow
    lineno: int


@dataclass
class Group:
    user_agents: list[str] = field(default_factory=list)   # as written
    rules: list[Rule] = field(default_factory=list)
    crawl_delay: float | None = None
    lineno: int = 0


@dataclass
class LineNote:
    lineno: int
    kind: str            # 'invalid' | 'unknown_field' | 'orphan_rule' | 'comment'
    detail: str


@dataclass
class RobotsDoc:
    groups: list[Group] = field(default_factory=list)
    sitemaps: list[tuple[str, int]] = field(default_factory=list)   # (url, lineno)
    notes: list[LineNote] = field(default_factory=list)
    size_bytes: int = 0
    truncated: bool = False
    line_count: int = 0

    # --- convenience reads ---------------------------------------------

    def group_for(self, user_agent: str) -> Group | None:
        """The FIRST group matching ``user_agent`` (case-insensitive),
        else the first ``*`` group, else None = unrestricted."""
        token = user_agent.strip().lower()
        star = None
        for group in self.groups:
            agents = [a.strip().lower() for a in group.user_agents]
            if token in agents:
                return group
            if star is None and "*" in agents:
                star = group
        return star

    def duplicate_groups(self) -> list[tuple[str, int, int]]:
        """(user-agent, first group lineno, later group lineno) for every
        token defined in more than one group — the later groups are the
        ones crawlers ignore. ``*`` included: a second ``*`` group is
        ignored exactly like any other duplicate, which is the classic
        "my Disallow stopped working" report."""
        seen: dict[str, int] = {}
        out = []
        for group in self.groups:
            for agent in group.user_agents:
                token = agent.strip().lower()
                if token in seen:
                    out.append((token, seen[token], group.lineno))
                else:
                    seen[token] = group.lineno
        return out

    def uses_wildcards(self) -> bool:
        return any("*" in r.path or r.path.endswith("$")
                   for g in self.groups for r in g.rules if r.path)

    def crawl_delays(self) -> list[tuple[str, float | None, int]]:
        """(first user-agent, delay, lineno) per group that sets one."""
        return [(g.user_agents[0] if g.user_agents else "?", g.crawl_delay, g.lineno)
                for g in self.groups if g.crawl_delay is not None]


def _split_comment(line: str) -> str:
    """Rule text before an unescaped ``#``. ``\\#`` is an escaped hash and
    stays in the value (RFC 9309 §2.2.3.4)."""
    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "#":
            out.append(line[i:i + 2])
            i += 2
            continue
        if ch == "#":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def parse_robots(text: str) -> RobotsDoc:
    """Parse robots.txt text into a document. Pure; no I/O, no judgment.

    Judgment (is this a problem?) lives in :mod:`src.checks`; every
    peculiarity the parser meets on the way becomes a :class:`LineNote`.
    """
    if text.startswith("﻿"):                      # UTF-8 BOM
        text = text[1:]
        # noted below via size-independent marker — a BOM is tolerated
        # but deserves a mention, so synthesize a note at line 1
        doc_bom = True
    else:
        doc_bom = False

    raw_lines = text.splitlines()
    doc = RobotsDoc(size_bytes=len(text.encode("utf-8")),
                    line_count=len(raw_lines))
    if doc.size_bytes > MAX_SIZE_BYTES:
        doc.truncated = True
        raw_lines = text.encode("utf-8")[:MAX_SIZE_BYTES] \
            .decode("utf-8", "ignore").splitlines()

    if doc_bom:
        doc.notes.append(LineNote(1, "comment",
                                  "byte-order mark at the start — tolerated, "
                                  "not all parsers expect it"))

    current: Group | None = None

    def ensure_group(lineno: int) -> Group:
        nonlocal current
        if current is None:
            current = Group(lineno=lineno)
            doc.groups.append(current)
        return current

    for lineno, raw in enumerate(raw_lines, start=1):
        line = _split_comment(raw).strip()
        if not line:
            continue

        if ":" not in line:
            doc.notes.append(LineNote(lineno, "invalid",
                                      f"no ':' — ignored by crawlers: {raw.strip()[:80]!r}"))
            continue

        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip().replace("\\#", "#")

        if field_name == "user-agent":
            if not value:
                doc.notes.append(LineNote(lineno, "invalid",
                                          "empty User-agent — ignored"))
                continue
            # A User-agent line after rules starts a new group; before
            # any rule it joins the current group's agent list.
            if current is not None and current.rules:
                current = Group(lineno=lineno)
                doc.groups.append(current)
            group = ensure_group(lineno)
            group.user_agents.append(value)
            continue

        if field_name in ("allow", "disallow"):
            if current is None:
                doc.notes.append(LineNote(
                    lineno, "orphan_rule",
                    f"{field_name} before any User-agent — ignored by crawlers"))
                continue
            ensure_group(lineno).rules.append(
                Rule(verb=field_name, path=value, lineno=lineno))
            continue

        if field_name == "sitemap":
            doc.sitemaps.append((value, lineno))
            continue

        if field_name == "crawl-delay":
            group = current if current is not None else None
            try:
                delay = float(value)
            except ValueError:
                doc.notes.append(LineNote(lineno, "invalid",
                                          f"Crawl-delay value {value!r} is not a number"))
                continue
            if group is not None:
                group.crawl_delay = delay
            else:
                doc.notes.append(LineNote(
                    lineno, "orphan_rule",
                    "Crawl-delay before any User-agent — ignored by crawlers"))
            continue

        doc.notes.append(LineNote(
            lineno, "unknown_field",
            f"unknown field {field_name!r} — ignored by RFC 9309 crawlers"))

    return doc
