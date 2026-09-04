"""The audit — findings over a parsed robots.txt.

Pure functions over already-collected facts (no I/O): the source's
verdict comes in from :mod:`src.robotsio`, the parsed document from
:mod:`src.parser`, the test-URL results from :mod:`src.evaluate`.
Every finding is a check name, a severity (info / warn / fail), what
was seen, and what to change — the same shape seo-checks uses, because
this is the same kind of tool: rule-based judgments over facts.

The severity philosophy: **fail** is reserved for "this will cost you
indexing" (the whole site disallowed, a key page blocked, a Sitemap
that can't exist). ``warn`` is "crawlers will do something you may not
expect" (ignored groups, orphan rules, silent truncation). ``info`` is
context worth knowing (wildcard extensions in use, crawl-delay
politics, no sitemap at all).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from src.evaluate import evaluate, url_path
from src.parser import RobotsDoc
from src.robotsio import RobotsSource

#: Crawl-delay past this is effectively "don't crawl me" for the bots
#: that honor it (Bing, Yandex) — worth a word before someone ships it.
AGGRESSIVE_CRAWL_DELAY = 30


@dataclass
class Finding:
    check: str
    severity: Literal["info", "warn", "fail"]
    detail: str
    recommendation: str


@dataclass
class TestResult:
    url: str
    allowed: bool
    deciding: str          # describe_rule() text


@dataclass
class SitemapCheck:
    url: str
    ok: bool
    detail: str


@dataclass
class AuditInput:
    source: RobotsSource
    doc: RobotsDoc | None
    tests: list[TestResult] = field(default_factory=list)
    sitemap_checks: list[SitemapCheck] = field(default_factory=list)
    user_agent: str = "*"

    @property
    def origin(self) -> str:
        return self.source.origin


def audit(data: AuditInput) -> list[Finding]:
    findings: list[Finding] = []
    source, doc = data.source, data.doc

    # --- how the file was obtained -----------------------------------
    if source.note:
        findings.append(Finding(
            "robots.txt source",
            source.severity if source.severity in ("info", "warn") else "warn",
            source.note,
            "Fix the serving of robots.txt" if source.text is None else ""))

    if doc is None:
        # No text to parse (404, auth wall, server error) — the source
        # finding carries it; nothing else can be checked.
        return findings

    # --- size ----------------------------------------------------------
    if doc.truncated:
        findings.append(Finding(
            "File size", "warn",
            f"{doc.size_bytes:,} bytes — over the 500 KiB limit; crawlers "
            f"read only the first 500 KiB and ignore the rest",
            "Shrink the file: fewer, broader rules instead of thousands "
            "of exact paths"))
    elif doc.size_bytes > 400 * 1024:
        findings.append(Finding(
            "File size", "info",
            f"{doc.size_bytes:,} bytes — approaching the 500 KiB limit",
            ""))

    # --- parse commentary ------------------------------------------------
    invalid = [n for n in doc.notes if n.kind == "invalid"]
    if invalid:
        shown = "; ".join(f"line {n.lineno}: {n.detail}" for n in invalid[:3])
        more = f" (+{len(invalid) - 3} more)" if len(invalid) > 3 else ""
        findings.append(Finding(
            "Invalid lines", "warn",
            f"{len(invalid)} line(s) crawlers ignore — {shown}{more}",
            "Fix or delete them; an ignored line is a rule you think you "
            "have but don't"))

    unknown = [n for n in doc.notes if n.kind == "unknown_field"]
    if unknown:
        fields_here = sorted({n.detail.split("'")[0].replace("unknown field ", "")
                              for n in unknown})
        findings.append(Finding(
            "Unknown fields", "info",
            f"{len(unknown)} line(s) with fields crawlers ignore "
            f"({', '.join(fields_here)})",
            "Non-standard extensions work only where they're supported; "
            "the RFC core is User-agent/Allow/Disallow/Sitemap"))

    orphan = [n for n in doc.notes if n.kind == "orphan_rule"]
    if orphan:
        findings.append(Finding(
            "Orphan rules", "warn",
            f"{len(orphan)} rule(s) before any User-agent line — ignored "
            f"by every compliant crawler",
            "Move them under their User-agent group"))

    # --- duplicate groups (the silent killer) ------------------------------
    for token, first_line, later_line in doc.duplicate_groups():
        findings.append(Finding(
            "Duplicate User-agent group", "warn",
            f"'{token}' is defined at line {first_line} and again at line "
            f"{later_line} — crawlers use only the FIRST group and ignore "
            f"the second one entirely",
            "Merge the rules into one group; the second block never runs"))

    # --- the big one: is the site blocked? -----------------------------------
    star_group = doc.group_for("*")
    allowed_root, deciding = evaluate(star_group, "/")
    if not allowed_root:
        findings.append(Finding(
            "Entire site disallowed", "fail",
            f"'/' is disallowed for the '*' group — {_rule_text(deciding)} "
            f"— every compliant crawler skips the whole site",
            "This is almost never intended: narrow the Disallow to the "
            "paths that should really be off-limits"))

    # --- crawl-delay -------------------------------------------------------
    for agent, delay, lineno in doc.crawl_delays():
        if delay is not None and delay > AGGRESSIVE_CRAWL_DELAY:
            findings.append(Finding(
                "Crawl-delay", "warn",
                f"{delay:g}s for '{agent}' (line {lineno}) — bots that "
                f"honor Crawl-delay (Bing, Yandex) will crawl at a crawl",
                "Values past ~30s are effectively 'don't index me' for the "
                "crawlers that obey it"))
        else:
            findings.append(Finding(
                "Crawl-delay", "info",
                f"{delay:g}s for '{agent}' — Google ignores it; Bing and "
                f"Yandex honor it",
                ""))

    # --- wildcards ----------------------------------------------------------
    if doc.uses_wildcards():
        findings.append(Finding(
            "Wildcard patterns", "info",
            "rules use * and/or $ — supported by Google, Bing and Yandex, "
            "but not required by RFC 9309; strict parsers read them "
            "literally",
            ""))

    # --- sitemaps --------------------------------------------------------------
    if not doc.sitemaps:
        findings.append(Finding(
            "Sitemap", "info",
            "no Sitemap: line — crawlers discover pages from links alone",
            "Add 'Sitemap: https://…/sitemap.xml' (absolute URL) — "
            "Sitemap Generator builds one from a Site Crawler snapshot"))
    else:
        for url, lineno in doc.sitemaps:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                findings.append(Finding(
                    "Sitemap", "fail",
                    f"line {lineno}: {url!r} is not an absolute URL — "
                    f"RFC 9309 requires Sitemap values to be absolute",
                    "Write the full URL: Sitemap: https://example.com/sitemap.xml"))
            elif data.origin and urlsplit(url).hostname != urlsplit(data.origin).hostname \
                    and not _same_registrable(url, data.origin):
                findings.append(Finding(
                    "Sitemap", "info",
                    f"line {lineno}: {url} points at another host — legal "
                    f"(cross-host sitemaps are allowed), just make sure "
                    f"it's intentional",
                    ""))
        if data.sitemap_checks:
            for check in data.sitemap_checks:
                if not check.ok:
                    findings.append(Finding(
                        "Sitemap reachability", "warn",
                        f"{check.url} — {check.detail}",
                        "A Sitemap line that doesn't answer 200 is a "
                        "broken promise to every crawler that reads it"))

    # --- test URLs -----------------------------------------------------------------
    blocked_tests = [t for t in data.tests if not t.allowed]
    for t in blocked_tests:
        findings.append(Finding(
            "Test URL blocked", "fail" if url_path(t.url) == "/" else "warn",
            f"{t.url} is disallowed for '{data.user_agent}' — {t.deciding}",
            "If this page should be crawlable, the rule is wider than "
            "you think"))

    return findings


def _rule_text(rule) -> str:
    if rule is None:
        return "no deciding rule recorded"
    return f"decided by {rule.verb.capitalize()}: {rule.path!r}, line {rule.lineno}"


def _same_registrable(url: str, origin: str) -> bool:
    """True when both share the last two labels — example.com and
    www.example.com are the same site; example.com and other.com are not."""
    def registrable(host: str) -> str:
        return ".".join(host.lower().split(".")[-2:])
    try:
        return registrable(urlsplit(url).hostname or "") == \
            registrable(urlsplit(origin).hostname or "")
    except ValueError:
        return False
