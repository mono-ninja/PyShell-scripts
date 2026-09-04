"""Charset — the server's claim vs the document's own.

The crawler decodes a body by preferring the server's ``Content-Type``
charset, then the document's ``<meta charset>``, then UTF-8 — so the
page *renders*, and the conflict survives into the snapshot quietly
(schema 6 finally put the whole ``Content-Type`` header there; the
normalized ``content_type`` field drops parameters by design). When the
two declarations disagree, every consumer that picks the other one —
a browser sniffing, a search engine, a feed reader — gets mojibake, and
"server says utf-8, document says cp1251" is exactly the half of that
diagnosis the markup cannot show.

Comparison is on canonical codec names (``utf8`` == ``utf-8``,
``windows-1251`` == ``cp1251``) via :mod:`codecs`, so spelling doesn't
create phantom conflicts; unknown spellings are skipped rather than
guessed at. Pages that declare no charset anywhere are reported as one
grouped note — the browser is guessing there too, it just isn't
guessing *wrong* yet.
"""
from __future__ import annotations

import codecs

from src.options import Options
from src.snapshot import Finding, Snapshot, header_value, join_urls, judgable


def _canonical(name: str) -> str | None:
    """The canonical codec name, or None for an unknown spelling."""
    try:
        return codecs.lookup(name).name
    except (LookupError, ValueError):
        return None


def _server_charset(header: str) -> str | None:
    for part in header.split(";")[1:]:
        key, sep, value = part.strip().partition("=")
        if sep and key.strip().lower() == "charset":
            return value.strip().strip('"') or None
    return None


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 6:
        return [Finding(
            "charset", "info", "site",
            "cannot compare charsets — the whole Content-Type header "
            "needs a schema-6 snapshot (this one is schema "
            f"{snapshot.schema})",
            "Re-crawl with a Site Crawler that records the full response "
            "headers (schema 6+)",
        )]

    findings: list[Finding] = []
    undeclared: list[str] = []
    for page in snapshot.pages:
        if not judgable(page):
            continue
        server = _server_charset(header_value(page, "content-type") or "")
        if not server and not page.charset:
            undeclared.append(page.url)
            continue
        if not server or not page.charset:
            continue               # one declaration: nothing to conflict
        canon_server = _canonical(server)
        canon_doc = _canonical(page.charset)
        if canon_server and canon_doc and canon_server != canon_doc:
            findings.append(Finding(
                "charset", "warn", page.url,
                f"charset conflict: the server declares {server}, the "
                f"document declares {page.charset}",
                "Pick one encoding (UTF-8), declare it in one place, and "
                "convert the document to it — every consumer that picks "
                "the other declaration gets mojibake",
            ))

    if undeclared:
        findings.append(Finding(
            "charset", "info", join_urls(undeclared),
            f"{len(undeclared)} page(s) declare no charset at all",
            "Browsers guess the encoding on such pages — declare "
            "charset=utf-8 (in the header or <meta charset>) so the "
            "guess isn't yours to debug later",
            pages=undeclared,
        ))

    return findings
