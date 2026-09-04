"""Language and direction — the i18n facts on the <html> element.

``lang`` (schema 2) is how a page says which language it is in — search
engines use it for the right market, screen readers for the right
voice, and a page without it makes both guess. ``dir`` (schema 6) is
its twin for script direction: an Arabic or Hebrew page without
``dir=rtl`` renders backwards, and hreflang alone cannot tell you that.

Findings, per content page:

* no ``lang`` at all → ``warn`` — the single most common i18n omission,
  and the cheapest to fix;
* a ``lang`` that isn't a language code → ``info``;
* a right-to-left language whose page lacks ``dir=rtl`` → ``warn``
  (schema 6+ only — before that ``dir`` was never recorded, so the
  question is unanswerable rather than answered wrong).
"""
from __future__ import annotations

import re

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable

# Rough BCP 47, same sieve as hreflang's: catches "english", "de_DE",
# stray punctuation. Not a validator.
_LANG = re.compile(r"^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$", re.IGNORECASE)

# Languages written right-to-left. Deliberately the well-established
# set — anything contested would turn a helpful rule into noise.
RTL_LANGS = {"ar", "he", "fa", "ur", "ps", "sd", "yi", "dv"}


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 2:
        return [Finding(
            "language", "info", "site",
            "cannot check the html lang attribute — this snapshot "
            "predates its capture (schema 1)",
            "Re-crawl with a Site Crawler that records <html lang> "
            "(schema 2+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page):
            continue

        if not page.lang:
            findings.append(Finding(
                "language", "warn", page.url,
                "no lang attribute on <html>",
                "Say which language the page is in (<html lang=\"…\">) — "
                "search engines target the right market and screen "
                "readers pick the right voice",
            ))
        else:
            if not _LANG.match(page.lang):
                findings.append(Finding(
                    "language", "info", page.url,
                    f"lang={page.lang!r} is not a language code",
                    "Use a BCP 47 tag (en, pt-BR, zh-Hans) — anything "
                    "else is ignored",
                ))
            if snapshot.schema >= 6 \
                    and page.lang.split("-")[0].lower() in RTL_LANGS \
                    and page.dir != "rtl":
                findings.append(Finding(
                    "language", "warn", page.url,
                    f"lang={page.lang} is right-to-left but the page has "
                    f"no dir=rtl (dir={page.dir or 'none'})",
                    "Set <html dir=\"rtl\"> — without it an RTL language "
                    "renders mirrored, punctuation first and last",
                ))

    return findings
