"""hreflang clusters — language annotations that only work as a set.

hreflang says "this URL's ``de`` version lives *there*``" — and the
contract is mutual: Google requires every member of a cluster to point
at all the others, and quietly ignores clusters where someone forgot
the return link. The facts for judging that are all in the snapshot:
each page's ``hreflang`` (schema 2) names its alternates, and the pages
they name are right there to be looked up.

Findings, per page that carries hreflang:

* an alternates URL that doesn't point back → ``warn`` — the cluster
  is broken from this side, and search engines may drop the whole set;
* two *language* keys pointing at the same URL → ``warn`` — one URL
  cannot be two language versions at once (a language key sharing its
  URL with ``x-default`` is the standard "this is also the default"
  pattern, not a duplicate);
* a key that isn't a language code (``x-default`` aside) → ``warn``;
* an alternate absent from the snapshot → ``info`` — reciprocity
  unverifiable: it may be out of crawl scope, or a typo.

A page set with no hreflang at all is a legitimate single-language
site, not a finding — the check stays silent then, the same way
``embeds`` does when there are no iframes.
"""
from __future__ import annotations

import re

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable, normalize_url

# Rough BCP 47: 2–3 letter language, optional subtags. Not a validator —
# a sieve for "english" and "de_DE"-style mistakes. x-default is the
# spec's own key for the fallback URL and always allowed.
_LANG_KEY = re.compile(r"^(?:x-default|[a-z]{2,3}(?:-[a-z0-9]{2,8})*)$",
                       re.IGNORECASE)


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 2:
        return [Finding(
            "hreflang", "info", "site",
            "cannot check hreflang clusters — this snapshot predates "
            "their capture (schema 1)",
            "Re-crawl with a Site Crawler that records hreflang "
            "alternates (schema 2+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page) or not page.hreflang:
            continue

        bad_keys = [k for k in page.hreflang if not _LANG_KEY.match(k)]
        if bad_keys:
            findings.append(Finding(
                "hreflang", "warn", page.url,
                f"invalid hreflang key(s): {', '.join(sorted(bad_keys))}",
                "hreflang keys are language codes (de, en-US, zh-Hans) or "
                "x-default — anything else is ignored by search engines",
            ))

        # One URL cannot be two language versions at once — but a
        # language key sharing its URL with x-default is the standard
        # "this is also the default" pattern, not a duplicate.
        by_target: dict[str, list[str]] = {}
        for lang, url in page.hreflang.items():
            if lang.lower() != "x-default":
                by_target.setdefault(normalize_url(url) or url, []).append(lang)
        dupes = {url: langs for url, langs in by_target.items()
                 if len(langs) > 1}
        for url, langs in sorted(dupes.items()):
            findings.append(Finding(
                "hreflang", "warn", page.url,
                f"hreflang {', '.join(sorted(langs))} all point at {url} — "
                f"one URL cannot be two language versions",
                "Give each language its own URL, or drop the extra key — "
                "a duplicated target splits the cluster's signals",
            ))

        unverified: list[str] = []
        unreciprocated: list[str] = []
        for lang, url in sorted(page.hreflang.items()):
            target = snapshot.resolve(url)
            if target is None:
                unverified.append(f"{lang} → {url}")
                continue
            back = {normalize_url(v) or v for v in target.hreflang.values()}
            if page.key not in back:
                unreciprocated.append(f"{lang} → {url}")
        if unreciprocated:
            findings.append(Finding(
                "hreflang", "warn", page.url,
                "not reciprocated: " + ", ".join(unreciprocated),
                "Every member of a hreflang cluster must point at all the "
                "others — add the return links, or search engines may "
                "ignore the whole cluster",
            ))
        if unverified:
            findings.append(Finding(
                "hreflang", "info", page.url,
                "reciprocity unverifiable, not in the snapshot: "
                + ", ".join(unverified),
                "The alternate URL wasn't crawled — it may be outside the "
                "crawl's scope, or a typo. Confirm it exists and points "
                "back",
            ))

    return findings
