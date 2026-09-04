"""A3. Canonical — tags that point somewhere they shouldn't.

A canonical's whole job is to say "this other URL is the real one," so
every finding here is a way of failing that job:

* more than one canonical tag → ``warn``: a template and a plugin both
  wrote one, and which one a search engine honors is nobody's choice
  (``canonical_all``, schema 2 — same shape as ``titles``' conflicting
  ``<title>`` tags). While the conflict stands, the first tag's target
  is deliberately *not* judged — that would be detail on an undecided
  question;
* target is broken, redirecting, robots-blocked, ``noindex``, or carries
  its own canonical to a third URL (a chain) → ``fail``. Consolidation
  will not happen through any of those;
* target is in scope but absent from the crawl → ``warn``: nothing links
  to the URL this page nominates as the real one;
* target is on another host → ``info``. Often legitimate — a cross-domain
  canonical to a syndication source — just worth confirming;
* the page says ``noindex`` *and* canonicalizes elsewhere → ``warn``:
  contradictory instructions, and search engines are free to pick either;
* a duplicate-content page with no canonical at all → ``warn``. This
  cross-check only runs when the ``duplicates`` check is also selected
  (main passes the groups in); rather than half-running it against groups
  the user didn't ask for, it's skipped.

Comparisons are on the normalized URL (``snapshot.py``), because a
canonical is written by hand and arrives with whatever fragment, port or
host casing the author typed; findings quote the raw value.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable, page_noindex


def run(snapshot: Snapshot, options: Options | None = None,
        duplicate_groups=None) -> list[Finding]:
    options = options or Options()
    groups = duplicate_groups if duplicate_groups is not None \
        else options.duplicate_groups
    findings: list[Finding] = []

    # canonical_all landed in schema 2 — a schema-1 snapshot never had
    # the fact, so "no conflicts found" could not be said honestly. One
    # note, same rule as duplicates' text_hash note.
    if snapshot.schema < 2:
        findings.append(Finding(
            "canonical", "info", "site",
            "cannot check for conflicting canonical tags — canonical_all "
            "needs a schema-2 snapshot",
            "Re-crawl with a Site Crawler that records every canonical "
            "(schema 2+)",
        ))

    for page in snapshot.pages:
        if not page.canonical:
            if options.flag_missing_canonical and judgable(page):
                findings.append(Finding(
                    "canonical", "info", page.url,
                    "no canonical tag",
                    "A self-referencing canonical costs nothing and settles "
                    "which URL variant is the real one",
                ))
            continue

        # Needed below regardless of which branch runs — including the
        # "conflicting tags" one, which judges no target and so never
        # sets it otherwise.
        shown = page.canonical_raw or page.canonical

        if len(page.canonical_all) > 1:
            findings.append(Finding(
                "canonical", "warn", page.url,
                f"{len(page.canonical_all)} conflicting canonical tags: "
                + " | ".join(page.canonical_all),
                "Exactly one canonical per page — two means a template and "
                "a plugin both wrote one. Delete the wrong one, then "
                "re-check what the survivor points at",
            ))
        elif page.canonical == page.key:
            continue  # self-referencing canonical: correct, the common case
        else:
            target = page.canonical              # normalized
            if not snapshot.in_scope(target):
                findings.append(Finding(
                    "canonical", "info", page.url,
                    f"canonical points outside the crawl scope: {shown}",
                    "Fine if deliberate (e.g. a syndication source owns the "
                    "content) — worth confirming it's intentional",
                ))
            else:
                findings.extend(_in_scope_target(snapshot, page, target,
                                                 shown))

        if page_noindex(page):
            findings.append(Finding(
                "canonical", "warn", page.url,
                f"page is noindex but canonicalizes to {shown} — "
                f"contradictory signals",
                "Pick one: either this page is the duplicate (canonical, no "
                "noindex) or it should not be indexed at all (noindex, no "
                "canonical to elsewhere)",
            ))

    if groups:
        for _label, _value, urls in groups:
            for url in urls:
                page = snapshot.resolve(url)
                if page is not None and not page.canonical:
                    findings.append(Finding(
                        "canonical", "warn", url,
                        f"{url} is part of a duplicate-content group but has "
                        f"no canonical",
                        "Add a canonical pointing at the preferred version of "
                        "the content",
                    ))

    return findings


def _in_scope_target(snapshot, page, target, shown) -> list[Finding]:
    """The first thing wrong with an in-scope canonical target, if any.

    One finding per page: a canonical that is both redirecting *and*
    eventually noindex is one broken canonical, not two.
    """
    def fail(detail, recommendation):
        return [Finding("canonical", "fail", page.url, detail, recommendation)]

    target_page = snapshot.resolve(target)
    final = snapshot.redirect_final(target)

    if target_page is not None and target_page.status is not None \
            and target_page.status >= 400:
        return fail(
            f"canonical points at a broken URL: {shown} "
            f"(HTTP {target_page.status})",
            f"Point the canonical at a URL that actually resolves — "
            f"or make it self-referencing ({page.url})")

    if final:
        return fail(
            f"canonical points at a redirecting URL: {shown} → {final}",
            f"Point the canonical straight at the final URL ({final}) — "
            f"a canonical through a redirect may not be consolidated")

    if target_page is None:
        return [Finding(
            "canonical", "warn", page.url,
            f"canonical points at {shown}, which is not in the snapshot",
            "Either nothing links to that URL, or it is outside the crawl's "
            "scope/limits — confirm it exists and is reachable")]

    if target_page.blocked_by_robots:
        return fail(
            f"canonical points at {shown}, which robots.txt disallows",
            "Search engines cannot fetch the target, so they cannot honor "
            "the canonical — allow it in robots.txt or canonicalize elsewhere")

    if page_noindex(target_page):
        return fail(
            f"canonical points at {shown}, which is noindex",
            "This page defers to a target that asks not to be indexed — "
            "neither URL ends up ranking; drop the noindex or the canonical")

    if target_page.canonical and target_page.canonical != target_page.key:
        return fail(
            f"canonical chain: {page.url} → {shown} → "
            f"{target_page.canonical_raw or target_page.canonical}",
            f"Point this canonical directly at "
            f"{target_page.canonical_raw or target_page.canonical} — chained "
            f"canonicals are not followed reliably")

    return []
