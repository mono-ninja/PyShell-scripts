"""Images without alt — the counts existed since schema 2, the srcs
since schema 3, and no check ever read either.

Alt text is how a page's images exist for screen readers, search
images, and every context that doesn't render pixels. The counts
(``images_total``/``images_without_alt``) say how big the problem is;
``images_missing_alt`` (schema 3) names the actual URLs, which is what
turns a statistic into a to-do list. ``alt=""`` is deliberately *not*
counted by the crawler — an explicit "decorative" marker is correct
markup.

One ``warn`` per content page with missing alts, naming the first few
srcs; the full list rides along in the structured ``pages`` field.
"""
from __future__ import annotations

from src.options import Options
from src.snapshot import Finding, Snapshot, judgable


def run(snapshot: Snapshot, options: Options | None = None) -> list[Finding]:
    if snapshot.schema < 3:
        return [Finding(
            "images", "info", "site",
            "cannot check image alt text — this snapshot predates image "
            "srcs (schema 2)",
            "Re-crawl with a Site Crawler that records image srcs "
            "(schema 3+)",
        )]

    findings: list[Finding] = []
    for page in snapshot.pages:
        if not judgable(page) or not page.images_missing_alt:
            continue
        missing = page.images_missing_alt
        # images_total is schema 2 but was never read before — an old or
        # foreign snapshot may lack it, and "N images" is still sayable.
        scope = f" of {page.images_total}" if page.images_total else ""
        shown = ", ".join(missing[:3])
        more = f" (+{len(missing) - 3} more)" if len(missing) > 3 else ""
        findings.append(Finding(
            "images", "warn", page.url,
            f"{len(missing)}{scope} image(s) have no alt "
            f"attribute: {shown}{more}",
            "Describe what the image shows — alt text is how it exists "
            "for screen readers and image search. Use alt=\"\" only for "
            "pure decoration",
            pages=missing,
        ))

    return findings
