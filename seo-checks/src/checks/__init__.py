"""Check registry: name -> check function.

Every check has the same contract — ``run(snapshot, options) ->
list[Finding]`` — so ``main.py`` dispatches generically over whatever's
selected rather than branching per name. ``external_links`` is deliberately
*not* in this registry: it's the one network-touching check, toggled by its
own option instead of the ``checks`` selection.
"""
from src.checks import (
    anchors,
    base_href,
    broken_links,
    canonical,
    charset,
    duplicates,
    embeds,
    headings,
    hreflang,
    images,
    indexability,
    language,
    meta_quality,
    meta_refresh,
    nofollow,
    orphans,
    redirects,
    sitemap,
    sitemap_freshness,
    social,
    structured_data,
    titles,
    url_variants,
    viewport,
)

# Display/execution order — also the order findings sort by within a
# severity tier, highest-value first: a dead link or a canonical pointing
# nowhere before an info-level note about title length.
CHECKS = {
    "broken_links": broken_links.run,
    "canonical": canonical.run,
    "redirects": redirects.run,
    "sitemap": sitemap.run,
    "duplicates": duplicates.run,
    "indexability": indexability.run,
    "orphans": orphans.run,
    "url_variants": url_variants.run,
    "nofollow": nofollow.run,
    "meta_quality": meta_quality.run,
    "headings": headings.run,
    "titles": titles.run,
    "meta_refresh": meta_refresh.run,
    "viewport": viewport.run,
    "social": social.run,
    "base_href": base_href.run,
    "structured_data": structured_data.run,
    "images": images.run,
    "sitemap_freshness": sitemap_freshness.run,
    "embeds": embeds.run,
    "anchors": anchors.run,
    "hreflang": hreflang.run,
    "language": language.run,
    "charset": charset.run,
}

ALL_CHECK_NAMES = list(CHECKS)
