"""Generate robots.txt recommendations from analysis data.

The generated robots.txt blocks known scrapers/scanners, sets ``Crawl-delay``
for aggressive SEO bots, and suggests ``Disallow`` for frequently-crawled 404
paths.
"""

from collections import Counter

# Whole-site paths must never be suggested for Disallow — uncommenting
# "# Disallow: /" would de-index the entire site from search engines.
_ROBOTS_404_DENYLIST = {'/', '', '/index.php', '/index.html'}


def _is_disallow_safe(url: str) -> bool:
    """A 404 path is safe to suggest for Disallow only if it is specific.

    Root/index paths are never suggested, and single-segment paths
    ("/about") are treated as real pages with a temporary 404 rather than
    junk-crawl targets — suggesting them risks de-indexing real content.
    Deep paths ("/wp-json/wp/v2/posts", "/junk/x") are fair game.
    """
    if url in _ROBOTS_404_DENYLIST or len(url) <= 1:
        return False
    return url.strip('/').count('/') >= 1  # at least two path segments


def build_robots_txt(
    bots_out: dict,
    not_found_urls: dict | Counter,
    domain: str = 'example.com',
) -> dict:
    """Build a robots.txt with recommendations based on real crawl data.

    Args:
        bots_out: bot activity dict from :func:`src.analyzer.analyze_logs`.
        not_found_urls: mapping of 404 URL -> hit count.
        domain: site domain, used for the ``Sitemap:`` directive.

    Returns:
        ``{'content': str, 'details': list[dict]}`` where *content* is the full
        robots.txt text and *details* is a list of explanation blocks for the
        report.
    """
    lines = [
        "User-agent: *",
        "Disallow: /wp-admin/",
        "Allow: /wp-admin/admin-ajax.php",
        "",
    ]
    details: list[dict] = []

    # 1. Block scrapers/scanners that actually respect robots.txt.
    #    curl/wget/python-requests/Go-http-client ignore robots.txt entirely,
    #    so (robots_token is None) excludes them — they belong only in the
    #    blocking rules.  Bots with a real token get a Disallow: / directive.
    blocked = []
    for name, data in sorted(bots_out.items(), key=lambda x: -x[1]['count']):
        if data['category'] in ('scraper', 'scanner') and not data['legitimate']:
            token = data.get('robots_token')
            if not token:
                continue
            blocked.append((name, data['count']))
            lines.append(f"User-agent: {token}")
            lines.append("Disallow: /")
            lines.append("")

    if blocked:
        details.append({
            'title': 'Blocked scrapers/scanners',
            'items': [f"{n} ({c:,} req)" for n, c in blocked],
        })

    # 2. Crawl-delay for aggressive SEO bots
    crawl_delays = []
    for name, data in sorted(bots_out.items(), key=lambda x: -x[1]['count']):
        if data['category'] == 'seo' and not data['legitimate'] and data['count'] > 50:
            token = data.get('robots_token') or name
            delay = 10 if data['count'] > 500 else 5
            crawl_delays.append((name, data['count'], delay))
            lines.append(f"User-agent: {token}")
            lines.append(f"Crawl-delay: {delay}")
            lines.append("")

    if crawl_delays:
        details.append({
            'title': 'Crawl-delay for SEO tools',
            'items': [f"{n} ({c:,} req) -> delay {d}s" for n, c, d in crawl_delays],
        })

    # 3. Disallow top 404 URLs (possible junk crawling).
    #    Root/single-segment paths are filtered out — suggesting
    #    "Disallow: /" in an SEO tool is unacceptable.
    if isinstance(not_found_urls, Counter):
        noisy_404 = not_found_urls.most_common(10)
    else:
        noisy_404 = sorted(not_found_urls.items(), key=lambda x: -x[1])[:10]
    noisy_404 = [(url, cnt) for url, cnt in noisy_404 if cnt >= 5 and _is_disallow_safe(url)]

    if noisy_404:
        lines.append("# Frequently crawled 404 paths - consider Disallow:")
        for url, cnt in noisy_404:
            lines.append(f"# Disallow: {url}  ({cnt} hits)")
        lines.append("")
        details.append({
            'title': 'Suggested Disallow (top 404 paths)',
            'items': [f"{url} ({cnt} hits)" for url, cnt in noisy_404],
        })

    # 4. Sitemap
    lines.append(f"Sitemap: https://{domain}/sitemap.xml")

    return {
        'content': '\n'.join(lines),
        'details': details,
    }
