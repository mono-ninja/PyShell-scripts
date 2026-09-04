"""Bot classification — UA signatures, disguised-bot detection, subnet analysis.

The classifier works in two layers:

1. **User-Agent matching** — ``classify_ua`` checks the UA string against a
   prioritised list of regex signatures.  Each signature carries a display name,
   a category (search, ads, ai, social, seo, monitor, scraper, scanner) and a
   ``legitimate`` flag.

2. **Behavioural detection** — after the first pass, IPs using browser UAs but
   exhibiting systematic scanning are flagged as *disguised bots*, and /24
   subnets with coordinated activity are identified as *suspicious subnets*.
"""

import ipaddress
import re
from collections import Counter, defaultdict
from functools import lru_cache
from typing import NamedTuple


class BotMatch(NamedTuple):
    """Immutable result of :func:`classify_ua` — safe to share across cache hits."""
    name: str
    category: str
    legitimate: bool
    robots_token: str | None  # real User-agent token for robots.txt, or None


# (regex, display_name, category, legitimate, robots_token, block_pattern)
# Order matters: more specific patterns must come before generic ones
# (e.g. WordPress before curl/wget).  robots_token is the real string a bot
# sends in User-Agent and recognises in robots.txt; None for scrapers that
# ignore robots.txt entirely (curl, wget, python-requests, ...).
# block_pattern is the nginx/Apache UA match pattern used by blocking.py —
# keeping it HERE (not in a parallel list in blocking.py) means a new
# scraper signature automatically ships with its blocking rule.
BOT_SIGNATURES: list[tuple] = [
    (re.compile(r'Googlebot',             re.I), 'Googlebot',          'search',  True,  'Googlebot',             None),
    (re.compile(r'Mediapartners-Google',  re.I), 'Google Adsense',     'ads',     True,  'Mediapartners-Google',  None),
    (re.compile(r'AdsBot-Google',         re.I), 'Google AdsBot',      'ads',     True,  'AdsBot-Google',         None),
    (re.compile(r'Google-InspectionTool', re.I), 'Google Inspection',  'search',  True,  'Google-InspectionTool', None),
    (re.compile(r'bingbot',               re.I), 'Bingbot',            'search',  True,  'bingbot',               None),
    (re.compile(r'msnbot',                re.I), 'MSNBot',             'search',  True,  'msnbot',                None),
    (re.compile(r'adidxbot',              re.I), 'Bing AdIdx',         'ads',     True,  'adidxbot',              None),
    (re.compile(r'Yandex',                re.I), 'Yandexbot',          'search',  True,  'YandexBot',             None),
    (re.compile(r'DuckDuckBot',           re.I), 'DuckDuckBot',        'search',  True,  'DuckDuckBot',           None),
    (re.compile(r'Baiduspider',           re.I), 'Baiduspider',        'search',  True,  'Baiduspider',           None),
    (re.compile(r'Sogou',                 re.I), 'Sogou',              'search',  True,  'Sogou',                 None),
    (re.compile(r'360Spider',             re.I), '360Spider',          'search',  True,  '360Spider',             None),
    (re.compile(r'facebookexternalhit',   re.I), 'Facebook',           'social',  True,  'facebookexternalhit',   None),
    (re.compile(r'Twitterbot',            re.I), 'Twitterbot',         'social',  True,  'Twitterbot',            None),
    (re.compile(r'LinkedInBot',           re.I), 'LinkedInBot',        'social',  True,  'LinkedInBot',           None),
    (re.compile(r'Slackbot',              re.I), 'Slackbot',           'social',  True,  'Slackbot',              None),
    (re.compile(r'TelegramBot',           re.I), 'TelegramBot',        'social',  True,  'TelegramBot',           None),
    (re.compile(r'GPTBot',                re.I), 'GPTBot',             'ai',      True,  'GPTBot',                None),
    (re.compile(r'ChatGPT-User',          re.I), 'ChatGPT-User',       'ai',      True,  'ChatGPT-User',          None),
    (re.compile(r'Claude-Web',            re.I), 'Claude-Web',         'ai',      True,  'Claude-Web',            None),
    (re.compile(r'anthropic-ai',          re.I), 'Anthropic',          'ai',      True,  'anthropic-ai',          None),
    (re.compile(r'PerplexityBot',         re.I), 'PerplexityBot',      'ai',      True,  'PerplexityBot',         None),
    (re.compile(r'cohere-ai',             re.I), 'Cohere',             'ai',      True,  'cohere-ai',             None),
    (re.compile(r'Applebot',              re.I), 'Applebot',           'search',  True,  'Applebot',              None),
    (re.compile(r'SemrushBot',            re.I), 'SemrushBot',         'seo',     False, 'SemrushBot',            None),
    (re.compile(r'AhrefsBot',             re.I), 'AhrefsBot',          'seo',     False, 'AhrefsBot',             None),
    (re.compile(r'MJ12bot',               re.I), 'Majestic',           'seo',     False, 'MJ12bot',               None),
    (re.compile(r'DotBot',                re.I), 'DotBot',             'seo',     False, 'DotBot',                None),
    (re.compile(r'rogerbot',              re.I), 'Moz',                'seo',     False, 'rogerbot',              None),
    (re.compile(r'SiteAuditBot',          re.I), 'SiteAudit',          'seo',     False, 'SiteAuditBot',          None),
    (re.compile(r'Screaming Frog',        re.I), 'Screaming Frog',     'seo',     False, 'Screaming Frog SEO Spider', None),
    (re.compile(r'UptimeRobot',           re.I), 'UptimeRobot',        'monitor', True,  'UptimeRobot',           None),
    (re.compile(r'Pingdom',               re.I), 'Pingdom',            'monitor', True,  'Pingdom',               None),
    (re.compile(r'StatusCake',            re.I), 'StatusCake',         'monitor', True,  'StatusCake',            None),
    (re.compile(r'site24x7',              re.I), 'Site24x7',           'monitor', True,  'Site24x7',              None),
    # WordPress internal/monitoring — must come BEFORE generic curl/wget
    (re.compile(r'WordPress/\d',          re.I), 'WordPress Cron',     'monitor', True,  None,                    None),
    (re.compile(r'WP Cron',               re.I), 'WordPress Cron',     'monitor', True,  None,                    None),
    # Scrapers/scanners below — robots_token is None: they ignore robots.txt,
    # so they belong only in the blocking rules.  block_pattern feeds
    # blocking.py's nginx map / .htaccess RewriteCond rules.
    (re.compile(r'python-requests',       re.I), 'python-requests',    'scraper', False, None,                    'python-requests'),
    (re.compile(r'Go-http-client',        re.I), 'Go HTTP client',     'scraper', False, None,                    'Go-http-client'),
    (re.compile(r'curl/',                 re.I), 'curl',               'scraper', False, None,                    'curl/'),
    (re.compile(r'wget/',                 re.I), 'wget',               'scraper', False, None,                    'wget/'),
    (re.compile(r'libwww-perl',           re.I), 'libwww-perl',        'scraper', False, None,                    'libwww-perl'),
    (re.compile(r'scrapy',                re.I), 'Scrapy',             'scraper', False, None,                    'Scrapy'),
    (re.compile(r'zgrab',                 re.I), 'zgrab',              'scanner', False, None,                    'zgrab'),
    (re.compile(r'masscan',               re.I), 'masscan',            'scanner', False, None,                    'masscan'),
    (re.compile(r'nikto',                 re.I), 'Nikto',              'scanner', False, None,                    'Nikto'),
]

# display_name -> nginx/Apache UA block pattern, derived from BOT_SIGNATURES.
# Single source of truth: adding a scraper signature with a block_pattern
# automatically extends the blocking rules.
SCRAPER_BLOCK_PATTERNS: dict[str, str] = {
    name: block_pattern
    for _regex, name, _category, _legit, _token, block_pattern in BOT_SIGNATURES
    if block_pattern
}

# Browser UA keywords for separating "human" traffic from unknown
_BROWSER_UA_RE = re.compile(r'Mozilla|Chrome|Safari|Firefox|Opera|Edge', re.I)

# Paths that indicate systematic scanning when accessed by browser-UA IPs
SCAN_PATHS = (
    '/authors/', '/plugins/', '/themes/', '/wp-json/',
    '/plugin-tag/', '/plugin-search/', '/wp-authors/',
)

# Single precompiled alternation — one C-level pass replaces up to 7 substring
# scans per browser-UA line.  SCAN_PATHS stays the source of truth.
_SCAN_PATH_RE = re.compile('|'.join(re.escape(p) for p in SCAN_PATHS))


@lru_cache(maxsize=8192)
def classify_ua(ua: str) -> BotMatch | None:
    """Classify a User-Agent string.

    Returns a :class:`BotMatch` (``name``, ``category``, ``legitimate``) or
    ``None`` if no signature matches.  Results are memoized because UA strings
    repeat heavily in real logs (~100× on a typical sample); the returned
    NamedTuple is immutable so callers cannot corrupt the cache.
    """
    if not ua or ua == '-':
        return None
    for pattern, name, category, legitimate, robots_token, _block_pattern in BOT_SIGNATURES:
        if pattern.search(ua):
            return BotMatch(name, category, legitimate, robots_token)
    return None


@lru_cache(maxsize=8192)
def is_browser_ua(ua: str) -> bool:
    """Check whether *ua* looks like a real browser (Mozilla-based)."""
    return bool(ua and ua != '-' and _BROWSER_UA_RE.search(ua))


def reclassify_wp_cron_bots(bots_out: dict) -> dict:
    """Reclassify curl/wget that exclusively access ``/wp-cron.php`` as
    legitimate WordPress cron jobs."""
    for bot_name in ('curl', 'wget'):
        if bot_name not in bots_out:
            continue
        data = bots_out[bot_name]
        if data['top_urls'].get('/wp-cron.php', 0) == data['count']:
            new_name = f'WordPress Cron ({bot_name})'
            bots_out[new_name] = dict(data, category='monitor', legitimate=True)
            del bots_out[bot_name]
    return bots_out


def detect_disguised_bots(
    human_ip_profiles: dict,
    min_requests: int = 30,
    scan_ratio_threshold: float = 0.40,
) -> list[dict]:
    """Detect IPs using browser UAs but exhibiting systematic scanning.

    A human IP is flagged when it has >= *min_requests* AND either:
    - ``scan_ratio`` >= *scan_ratio_threshold* (scanning wp-json, plugins, etc.)
    - ``unique_ratio`` >= 0.70 with >= 50 requests (high URL diversity)

    ``unique_ratio`` is computed against ``counted`` — the requests actually
    sampled into ``url_counter`` — falling back to ``count`` for profiles
    built by older versions.  Using the full ``count`` would dilute the ratio
    towards zero once the unique-URL cap (``_URL_SAMPLE_CAP``) is reached,
    letting the most aggressive scrapers evade detection.
    """
    suspicious: list[dict] = []
    for ip, p in human_ip_profiles.items():
        count = p['count']
        if count < min_requests:
            continue
        scan_ratio = p['scan_count'] / count if count else 0
        unique_urls = len(p['url_counter'])
        denom = p.get('counted') or count
        unique_ratio = unique_urls / denom if denom else 0

        is_scan = scan_ratio >= scan_ratio_threshold
        # Volume gate stays on the full count: the sample must reflect real
        # traffic volume, not the capped sample size.
        is_high_unique = count >= 50 and unique_ratio >= 0.70

        if not (is_scan or is_high_unique):
            continue

        evidence = []
        if is_scan:
            evidence.append(f"{scan_ratio:.0%} requests to scan-type paths")
        if is_high_unique:
            sample_note = f"first {denom:,}" if denom < count else f"{denom:,}"
            evidence.append(
                f"{unique_urls} unique URLs / {sample_note} requests ({unique_ratio:.0%})"
            )

        suspicious.append({
            'ip':           ip,
            'requests':     count,
            'scan_ratio':   round(scan_ratio, 2),
            'unique_urls':  unique_urls,
            'unique_ratio': round(unique_ratio, 2),
            'top_urls':     dict(p['url_counter'].most_common(5)),
            'user_agent':   (p['ua'] or '')[:140],
            'evidence':     '; '.join(evidence),
        })
    suspicious.sort(key=lambda x: -x['requests'])
    return suspicious


def analyze_suspicious_subnets(
    ip_counter: Counter,
    min_ips: int = 3,
    min_total: int = 150,
    legit_bot_ips: set | None = None,
) -> dict:
    """Find subnets with coordinated activity (3+ IPs or high traffic).

    IPv4 addresses are grouped into /24 networks, IPv6 into /64.  Excludes IPs
    already identified as legitimate bots (Googlebot, Bingbot, etc.) so their
    well-known subnets are never flagged.
    """
    legit_bot_ips = legit_bot_ips or set()
    subnet_map: dict = defaultdict(list)
    for ip, count in ip_counter.items():
        if ip in legit_bot_ips:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        prefix = 24 if addr.version == 4 else 64
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        subnet_map[str(net)].append((ip, count))

    result = {}
    for subnet, ip_list in subnet_map.items():
        total = sum(c for _, c in ip_list)
        if len(ip_list) >= min_ips or (len(ip_list) >= 2 and total >= min_total):
            result[subnet] = {
                'unique_ips':     len(ip_list),
                'total_requests': total,
                'ips': [{'ip': ip, 'requests': c}
                        for ip, c in sorted(ip_list, key=lambda x: -x[1])],
            }
    return dict(sorted(result.items(), key=lambda x: -x[1]['total_requests']))
