"""Log analysis orchestration — parse, classify, aggregate.

The analyzer reads all log files in a single pass, aggregating per-bot
statistics, status-code distributions, hourly activity, and per-IP behavioural
profiles.  After the pass it runs the behavioural detectors (disguised bots,
suspicious subnets) and the Google rate-limit analysis.

A ``progress_callback(pct, message)`` can be supplied for UI updates; it
receives percentages in the 0-85 range (parsing 0-80, detection 80-85).
"""

import logging
from collections import Counter, defaultdict
from datetime import timezone
from pathlib import Path

from src.classifier import (
    classify_ua,
    is_browser_ua,
    reclassify_wp_cron_bots,
    detect_disguised_bots,
    analyze_suspicious_subnets,
    _SCAN_PATH_RE,
)
from src.parser import open_log_file, parse_log_line, classify_skip

logger = logging.getLogger(__name__)

# Pruning threshold for human_ip_profiles (O4: bound memory).  Profiles with
# only 1 request can never reach min_requests=30, so they are safe to drop
# periodically on very large logs.  Kept conservative to avoid losing IPs
# that are still accumulating requests.
_PRUNE_THRESHOLD = 2

# Cap on unique URLs tracked per human IP profile (bounds memory on large
# logs).  Once reached, url_counter stops accepting NEW urls, but the
# `counted` field keeps tracking how many requests were actually sampled.
# detect_disguised_bots() computes unique_ratio against `counted`, NOT the
# full request count — otherwise the ratio decays towards zero as an
# aggressive scraper keeps hammering.
_URL_SAMPLE_CAP = 200


def _prune_single_request_profiles(profiles: dict) -> None:
    """Drop browser-UA IP profiles that cannot reach min_requests=30."""
    to_drop = [ip for ip, p in profiles.items() if p['count'] < _PRUNE_THRESHOLD]
    for ip in to_drop:
        del profiles[ip]


def analyze_logs(
    log_files: list[Path],
    max_lines: int = 0,
    progress_callback=None,
) -> dict:
    """Parse and aggregate all log files.

    Args:
        log_files: list of log file paths (from :func:`src.parser.find_log_files`).
        max_lines: maximum lines to read per file (0 = unlimited).
        progress_callback: optional ``fn(pct: float, message: str)`` for UI.

    Returns:
        Dict with all aggregated statistics, bot profiles, disguised bots,
        suspicious subnets, and Google rate-limit data.
    """
    total_lines = 0
    parsed_lines = 0
    skipped_lines = 0
    skip_reasons: Counter = Counter()       # 'no-match' / 'php-fpm' -> count
    parse_formats: Counter = Counter()      # 'combined' / 'vhost_combined' -> count
    skip_samples: dict = {}                 # reason -> first sample line
    skipped_files: list = []                # paths that raised on read
    total_bytes = 0
    human_requests = 0
    unknown_count = 0
    date_min = date_max = None

    bot_requests = defaultdict(lambda: {
        'count': 0, 'bytes': 0, 'category': '', 'legitimate': True,
        'robots_token': None,
        'status_codes': Counter(), 'top_urls': Counter(), 'ips': set(),
        'hourly': Counter(),
    })
    status_counter = Counter()
    hourly_counter = Counter()
    url_counter = Counter()
    ip_counter = Counter()
    redirect_counter = Counter()   # url -> count where status == 301
    not_found_counter = Counter()  # url -> count where status == 404

    # Per-IP profiles for browser-UA traffic (disguised bot detection).
    # `counted` = requests actually sampled into url_counter; it stops
    # growing once the unique-URL cap is hit, unlike `count`.
    human_ip_profiles: dict = defaultdict(lambda: {
        'count': 0, 'url_counter': Counter(), 'ua': '', 'scan_count': 0,
        'counted': 0,
    })

    n_files = len(log_files)

    # ── Phase 1: parse + aggregate (0-80%) ──
    for i, log_path in enumerate(log_files):
        if progress_callback:
            pct = (i / n_files) * 80 if n_files else 0
            progress_callback(pct, f"Parsing {log_path.name} ({i + 1}/{n_files})")

        file_lines = 0
        _prune_counter = 0
        try:
            with open_log_file(log_path) as fh:
                for line in fh:
                    if max_lines and file_lines >= max_lines:
                        break
                    total_lines += 1
                    file_lines += 1

                    entry = parse_log_line(line)
                    if not entry:
                        skipped_lines += 1
                        reason = classify_skip(line)
                        skip_reasons[reason] += 1
                        if reason not in skip_samples:
                            skip_samples[reason] = line.strip()[:200]
                        continue

                    parsed_lines += 1
                    parse_formats[entry.get('format', 'combined')] += 1
                    total_bytes += entry['size']
                    status_counter[entry['status']] += 1
                    ip_counter[entry['ip']] += 1
                    url_counter[entry['url']] += 1

                    if entry['status'] == 301:
                        redirect_counter[entry['url']] += 1
                    elif entry['status'] == 404:
                        not_found_counter[entry['url']] += 1

                    hour_str = None
                    if entry['datetime']:
                        # Normalize to UTC before bucketing: logs crossing a
                        # DST transition or collected from servers in
                        # different zones otherwise land in different hour
                        # buckets, skewing max_rph / peak_hours.
                        dt_utc = entry['datetime'].astimezone(timezone.utc)
                        hour_str = dt_utc.strftime('%Y-%m-%d %H:00 UTC')
                        hourly_counter[hour_str] += 1
                        d = dt_utc.date()
                        if date_min is None or d < date_min:
                            date_min = d
                        if date_max is None or d > date_max:
                            date_max = d

                    bot = classify_ua(entry['user_agent'])
                    if bot:
                        name = bot.name
                        bot_requests[name]['count'] += 1
                        bot_requests[name]['bytes'] += entry['size']
                        bot_requests[name]['category'] = bot.category
                        bot_requests[name]['legitimate'] = bot.legitimate
                        bot_requests[name]['robots_token'] = bot.robots_token
                        bot_requests[name]['status_codes'][entry['status']] += 1
                        bot_requests[name]['top_urls'][entry['url']] += 1
                        bot_requests[name]['ips'].add(entry['ip'])
                        if hour_str:
                            bot_requests[name]['hourly'][hour_str] += 1
                    elif entry['user_agent'] and entry['user_agent'] != '-':
                        if is_browser_ua(entry['user_agent']):
                            human_requests += 1
                            p = human_ip_profiles[entry['ip']]
                            p['count'] += 1
                            if len(p['url_counter']) < _URL_SAMPLE_CAP:
                                p['url_counter'][entry['url']] += 1
                                p['counted'] += 1
                            if _SCAN_PATH_RE.search(entry['url']):
                                p['scan_count'] += 1
                            if not p['ua']:
                                p['ua'] = entry['user_agent']
                            # Periodic pruning: IPs with a single request can
                            # never reach min_requests=30, so drop them to bound
                            # memory on large logs.  Runs every 50k lines.
                            _prune_counter += 1
                            if _prune_counter >= 50000:
                                _prune_counter = 0
                                _prune_single_request_profiles(human_ip_profiles)
                        else:
                            unknown_count += 1
                    else:
                        # Blank/absent UA ("-") — characteristic of scripted
                        # clients, not browsers; route to unknown, not human.
                        unknown_count += 1

        except Exception as e:
            logger.warning("Error reading %s: %s", log_path, e)
            skipped_files.append(str(log_path))

    if progress_callback:
        progress_callback(80, "Reclassifying WordPress cron bots")

    # ── Phase 2: finalise bot stats ──
    bots_out = {}
    for name, data in bot_requests.items():
        bots_out[name] = {
            'count':        data['count'],
            'bytes':        data['bytes'],
            'category':     data['category'],
            'legitimate':   data['legitimate'],
            'robots_token': data['robots_token'],
            'status_codes': dict(data['status_codes']),
            'top_urls':     dict(data['top_urls'].most_common(10)),
            'unique_ips':   list(data['ips']),
            'hourly':       dict(sorted(data['hourly'].items())),
        }

    bots_out = reclassify_wp_cron_bots(bots_out)

    # ── Phase 3: behavioural detection (80-85%) ──
    if progress_callback:
        progress_callback(82, "Detecting disguised bots")

    disguised_bots = detect_disguised_bots(human_ip_profiles)
    disguised_bot_requests = sum(d['requests'] for d in disguised_bots)

    # Build set of IPs from LEGITIMATE bots — exclude from subnet analysis
    legit_bot_ips: set = set()
    for data in bots_out.values():
        if data.get('legitimate'):
            legit_bot_ips.update(data['unique_ips'])

    if progress_callback:
        progress_callback(84, "Analyzing suspicious subnets")

    suspicious_subnets = analyze_suspicious_subnets(
        ip_counter, legit_bot_ips=legit_bot_ips,
    )

    # Trim per-bot IP lists to a count + capped sample.  The full list was only
    # needed to build legit_bot_ips above; shipping it bloats the JSON artifact
    # (~20 KB per bot) and no report consumer reads it.
    for data in bots_out.values():
        full_ips = data['unique_ips']
        data['unique_ip_count'] = len(full_ips)
        data['unique_ips'] = sorted(full_ips)[:10]

    if progress_callback:
        progress_callback(85, "Analysis complete")

    return {
        'total_lines':      total_lines,
        'parsed_lines':     parsed_lines,
        'skipped_lines':    skipped_lines,
        'skip_reasons':     dict(skip_reasons),
        'parse_formats':    dict(parse_formats),
        'skip_samples':     skip_samples,
        'skipped_files':    skipped_files,
        'total_bytes':      total_bytes,
        'total_requests':   parsed_lines,
        'human_requests':   human_requests,
        'bot_requests':     sum(d['count'] for d in bots_out.values()),
        'unknown_requests': unknown_count,
        'date_range': {
            'from': str(date_min) if date_min else None,
            'to':   str(date_max) if date_max else None,
        },
        'bots':                bots_out,
        'status_codes':        dict(status_counter),
        'top_urls':            dict(url_counter.most_common(20)),
        'top_ips':             dict(ip_counter.most_common(20)),
        'hourly_activity':     dict(sorted(hourly_counter.items())),
        'top_301_redirects':   dict(redirect_counter.most_common(30)),
        'top_404_urls':        dict(not_found_counter.most_common(20)),
        'disguised_bots':      disguised_bots,
        'disguised_bot_requests': disguised_bot_requests,
        'suspicious_subnets':  suspicious_subnets,
    }


def build_google_rate_limit(bots_out: dict) -> dict:
    """Analyze rate limiting (429 responses) for Google bots."""
    google_bots = ['Googlebot', 'Google Adsense', 'Google AdsBot', 'Google Inspection']
    result = {}
    for name in google_bots:
        if name not in bots_out:
            continue
        data = bots_out[name]
        total = data['count']
        if total == 0:
            continue
        hits_429 = data['status_codes'].get(429, 0)
        hits_503 = data['status_codes'].get(503, 0)
        rate_429 = hits_429 / total * 100

        hourly = data.get('hourly', {})
        peak_hours = sorted(hourly.items(), key=lambda x: -x[1])[:3]
        max_rph = max(hourly.values()) if hourly else 0

        severity = (
            'critical' if rate_429 > 5 else
            'warning' if rate_429 > 1 else
            'ok'
        )
        result[name] = {
            'total_requests': total,
            'hits_429':       hits_429,
            'hits_503':       hits_503,
            'rate_429_pct':   round(rate_429, 2),
            'max_rph':        max_rph,
            'peak_hours':     peak_hours,
            'severity':       severity,
            'recommendation': _rate_limit_recommendation(rate_429, max_rph),
        }
    return result


def _rate_limit_recommendation(rate_429: float, max_rph: int) -> str:
    if rate_429 > 5:
        return (
            f"CRITICAL: {rate_429:.1f}% of requests throttled. "
            "Increase server capacity or add Crawl-delay in robots.txt. "
            "Consider CDN caching for static assets."
        )
    if rate_429 > 1:
        return (
            f"WARNING: {rate_429:.1f}% of requests throttled. "
            "Monitor server load during peak hours. "
            f"Peak load: {max_rph} req/h."
        )
    if max_rph > 500:
        return (
            f"OK: No significant throttling. "
            f"Peak: {max_rph} req/h - watch if server load grows."
        )
    return "OK: No rate limiting issues detected."
