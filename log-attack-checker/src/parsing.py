"""Log parsing: the line matcher, byte-range chunking, the parallel chunk worker.

``process_file_chunk`` runs in Pool workers: it reads the module-level caches
populated by ``init_worker`` (never a ``cfg`` object), so everything a worker
needs must be pickle-serialisable ``Config`` fields.
"""
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from urllib.parse import unquote

from src.config import Config
from src.patterns import (COMBINED_LOG_RE, DATE_PATTERN, SCANNER_UA_DEFINITE,
                          SCANNER_UA_SUSPICIOUS, SUSPICIOUS_METHODS,
                          _LEADING_IP_RE, build_patterns,
                          build_wp_attack_vectors)

def parse_line(line: str, patterns: dict) -> dict:
    results = {
        'attacks': [],
        'ip': 'Unknown',
        'timestamp': None,
        'status': 0,
        'path': 'Unknown',
        'method': 'Unknown',
        'response_size': 0,
        'user_agent': '',
        'referer': '',
        'is_successful': False,
        'is_server_error': False,
    }

    m = COMBINED_LOG_RE.match(line)
    if m:
        results['ip'] = m.group(1)
        ts_str = m.group(2)
        results['method'] = m.group(3)
        results['path'] = m.group(4)
        results['status'] = int(m.group(5))
        size_str = m.group(6)
        results['response_size'] = int(size_str) if size_str and size_str != '-' else 0
        results['referer'] = m.group(7) or ''
        results['user_agent'] = m.group(8) or ''

        date_m = DATE_PATTERN.search(ts_str)
        if date_m:
            try:
                results['timestamp'] = datetime.strptime(date_m.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass

        if 200 <= results['status'] < 400:
            results['is_successful'] = True
        results['is_server_error'] = (results['status'] == 500)
    else:
        # Fallback: try to extract IP from start of line
        ip_match = re.match(r"^(\S+)", line)
        if ip_match:
            results['ip'] = ip_match.group(1)

        req_match = re.search(r'"([A-Z]+)\s+(.*?)\s+HTTP/[^"]*"\s+(\d{3})\s+(\d+|-)', line)
        if req_match:
            results['method'] = req_match.group(1)
            results['path'] = req_match.group(2)
            results['status'] = int(req_match.group(3))
            size_str = req_match.group(4)
            results['response_size'] = int(size_str) if size_str != '-' else 0
            if 200 <= results['status'] < 400:
                results['is_successful'] = True
            results['is_server_error'] = (results['status'] == 500)

        date_match = DATE_PATTERN.search(line)
        if date_match:
            try:
                results['timestamp'] = datetime.strptime(date_match.group(1), "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                pass

    # Match patterns against a narrowed, pre-lowercased haystack of
    # path + referer + user-agent (not the raw line). This excludes the client
    # IP, so IPv6 addresses containing "::1" no longer trigger SSRF, and the
    # case-sensitive lowercase patterns run ~3x faster than IGNORECASE on the
    # full line. Referer/UA are included because real attacks arrive via them.
    haystack = (results['path'] + ' ' + results['referer'] + ' ' + results['user_agent']).lower()
    # (M1) Append one URL-decoded copy when the line carries percent escapes,
    # so single-encoded payloads (`..%2fetc%2fpasswd`, `%24%7Bjndi:...`) reach
    # the literal patterns too. The raw text stays in front — patterns written
    # against encoded forms (`%27`, `%0d%0a`, `%2e%2e`) keep matching — and the
    # '%' guard keeps encoding-free lines at zero extra cost. Double-encoded
    # payloads remain out of scope (WAF/ModSecurity territory).
    if '%' in haystack:
        haystack += ' ' + unquote(haystack, errors='ignore')
    for attack_name, pattern in patterns.items():
        if pattern.search(haystack):
            results['attacks'].append(attack_name)

    if results['method'] in SUSPICIOUS_METHODS:
        results['attacks'].append(f'Suspicious Method ({results["method"]})')

    ua = results['user_agent']
    if ua:
        if SCANNER_UA_DEFINITE.search(ua):
            results['attacks'].append('Known Scanner')
        elif SCANNER_UA_SUSPICIOUS.search(ua):
            results['attacks'].append('Suspicious Bot')

    return results

def get_file_chunks(filepath: str, num_chunks: int) -> list:
    file_size = os.path.getsize(filepath)
    if file_size == 0:
        return [(0, 0)]
    chunk_size = max(file_size // num_chunks, 1)
    chunks = []
    with open(filepath, 'rb') as f:
        start = 0
        for i in range(num_chunks):
            if i == num_chunks - 1 or start >= file_size:
                chunks.append((start, file_size))
                break
            f.seek(min(start + chunk_size, file_size))
            f.readline()
            end = min(f.tell(), file_size)
            chunks.append((start, end))
            start = end
            if start >= file_size:
                break
    return chunks

def process_file_chunk(args: tuple) -> dict:
    filepath, start_byte, end_byte = args
    patterns = PATTERNS_CACHE
    wp_vectors = WP_ATTACK_VECTORS_CACHE
    large_resp_threshold = LARGE_RESP_CACHE
    stats = Counter()
    ips_involved = Counter()
    endpoint_hits = Counter()

    login_timestamps = defaultdict(list)
    ip_minute_counts = defaultdict(Counter)
    wp_login_posts = defaultdict(list)
    xmlrpc_posts = defaultdict(list)
    notfound_timestamps = defaultdict(list)
    wp_cron_timestamps = defaultdict(list)
    attack_vector_urls = defaultdict(Counter)
    ip_wp_attack_types = defaultdict(set)
    ip_paths = defaultdict(Counter)
    hourly_requests = Counter()
    hourly_attacks = Counter()
    hourly_4xx = Counter()
    hourly_5xx = Counter()
    ip_2xx = Counter()
    ip_4xx = Counter()
    ip_5xx = Counter()
    wp_login_success = defaultdict(list)
    wp_login_401 = defaultdict(list)

    successful_attacks = []
    server_error_attacks = []
    all_wp_events = []
    total_lines = 0
    large_response_attacks = []
    chunk_size = end_byte - start_byte

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(start_byte)
        while f.tell() < end_byte:
            line = f.readline()
            if not line:
                break
            total_lines += 1
            # Whitelist short-circuit (P3): extract the leading IP token and
            # skip full parsing for whitelisted addresses — saves ~149 µs/line
            # (44 regexes) for monitoring bots and the server's own IP.
            if WHITELIST_CACHE:
                wl_match = _LEADING_IP_RE.match(line)
                if wl_match and wl_match.group(1) in WHITELIST_CACHE:
                    continue
            data = parse_line(line, patterns)
            ip = data['ip']
            hour_key = None

            if data['timestamp']:
                ip_minute_counts[ip][int(data['timestamp'].timestamp()) // 60] += 1
                hour_key = (data['timestamp'].strftime('%Y-%m-%d'), data['timestamp'].hour)
                hourly_requests[hour_key] += 1
                if data['status'] == 401:
                    login_timestamps[ip].append(data['timestamp'])
                    if 'wp-login.php' in data['path']:
                        wp_login_401[ip].append(data['timestamp'])
                if data['status'] == 404:
                    notfound_timestamps[ip].append(data['timestamp'])
                if 400 <= data['status'] < 500:
                    hourly_4xx[hour_key] += 1
                elif data['status'] == 500:
                    hourly_5xx[hour_key] += 1
                if 'wp-cron.php' in data['path']:
                    wp_cron_timestamps[ip].append(data['timestamp'])
                if data['method'] == 'POST':
                    if 'wp-login.php' in data['path']:
                        wp_login_posts[ip].append(data['timestamp'])
                        if data['status'] == 302:
                            wp_login_success[ip].append(data['timestamp'])
                    if 'xmlrpc.php' in data['path']:
                        xmlrpc_posts[ip].append(data['timestamp'])

            if 200 <= data['status'] < 300:
                ip_2xx[ip] += 1
            elif 400 <= data['status'] < 500:
                ip_4xx[ip] += 1
            elif 500 <= data['status'] < 600:
                ip_5xx[ip] += 1

            endpoint_hits[data['path']] += 1
            ipc = ip_paths[ip]
            ipc[data['path']] += 1
            if len(ipc) > 20:
                top = ipc.most_common(10)
                ip_paths[ip] = Counter(dict(top))

            for attack in data['attacks']:
                if data['is_server_error']:
                    status_label = "Vulnerable"
                elif data['is_successful']:
                    status_label = "SUCCESS"
                else:
                    status_label = "Blocked"
                stats[f"{attack} ({status_label})"] += 1
                ips_involved[ip] += 1
                attack_vector_urls[attack][data['path']] += 1
                if attack in wp_vectors:
                    ip_wp_attack_types[ip].add(attack)
                if data['timestamp'] and hour_key:
                    hourly_attacks[hour_key] += 1

                event = {
                    'ip': ip,
                    'type': attack,
                    'path': data['path'],
                    'status': data['status'],
                    'time': data['timestamp'],
                    'is_success': data['is_successful'],
                    'response_size': data['response_size'],
                    'ua': data['user_agent'],
                }

                # (H1) Route per attack, not per line: a line that trips a
                # `WP hseo *` pattern AND an unrelated one must send only its
                # hseo event to wp_events — the other events still belong in
                # successful_attacks / server_error_attacks, otherwise the
                # verdict, the Sensitive Files "Successful" column and the
                # successful-attacks tables silently lose them.
                if 'WP hseo' in attack:
                    all_wp_events.append(event)
                elif data['is_server_error']:
                    server_error_attacks.append(event)
                elif data['is_successful']:
                    successful_attacks.append(event)

                if data['is_successful'] and data['response_size'] > large_resp_threshold:
                    large_response_attacks.append(event)

    # Trim display-only tail counters before IPC to cut pickling volume (P5).
    # These are never reported as exact totals — only top-N is rendered.
    if len(endpoint_hits) > 200:
        endpoint_hits = Counter(dict(endpoint_hits.most_common(100)))
    for av in attack_vector_urls:
        if len(attack_vector_urls[av]) > 50:
            attack_vector_urls[av] = Counter(dict(attack_vector_urls[av].most_common(25)))

    return {
        'stats': stats,
        'ips_involved': ips_involved,
        'endpoint_hits': endpoint_hits,
        'total_lines': total_lines,
        'login_timestamps': dict(login_timestamps),
        'ip_minute_counts': {ip: dict(c) for ip, c in ip_minute_counts.items()},
        'wp_login_posts': dict(wp_login_posts),
        'xmlrpc_posts': dict(xmlrpc_posts),
        'notfound_timestamps': dict(notfound_timestamps),
        'wp_cron_timestamps': dict(wp_cron_timestamps),
        'wp_login_success': dict(wp_login_success),
        'wp_login_401': dict(wp_login_401),
        'attack_vector_urls': {k: dict(v) for k, v in attack_vector_urls.items()},
        'ip_wp_attack_types': {ip: list(types) for ip, types in ip_wp_attack_types.items()},
        'ip_paths': {ip: dict(counter) for ip, counter in ip_paths.items()},
        'hourly_requests': dict(hourly_requests),
        'hourly_attacks': dict(hourly_attacks),
        'hourly_4xx': dict(hourly_4xx),
        'hourly_5xx': dict(hourly_5xx),
        'ip_2xx': dict(ip_2xx),
        'ip_4xx': dict(ip_4xx),
        'ip_5xx': dict(ip_5xx),
        'successful_attacks': successful_attacks,
        'server_error_attacks': server_error_attacks,
        'wp_events': all_wp_events,
        'large_response_attacks': large_response_attacks,
        'chunk_size': chunk_size,
    }

# Module-level caches for multiprocessing (workers re-import module)
WP_ATTACK_VECTORS_CACHE = set()
LARGE_RESP_CACHE = 100_000
PATTERNS_CACHE = {}
WHITELIST_CACHE = set()


def init_worker(cfg_dict: dict):
    global WP_ATTACK_VECTORS_CACHE, LARGE_RESP_CACHE, PATTERNS_CACHE, WHITELIST_CACHE
    cfg = Config(**cfg_dict)
    PATTERNS_CACHE = build_patterns(cfg)
    WP_ATTACK_VECTORS_CACHE = build_wp_attack_vectors(PATTERNS_CACHE)
    LARGE_RESP_CACHE = cfg.large_response_bytes
    WHITELIST_CACHE = set(cfg.whitelist)
