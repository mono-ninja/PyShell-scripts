"""Analysis orchestration: config → DNS resolve → parallel parse → detect → report."""
import argparse
import os
import re
import socket
from collections import Counter, defaultdict
from dataclasses import asdict
from multiprocessing import Pool, cpu_count

from src.config import Config, parse_whitelist
from src.detectors import (detect_attack_bursts, detect_attack_chains,
                           detect_bruteforce, detect_rate_limiting)
from src.display import display_results
from src.events import ProgressUi, UNDER_PYSHELL, console, emit, logger
from src.geoip import get_geoip
from src.hardening import CHAIN_HOSTILE_VECTORS
from src.parsing import get_file_chunks, init_worker, process_file_chunk
from src.report import save_report_json, save_report_md
from src.report_html import save_report_html
from src.result import (AnalysisResult, build_summary_markdown,
                        build_summary_table, build_timeline_chart)

def analyze_logs(args: argparse.Namespace) -> bool:
    """Run the full analysis. Returns True on success, False on a fatal error
    (missing logs dir / no log files) so the caller can exit non-zero — a plain
    ``return`` would leave the process at exit code 0 and fool CI/cron wrappers.
    """
    cfg = Config(
        logs_dir=args.logs_dir,
        output_dir=args.output_dir,
        site=args.site,
        whitelist=parse_whitelist(args.whitelist),
        bruteforce_threshold=args.bruteforce_threshold,
        wp_login_post_threshold=args.wp_login_post_threshold,
        notfound_flood_threshold=args.notfound_flood_threshold,
        wp_cron_flood_threshold=args.wp_cron_flood_threshold,
        attack_chain_min_vectors=args.attack_chain_min_vectors,
        time_window_minutes=args.time_window_minutes,
        rate_limit_threshold=args.rate_limit_threshold,
        geoip_limit=args.geoip_limit,
        skip_geoip=args.skip_geoip,
        large_response_bytes=args.large_response_bytes,
        attack_burst_factor=args.attack_burst_factor,
    )

    # Auto-resolve site domain → server IP (bounded by a 3s timeout so a
    # hanging resolver cannot stall the whole run before any log is read).
    if cfg.site:
        raw = cfg.site.strip()
        # Strip scheme for DNS lookup
        hostname = re.sub(r'^https?://', '', raw).rstrip('/').split('/')[0]
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(3)
            resolved = socket.gethostbyname(hostname)
            cfg.resolved_ip = resolved
            logger.info("Resolved %s → %s", hostname, resolved)
        except (socket.gaierror, socket.timeout):
            logger.warning("Could not resolve hostname: %s", hostname)
        finally:
            socket.setdefaulttimeout(old_timeout)

    if not os.path.exists(cfg.logs_dir):
        console.print("[danger]Error: logs directory not found![/danger]")
        logger.error("Logs directory not found: %s", cfg.logs_dir)
        return False

    all_entries = os.listdir(cfg.logs_dir)
    log_files = [
        os.path.join(cfg.logs_dir, f)
        for f in all_entries
        if re.search(r'\.log(\.\d+)?$', f)
    ]
    if not log_files:
        # (L3) Distinguish "directory is empty" from "files exist but none
        # match .log / .log.N" (compressed rotations like access.log.2.gz,
        # .old backups) — both used to print the same message, hiding the fix
        # (decompress / rename). Dotfiles and subdirectories are not counted.
        ignored = sorted(
            f for f in all_entries
            if not f.startswith('.') and os.path.isfile(os.path.join(cfg.logs_dir, f))
        )
        hint = ""
        if ignored:
            sample = ", ".join(ignored[:3]) + (", ..." if len(ignored) > 3 else "")
            hint = (f" {len(ignored)} file(s) present but unsupported ({sample}) — "
                    f"expected .log / .log.N; decompress or rename them.")
        console.print(f"[warning]No logs found.{hint}[/warning]")
        logger.warning("No .log files found in %s.%s", cfg.logs_dir, hint)
        return False

    logger.info("Found %d log files", len(log_files))

    total_size = sum(os.path.getsize(f) for f in log_files)
    num_cores = cpu_count()

    all_chunks = []
    for filepath in log_files:
        for start, end in get_file_chunks(filepath, num_cores):
            all_chunks.append((filepath, start, end))

    final_stats = Counter()
    final_ips = Counter()
    final_endpoints = Counter()
    all_success = []
    all_server_errors = []
    all_wp = []
    all_large = []
    merged_login_ts = defaultdict(list)
    merged_ip_minute_counts = defaultdict(Counter)
    merged_wp_login_posts = defaultdict(list)
    merged_xmlrpc_posts = defaultdict(list)
    merged_notfound_ts = defaultdict(list)
    merged_wp_cron_ts = defaultdict(list)
    merged_attack_vector_urls = defaultdict(Counter)
    merged_ip_wp_attack_types = defaultdict(set)
    merged_ip_paths = defaultdict(Counter)
    merged_wp_login_success = defaultdict(list)
    merged_wp_login_failed = defaultdict(list)
    merged_hourly_requests = Counter()
    merged_hourly_attacks = Counter()
    merged_hourly_4xx = Counter()
    merged_hourly_5xx = Counter()
    merged_ip_2xx = Counter()
    merged_ip_4xx = Counter()
    merged_ip_5xx = Counter()
    total_lines = 0
    merge_count = [0]

    cfg_dict = asdict(cfg)

    with ProgressUi(total_size, console, "Ninja Analyzing") as ui:
        with Pool(num_cores, initializer=init_worker, initargs=(cfg_dict,)) as pool:
            for result in pool.imap_unordered(process_file_chunk, all_chunks):
                final_stats.update(result['stats'])
                final_ips.update(result['ips_involved'])
                final_endpoints.update(result['endpoint_hits'])
                total_lines += result['total_lines']
                all_success.extend(result['successful_attacks'])
                all_server_errors.extend(result['server_error_attacks'])
                all_wp.extend(result['wp_events'])
                all_large.extend(result['large_response_attacks'])
                for ip, ts in result['login_timestamps'].items():
                    merged_login_ts[ip].extend(ts)
                for ip, ts in result['wp_login_401'].items():
                    merged_wp_login_failed[ip].extend(ts)
                for ip, mc in result['ip_minute_counts'].items():
                    merged_ip_minute_counts[ip].update(mc)
                for ip, ts in result['wp_login_posts'].items():
                    merged_wp_login_posts[ip].extend(ts)
                for ip, ts in result['xmlrpc_posts'].items():
                    merged_xmlrpc_posts[ip].extend(ts)
                for ip, ts in result['notfound_timestamps'].items():
                    merged_notfound_ts[ip].extend(ts)
                for ip, ts in result['wp_cron_timestamps'].items():
                    merged_wp_cron_ts[ip].extend(ts)
                for attack, url_counts in result['attack_vector_urls'].items():
                    merged_attack_vector_urls[attack].update(url_counts)
                for ip, path_counts in result['ip_paths'].items():
                    merged_ip_paths[ip].update(path_counts)
                for ip, types in result['ip_wp_attack_types'].items():
                    merged_ip_wp_attack_types[ip].update(types)
                for ip, ts in result['wp_login_success'].items():
                    merged_wp_login_success[ip].extend(ts)
                merged_hourly_requests.update(result['hourly_requests'])
                merged_hourly_attacks.update(result['hourly_attacks'])
                merged_hourly_4xx.update(result['hourly_4xx'])
                merged_hourly_5xx.update(result['hourly_5xx'])
                merged_ip_2xx.update(result['ip_2xx'])
                merged_ip_4xx.update(result['ip_4xx'])
                merged_ip_5xx.update(result['ip_5xx'])
                # Trim display-only tail counters periodically to bound memory (P2).
                # Exact totals are never shown for endpoints/URLs — only top-N.
                merge_count[0] += 1
                if merge_count[0] % num_cores == 0:
                    if len(final_endpoints) > 500:
                        final_endpoints = Counter(dict(final_endpoints.most_common(200)))
                    for av in merged_attack_vector_urls:
                        if len(merged_attack_vector_urls[av]) > 200:
                            merged_attack_vector_urls[av] = Counter(dict(merged_attack_vector_urls[av].most_common(100)))
                ui.advance(result['chunk_size'], total_lines)

    emit({"type": "progress", "pct": 76, "message": "Running detectors"})
    logger.info("Parsed %d lines, running detectors...", total_lines)

    all_bruteforce_ips = detect_bruteforce(merged_login_ts, cfg.bruteforce_threshold, cfg.time_window_minutes)
    all_rate_ips = detect_rate_limiting(merged_ip_minute_counts, cfg.rate_limit_threshold, cfg.time_window_minutes)
    wp_login_bruteforce_ips = detect_bruteforce(merged_wp_login_posts, cfg.wp_login_post_threshold, cfg.time_window_minutes)
    xmlrpc_bruteforce_ips = detect_bruteforce(merged_xmlrpc_posts, cfg.bruteforce_threshold, cfg.time_window_minutes)
    notfound_flood_ips = detect_bruteforce(merged_notfound_ts, cfg.notfound_flood_threshold, cfg.time_window_minutes)
    wp_cron_flood_ips = detect_bruteforce(merged_wp_cron_ts, cfg.wp_cron_flood_threshold, cfg.time_window_minutes)
    attack_chains = detect_attack_chains(
        merged_ip_wp_attack_types, cfg.attack_chain_min_vectors,
        CHAIN_HOSTILE_VECTORS, merged_ip_2xx, merged_ip_4xx, merged_ip_5xx,
    )
    attack_bursts = detect_attack_bursts(merged_hourly_attacks, cfg.attack_burst_factor)
    emit({"type": "progress", "pct": 82, "message": "Aggregating results"})

    # Truncate AFTER merge (was truncating per-chunk before)
    MAX_SUCCESS = 200
    MAX_SERVER_ERRORS = 100
    MAX_WP = 300
    MAX_LARGE = 100

    # Deduplicate: keep unique (ip, type, path) for successful attacks
    seen = set()
    deduped_success = []
    for e in all_success:
        key = (e['ip'], e['type'], e['path'])
        if key not in seen:
            seen.add(key)
            deduped_success.append(e)
    deduped_success = deduped_success[:MAX_SUCCESS]

    seen_err = set()
    deduped_server_errors = []
    for e in all_server_errors:
        key = (e['ip'], e['type'], e['path'])
        if key not in seen_err:
            seen_err.add(key)
            deduped_server_errors.append(e)
    deduped_server_errors = deduped_server_errors[:MAX_SERVER_ERRORS]

    all_wp = all_wp[:MAX_WP]
    all_large = all_large[:MAX_LARGE]

    # Compromised accounts: brute force IPs + successful login
    compromised_ips = {
        ip: sorted(merged_wp_login_success[ip])
        for ip in wp_login_bruteforce_ips
        if ip in merged_wp_login_success
    }

    # Extended compromised: any IP with failed login (401) followed by success (302)
    for ip in merged_wp_login_success:
        if ip not in compromised_ips and ip in merged_wp_login_failed:
            failed_times = sorted(merged_wp_login_failed[ip])
            success_times = sorted(merged_wp_login_success[ip])
            if failed_times and success_times and failed_times[0] < success_times[0]:
                compromised_ips[ip] = success_times

    # Hostility-based IP ranking (C4): rank by a score that rewards hostile
    # vectors, error responses and successful attacks, not raw request volume.
    # A monitoring bot with 10k benign 2xx admin-ajax requests scores 0 and
    # drops out of the top list; a scanner with 3k 4xxs and a hostile vector
    # rises to the top. Only *hostile*-vector successes count — a 2xx hit on
    # admin-ajax.php is a normal request, not a breach.
    ip_success_hostile_types = defaultdict(set)
    for e in deduped_success:
        if e['type'] in CHAIN_HOSTILE_VECTORS:
            ip_success_hostile_types[e['ip']].add(e['type'])
    ip_server_error_count = Counter(e['ip'] for e in deduped_server_errors)
    hostility_scores = Counter()
    for ip in final_ips:
        score = 0
        hostile_hits = merged_ip_wp_attack_types.get(ip, set()) & CHAIN_HOSTILE_VECTORS
        score += len(hostile_hits) * 1000
        score += (merged_ip_4xx.get(ip, 0) + merged_ip_5xx.get(ip, 0))
        score += len(ip_success_hostile_types.get(ip, set())) * 500
        score += ip_server_error_count.get(ip, 0) * 200
        if score > 0:
            hostility_scores[ip] = score

    # IP response distribution + top paths for top attacker IPs (ranked by hostility)
    top_attacker_ips = [ip for ip, _ in hostility_scores.most_common(20)]
    ip_top_paths = {
        ip: merged_ip_paths[ip].most_common(3)
        for ip in top_attacker_ips
        if ip in merged_ip_paths
    }
    ip_resp_dist = {
        ip: {
            '2xx': merged_ip_2xx.get(ip, 0),
            '4xx': merged_ip_4xx.get(ip, 0),
            '5xx': merged_ip_5xx.get(ip, 0),
            'total': merged_ip_2xx.get(ip, 0) + merged_ip_4xx.get(ip, 0) + merged_ip_5xx.get(ip, 0),
        }
        for ip in top_attacker_ips
    }

    emit({"type": "progress", "pct": 86, "message": "GeoIP lookups"})
    top_ips = [ip for ip, _ in hostility_scores.most_common(cfg.geoip_limit)]
    country_stats, proxy_types, ip_countries = get_geoip(top_ips, cfg)

    # Convert attack_vector_urls Counter values back
    avu_final = {}
    for attack, url_counter in merged_attack_vector_urls.items():
        avu_final[attack] = Counter(url_counter)

    result = AnalysisResult(
        cfg=cfg,
        stats=final_stats,
        ips=final_ips,
        ip_hostility=hostility_scores,
        endpoints=final_endpoints,
        total_lines=total_lines,
        log_files=log_files,
        country_stats=country_stats,
        proxy_types=proxy_types,
        ip_countries=ip_countries,
        successful_attacks=deduped_success,
        wp_events=all_wp,
        large_responses=all_large,
        server_error_attacks=deduped_server_errors,
        bruteforce_ips=all_bruteforce_ips,
        rate_ips=all_rate_ips,
        wp_login_bruteforce_ips=wp_login_bruteforce_ips,
        xmlrpc_bruteforce_ips=xmlrpc_bruteforce_ips,
        notfound_flood_ips=notfound_flood_ips,
        wp_cron_flood_ips=wp_cron_flood_ips,
        attack_chains=attack_chains,
        attack_bursts=attack_bursts,
        compromised_ips=compromised_ips,
        ip_resp_dist=ip_resp_dist,
        ip_top_paths=ip_top_paths,
        attack_vector_urls=avu_final,
        hourly_requests=merged_hourly_requests,
        hourly_attacks=merged_hourly_attacks,
        hourly_4xx=merged_hourly_4xx,
        hourly_5xx=merged_hourly_5xx,
    )

    emit({"type": "progress", "pct": 94, "message": "Building reports"})

    # Rich terminal tables only make sense in a real terminal; under PyShell the
    # structured events below plus the report artifacts are the output.
    if not UNDER_PYSHELL:
        display_results(result)

    report_path = save_report_md(result)
    json_path = save_report_json(result)
    html_path = save_report_html(result)

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit({"type": "status", "message": f"Done — {result.total_lines:,} lines, {len(result.ips):,} attacker IPs"})
    emit(build_summary_table(result))
    _chart = build_timeline_chart(result)
    if _chart:
        emit(_chart)
    emit({"type": "markdown", "content": build_summary_markdown(result)})

    console.print(f"\n[info]Markdown report -> {report_path}[/info]")
    console.print(f"[info]JSON report    -> {json_path}[/info]")
    console.print(f"[info]HTML report    -> {html_path}[/info]")
    logger.info("Reports saved: %s, %s, %s", report_path, json_path, html_path)
    return True
