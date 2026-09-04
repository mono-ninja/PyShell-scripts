"""Markdown and JSON report writers (the HTML report lives in report_html)."""
import json
import os
from collections import Counter
from datetime import datetime

from src.events import get_output_dir, logger
from src.hardening import WP_DISPLAY_VECTORS
from src.result import (AnalysisResult, build_geo_recommendation,
                        build_hardening_plan, build_sensitive_hits)

def event_to_serializable(event: dict) -> dict:
    e = dict(event)
    if isinstance(e.get('time'), datetime):
        e['time'] = e['time'].isoformat()
    return e

def save_report_json(result: AnalysisResult):
    cfg = result.cfg
    output_path = os.path.join(get_output_dir(cfg), "report.json")
    data = {
        'generated_at': datetime.now().isoformat(),
        'config': {
            'logs_dir': cfg.logs_dir,
            'bruteforce_threshold': cfg.bruteforce_threshold,
            'time_window_minutes': cfg.time_window_minutes,
            'rate_limit_threshold': cfg.rate_limit_threshold,
        },
        'summary': {
            'total_lines': result.total_lines,
            'unique_attacker_ips': len(result.ips),
            'bruteforce_ips': len(result.bruteforce_ips),
            'wp_login_bruteforce_ips': len(result.wp_login_bruteforce_ips),
            'xmlrpc_bruteforce_ips': len(result.xmlrpc_bruteforce_ips),
            'notfound_flood_ips': len(result.notfound_flood_ips),
            'wp_cron_flood_ips': len(result.wp_cron_flood_ips),
            'attack_chains': len(result.attack_chains),
            'attack_bursts': len(result.attack_bursts),
            'compromised_accounts': len(result.compromised_ips),
            'successful_attacks': len(result.successful_attacks),
            'server_errors': len(result.server_error_attacks),
            'large_responses': len(result.large_responses),
        },
        'attack_stats': dict(result.stats),
        'top_ips': [(ip, result.ips.get(ip, 0)) for ip, _ in result.ip_hostility.most_common(20)],
        'top_ip_paths': {
            ip: [[path, hits] for path, hits in paths]
            for ip, paths in result.ip_top_paths.items()
        },
        'top_endpoints': result.endpoints.most_common(20),
        'geoip': dict(result.country_stats),
        'proxy_types': dict(result.proxy_types),
        'bruteforce_ips': sorted(result.bruteforce_ips)[:50],
        'bruteforce_ips_truncated': len(result.bruteforce_ips) > 50,
        'rate_limit_ips': sorted(result.rate_ips)[:50],
        'rate_limit_ips_truncated': len(result.rate_ips) > 50,
        'compromised_ips': {ip: [t.isoformat() for t in times] for ip, times in result.compromised_ips.items()},
        'attack_chains': dict(sorted(result.attack_chains.items(), key=lambda x: len(x[1]), reverse=True)[:50]),
        'attack_chains_truncated': len(result.attack_chains) > 50,
        'successful_attacks': [event_to_serializable(e) for e in result.successful_attacks[:50]],
        'server_error_attacks': [event_to_serializable(e) for e in result.server_error_attacks[:50]],
        'large_responses': [event_to_serializable(e) for e in result.large_responses[:50]],
        'ip_response_distribution': result.ip_resp_dist,
    }

    if result.hourly_requests:
        timeline = []
        all_keys = sorted(set(result.hourly_requests) | set(result.hourly_attacks or {}) | set(result.hourly_4xx or {}) | set(result.hourly_5xx or {}))
        for key in all_keys:
            date_str, hour = key
            timeline.append({
                'date': date_str,
                'hour': hour,
                'requests': result.hourly_requests.get(key, 0),
                'attacks': result.hourly_attacks.get(key, 0) if result.hourly_attacks else 0,
                '4xx': result.hourly_4xx.get(key, 0) if result.hourly_4xx else 0,
                '5xx': result.hourly_5xx.get(key, 0) if result.hourly_5xx else 0,
            })
        data['timeline'] = timeline

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("JSON report saved to %s", output_path)
    return output_path

def save_report_md(result: AnalysisResult):
    cfg = result.cfg
    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = []

    lines.append("# NinjaLog Security Report")
    lines.append(f"Generated: {generated_at}")
    lines.append(f"Log files analysed: {len(result.log_files)}")
    lines.append("")

    wp_success = sum(1 for e in result.wp_events if e['is_success'])
    lines.append("## Summary")
    lines.append(f"- Total log lines processed: {result.total_lines:,}")
    lines.append(f"- Unique attacker IPs: {len(result.ips):,}")
    lines.append(f"- Brute force IPs (windowed, 401-based): {len(result.bruteforce_ips)}")
    lines.append(f"- WP Login POST brute force IPs: {len(result.wp_login_bruteforce_ips)}")
    lines.append(f"- XML-RPC brute force IPs: {len(result.xmlrpc_bruteforce_ips)}")
    lines.append(f"- 404 Flood / Scanner IPs: {len(result.notfound_flood_ips)}")
    lines.append(f"- WP Cron Flood IPs: {len(result.wp_cron_flood_ips)}")
    lines.append(f"- Coordinated attack chain IPs: {len(result.attack_chains)}")
    lines.append(f"- Attack burst hours: {len(result.attack_bursts)}")
    lines.append(f"- Vulnerable endpoints (attack->500): {len(result.server_error_attacks)}")
    lines.append(f"- Rate limit exceeded IPs: {len(result.rate_ips)}")
    lines.append(f"- WP hseo attempts: {len(result.wp_events)}")
    lines.append(f"- Successful WP hseo actions: {wp_success}")
    lines.append(f"- Other successful attacks (deduplicated): {len(result.successful_attacks)}")
    lines.append(f"- Possible data exfiltration events: {len(result.large_responses)}")
    lines.append(f"- Compromised accounts (brute force + 302): {len(result.compromised_ips)}")
    lines.append("")

    if result.compromised_ips:
        lines.append("## CRITICAL: Compromised Accounts (Brute Force -> Successful Login)")
        for ip, times in sorted(result.compromised_ips.items()):
            first = times[0].strftime('%Y-%m-%d %H:%M') if times else 'N/A'
            lines.append(f"- {ip}: {len(times)} successful login(s), first at {first}")
        lines.append("")

    # --- Sensitive files under attack ---
    sensitive_rows = build_sensitive_hits(result)
    if sensitive_rows:
        lines.append("## Sensitive Files Under Attack")
        lines.append("| File / Path | Attack Type | Total Hits | Successful |")
        lines.append("|-------------|-------------|:----------:|:----------:|")
        for r in sensitive_rows[:30]:
            flag = " ⚠" if r['success'] > 0 else ""
            lines.append(f"| `{r['path'][:80]}` | {r['type']} | {r['total']:,} | {r['success']:,}{flag} |")
        lines.append("")

    # --- Server hardening plan ---
    hardening = build_hardening_plan(result)
    if hardening:
        lines.append("## Server Hardening Plan")
        lines.append("Ordered by severity. Apply the fixes below to close the detected attack vectors.")
        lines.append("")
        for h in hardening:
            badge = f"[{h['priority']}]"
            lines.append(f"### {badge} {h['type']}")
            lines.append(f"> **Risk:** {h['risk']}")
            lines.append(f"> **Hits:** {h['total']:,} total — {h['success']:,} successful")
            lines.append("")
            if h['nginx']:
                lines.append("**Nginx:**")
                lines.append("```nginx")
                lines.append(h['nginx'])
                lines.append("```")
                lines.append("")
            if h['apache']:
                lines.append("**Apache:**")
                lines.append("```apache")
                lines.append(h['apache'])
                lines.append("```")
                lines.append("")
            if h['extra']:
                lines.append(f"**Note:** {h['extra']}")
                lines.append("")
            lines.append("---")
            lines.append("")

    if result.attack_bursts:
        lines.append("## Attack Burst Hours (anomalies)")
        for (date_str, hour), count in sorted(result.attack_bursts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- {date_str} {hour:02d}:00 — {count:,} attacks")
        lines.append("")

    if result.hourly_requests:
        all_keys = sorted(set(result.hourly_requests) | set(result.hourly_attacks) | set(result.hourly_4xx) | set(result.hourly_5xx))
        if all_keys:
            lines.append("## Hourly Attack Timeline")
            lines.append("| Date       | Hour  | Requests | Attacks | 4xx | 5xx |")
            lines.append("|------------|-------|----------|---------|-----|-----|")
            for key in all_keys:
                date_str, hour = key
                req = result.hourly_requests.get(key, 0)
                atk = result.hourly_attacks.get(key, 0)
                e4 = result.hourly_4xx.get(key, 0)
                e5 = result.hourly_5xx.get(key, 0)
                lines.append(f"| {date_str} | {hour:02d}:00 | {req:>8,} | {atk:>7,} | {e4:>3,} | {e5:>3,} |")
            lines.append("")

    if result.ip_resp_dist:
        lines.append("## Top Attacker IPs -- Response Distribution")
        lines.append("| IP Address | Total | 2xx | 4xx | 5xx | Succ% |")
        lines.append("|------------|-------|-----|-----|-----|-------|")
        for ip, d in list(result.ip_resp_dist.items())[:15]:
            total = d['total'] or 1
            pct = f"{100 * d['2xx'] / total:.1f}%"
            lines.append(f"| {ip} | {d['total']:,} | {d['2xx']:,} | {d['4xx']:,} | {d['5xx']:,} | {pct} |")
        lines.append("")

    lines.append("## Attack Breakdown")
    for cat, count in sorted(result.stats.items()):
        if count > 0:
            lines.append(f"- {cat}: {count:,}")
    lines.append("")

    if result.ips:
        lines.append("## Top 15 Attacker IPs")
        for ip, _ in result.ip_hostility.most_common(15):
            lines.append(f"- {ip}: {result.ips.get(ip, 0):,} events")
        lines.append("")

    if result.ip_top_paths:
        lines.append("## Top Attacker IPs — Most Requested Paths")
        lines.append("| IP | Attacks | Path | Hits |")
        lines.append("|----|---------|------|------|")
        for ip, top_paths in result.ip_top_paths.items():
            attacks = result.ips.get(ip, 0)
            for i, (path, hits) in enumerate(top_paths):
                ip_cell = ip if i == 0 else ""
                atk_cell = f"{attacks:,}" if i == 0 else ""
                lines.append(f"| {ip_cell} | {atk_cell} | {path[:100]} | {hits:,} |")
        lines.append("")

    if result.bruteforce_ips:
        n_bf = len(result.bruteforce_ips)
        lines.append(f"## Brute Force IPs ({cfg.time_window_minutes}-min window) — {n_bf:,} total")
        for ip in sorted(result.bruteforce_ips)[:20]:
            lines.append(f"- {ip}")
        if n_bf > 20:
            lines.append(f"- *... and {n_bf - 20:,} more*")
        lines.append("")

    if result.rate_ips:
        n_rate = len(result.rate_ips)
        lines.append(f"## Rate Limit Exceeded IPs (>{cfg.rate_limit_threshold} req/{cfg.time_window_minutes}min) — {n_rate:,} total")
        for ip in sorted(result.rate_ips)[:20]:
            lines.append(f"- {ip}")
        if n_rate > 20:
            lines.append(f"- *... and {n_rate - 20:,} more*")
        lines.append("")

    if result.country_stats:
        total_geo = sum(result.country_stats.values())
        lines.append("## Attacker Geography")
        for country, count in result.country_stats.most_common():
            lines.append(f"- {country}: {count} ({100*count/total_geo:.0f}%)")
        lines.append("")

        if result.proxy_types:
            lines.append("## Proxy/VPN/Hosting Detection")
            for ptype, count in result.proxy_types.most_common():
                lines.append(f"- {ptype}: {count} IPs")
            lines.append("")

        geo_rec = build_geo_recommendation(result)
        if geo_rec:
            lines.append("## Geo-Blocking Recommendation")
            lines.append(f"Top attack sources: {geo_rec['candidates_str']} -- combined {geo_rec['combined_pct']}% of attack traffic.")
            lines.append(f"*(Based on {geo_rec['sample_size']} highest-volume attacker IPs out of {geo_rec['total_attackers']:,} total — weight by request volume, not IP count.)*")
            lines.append("Consider blocking these countries in your firewall or CDN:")
            lines.append("- **Cloudflare:** Security -> WAF -> Tools -> IP Access Rules")
            lines.append("- **Nginx:** `ngx_http_geoip_module` + `geoip_country` directive")
            lines.append("- **Apache:** `mod_geoip` or `mod_maxminddb`")
            lines.append("")

    if result.endpoints:
        lines.append("## Top 10 Attacked Endpoints")
        for path, count in result.endpoints.most_common(10):
            lines.append(f"- {path}: {count:,}")
        lines.append("")

    if result.notfound_flood_ips:
        n_nf = len(result.notfound_flood_ips)
        lines.append(f"## 404 Flood / Directory Scanner IPs (>{cfg.notfound_flood_threshold} 404s/{cfg.time_window_minutes}min) — {n_nf:,} total")
        for ip in sorted(result.notfound_flood_ips)[:20]:
            lines.append(f"- {ip}")
        if n_nf > 20:
            lines.append(f"- *... and {n_nf - 20:,} more*")
        lines.append("")

    if result.wp_cron_flood_ips:
        n_wc = len(result.wp_cron_flood_ips)
        lines.append(f"## WP Cron Flood / DoS IPs (>{cfg.wp_cron_flood_threshold} hits/{cfg.time_window_minutes}min) — {n_wc:,} total")
        for ip in sorted(result.wp_cron_flood_ips)[:20]:
            lines.append(f"- {ip}")
        if n_wc > 20:
            lines.append(f"- *... and {n_wc - 20:,} more*")
        lines.append("")

    if result.attack_chains:
        n_chains = len(result.attack_chains)
        sorted_chains = sorted(result.attack_chains.items(), key=lambda x: len(x[1]), reverse=True)
        vec_dist = Counter(len(types) for _, types in sorted_chains)
        lines.append(f"## Coordinated Attack Chains (>= {cfg.attack_chain_min_vectors} WP vectors) — {n_chains:,} IPs")
        lines.append("**Distribution:** " + ", ".join(f"{v} vectors: {c} IPs" for v, c in sorted(vec_dist.items(), reverse=True)) + "\n")
        for ip, types in sorted_chains[:20]:
            lines.append(f"- {ip} ({len(types)} vectors): {', '.join(types)}")
        if n_chains > 20:
            lines.append(f"- *... and {n_chains - 20:,} more*")
        lines.append("")

    if result.server_error_attacks:
        lines.append("## Vulnerable Endpoints (Attack -> HTTP 500)")
        for e in result.server_error_attacks[:20]:
            lines.append(f"- {e['ip']} | {e['type']} | {e['path'][:80]}")
        lines.append("")

    if result.wp_login_bruteforce_ips:
        n_wl = len(result.wp_login_bruteforce_ips)
        lines.append(f"## WP Login POST Brute Force / Credential Stuffing (>{cfg.wp_login_post_threshold} POST/{cfg.time_window_minutes}min) — {n_wl:,} total")
        for ip in sorted(result.wp_login_bruteforce_ips)[:20]:
            lines.append(f"- {ip}")
        if n_wl > 20:
            lines.append(f"- *... and {n_wl - 20:,} more*")
        lines.append("")

    if result.xmlrpc_bruteforce_ips:
        n_xml = len(result.xmlrpc_bruteforce_ips)
        lines.append(f"## XML-RPC Brute Force (>{cfg.bruteforce_threshold} POST/{cfg.time_window_minutes}min) — {n_xml:,} total")
        for ip in sorted(result.xmlrpc_bruteforce_ips)[:20]:
            lines.append(f"- {ip}")
        if n_xml > 20:
            lines.append(f"- *... and {n_xml - 20:,} more*")
        lines.append("")

    if result.attack_vector_urls:
        wp_url_data = [(v, result.attack_vector_urls[v]) for v in WP_DISPLAY_VECTORS if v in result.attack_vector_urls]
        if wp_url_data:
            lines.append("## WordPress Attack Vector URLs")
            for vector, url_counter in sorted(wp_url_data, key=lambda x: sum(x[1].values()), reverse=True):
                total = sum(url_counter.values())
                lines.append(f"### {vector} ({total:,} hits)")
                for url, hits in Counter(url_counter).most_common(5):
                    lines.append(f"- {url[:100]}: {hits:,}")
            lines.append("")

    if result.wp_events:
        lines.append("## WordPress 'hseo' Plugin Activity")
        wp_events_sorted = sorted(result.wp_events, key=lambda x: x['time'] if x['time'] else datetime.min)
        for e in wp_events_sorted:
            t = e['time'].strftime('%Y-%m-%d %H:%M') if e['time'] else 'N/A'
            res = "SUCCESS" if e['is_success'] else "Blocked"
            lines.append(f"- [{t}] {e['ip']} | {e['type']} | HTTP {e['status']} | {res}")
        lines.append("")

    if result.successful_attacks:
        lines.append("## Successful Attacks (Critical)")
        for e in result.successful_attacks[:20]:
            # (L4) Surface the matched UA — the corroborating detail when
            # triaging a "Known Scanner" / "Suspicious Bot" classification.
            ua = f" | UA: {e['ua'][:60]}" if e.get('ua') else ""
            lines.append(f"- {e['ip']} | {e['type']} | {e['path'][:80]} | HTTP {e['status']}{ua}")
        lines.append("")

    if result.large_responses:
        lines.append("## Possible Data Exfiltration (attack + large response)")
        for e in sorted(result.large_responses, key=lambda x: x['response_size'], reverse=True)[:10]:
            lines.append(f"- {e['ip']} | {e['type']} | {e['path'][:80]} | {e['response_size']:,} bytes")
        lines.append("")

    lines.append("---")
    lines.append("Paste this report into an AI assistant and ask:")
    lines.append("> Analyse this security log report. Identify the most critical threats,")
    lines.append("> explain what each attack type means, assess whether any breaches occurred,")
    lines.append("> and provide prioritised remediation recommendations.")

    report_path = os.path.join(get_output_dir(cfg), "report.md")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    logger.info("Markdown report saved to %s", report_path)
    return report_path
