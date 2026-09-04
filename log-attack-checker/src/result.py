"""AnalysisResult model, verdict logic and PyShell summary builders."""
from collections import Counter
from dataclasses import dataclass, field

from src.config import Config
from src.hardening import CURL_MAP, HARDENING_MAP, SENSITIVE_VECTORS


@dataclass
class AnalysisResult:
    cfg: Config = None
    stats: Counter = field(default_factory=Counter)
    ips: Counter = field(default_factory=Counter)
    ip_hostility: Counter = field(default_factory=Counter)
    endpoints: Counter = field(default_factory=Counter)
    total_lines: int = 0
    log_files: list = field(default_factory=list)
    country_stats: Counter = field(default_factory=Counter)
    proxy_types: Counter = field(default_factory=Counter)
    ip_countries: dict = field(default_factory=dict)
    successful_attacks: list = field(default_factory=list)
    wp_events: list = field(default_factory=list)
    large_responses: list = field(default_factory=list)
    server_error_attacks: list = field(default_factory=list)
    bruteforce_ips: set = field(default_factory=set)
    rate_ips: set = field(default_factory=set)
    wp_login_bruteforce_ips: set = field(default_factory=set)
    xmlrpc_bruteforce_ips: set = field(default_factory=set)
    notfound_flood_ips: set = field(default_factory=set)
    wp_cron_flood_ips: set = field(default_factory=set)
    attack_chains: dict = field(default_factory=dict)
    attack_bursts: dict = field(default_factory=dict)
    compromised_ips: dict = field(default_factory=dict)
    ip_resp_dist: dict = field(default_factory=dict)
    ip_top_paths: dict = field(default_factory=dict)
    attack_vector_urls: dict = field(default_factory=dict)
    hourly_requests: Counter = field(default_factory=Counter)
    hourly_attacks: Counter = field(default_factory=Counter)
    hourly_4xx: Counter = field(default_factory=Counter)
    hourly_5xx: Counter = field(default_factory=Counter)

def build_sensitive_hits(result) -> list:
    """Return rows of sensitive file hits sorted by success desc, total hits desc."""
    success_by = Counter((e['path'], e['type']) for e in result.successful_attacks)
    rows = []
    for vtype in SENSITIVE_VECTORS:
        url_counter = result.attack_vector_urls.get(vtype)
        if not url_counter:
            continue
        for path, total in url_counter.most_common(8):
            rows.append({
                'path': path,
                'type': vtype,
                'total': total,
                'success': success_by.get((path, vtype), 0),
            })
    rows.sort(key=lambda x: (-x['success'], -x['total']))
    return rows


def build_hardening_plan(result) -> list:
    """Return per-attack-type hardening entries for attacks that actually occurred."""
    priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    plan = []
    for vtype, info in HARDENING_MAP.items():
        total = sum(c for k, c in result.stats.items() if k.startswith(vtype + ' ('))
        if total == 0:
            continue
        success = sum(c for k, c in result.stats.items() if k.startswith(vtype + ' (') and 'SUCCESS' in k)
        plan.append({
            'type': vtype,
            'priority': info['priority'],
            'risk': info['risk'],
            'total': total,
            'success': success,
            'nginx': info.get('nginx', ''),
            'apache': info.get('apache', ''),
            'curl': CURL_MAP.get(vtype, ''),
            'extra': info.get('extra', ''),
        })
    plan.sort(key=lambda x: (priority_order.get(x['priority'], 99), -x['success'], -x['total']))
    return plan


def build_geo_recommendation(result) -> dict:
    """Single source of truth for the geo-blocking recommendation (C7 + R4).

    Countries are weighted by *request volume* (sum of attack events per IP),
    not bare IP count, so a country with one high-volume scanner outranks one
    with many low-volume visitors.  The panel reports its sample size and is
    suppressed entirely when fewer than ``GEO_MIN_SAMPLE`` IPs were looked up —
    extrapolating a country share from ≤20 IPs out of 30,000 is misleading.

    Returns ``None`` when no recommendation should be shown.
    """
    GEO_MIN_SAMPLE = 10
    if not result.country_stats or not result.ip_countries:
        return None
    sample_size = len(result.ip_countries)
    if sample_size < GEO_MIN_SAMPLE:
        return None

    # Weight countries by request volume (attack events per IP)
    country_volume = Counter()
    for ip, country in result.ip_countries.items():
        country_volume[country] += result.ips.get(ip, 1)
    total_volume = sum(country_volume.values()) or 1

    candidates = [
        (c, v) for c, v in country_volume.most_common()
        if 100 * v / total_volume >= 10
    ]
    if not candidates:
        return None
    combined_pct = round(sum(v for _, v in candidates) * 100 / total_volume)
    return {
        'candidates': candidates,
        'combined_pct': combined_pct,
        'sample_size': sample_size,
        'total_attackers': len(result.ips),
        'candidates_str': ", ".join(f"{c} ({100*v/total_volume:.0f}%)" for c, v in candidates),
    }


def compute_verdict(result) -> tuple:
    """Single source of truth for the severity verdict. Returns (level, text)."""
    wp_success = sum(1 for e in result.wp_events if e['is_success'])
    webshell_hits = [e for e in result.successful_attacks if e['type'] == 'WP Webshell Upload']
    n_compromised = len(result.compromised_ips)
    n_server_errors = len(result.server_error_attacks)
    n_chains = len(result.attack_chains)
    if n_compromised:
        return 'critical', f'CRITICAL — {n_compromised} Account(s) Compromised'
    if webshell_hits:
        return 'critical', 'CRITICAL — Webshell Execution in Uploads Directory'
    if wp_success:
        return 'critical', f'CRITICAL — {wp_success} Successful hseo Plugin Action(s)'
    if result.large_responses:
        return 'high', f'HIGH — {len(result.large_responses)} Possible Data Exfiltration Event(s)'
    if result.successful_attacks:
        return 'high', f'HIGH — {len(result.successful_attacks)} Successful Attack(s) Detected'
    if n_server_errors:
        return 'high', f'HIGH — {n_server_errors} Vulnerable Endpoint(s) (HTTP 500)'
    if n_chains:
        return 'medium', f'MEDIUM — {n_chains} Coordinated Attack Chain(s)'
    if result.bruteforce_ips or result.wp_login_bruteforce_ips:
        return 'medium', 'MEDIUM — Active Brute Force Detected'
    return 'low', 'STABLE — All Detected Attacks Were Blocked'


def build_summary_table(result) -> dict:
    """One-shot summary table for the PyShell Results tab (replaces, not appends)."""
    rows = [
        ["Lines processed", f"{result.total_lines:,}"],
        ["Attacker IPs", f"{len(result.ips):,}"],
        ["Successful attacks", str(len(result.successful_attacks))],
        ["Compromised accounts", str(len(result.compromised_ips))],
        ["Attack chains", str(len(result.attack_chains))],
        ["Exfiltration events", str(len(result.large_responses))],
        ["Vulnerable endpoints (500)", str(len(result.server_error_attacks))],
        ["Brute force IPs", str(len(result.bruteforce_ips))],
        ["Rate limit IPs", str(len(result.rate_ips))],
        ["Log files", str(len(result.log_files))],
    ]
    return {"type": "table", "columns": ["Metric", "Value"], "rows": rows}


def build_timeline_chart(result) -> dict:
    """Hourly requests vs attacks bar chart, windowed to the last 48 hours."""
    if not result.hourly_requests:
        return None
    all_keys = sorted(set(result.hourly_requests) | set(result.hourly_attacks))
    keys = all_keys[-48:]
    labels = [f"{date[5:]} {hour:02d}:00" for date, hour in keys]
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": "Hourly requests vs attacks",
        "labels": labels,
        "series": [
            {"name": "Requests", "values": [result.hourly_requests.get(k, 0) for k in keys]},
            {"name": "Attacks", "values": [result.hourly_attacks.get(k, 0) for k in keys]},
        ],
    }


def build_summary_markdown(result) -> str:
    """Final markdown result for the PyShell Results tab."""
    _, text = compute_verdict(result)
    lines = ["## NinjaLog Verdict", "", f"**{text}**", "", "| Metric | Value |", "| --- | --- |"]
    lines += [
        f"| Lines processed | {result.total_lines:,} |",
        f"| Unique attacker IPs | {len(result.ips):,} |",
        f"| Successful attacks | {len(result.successful_attacks)} |",
        f"| Compromised accounts | {len(result.compromised_ips)} |",
        f"| Attack chains | {len(result.attack_chains)} |",
        f"| Data exfiltration events | {len(result.large_responses)} |",
        f"| Vulnerable endpoints (500) | {len(result.server_error_attacks)} |",
        f"| Brute force IPs | {len(result.bruteforce_ips)} |",
        "",
    ]
    if result.compromised_ips:
        lines.append("### Compromised Accounts")
        for ip, times in sorted(result.compromised_ips.items())[:10]:
            first = times[0].strftime('%Y-%m-%d %H:%M') if times else 'N/A'
            lines.append(f"- `{ip}` — {len(times)} successful login(s), first at {first}")
        lines.append("")
    if result.successful_attacks:
        lines.append("### Top Successful Attacks")
        for e in result.successful_attacks[:10]:
            lines.append(f"- `{e['ip']}` — {e['type']} — `{e['path'][:60]}` (HTTP {e['status']})")
        lines.append("")
    if result.ips:
        lines.append("### Top Attacker IPs")
        for ip, _ in result.ip_hostility.most_common(10):
            lines.append(f"- `{ip}` — {result.ips.get(ip, 0):,} events")
        lines.append("")
    lines.append("Full details in the `report.html`, `report.md` and `report.json` artifacts.")
    return "\n".join(lines)
