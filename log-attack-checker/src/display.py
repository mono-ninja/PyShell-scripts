"""Rich terminal output — skipped under PyShell (structured events replace it)."""
from collections import Counter
from datetime import datetime

from rich.panel import Panel
from rich.table import Table

from src.events import console
from src.hardening import WP_DISPLAY_VECTORS
from src.result import (AnalysisResult, build_geo_recommendation,
                        build_hardening_plan, build_sensitive_hits)

def display_results(result: AnalysisResult):
    cfg = result.cfg

    if cfg.site or cfg.whitelist:
        info_parts = []
        if cfg.site:
            info_parts.append(f"[bold cyan]Site:[/bold cyan] {cfg.site}")
            if cfg.resolved_ip:
                in_wl = cfg.resolved_ip in set(cfg.whitelist)
                wl_hint = " [green](whitelisted)[/green]" if in_wl else f" [yellow]— add to whitelist: -w {cfg.resolved_ip}[/yellow]"
                info_parts.append(f"[bold cyan]Server IP:[/bold cyan] {cfg.resolved_ip}{wl_hint}")
        if cfg.whitelist:
            info_parts.append(f"[bold cyan]Whitelist:[/bold cyan] {', '.join(cfg.whitelist)}")
        console.print(Panel("\n".join(info_parts), expand=False))

    # --- Main attack table ---
    table = Table(title="NinjaLog Security Report", header_style="bold magenta")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Status", justify="center")

    for cat, count in sorted(result.stats.items()):
        if count == 0:
            continue
        color = "red" if "SUCCESS" in cat or "Brute" in cat else "yellow"
        table.add_row(f"[{color}]{cat}[/{color}]", f"{count:,}", "[bold]Detected[/bold]")
    console.print(table)

    # --- Sensitive files under attack ---
    sensitive_rows = build_sensitive_hits(result)
    if sensitive_rows:
        sf_table = Table(title="Sensitive Files Under Attack", header_style="bold red", border_style="red")
        sf_table.add_column("File / Path", style="cyan")
        sf_table.add_column("Attack Type", style="yellow")
        sf_table.add_column("Total", justify="right")
        sf_table.add_column("Successful", justify="right", style="bold red")
        for r in sensitive_rows[:25]:
            succ_str = f"[bold red]{r['success']:,}[/bold red]" if r['success'] > 0 else "0"
            sf_table.add_row(r['path'][:70], r['type'], f"{r['total']:,}", succ_str)
        console.print(sf_table)

    # --- Top attacked endpoints ---
    top_endpoints = result.endpoints.most_common(10)
    if top_endpoints:
        ep_table = Table(title="Top 10 Attacked Endpoints", header_style="bold blue")
        ep_table.add_column("Path", style="cyan")
        ep_table.add_column("Hits", justify="right")
        for path, count in top_endpoints:
            ep_table.add_row(path[:80], f"{count:,}")
        console.print(ep_table)

    # --- Top attacker IPs with most requested paths ---
    if result.ip_top_paths:
        itp_table = Table(title="Top Attacker IPs — Most Requested Paths", header_style="bold blue")
        itp_table.add_column("IP Address", style="cyan", min_width=15)
        itp_table.add_column("Attacks", justify="right")
        itp_table.add_column("Top Requested Path", style="yellow")
        itp_table.add_column("Hits", justify="right")
        for ip, top_paths in result.ip_top_paths.items():
            attacks = result.ips.get(ip, 0)
            for i, (path, hits) in enumerate(top_paths):
                itp_table.add_row(
                    ip if i == 0 else "",
                    f"{attacks:,}" if i == 0 else "",
                    path[:70],
                    f"{hits:,}",
                )
        console.print(itp_table)

    # --- GeoIP ---
    if result.country_stats:
        total_geo = sum(result.country_stats.values())
        geo_table = Table(title="Attacker Geography (Top IPs)", header_style="bold blue")
        geo_table.add_column("Country", style="cyan")
        geo_table.add_column("IPs", justify="right")
        geo_table.add_column("%", justify="right")
        for country, count in result.country_stats.most_common():
            geo_table.add_row(country, str(count), f"{100*count/total_geo:.0f}%")
        console.print(geo_table)

        # --- Proxy/VPN/Hosting ---
        if result.proxy_types:
            pt_table = Table(title="Proxy / VPN / Hosting Detection", header_style="bold yellow", border_style="yellow")
            pt_table.add_column("Type", style="cyan")
            pt_table.add_column("IPs", justify="right")
            for ptype, count in result.proxy_types.most_common():
                pt_table.add_row(ptype, str(count))
            console.print(pt_table)

        geo_rec = build_geo_recommendation(result)
        if geo_rec:
            console.print(Panel(
                f"[bold]Top attack sources:[/bold] {geo_rec['candidates_str']}\n"
                f"Consider geo-blocking these countries in your firewall / CDN (Cloudflare, Nginx geo module).\n"
                f"Combined share: [bold red]{geo_rec['combined_pct']}%[/bold red] of attack traffic "
                f"(based on {geo_rec['sample_size']} highest-volume IPs of {geo_rec['total_attackers']:,} total, weighted by request volume).",
                title="Geo-Blocking Recommendation",
                border_style="yellow",
            ))

    # --- Brute force IPs (top 20 + summary) ---
    if result.bruteforce_ips:
        n_bf = len(result.bruteforce_ips)
        top_bf = sorted(result.bruteforce_ips)[:20]
        bf_table = Table(title=f"Brute Force IPs ({cfg.time_window_minutes}-min window) — {n_bf:,} IPs", header_style="bold red", border_style="red")
        bf_table.add_column("IP Address", style="bold")
        for ip in top_bf:
            bf_table.add_row(ip)
        if n_bf > 20:
            bf_table.add_row(f"[dim]... and {n_bf - 20:,} more[/dim]", style="dim")
        console.print(bf_table)

    # --- Rate limit IPs (top 20 + summary) ---
    if result.rate_ips:
        n_rate = len(result.rate_ips)
        top_rate = sorted(result.rate_ips)[:20]
        rl_table = Table(title=f"Rate Limit Exceeded (>{cfg.rate_limit_threshold} req/{cfg.time_window_minutes}min) — {n_rate:,} IPs total", header_style="bold yellow", border_style="yellow")
        rl_table.add_column("IP Address", style="bold")
        for ip in top_rate:
            rl_table.add_row(ip)
        if n_rate > 20:
            rl_table.add_row(f"[dim]... and {n_rate - 20:,} more[/dim]", style="dim")
        console.print(rl_table)

    # --- WP hseo events ---
    if result.wp_events:
        wp_table = Table(title="WordPress 'hseo' Plugin Activity", header_style="bold green", border_style="green")
        wp_table.add_column("Time", style="cyan")
        wp_table.add_column("IP Address", style="bold")
        wp_table.add_column("Action Type", style="warning")
        wp_table.add_column("HTTP", justify="center")
        wp_table.add_column("Result", justify="center")

        sorted_wp = sorted(result.wp_events, key=lambda x: x['time'] if x['time'] else datetime.min)
        for ev in sorted_wp:
            t_str = ev['time'].strftime('%Y-%m-%d %H:%M') if ev['time'] else "N/A"
            res = "[bold red]SUCCESS[/bold red]" if ev['is_success'] else "[yellow]Blocked[/yellow]"
            wp_table.add_row(t_str, ev['ip'], ev['type'], str(ev['status']), res)
        console.print(wp_table)

    # --- Successful attacks ---
    if result.successful_attacks:
        s_table = Table(title="Successful Attack Payloads -- Critical (deduplicated)", header_style="bold red", border_style="red")
        s_table.add_column("IP Address")
        s_table.add_column("Type")
        s_table.add_column("Path")
        s_table.add_column("Resp. Size", justify="right")
        # (L4) The matched UA is the corroborating detail when triaging a
        # "Known Scanner" / "Suspicious Bot" hit — show the string that fired.
        s_table.add_column("User-Agent")
        for s in result.successful_attacks[:20]:
            s_table.add_row(s['ip'], s['type'], s['path'][:60], f"{s['response_size']:,}",
                            (s.get('ua') or '')[:40] or "-")
        console.print(s_table)

    # --- Large response attacks (possible exfiltration) ---
    if result.large_responses:
        lr_table = Table(title="Possible Data Exfiltration (attack + large response)", header_style="bold red", border_style="red")
        lr_table.add_column("IP Address")
        lr_table.add_column("Type")
        lr_table.add_column("Path")
        lr_table.add_column("Resp. Size", justify="right")
        for e in result.large_responses[:10]:
            lr_table.add_row(e['ip'], e['type'], e['path'][:60], f"{e['response_size']:,}")
        console.print(lr_table)

    # --- Attacks that caused server errors (Vulnerable endpoints) ---
    if result.server_error_attacks:
        se_table = Table(title="Vulnerable Endpoints (Attack -> HTTP 500)", header_style="bold red", border_style="red")
        se_table.add_column("IP Address")
        se_table.add_column("Type")
        se_table.add_column("Path")
        for e in result.server_error_attacks[:20]:
            se_table.add_row(e['ip'], e['type'], e['path'][:70])
        console.print(se_table)

    # --- 404 flood (top 20 + summary) ---
    if result.notfound_flood_ips:
        n_nf = len(result.notfound_flood_ips)
        top_nf = sorted(result.notfound_flood_ips)[:20]
        nf_table = Table(
            title=f"404 Flood / Directory Scanner (>{cfg.notfound_flood_threshold} 404s/{cfg.time_window_minutes}min) — {n_nf:,} IPs",
            header_style="bold yellow", border_style="yellow"
        )
        nf_table.add_column("IP Address", style="bold")
        for ip in top_nf:
            nf_table.add_row(ip)
        if n_nf > 20:
            nf_table.add_row(f"[dim]... and {n_nf - 20:,} more[/dim]", style="dim")
        console.print(nf_table)

    # --- wp-cron.php flood (top 20 + summary) ---
    if result.wp_cron_flood_ips:
        n_wc = len(result.wp_cron_flood_ips)
        top_wc = sorted(result.wp_cron_flood_ips)[:20]
        wc_table = Table(
            title=f"WP Cron Flood / DoS (>{cfg.wp_cron_flood_threshold} hits/{cfg.time_window_minutes}min) — {n_wc:,} IPs",
            header_style="bold red", border_style="red"
        )
        wc_table.add_column("IP Address", style="bold")
        for ip in top_wc:
            wc_table.add_row(ip)
        if n_wc > 20:
            wc_table.add_row(f"[dim]... and {n_wc - 20:,} more[/dim]", style="dim")
        console.print(wc_table)

    # --- WP Login POST brute force (top 20 + summary) ---
    if result.wp_login_bruteforce_ips:
        n_wl = len(result.wp_login_bruteforce_ips)
        top_wl = sorted(result.wp_login_bruteforce_ips)[:20]
        wl_table = Table(
            title=f"WP Login POST Brute Force / Credential Stuffing (>{cfg.wp_login_post_threshold} POST/{cfg.time_window_minutes}min) — {n_wl:,} IPs",
            header_style="bold red", border_style="red"
        )
        wl_table.add_column("IP Address", style="bold")
        for ip in top_wl:
            wl_table.add_row(ip)
        if n_wl > 20:
            wl_table.add_row(f"[dim]... and {n_wl - 20:,} more[/dim]", style="dim")
        console.print(wl_table)

    # --- XML-RPC brute force (top 20 + summary) ---
    if result.xmlrpc_bruteforce_ips:
        n_xml = len(result.xmlrpc_bruteforce_ips)
        top_xml = sorted(result.xmlrpc_bruteforce_ips)[:20]
        xr_table = Table(
            title=f"XML-RPC Brute Force (>{cfg.bruteforce_threshold} POST/{cfg.time_window_minutes}min) — {n_xml:,} IPs",
            header_style="bold red", border_style="red"
        )
        xr_table.add_column("IP Address", style="bold")
        for ip in top_xml:
            xr_table.add_row(ip)
        if n_xml > 20:
            xr_table.add_row(f"[dim]... and {n_xml - 20:,} more[/dim]", style="dim")
        console.print(xr_table)

    # --- Attack bursts ---
    if result.attack_bursts:
        ab_table = Table(
            title=f"Attack Burst Hours (>{cfg.attack_burst_factor}x average)",
            header_style="bold red", border_style="red"
        )
        ab_table.add_column("Date", style="cyan")
        ab_table.add_column("Hour", justify="center")
        ab_table.add_column("Attacks", justify="right", style="red")
        for (date_str, hour), count in sorted(result.attack_bursts.items(), key=lambda x: x[1], reverse=True):
            ab_table.add_row(date_str, f"{hour:02d}:00", f"{count:,}")
        console.print(ab_table)

    # --- Coordinated attack chains (top 20 by vector count + distribution summary) ---
    if result.attack_chains:
        n_chains = len(result.attack_chains)
        sorted_chains = sorted(result.attack_chains.items(), key=lambda x: len(x[1]), reverse=True)
        top_chains = sorted_chains[:20]

        # Compute distribution: how many IPs have 3, 4, 5... vectors
        vec_dist = Counter(len(types) for _, types in sorted_chains)

        title = f"Coordinated Attack Chains (>= {cfg.attack_chain_min_vectors} WP vectors) — {n_chains:,} IPs"
        ac_table = Table(title=title, header_style="bold red", border_style="red")
        ac_table.add_column("IP Address", style="bold", min_width=16)
        ac_table.add_column("Attack Vectors Used", style="cyan")
        ac_table.add_column("#", justify="right")
        for ip, types in top_chains:
            ac_table.add_row(ip, ", ".join(types[:5]) + ("..." if len(types) > 5 else ""), str(len(types)))
        if n_chains > 20:
            dist_str = ", ".join(f"{v} vectors: {c} IPs" for v, c in sorted(vec_dist.items(), reverse=True)[:5])
            ac_table.add_row(f"[dim]... and {n_chains - 20:,} more[/dim]", f"[dim]{dist_str}[/dim]", "", style="dim")
        console.print(ac_table)

    # --- WordPress attack vectors with top URLs ---
    if result.attack_vector_urls:
        wp_url_data = [(v, result.attack_vector_urls[v]) for v in WP_DISPLAY_VECTORS if v in result.attack_vector_urls]
        if wp_url_data:
            av_table = Table(title="WordPress Attack Vectors -- Top URLs", header_style="bold magenta", border_style="magenta")
            av_table.add_column("Attack Vector", style="cyan", min_width=22)
            av_table.add_column("Total", justify="right")
            av_table.add_column("Top URL", style="yellow")
            av_table.add_column("Hits", justify="right")
            for vector, url_counter in sorted(wp_url_data, key=lambda x: sum(x[1].values()), reverse=True):
                total = sum(url_counter.values())
                top_url, top_hits = url_counter.most_common(1)[0]
                av_table.add_row(vector, f"{total:,}", top_url[:70], f"{top_hits:,}")
            console.print(av_table)

    # --- Compromised accounts (brute force -> successful login) ---
    if result.compromised_ips:
        ci_table = Table(
            title="CRITICAL: Brute Force -> Successful Login (Possible Account Takeover)",
            header_style="bold white on red", border_style="red"
        )
        ci_table.add_column("IP Address", style="bold")
        ci_table.add_column("Successful Logins", justify="right")
        ci_table.add_column("First Seen")
        for ip, times in sorted(result.compromised_ips.items()):
            first = times[0].strftime('%Y-%m-%d %H:%M') if times else 'N/A'
            ci_table.add_row(ip, str(len(times)), first)
        console.print(ci_table)

    # --- IP response distribution ---
    if result.ip_resp_dist:
        rd_table = Table(title="Top Attacker IPs -- Response Distribution", header_style="bold blue")
        rd_table.add_column("IP Address", style="cyan")
        rd_table.add_column("Total", justify="right")
        rd_table.add_column("2xx", justify="right", style="green")
        rd_table.add_column("4xx", justify="right", style="yellow")
        rd_table.add_column("5xx", justify="right", style="red")
        rd_table.add_column("Succ%", justify="right")
        for ip, d in list(result.ip_resp_dist.items())[:15]:
            total = d['total'] or 1
            pct = f"{100 * d['2xx'] / total:.1f}%"
            rd_table.add_row(ip, f"{d['total']:,}", f"{d['2xx']:,}", f"{d['4xx']:,}", f"{d['5xx']:,}", pct)
        console.print(rd_table)

    # --- Hourly attack timeline ---
    if result.hourly_requests:
        all_keys = sorted(set(result.hourly_requests) | set(result.hourly_attacks) | set(result.hourly_4xx) | set(result.hourly_5xx))
        if all_keys:
            tl_table = Table(title="Hourly Attack Timeline", header_style="bold blue")
            tl_table.add_column("Date", style="cyan")
            tl_table.add_column("Hour", justify="center")
            tl_table.add_column("Requests", justify="right")
            tl_table.add_column("Attacks", justify="right", style="red")
            tl_table.add_column("4xx", justify="right", style="yellow")
            tl_table.add_column("5xx", justify="right", style="red")
            for key in all_keys:
                date_str, hour = key
                req = result.hourly_requests.get(key, 0)
                atk = result.hourly_attacks.get(key, 0)
                e4 = result.hourly_4xx.get(key, 0)
                e5 = result.hourly_5xx.get(key, 0)
                row_style = "bold red" if atk > 100 else ("yellow" if atk > 10 else "")
                tl_table.add_row(date_str, f"{hour:02d}:00", f"{req:,}", f"{atk:,}", f"{e4:,}", f"{e5:,}", style=row_style)
            console.print(tl_table)

    # --- Server hardening plan ---
    hardening = build_hardening_plan(result)
    if hardening:
        priority_color = {'CRITICAL': 'bold red', 'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'dim'}
        hp_table = Table(title="Server Hardening Plan", header_style="bold magenta", border_style="magenta")
        hp_table.add_column("Priority", justify="center", min_width=10)
        hp_table.add_column("Attack Vector", style="cyan", min_width=22)
        hp_table.add_column("Hits", justify="right")
        hp_table.add_column("Successful", justify="right")
        hp_table.add_column("Risk / Fix", style="yellow")
        for h in hardening:
            col = priority_color.get(h['priority'], '')
            prio = f"[{col}]{h['priority']}[/{col}]"
            succ_str = f"[bold red]{h['success']:,}[/bold red]" if h['success'] > 0 else "0"
            fix_hint = h['nginx'].split('\n')[0][:55] if h['nginx'] else h['risk'][:55]
            hp_table.add_row(prio, h['type'], f"{h['total']:,}", succ_str, fix_hint)
        console.print(hp_table)

    # --- Final verdict ---
    wp_success = sum(1 for e in result.wp_events if e['is_success'])
    webshell_hits = [e for e in result.successful_attacks if e['type'] == 'WP Webshell Upload']
    n_compromised = len(result.compromised_ips)
    n_chains = len(result.attack_chains)
    n_server_errors = len(result.server_error_attacks)
    n_404_flood = len(result.notfound_flood_ips)
    n_cron_flood = len(result.wp_cron_flood_ips)
    n_bursts = len(result.attack_bursts)

    color = "red" if n_compromised > 0 or wp_success > 0 or webshell_hits or result.successful_attacks else \
            "yellow" if result.wp_events or result.bruteforce_ips or n_chains > 0 else "green"

    msg = (
        f"Total processed lines:        {result.total_lines:,}\n"
        f"Unique attacker IPs:          {len(result.ips):,}\n"
        f"Brute force IPs (windowed):   {len(result.bruteforce_ips)}\n"
        f"Compromised accounts:         [bold red]{n_compromised}[/bold red]\n"
        f"Rate limit exceeded IPs:      {len(result.rate_ips)}\n"
        f"404 Flood / Scanner IPs:      {n_404_flood}\n"
        f"WP Cron Flood IPs:            {n_cron_flood}\n"
        f"Attack burst hours:           {n_bursts}\n"
        f"Coordinated attack chains:    {n_chains}\n"
        f"Vulnerable endpoints (500):   {n_server_errors}\n"
        f"WP hseo attempts:             {len(result.wp_events)}\n"
        f"Successful WP hseo actions:   [bold red]{wp_success}[/bold red]\n"
        f"Webshell execution attempts:  [bold red]{len(webshell_hits)}[/bold red]\n"
        f"Other successful attacks:     {len(result.successful_attacks)}\n"
        f"Possible exfiltration events: {len(result.large_responses)}\n"
    )

    if n_compromised > 0:
        verdict = f"CRITICAL: {n_compromised} account(s) likely compromised (brute force + successful login)!"
    elif webshell_hits:
        verdict = "CRITICAL: Webshell execution detected in uploads directory!"
    elif wp_success > 0:
        verdict = "URGENT: Successful hseo plugin activation/access detected!"
    elif result.large_responses:
        verdict = "CRITICAL: Possible data exfiltration detected!"
    elif result.successful_attacks:
        verdict = "WARNING: Successful attacks found in logs."
    elif n_server_errors > 0:
        verdict = "WARNING: Vulnerable endpoints found (attack -> HTTP 500)."
    elif n_chains > 0:
        verdict = f"WARNING: {n_chains} coordinated multi-vector attack(s) detected."
    elif result.bruteforce_ips:
        verdict = "WARNING: Active brute force detected."
    else:
        verdict = "System security status stable."

    console.print(Panel(msg + f"\n[bold]{verdict}[/bold]", title="Final Ninja Verdict", border_style=color))
