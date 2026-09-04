"""Self-contained dark-theme HTML report writer (inlined CSS/JS, no assets)."""
import os
from datetime import datetime

from src.events import get_output_dir, logger
from src.result import (AnalysisResult, build_geo_recommendation,
                        build_hardening_plan, build_sensitive_hits,
                        compute_verdict)

def save_report_html(result: AnalysisResult) -> str:
    cfg = result.cfg
    output_path = os.path.join(get_output_dir(cfg), "report.html")
    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    sensitive_rows = build_sensitive_hits(result)
    hardening = build_hardening_plan(result)
    n_compromised = len(result.compromised_ips)
    n_server_errors = len(result.server_error_attacks)
    n_chains = len(result.attack_chains)

    vlevel, vtext = compute_verdict(result)

    def h(s):
        return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    # Build base URL for cURL substitution
    if cfg.site:
        _srv = cfg.site.strip().rstrip('/')
        site_url = _srv if _srv.startswith(('http://', 'https://')) else f'https://{_srv}'
    else:
        site_url = 'https://SITE'

    pcls = {'CRITICAL': 'p-critical', 'HIGH': 'p-high', 'MEDIUM': 'p-medium', 'LOW': 'p-low'}

    # ── CSS ──────────────────────────────────────────────────────────────────
    css = """
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e;
  --critical: #f85149; --high: #e07b39; --medium: #e3b341; --low: #3fb950;
  --blue: #58a6ff; --purple: #bc8cff;
  --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font);
       font-size: 14px; line-height: 1.6; }
a { color: var(--blue); text-decoration: none; }
.wrap { max-width: 1400px; margin: 0 auto; padding: 24px 20px 60px; }

/* Header */
.hdr { display: flex; align-items: center; justify-content: space-between;
       padding: 20px 0 28px; border-bottom: 1px solid var(--border); margin-bottom: 28px; }
.hdr-left h1 { font-size: 22px; font-weight: 700; color: var(--text); }
.hdr-left h1 span { color: var(--critical); }
.hdr-meta { font-size: 12px; color: var(--muted); margin-top: 4px; }
.hdr-badge { background: var(--surface); border: 1px solid var(--border);
             border-radius: 6px; padding: 6px 14px; font-size: 12px; color: var(--muted); }

/* Verdict */
.verdict { border-radius: 8px; padding: 16px 24px; margin-bottom: 28px;
           font-size: 16px; font-weight: 700; letter-spacing: .3px;
           display: flex; align-items: center; gap: 12px; }
.verdict::before { content: ''; width: 10px; height: 10px; border-radius: 50%;
                   background: currentColor; flex-shrink: 0; }
.v-critical { background: rgba(248,81,73,.12); color: var(--critical); border: 1px solid rgba(248,81,73,.3); }
.v-high     { background: rgba(224,123,57,.12); color: var(--high);     border: 1px solid rgba(224,123,57,.3); }
.v-medium   { background: rgba(227,179,65,.12); color: var(--medium);   border: 1px solid rgba(227,179,65,.3); }
.v-low      { background: rgba(63,185,80,.12);  color: var(--low);      border: 1px solid rgba(63,185,80,.3); }

/* Cards */
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
         gap: 14px; margin-bottom: 32px; }
.card { background: var(--surface); border: 1px solid var(--border);
        border-radius: 8px; padding: 16px 18px; }
.card-label { font-size: 11px; text-transform: uppercase; letter-spacing: .8px;
              color: var(--muted); margin-bottom: 6px; }
.card-value { font-size: 28px; font-weight: 700; line-height: 1; }
.card-value.danger { color: var(--critical); }
.card-value.warn   { color: var(--medium); }
.card-value.ok     { color: var(--low); }

/* Sections */
.sec { background: var(--surface); border: 1px solid var(--border);
       border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
.sec-hdr { display: flex; align-items: center; justify-content: space-between;
           padding: 14px 20px; cursor: pointer; user-select: none; }
.sec-hdr:hover { background: rgba(255,255,255,.03); }
.sec-title { font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
.sec-title .cnt { font-size: 12px; color: var(--muted); font-weight: 400; }
.toggle-icon { color: var(--muted); font-size: 12px; transition: transform .2s; }
.sec-body { padding: 0 20px 20px; }
.sec.collapsed .toggle-icon { transform: rotate(-90deg); }
.sec.collapsed .sec-body { display: none; }

/* Tables */
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border);
     font-size: 11px; text-transform: uppercase; letter-spacing: .6px; color: var(--muted); }
td { padding: 7px 12px; border-bottom: 1px solid rgba(48,54,61,.5); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,.02); }
.td-path { font-family: var(--mono); font-size: 12px; color: var(--blue); word-break: break-all; }
.td-ip   { font-family: var(--mono); font-size: 12px; }
.td-num  { text-align: right; font-variant-numeric: tabular-nums; }
.td-succ-pos { color: var(--critical); font-weight: 700; text-align: right; }
.td-succ-zero { color: var(--muted); text-align: right; }
/* (L4) Matched user-agent in the Successful Attacks table */
.td-ua   { font-family: var(--mono); font-size: 11px; color: var(--muted); word-break: break-all; }

/* Priority badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: 11px; font-weight: 700; letter-spacing: .4px; }
.p-critical { background: rgba(248,81,73,.15);  color: var(--critical); border: 1px solid rgba(248,81,73,.4); }
.p-high     { background: rgba(224,123,57,.15); color: var(--high);     border: 1px solid rgba(224,123,57,.4); }
.p-medium   { background: rgba(227,179,65,.15); color: var(--medium);   border: 1px solid rgba(227,179,65,.4); }
.p-low      { background: rgba(63,185,80,.15);  color: var(--low);      border: 1px solid rgba(63,185,80,.4); }

/* Hardening cards */
.harden-grid { display: grid; gap: 14px; }
.hcard { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.hcard-hdr { padding: 12px 16px; display: flex; align-items: flex-start; gap: 12px; }
.hcard-info { flex: 1; min-width: 0; }
.hcard-name { font-weight: 600; font-size: 14px; margin-bottom: 2px; }
.hcard-risk { font-size: 12px; color: var(--muted); }
.hcard-stats { display: flex; gap: 16px; font-size: 12px; margin-top: 6px; }
.hcard-stats span { color: var(--muted); }
.hcard-stats .hits-succ { color: var(--critical); font-weight: 600; }
/* Code tabs */
.code-tabs { border-top: 1px solid var(--border); }
.tab-btns { display: flex; background: rgba(0,0,0,.2); }
.tab-btn { padding: 6px 16px; font-size: 12px; color: var(--muted); cursor: pointer;
           border: none; background: none; font-family: var(--font); border-bottom: 2px solid transparent; }
.tab-btn.active { color: var(--blue); border-bottom-color: var(--blue); }
.tab-btn[data-tab="apache"].active { color: var(--high); border-bottom-color: var(--high); }
.tab-btn[data-tab="curl"].active   { color: var(--low);  border-bottom-color: var(--low); }
.tab-pane { display: none; position: relative; }
.tab-pane.active { display: block; }
pre { padding: 14px 16px; font-family: var(--mono); font-size: 12px;
      line-height: 1.6; color: #cdd9e5; overflow-x: auto; white-space: pre; margin: 0; }
.copy-btn { position: absolute; top: 8px; right: 10px; padding: 3px 8px;
            font-size: 11px; background: var(--surface); color: var(--muted);
            border: 1px solid var(--border); border-radius: 4px; cursor: pointer; }
.copy-btn:hover { color: var(--text); border-color: var(--muted); }
.note { padding: 8px 16px 12px; font-size: 12px; color: var(--muted);
        background: rgba(88,166,255,.05); border-top: 1px solid var(--border); }

/* Timeline chart */
.chart-wrap { overflow-x: auto; padding: 8px 0 4px; }
.chart-bars { display: flex; align-items: flex-end; gap: 2px; height: 100px; padding: 0 4px; }
.bar-group { display: flex; flex-direction: column; align-items: center; gap: 2px; flex: 1; min-width: 8px; }
.bar { width: 100%; border-radius: 2px 2px 0 0; min-height: 2px; cursor: default; }
.bar-req { background: #30363d; }
.bar-atk { background: var(--critical); }
.chart-legend { display: flex; gap: 16px; padding: 8px 4px 0; font-size: 11px; color: var(--muted); }
.chart-legend span { display: flex; align-items: center; gap: 5px; }
.leg-dot { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }

/* Geo bar */
.geo-bar { height: 6px; background: var(--critical); border-radius: 3px; max-width: 200px; }

/* IP path indent */
.ip-path-row td:first-child { padding-left: 32px; color: var(--muted); font-size: 12px; }

/* Attack stat row */
.atk-success td { color: var(--critical); }
.atk-blocked td { color: var(--medium); }

/* Section separator */
.sec-title .dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; flex-shrink: 0; }

/* Responsive */
@media (max-width: 700px) {
  .cards { grid-template-columns: repeat(2, 1fr); }
  .hdr { flex-direction: column; align-items: flex-start; gap: 10px; }
}
"""

    # ── JS ───────────────────────────────────────────────────────────────────
    js = """
function toggleSec(id) {
  document.getElementById(id).classList.toggle('collapsed');
}
function switchTab(cardEl, tab) {
  cardEl.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  cardEl.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.dataset.pane === tab));
}
function copyCode(btn) {
  const pre = btn.nextElementSibling;
  navigator.clipboard.writeText(pre.textContent).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 1500);
  });
}
"""

    # ── Helpers ──────────────────────────────────────────────────────────────
    sec_id = [0]
    def sec_open(title, dot_color='var(--blue)', count_str='', collapsed=False):
        sec_id[0] += 1
        sid = f's{sec_id[0]}'
        cls = 'sec collapsed' if collapsed else 'sec'
        count_html = f'<span class="cnt">{h(count_str)}</span>' if count_str else ''
        dot = f'<span class="dot" style="background:{dot_color}"></span>'
        return (f'<div class="{cls}" id="{sid}">'
                f'<div class="sec-hdr" onclick="toggleSec(\'{sid}\')">'
                f'<span class="sec-title">{dot} {h(title)} {count_html}</span>'
                f'<span class="toggle-icon">▼</span></div>'
                f'<div class="sec-body">')

    def sec_close():
        return '</div></div>'

    def card(label, value, cls=''):
        return (f'<div class="card"><div class="card-label">{h(label)}</div>'
                f'<div class="card-value {cls}">{h(str(value))}</div></div>')

    # ── Summary cards ────────────────────────────────────────────────────────
    n_succ = len(result.successful_attacks)
    n_large = len(result.large_responses)
    n_bf = len(result.bruteforce_ips)
    n_rate = len(result.rate_ips)

    succ_cls = 'danger' if n_succ else 'ok'
    comp_cls = 'danger' if n_compromised else 'ok'
    chain_cls = 'warn' if n_chains > 0 else 'ok'

    cards_html = (
        '<div class="cards">'
        + card('Lines Processed', f'{result.total_lines:,}')
        + card('Unique Attacker IPs', f'{len(result.ips):,}', 'warn' if len(result.ips) > 100 else '')
        + card('Successful Attacks', f'{n_succ:,}', succ_cls)
        + card('Compromised Accounts', f'{n_compromised}', comp_cls)
        + card('Attack Chains', f'{n_chains:,}', chain_cls)
        + card('Data Exfiltration', f'{n_large}', 'danger' if n_large else 'ok')
        + card('Vulnerable (500)', f'{n_server_errors}', 'warn' if n_server_errors else 'ok')
        + card('Rate Limit IPs', f'{n_rate}', 'warn' if n_rate else 'ok')
        + card('Brute Force IPs', f'{n_bf}', 'warn' if n_bf else 'ok')
        + card('Log Files', str(len(result.log_files)))
        + '</div>'
    )

    # ── Sensitive files ───────────────────────────────────────────────────────
    sf_rows = ''
    for r in sensitive_rows[:40]:
        succ_cls2 = 'td-succ-pos' if r['success'] > 0 else 'td-succ-zero'
        sf_rows += (f'<tr><td class="td-path">{h(r["path"][:90])}</td>'
                    f'<td>{h(r["type"])}</td>'
                    f'<td class="td-num">{r["total"]:,}</td>'
                    f'<td class="{succ_cls2}">{r["success"]:,}</td></tr>\n')

    sf_section = (
        sec_open('Sensitive Files Under Attack', 'var(--critical)', f'{len(sensitive_rows)} files')
        + '<div class="tbl-wrap"><table>'
        + '<tr><th>File / Path</th><th>Attack Type</th><th>Total Hits</th><th>Successful</th></tr>'
        + sf_rows
        + '</table></div>'
        + sec_close()
    ) if sensitive_rows else ''

    # ── Hardening plan ────────────────────────────────────────────────────────
    hcards = ''
    for hid, hh in enumerate(hardening):
        hcard_html = (
            f'<div class="hcard" id="hc{hid}">'
            f'<div class="hcard-hdr">'
            f'<span class="badge {pcls.get(hh["priority"], "")}">{h(hh["priority"])}</span>'
            f'<div class="hcard-info">'
            f'<div class="hcard-name">{h(hh["type"])}</div>'
            f'<div class="hcard-risk">{h(hh["risk"])}</div>'
            f'<div class="hcard-stats">'
            f'<span>Hits: <b>{hh["total"]:,}</b></span>'
        )
        if hh['success']:
            hcard_html += f'<span class="hits-succ">Successful: {hh["success"]:,}</span>'
        hcard_html += '</div></div></div>'

        if hh['nginx'] or hh['apache'] or hh['curl']:
            hcard_html += '<div class="code-tabs"><div class="tab-btns">'
            first = True
            for tab_id, tab_label in [('nginx', 'Nginx'), ('apache', 'Apache'), ('curl', 'cURL — verify')]:
                if hh.get(tab_id):
                    active = 'active' if first else ''
                    hcard_html += (f'<button class="tab-btn {active}" data-tab="{tab_id}" '
                                   f'onclick="switchTab(document.getElementById(\'hc{hid}\'),\'{tab_id}\')">'
                                   f'{tab_label}</button>')
                    first = False
            hcard_html += '</div>'
            first_pane = True
            for tab_id in ('nginx', 'apache', 'curl'):
                if hh.get(tab_id):
                    active = 'active' if first_pane else ''
                    content = hh[tab_id]
                    if tab_id == 'curl':
                        content = content.replace('https://SITE', site_url)
                    hcard_html += (f'<div class="tab-pane {active}" data-pane="{tab_id}">'
                                   f'<button class="copy-btn" onclick="copyCode(this)">Copy</button>'
                                   f'<pre>{h(content)}</pre></div>')
                    first_pane = False
            hcard_html += '</div>'

        if hh['extra']:
            hcard_html += f'<div class="note">📝 {h(hh["extra"])}</div>'
        hcard_html += '</div>'
        hcards += hcard_html

    hp_section = (
        sec_open('Server Hardening Plan', 'var(--medium)', f'{len(hardening)} vectors')
        + '<div class="harden-grid">' + hcards + '</div>'
        + sec_close()
    ) if hardening else ''

    # ── Attack breakdown ──────────────────────────────────────────────────────
    atk_rows = ''
    for cat, count in sorted(result.stats.items(), key=lambda x: -x[1]):
        if count == 0:
            continue
        row_cls = 'atk-success' if 'SUCCESS' in cat else ('atk-blocked' if 'Blocked' in cat else '')
        atk_rows += f'<tr class="{row_cls}"><td>{h(cat)}</td><td class="td-num">{count:,}</td></tr>\n'

    atk_section = (
        sec_open('Attack Breakdown', 'var(--blue)', f'{len(result.stats)} categories', collapsed=True)
        + '<div class="tbl-wrap"><table>'
        + '<tr><th>Category</th><th>Count</th></tr>'
        + atk_rows + '</table></div>'
        + sec_close()
    )

    # ── Top IPs ───────────────────────────────────────────────────────────────
    ip_rows = ''
    for ip, _ in result.ip_hostility.most_common(20):
        count = result.ips.get(ip, 0)
        d = result.ip_resp_dist.get(ip, {})
        total = d.get('total', 1) or 1
        pct = f"{100 * d.get('2xx', 0) / total:.0f}%" if d else '—'
        ip_rows += (f'<tr><td class="td-ip">{h(ip)}</td>'
                    f'<td class="td-num">{count:,}</td>'
                    f'<td class="td-num">{d.get("2xx","—"):,}</td>'
                    f'<td class="td-num">{d.get("4xx","—"):,}</td>'
                    f'<td class="td-num">{pct}</td></tr>\n')
        if ip in result.ip_top_paths:
            for path, hits in result.ip_top_paths[ip][:2]:
                ip_rows += (f'<tr class="ip-path-row">'
                            f'<td colspan="2" class="td-path">↳ {h(path[:80])}</td>'
                            f'<td class="td-num" colspan="3">{hits:,} hits</td></tr>\n')

    ip_section = (
        sec_open('Top Attacker IPs', 'var(--critical)', f'{len(result.ips):,} total')
        + '<div class="tbl-wrap"><table>'
        + '<tr><th>IP Address</th><th>Events</th><th>2xx</th><th>4xx</th><th>Succ%</th></tr>'
        + ip_rows + '</table></div>'
        + sec_close()
    )

    # ── Geography ─────────────────────────────────────────────────────────────
    geo_section = ''
    if result.country_stats:
        total_geo = sum(result.country_stats.values()) or 1
        geo_rows = ''
        for country, count in result.country_stats.most_common():
            pct = int(100 * count / total_geo)
            geo_rows += (f'<tr><td>{h(country)}</td>'
                         f'<td class="td-num">{count}</td>'
                         f'<td><div class="geo-bar" style="width:{min(pct*2,200)}px" title="{pct}%"></div></td>'
                         f'<td class="td-num">{pct}%</td></tr>\n')
        proxy_rows = ''.join(
            f'<tr><td>{h(pt)}</td><td class="td-num">{c}</td></tr>'
            for pt, c in result.proxy_types.most_common()
        ) if result.proxy_types else '<tr><td colspan="2" style="color:var(--muted)">No proxy/VPN/hosting detected</td></tr>'
        geo_rec = build_geo_recommendation(result)
        geo_rec_html = ''
        if geo_rec:
            geo_rec_html = (
                f'<div style="margin-top:14px;padding:12px 16px;background:rgba(227,179,65,.08);'
                f'border:1px solid rgba(227,179,65,.3);border-radius:6px;font-size:13px">'
                f'<div style="font-weight:600;margin-bottom:4px">Geo-Blocking Recommendation</div>'
                f'Top attack sources: {h(geo_rec["candidates_str"])} — combined '
                f'<b style="color:var(--medium)">{geo_rec["combined_pct"]}%</b> of attack traffic.<br>'
                f'<span style="color:var(--muted);font-size:12px">Based on {geo_rec["sample_size"]} highest-volume '
                f'attacker IPs of {geo_rec["total_attackers"]:,} total, weighted by request volume. '
                f'Block via Cloudflare WAF, Nginx geo module, or Apache mod_maxminddb.</span>'
                f'</div>'
            )
        geo_section = (
            sec_open('Attacker Geography', 'var(--purple)')
            + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;flex-wrap:wrap">'
            + '<div><div class="tbl-wrap"><table><tr><th>Country</th><th>IPs</th><th>Share</th><th>%</th></tr>'
            + geo_rows + '</table></div></div>'
            + '<div><div class="tbl-wrap"><table><tr><th>Proxy / VPN / Hosting</th><th>IPs</th></tr>'
            + proxy_rows + '</table></div></div></div>'
            + geo_rec_html
            + sec_close()
        )

    # ── Coordinated attack chains ─────────────────────────────────────────────
    chain_section = ''
    if result.attack_chains:
        sorted_chains = sorted(result.attack_chains.items(), key=lambda x: len(x[1]), reverse=True)
        chain_rows = ''
        for ip, types in sorted_chains[:30]:
            badges = ' '.join(f'<span style="font-size:11px;color:var(--muted);background:rgba(255,255,255,.05);padding:1px 6px;border-radius:3px">{h(t)}</span>' for t in list(types)[:6])
            chain_rows += (f'<tr><td class="td-ip">{h(ip)}</td>'
                           f'<td class="td-num">{len(types)}</td>'
                           f'<td style="padding:5px 12px">{badges}</td></tr>\n')
        if len(result.attack_chains) > 30:
            chain_rows += f'<tr><td colspan="3" style="color:var(--muted);font-size:12px">... and {len(result.attack_chains)-30:,} more</td></tr>'
        chain_section = (
            sec_open('Coordinated Attack Chains', 'var(--high)', f'{n_chains:,} IPs', collapsed=True)
            + '<div class="tbl-wrap"><table>'
            + '<tr><th>IP Address</th><th># Vectors</th><th>Attack Types</th></tr>'
            + chain_rows + '</table></div>'
            + sec_close()
        )

    # ── WP attack vectors + top URLs ──────────────────────────────────────────
    vec_section = ''
    if result.attack_vector_urls:
        vec_rows = ''
        sorted_vecs = sorted(result.attack_vector_urls.items(), key=lambda x: sum(x[1].values()), reverse=True)
        for vtype, url_counter in sorted_vecs[:20]:
            total_hits = sum(url_counter.values())
            vec_rows += f'<tr><td style="font-weight:600">{h(vtype)}</td><td class="td-num">{total_hits:,}</td><td></td></tr>\n'
            for url, hits in url_counter.most_common(3):
                vec_rows += (f'<tr style="opacity:.8"><td class="td-path" style="padding-left:28px">↳ {h(url[:80])}</td>'
                             f'<td></td><td class="td-num">{hits:,}</td></tr>\n')
        vec_section = (
            sec_open('WordPress Attack Vectors', 'var(--blue)', f'{len(result.attack_vector_urls)} types', collapsed=True)
            + '<div class="tbl-wrap"><table>'
            + '<tr><th>Vector / URL</th><th>Total</th><th>URL Hits</th></tr>'
            + vec_rows + '</table></div>'
            + sec_close()
        )

    # ── Successful attacks ────────────────────────────────────────────────────
    succ_section = ''
    if result.successful_attacks:
        s_rows = ''
        for e in result.successful_attacks[:30]:
            # (L4) Surface the matched UA — the corroborating detail when
            # triaging a "Known Scanner" / "Suspicious Bot" classification.
            ua = e['ua'][:60] if e.get('ua') else '—'
            s_rows += (f'<tr><td class="td-ip">{h(e["ip"])}</td>'
                       f'<td>{h(e["type"])}</td>'
                       f'<td class="td-path">{h(e["path"][:70])}</td>'
                       f'<td class="td-num">{e["status"]}</td>'
                       f'<td class="td-num">{e["response_size"]:,}</td>'
                       f'<td class="td-ua">{h(ua)}</td></tr>\n')
        succ_section = (
            sec_open('Successful Attacks', 'var(--critical)', f'{len(result.successful_attacks)} events')
            + '<div class="tbl-wrap"><table>'
            + '<tr><th>IP</th><th>Type</th><th>Path</th><th>HTTP</th><th>Bytes</th><th>User-Agent</th></tr>'
            + s_rows + '</table></div>'
            + sec_close()
        )

    # ── Data exfiltration ─────────────────────────────────────────────────────
    exfil_section = ''
    if result.large_responses:
        ex_rows = ''
        for e in sorted(result.large_responses, key=lambda x: -x['response_size'])[:20]:
            ex_rows += (f'<tr><td class="td-ip">{h(e["ip"])}</td>'
                        f'<td>{h(e["type"])}</td>'
                        f'<td class="td-path">{h(e["path"][:70])}</td>'
                        f'<td class="td-num" style="color:var(--critical)">{e["response_size"]:,}</td></tr>\n')
        exfil_section = (
            sec_open('Possible Data Exfiltration', 'var(--critical)', f'{len(result.large_responses)} events')
            + '<div class="tbl-wrap"><table>'
            + '<tr><th>IP</th><th>Type</th><th>Path</th><th>Bytes</th></tr>'
            + ex_rows + '</table></div>'
            + sec_close()
        )

    # ── Compromised accounts ──────────────────────────────────────────────────
    comp_section = ''
    if result.compromised_ips:
        comp_rows = ''.join(
            f'<tr><td class="td-ip">{h(ip)}</td>'
            f'<td class="td-num" style="color:var(--critical)">{len(times)}</td>'
            f'<td>{times[0].strftime("%Y-%m-%d %H:%M") if times else "N/A"}</td></tr>'
            for ip, times in sorted(result.compromised_ips.items())
        )
        comp_section = (
            '<div class="sec" style="border-color:var(--critical)">'
            '<div class="sec-hdr" style="background:rgba(248,81,73,.08)" onclick="toggleSec(\'comp\')">'
            '<span class="sec-title"><span class="dot" style="background:var(--critical)"></span>'
            ' ⚠ CRITICAL: Compromised Accounts</span><span class="toggle-icon">▼</span></div>'
            '<div class="sec-body" id="comp">'
            '<div class="tbl-wrap"><table>'
            '<tr><th>IP Address</th><th>Successful Logins</th><th>First Seen</th></tr>'
            + comp_rows + '</table></div></div></div>'
        )

    # ── Hourly timeline chart ─────────────────────────────────────────────────
    tl_section = ''
    if result.hourly_requests:
        all_keys = sorted(set(result.hourly_requests) | set(result.hourly_attacks))
        max_req = max((result.hourly_requests.get(k, 0) for k in all_keys), default=1) or 1

        bars_html = ''
        tl_table_rows = ''
        for key in all_keys:
            date_str, hour = key
            req = result.hourly_requests.get(key, 0)
            atk = result.hourly_attacks.get(key, 0)
            e4 = result.hourly_4xx.get(key, 0)
            e5 = result.hourly_5xx.get(key, 0)
            h_req = max(2, int(req / max_req * 80))
            h_atk = max(0, int(atk / max_req * 80))
            label = f'{date_str} {hour:02d}:00 — {req:,} req / {atk:,} attacks'
            bars_html += (f'<div class="bar-group" title="{h(label)}">'
                          f'<div class="bar bar-req" style="height:{h_req}px"></div>'
                          f'<div class="bar bar-atk" style="height:{h_atk}px;margin-top:-{h_atk}px;opacity:.85"></div>'
                          f'</div>')
            row_style = 'color:var(--critical)' if atk > 100 else ''
            tl_table_rows += (f'<tr style="{row_style}"><td>{h(date_str)}</td>'
                              f'<td class="td-num">{hour:02d}:00</td>'
                              f'<td class="td-num">{req:,}</td>'
                              f'<td class="td-num">{atk:,}</td>'
                              f'<td class="td-num">{e4:,}</td>'
                              f'<td class="td-num">{e5:,}</td></tr>\n')

        tl_section = (
            sec_open('Hourly Timeline', 'var(--blue)', f'{len(all_keys)} hours', collapsed=True)
            + '<div class="chart-wrap"><div class="chart-bars">' + bars_html + '</div>'
            + '<div class="chart-legend">'
            + '<span><span class="leg-dot" style="background:#30363d"></span>Requests</span>'
            + '<span><span class="leg-dot" style="background:var(--critical)"></span>Attacks</span>'
            + '</div></div>'
            + '<div class="tbl-wrap" style="margin-top:16px"><table>'
            + '<tr><th>Date</th><th>Hour</th><th>Requests</th><th>Attacks</th><th>4xx</th><th>5xx</th></tr>'
            + tl_table_rows + '</table></div>'
            + sec_close()
        )

    # ── Brute force / rate limit lists ────────────────────────────────────────
    def ip_list_section(title, ip_set, color='var(--high)'):
        if not ip_set:
            return ''
        items = ''.join(f'<span class="td-ip" style="display:inline-block;margin:3px 6px 3px 0;padding:2px 8px;background:rgba(255,255,255,.04);border-radius:4px;font-size:12px">{h(ip)}</span>'
                        for ip in sorted(ip_set)[:40])
        extra = f'<div style="color:var(--muted);font-size:12px;margin-top:6px">... and {len(ip_set)-40:,} more</div>' if len(ip_set) > 40 else ''
        return (sec_open(title, color, f'{len(ip_set)} IPs', collapsed=True)
                + '<div style="padding:4px 0">' + items + extra + '</div>'
                + sec_close())

    bf_section = ip_list_section('Brute Force IPs (401-based)', result.bruteforce_ips, 'var(--critical)')
    rl_section = ip_list_section('Rate Limit Exceeded IPs', result.rate_ips, 'var(--high)')
    nf_section = ip_list_section('404 Flood / Directory Scanner IPs', result.notfound_flood_ips, 'var(--high)')
    wc_section = ip_list_section('WP Cron Flood / DoS IPs', result.wp_cron_flood_ips, 'var(--critical)')
    wl_section = ip_list_section('WP Login POST Brute Force IPs', result.wp_login_bruteforce_ips, 'var(--critical)')
    xr_section = ip_list_section('XML-RPC Brute Force IPs', result.xmlrpc_bruteforce_ips, 'var(--critical)')

    # ── Header ────────────────────────────────────────────────────────────────
    if cfg.site:
        ip_badge = (f' <span style="font-size:12px;color:var(--muted);background:rgba(255,255,255,.06);'
                    f'padding:2px 8px;border-radius:4px;font-weight:400">{h(cfg.resolved_ip)}</span>'
                    if cfg.resolved_ip else '')
        server_str = f' — <span style="color:var(--muted);font-weight:400">{h(cfg.site)}</span>{ip_badge}'
    else:
        server_str = ''
    header_html = (
        f'<div class="hdr">'
        f'<div class="hdr-left">'
        f'<h1><span>Ninja</span>Log Security Report{server_str}</h1>'
        f'<div class="hdr-meta">Generated: {h(generated_at)} &nbsp;·&nbsp; '
        f'{len(result.log_files)} log file(s) &nbsp;·&nbsp; {result.total_lines:,} lines processed</div>'
        f'</div>'
        f'<div class="hdr-badge">ninjaLog v2</div>'
        f'</div>'
    )

    # ── Assemble ──────────────────────────────────────────────────────────────
    body = '\n'.join(filter(None, [
        header_html,
        f'<div class="verdict v-{vlevel}">{h(vtext)}</div>',
        cards_html,
        comp_section,
        sf_section,
        hp_section,
        succ_section,
        exfil_section,
        atk_section,
        ip_section,
        geo_section,
        chain_section,
        vec_section,
        bf_section, rl_section, nf_section, wc_section, wl_section, xr_section,
        tl_section,
    ]))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NinjaLog Security Report</title>
<style>{css}</style>
</head>
<body>
<div class="wrap">
{body}
</div>
<script>{js}</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    logger.info("HTML report saved to %s", output_path)
    return output_path
