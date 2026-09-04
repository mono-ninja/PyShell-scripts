"""Report generation — JSON, HTML, Markdown, and PyShell table/chart builders.

The HTML report is a self-contained file with inline CSS, suitable for sending
to clients.  The Markdown report is emitted as a PyShell ``markdown`` event for
the Results tab.  Table and chart builders produce PyShell structured events.
"""

import html
import json
from pathlib import Path


def e(v) -> str:
    """HTML-escape a log-derived value for safe interpolation into the report."""
    return html.escape(str(v))


# ── File writers ───────────────────────────────────────────────

def write_json_report(report: dict, path: Path) -> None:
    """Write the full report dict as JSON."""
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)


def write_html_report(report: dict, path: Path) -> None:
    """Write a self-contained HTML report with inline CSS."""
    domain = report['meta']['domain']
    gen_date = report['meta']['generated_at']
    stats = report['stats']
    bots = stats['bots']
    dr = stats['date_range']
    total = stats['total_requests']

    bot_pct = stats['bot_requests'] / total * 100 if total else 0
    human_pct = stats['human_requests'] / total * 100 if total else 0
    disguised_count = stats.get('disguised_bot_requests', 0)
    parse_pct = stats['parsed_lines'] / stats['total_lines'] * 100 if stats['total_lines'] else 0

    # ── Bot activity rows ──
    bots_sorted = sorted(bots.items(), key=lambda x: -x[1]['count'])
    rows_bots = ''
    for name, data in bots_sorted:
        legit = '✅' if data['legitimate'] else '⚠️'
        pct = data['count'] / total * 100 if total else 0
        statuses = ', '.join(f"{k}:{v}" for k, v in sorted(data['status_codes'].items()))
        rows_bots += (
            f"<tr><td><strong>{e(name)}</strong></td><td>{e(data['category'])}</td>"
            f"<td>{data['count']:,}</td><td>{pct:.1f}%</td>"
            f"<td>{data['bytes'] / 1024:.1f} KB</td><td>{legit}</td>"
            f"<td style='font-size:12px'>{e(statuses)}</td></tr>"
        )

    rows_urls = ''.join(
        f"<tr><td><code>{e(url)}</code></td><td>{cnt:,}</td></tr>"
        for url, cnt in list(stats['top_urls'].items())[:20]
    )

    rows_status = ''
    for code, cnt in sorted(stats['status_codes'].items()):
        c = str(code)
        color = ('#28a745' if c.startswith('2') else
                 '#fd7e14' if c.startswith('3') else
                 '#dc3545' if c.startswith(('4', '5')) else '#6c757d')
        rows_status += f"<tr><td><span style='color:{color};font-weight:bold'>{code}</span></td><td>{cnt:,}</td></tr>"

    rows_ips = ''.join(
        f"<tr><td><code>{e(ip)}</code></td><td>{cnt:,}</td></tr>"
        for ip, cnt in list(stats['top_ips'].items())[:15]
    )

    rows_301 = ''.join(
        f"<tr><td><code>{e(url)}</code></td><td>{cnt:,}</td></tr>"
        for url, cnt in list(stats.get('top_301_redirects', {}).items())[:30]
    )

    # ── Google rate limiting ──
    grl = stats.get('google_rate_limit', {})
    rows_grl = ''
    for name, d in grl.items():
        sev = d['severity']
        color = '#dc3545' if sev == 'critical' else '#fd7e14' if sev == 'warning' else '#198754'
        badge = f"<span style='color:{color};font-weight:bold'>{sev.upper()}</span>"
        peaks = ', '.join(f"{h} ({c})" for h, c in d['peak_hours'])
        rows_grl += (
            f"<tr><td><strong>{e(name)}</strong></td>"
            f"<td>{d['total_requests']:,}</td>"
            f"<td style='color:{color};font-weight:bold'>{d['hits_429']:,}</td>"
            f"<td style='color:{color}'>{d['rate_429_pct']}%</td>"
            f"<td>{d['max_rph']:,}</td>"
            f"<td>{badge}</td>"
            f"<td style='font-size:12px;color:#666'>{e(peaks)}</td>"
            f"<td style='font-size:12px'>{e(d['recommendation'])}</td></tr>"
        )

    # ── Disguised bots ──
    disguised_bots_list = stats.get('disguised_bots', [])
    rows_disguised = ''
    disguised_display = disguised_bots_list[:50]
    for d in disguised_display:
        top_urls_str = ', '.join(f"{e(u)} ({c})" for u, c in list(d['top_urls'].items())[:3])
        rows_disguised += (
            f"<tr>"
            f"<td><code style='color:#dc3545'>{e(d['ip'])}</code></td>"
            f"<td>{d['requests']:,}</td>"
            f"<td>{d['scan_ratio']:.0%}</td>"
            f"<td>{d['unique_urls']}</td>"
            f"<td style='font-size:12px;color:#555'>{e(d['evidence'])}</td>"
            f"<td style='font-size:11px;color:#888;max-width:260px;overflow:hidden'>{e(d['user_agent'][:80])}</td>"
            f"<td style='font-size:12px'>{top_urls_str}</td>"
            f"</tr>"
        )
    disguised_more = len(disguised_bots_list) - len(disguised_display)

    # ── Suspicious subnets ──
    suspicious_subnets = stats.get('suspicious_subnets', {})
    rows_subnets = ''
    for subnet, sd in list(suspicious_subnets.items())[:15]:
        ips_str = ', '.join(f"{e(entry['ip'])} ({entry['requests']})" for entry in sd['ips'][:5])
        rows_subnets += (
            f"<tr><td><code>{e(subnet)}</code></td>"
            f"<td>{sd['unique_ips']}</td>"
            f"<td>{sd['total_requests']:,}</td>"
            f"<td style='font-size:12px;color:#666'>{ips_str}</td></tr>"
        )

    # ── robots.txt ──
    robots = stats.get('robots_txt', {})
    robots_txt = e(robots.get('content', ''))
    robots_details = robots.get('details', [])
    rows_robots_details = ''
    for block in robots_details:
        rows_robots_details += f"<h4 style='margin:12px 0 6px;color:#444'>{e(block['title'])}</h4><ul style='padding-left:20px'>"
        for item in block['items']:
            rows_robots_details += f"<li style='font-size:13px;margin:2px 0'>{e(item)}</li>"
        rows_robots_details += "</ul>"

    # ── Blocking rules ──
    blocking = stats.get('blocking_rules', {})
    nginx_conf = e(blocking.get('nginx', ''))
    nginx_snip = e(blocking.get('nginx_snippet', ''))
    htaccess = e(blocking.get('htaccess', ''))
    rows_block_ips = ''.join(
        f"<tr>"
        f"<td><code style='color:#dc3545'>{e(entry['ip'])}</code></td>"
        f"<td><span style='color:{'#dc3545' if entry['confidence'] == 'HIGH' else '#fd7e14'};font-weight:bold'>"
        f"{entry['confidence']}</span></td>"
        f"<td>{entry['requests']:,}</td>"
        f"<td style='font-size:12px;color:#555'>{e(entry['reason'])}</td>"
        f"</tr>"
        for entry in blocking.get('blocked_ips', [])
    )
    rows_block_subnets = ''.join(
        f"<tr>"
        f"<td><code style='color:#dc3545'>{e(entry['cidr'])}</code></td>"
        f"<td><span style='color:{'#dc3545' if entry['confidence'] == 'HIGH' else '#fd7e14'};font-weight:bold'>"
        f"{entry['confidence']}</span></td>"
        f"<td>{entry['requests']:,}</td>"
        f"<td style='font-size:12px;color:#555'>{entry['unique_ips']} IPs in subnet</td>"
        f"</tr>"
        for entry in blocking.get('blocked_subnets', [])
    )
    rows_block_uas = ''.join(
        f"<tr><td><strong>{e(entry['name'])}</strong></td>"
        f"<td><code>{e(entry['pattern'])}</code></td>"
        f"<td>{entry['count']:,}</td></tr>"
        for entry in sorted(blocking.get('blocked_uas', []), key=lambda x: -x['count'])
    )

    if rows_block_ips or rows_block_subnets:
        html_block_iptable = (
            "<h3 style='font-size:14px;margin:0 0 10px;color:#333'>IPs &amp; Subnets to Block</h3>"
            "<table style='margin-bottom:20px'><thead>"
            "<tr><th>Address</th><th>Confidence</th><th>Requests</th><th>Reason</th></tr>"
            f"</thead><tbody>{rows_block_ips}{rows_block_subnets}</tbody></table>"
        )
    else:
        html_block_iptable = ""

    if rows_block_uas:
        html_block_uatable = (
            "<h3 style='font-size:14px;margin:0 0 10px;color:#333'>User-Agents to Block</h3>"
            "<table style='margin-bottom:20px'><thead>"
            "<tr><th>Bot name</th><th>Pattern</th><th>Requests</th></tr>"
            f"</thead><tbody>{rows_block_uas}</tbody></table>"
        )
    else:
        html_block_uatable = ""

    total_mb = stats['total_bytes'] / 1024 / 1024
    # No recognized dates in any line -> render an em dash, not "None – None"
    period = (f"{e(dr['from'])} – {e(dr['to'])}"
              if (dr['from'] or dr['to']) else "—")
    disguised_warning = (
        f"<div style='background:#fff3cd;border:1px solid #ffc107;border-radius:6px;"
        f"padding:10px 16px;margin-bottom:8px;font-size:13px'>"
        f"⚠️ <strong>{disguised_count:,} requests</strong> counted as human traffic are "
        f"likely disguised bots - see <a href='#disguised-bots'>Disguised Bots</a> section.</div>"
        if disguised_count else ""
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BotHunter Report — {e(domain)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f6fa;color:#333}}
  header{{background:#1a1a2e;color:#fff;padding:24px 32px}}
  header h1{{font-size:24px}}
  header p{{margin-top:4px;opacity:.7;font-size:14px}}
  .container{{max-width:1200px;margin:0 auto;padding:24px 16px}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:16px;margin-bottom:28px}}
  .card{{background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .card .label{{font-size:12px;color:#888;text-transform:uppercase;letter-spacing:.5px}}
  .card .value{{font-size:28px;font-weight:700;margin-top:4px}}
  .red{{color:#dc3545}}.blue{{color:#0d6efd}}.green{{color:#198754}}.orange{{color:#fd7e14}}
  section{{background:#fff;border-radius:8px;padding:20px 24px;margin-bottom:24px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  section h2{{font-size:16px;margin-bottom:16px;border-bottom:1px solid #eee;padding-bottom:10px}}
  table{{width:100%;border-collapse:collapse;font-size:14px}}
  th{{text-align:left;padding:8px 10px;background:#f8f9fa;font-size:12px;text-transform:uppercase;color:#666;border-bottom:2px solid #dee2e6}}
  td{{padding:8px 10px;border-bottom:1px solid #f0f0f0}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#fafafa}}
  code{{background:#f3f4f6;padding:1px 5px;border-radius:3px;font-size:13px}}
  .warn-section{{border-left:4px solid #ffc107}}
  footer{{text-align:center;padding:20px;color:#aaa;font-size:12px}}
</style>
</head>
<body>
<header>
  <h1>BotHunter — SEO Log Analysis Report</h1>
  <p>Domain: <strong>{e(domain)}</strong> &nbsp;|&nbsp; Period: {period} &nbsp;|&nbsp; Generated: {e(gen_date[:19])}</p>
</header>
<div class="container">
  {disguised_warning}
  <div class="cards">
    <div class="card"><div class="label">Total Requests</div><div class="value blue">{total:,}</div></div>
    <div class="card"><div class="label">Bot Requests</div><div class="value red">{stats['bot_requests']:,}</div><div style="font-size:13px;color:#888;margin-top:4px">{bot_pct:.1f}%</div></div>
    <div class="card"><div class="label">Human Requests</div><div class="value green">{stats['human_requests']:,}</div><div style="font-size:13px;color:#888;margin-top:4px">{human_pct:.1f}%{'&nbsp;⚠' if disguised_count else ''}</div></div>
    {'<div class="card" style="border:1px solid #ffc107"><div class="label" style="color:#e0a800">Disguised Bots</div><div class="value orange">' + f'{disguised_count:,}' + '</div><div style="font-size:12px;color:#888;margin-top:4px">in human count</div></div>' if disguised_count else ''}
    <div class="card"><div class="label">Unknown</div><div class="value orange">{stats['unknown_requests']:,}</div></div>
    <div class="card"><div class="label">Unique Bots</div><div class="value">{len(bots)}</div></div>
    <div class="card"><div class="label">Total Traffic</div><div class="value">{total_mb:.1f} <span style="font-size:16px;font-weight:400">MB</span></div></div>
    <div class="card"><div class="label">Log Files</div><div class="value">{len(report['meta']['log_files'])}</div></div>
    <div class="card"><div class="label">Parse Rate</div><div class="value">{parse_pct:.0f}<span style="font-size:16px;font-weight:400">%</span></div></div>
  </div>
  <section><h2>Bot Activity</h2>
    <table><thead><tr><th>Bot</th><th>Category</th><th>Requests</th><th>% Total</th><th>Traffic</th><th>Legit</th><th>Status Codes</th></tr></thead>
    <tbody>{rows_bots}</tbody></table>
  </section>
  <section id="disguised-bots" class="warn-section"><h2>⚠ Disguised Bots (Browser UA + Bot Behaviour)</h2>
    {'<p style="color:#888;font-size:13px">No disguised bots detected.</p>' if not rows_disguised else f'''
    <p style="font-size:13px;color:#666;margin-bottom:12px">
      These IPs send requests with legitimate-looking browser User-Agents but exhibit systematic
      content-scanning patterns typical of scrapers or botnets. They are currently counted in
      "Human Requests" — the actual human traffic may be lower.
    </p>
    <table><thead><tr>
      <th>IP</th><th>Requests</th><th>Scan ratio</th><th>Unique URLs</th>
      <th>Evidence</th><th>User-Agent</th><th>Top URLs</th>
    </tr></thead>
    <tbody>{rows_disguised}</tbody></table>
    {f'<p style="font-size:12px;color:#888;margin-top:8px">{disguised_more} more disguised bots — see JSON report for full list.</p>' if disguised_more > 0 else ''}'''}
  </section>
  <section class="warn-section"><h2>Suspicious Subnets (Coordinated Activity)</h2>
    {'<p style="color:#888;font-size:13px">No suspicious subnet clusters detected.</p>' if not rows_subnets else f'''
    <p style="font-size:13px;color:#666;margin-bottom:12px">
      Multiple IPs from the same /24 subnet — possible botnet or distributed scraper.
    </p>
    <table><thead><tr><th>Subnet /24</th><th>Unique IPs</th><th>Total Requests</th><th>IPs</th></tr></thead>
    <tbody>{rows_subnets}</tbody></table>'''}
  </section>
  <section><h2>Top Crawled URLs</h2>
    <table><thead><tr><th>URL</th><th>Requests</th></tr></thead>
    <tbody>{rows_urls}</tbody></table>
  </section>
  <section><h2>HTTP Status Codes</h2>
    <table><thead><tr><th>Status</th><th>Count</th></tr></thead>
    <tbody>{rows_status}</tbody></table>
  </section>
  <section><h2>Top IP Addresses</h2>
    <table><thead><tr><th>IP</th><th>Requests</th></tr></thead>
    <tbody>{rows_ips}</tbody></table>
  </section>
  <section><h2>Top 301 Redirects</h2>
    {'<p style="color:#888;font-size:13px">No 301 redirects found.</p>' if not rows_301 else f'''
    <p style="font-size:13px;color:#666;margin-bottom:12px">
      These URLs return 301 and waste crawl budget — consider updating internal links to point directly to final URLs.
    </p>
    <table><thead><tr><th>URL (source)</th><th>301 hits</th></tr></thead>
    <tbody>{rows_301}</tbody></table>'''}
  </section>
  <section><h2>Google Rate Limiting (429)</h2>
    {'<p style="color:#888;font-size:13px">No Google rate limiting data.</p>' if not rows_grl else f'''
    <table><thead>
      <tr><th>Bot</th><th>Requests</th><th>429 hits</th><th>Rate</th><th>Max req/h</th><th>Status</th><th>Peak hours</th><th>Recommendation</th></tr>
    </thead><tbody>{rows_grl}</tbody></table>'''}
  </section>
  <section><h2>robots.txt Recommendations</h2>
    {rows_robots_details}
    <pre style="background:#1e1e2e;color:#cdd6f4;padding:16px;border-radius:6px;font-size:13px;overflow-x:auto;margin-top:16px;line-height:1.6">{robots_txt}</pre>
  </section>
  <section id="blocking-rules" class="warn-section"><h2>🛡 Blocking Rules — nginx &amp; .htaccess</h2>
    <p style="font-size:13px;color:#666;margin-bottom:16px">
      Auto-generated rules based on detected disguised bots, suspicious subnets, and known scraper UAs.
      Config files are saved alongside this report (<code>*.nginx.conf</code> / <code>*.htaccess</code>).
    </p>
    {html_block_iptable}
    {html_block_uatable}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:8px">
      <div>
        <h3 style="font-size:13px;color:#555;margin-bottom:8px">nginx
          <span style="font-weight:normal;font-size:12px;color:#888">
             — save as <code>{e(domain)}_block.conf</code> and <code>include</code> in nginx http{{}} block
          </span>
        </h3>
        <pre style="background:#1e1e2e;color:#cdd6f4;padding:14px;border-radius:6px;font-size:12px;overflow-x:auto;line-height:1.5;max-height:420px;overflow-y:auto">{nginx_conf}

{nginx_snip}</pre>
      </div>
      <div>
        <h3 style="font-size:13px;color:#555;margin-bottom:8px">.htaccess
          <span style="font-weight:normal;font-size:12px;color:#888">
            — paste at the <strong>top</strong> of your .htaccess file
          </span>
        </h3>
        <pre style="background:#1e1e2e;color:#cdd6f4;padding:14px;border-radius:6px;font-size:12px;overflow-x:auto;line-height:1.5;max-height:420px;overflow-y:auto">{htaccess}</pre>
      </div>
    </div>
  </section>
</div>
<footer>Generated by BotHunter v{report['meta']['version']} &nbsp;|&nbsp; {gen_date[:19]}</footer>
</body></html>"""

    with open(path, 'w', encoding='utf-8') as f:
        f.write(doc)


# ── PyShell event builders ─────────────────────────────────────

def build_bot_table(stats: dict) -> dict | None:
    """Build a PyShell table event for bot activity (top 20 bots)."""
    bots = stats.get('bots', {})
    if not bots:
        return None
    total = stats['total_requests']
    rows = []
    for name, data in sorted(bots.items(), key=lambda x: -x[1]['count'])[:20]:
        pct = f"{data['count'] / total * 100:.1f}%" if total else "0%"
        legit = 'yes' if data['legitimate'] else 'NO'
        kb = data['bytes'] / 1024
        size = f"{kb / 1024:.1f} MB" if kb > 1024 else f"{kb:.0f} KB"
        rows.append([name, data['category'], f"{data['count']:,}", pct, size, legit])
    return {
        'columns': ['Bot', 'Category', 'Requests', '% Total', 'Traffic', 'Legit'],
        'rows': rows,
    }


def build_disguised_table(stats: dict) -> dict | None:
    """Build a PyShell table event for disguised bots."""
    disguised = stats.get('disguised_bots', [])
    if not disguised:
        return None
    rows = []
    for d in disguised[:50]:
        rows.append([
            d['ip'],
            f"{d['requests']:,}",
            f"{d['scan_ratio']:.0%}",
            str(d['unique_urls']),
            d['evidence'],
        ])
    return {
        'columns': ['IP', 'Requests', 'Scan ratio', 'Unique URLs', 'Evidence'],
        'rows': rows,
    }


def build_blocking_table(stats: dict) -> dict | None:
    """Build a PyShell table event for blocking rules summary."""
    blocking = stats.get('blocking_rules', {})
    if not blocking:
        return None
    rows = []
    for entry in blocking.get('blocked_ips', []):
        rows.append(['IP', entry['ip'], entry['confidence'], f"{entry['requests']:,}", entry['reason']])
    for entry in blocking.get('blocked_subnets', []):
        rows.append(['Subnet', entry['cidr'], entry['confidence'],
                     f"{entry['requests']:,}", f"{entry['unique_ips']} IPs in subnet"])
    for entry in sorted(blocking.get('blocked_uas', []), key=lambda x: -x['count']):
        rows.append(['UA', entry['name'], '-', f"{entry['count']:,}", entry['pattern']])
    if not rows:
        return None
    return {
        'columns': ['Type', 'Address', 'Confidence', 'Requests', 'Reason / Pattern'],
        'rows': rows,
    }


def build_category_chart(stats: dict) -> dict | None:
    """Build a PyShell bar chart for bot distribution by category."""
    bots = stats.get('bots', {})
    if not bots:
        return None
    cat_totals: dict = {}
    for data in bots.values():
        cat = data['category']
        cat_totals[cat] = cat_totals.get(cat, 0) + data['count']
    if not cat_totals:
        return None
    sorted_cats = sorted(cat_totals.items(), key=lambda x: -x[1])
    return {
        'chart_type': 'bar',
        'title': 'Requests by bot category',
        'labels': [cat for cat, _ in sorted_cats],
        'series': [{'name': 'requests', 'values': [cnt for _, cnt in sorted_cats]}],
    }


def build_status_chart(stats: dict) -> dict | None:
    """Build a PyShell bar chart for HTTP status code distribution."""
    codes = stats.get('status_codes', {})
    if not codes:
        return None
    sorted_codes = sorted(codes.items())
    return {
        'chart_type': 'bar',
        'title': 'HTTP status codes',
        'labels': [str(code) for code, _ in sorted_codes],
        'series': [{'name': 'count', 'values': [cnt for _, cnt in sorted_codes]}],
    }


def build_markdown_report(report: dict) -> str:
    """Build a markdown summary for the PyShell Results tab."""
    meta = report['meta']
    stats = report['stats']
    domain = meta['domain']
    gen_date = meta['generated_at'][:19]
    dr = stats['date_range']
    total = stats['total_requests']

    bot_pct = stats['bot_requests'] / total * 100 if total else 0
    human_pct = stats['human_requests'] / total * 100 if total else 0
    parse_pct = stats['parsed_lines'] / stats['total_lines'] * 100 if stats['total_lines'] else 0
    disguised_count = stats.get('disguised_bot_requests', 0)
    total_mb = stats['total_bytes'] / 1024 / 1024
    period = (f"{dr['from']} -> {dr['to']}"
              if (dr['from'] or dr['to']) else "—")

    lines = [
        f"## BotHunter Report - {domain}",
        "",
        f"**Period:** {period} | **Generated:** {gen_date}",
        "",
        "### Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Total requests | {total:,} |",
        f"| Bot requests | {stats['bot_requests']:,} ({bot_pct:.1f}%) |",
        f"| Human requests | {stats['human_requests']:,} ({human_pct:.1f}%) |",
        f"| Unknown | {stats['unknown_requests']:,} |",
        f"| Unique bots | {len(stats['bots'])} |",
        f"| Total traffic | {total_mb:.1f} MB |",
        f"| Parse rate | {parse_pct:.0f}% |",
    ]

    # Skip diagnostics — separates foreign log formats from real regex misses
    skip_reasons = stats.get('skip_reasons', {})
    if skip_reasons:
        lines += ["", "| Skip reason | Count |", "| --- | --- |"]
        for reason, cnt in sorted(skip_reasons.items(), key=lambda x: -x[1]):
            lines.append(f"| {reason} | {cnt:,} |")
    # Recognized log formats — shows whether vhost_combined lines were parsed
    parse_formats = stats.get('parse_formats', {})
    if parse_formats:
        lines += ["", "| Recognized log format | Lines |", "| --- | --- |"]
        for fmt, cnt in sorted(parse_formats.items(), key=lambda x: -x[1]):
            lines.append(f"| {fmt} | {cnt:,} |")
    skip_samples = stats.get('skip_samples', {})
    if skip_samples:
        lines += ["", "<details><summary>Sample skipped lines</summary>", ""]
        for reason, sample in skip_samples.items():
            lines.append(f"- **{reason}**: `{sample}`")
        lines += ["", "</details>", ""]

    lines.append("")

    # Bot activity table (top 15)
    bots = stats['bots']
    if bots:
        lines += ["### Bot Activity", "",
                  "| Bot | Category | Requests | % Total | Legit |",
                  "| --- | --- | --- | --- | --- |"]
        for name, data in sorted(bots.items(), key=lambda x: -x[1]['count'])[:15]:
            pct = f"{data['count'] / total * 100:.1f}%" if total else "0%"
            legit = 'yes' if data['legitimate'] else '**NO**'
            lines.append(f"| {name} | {data['category']} | {data['count']:,} | {pct} | {legit} |")
        lines.append("")

    # Disguised bots
    disguised = stats.get('disguised_bots', [])
    if disguised:
        lines += [
            "### Disguised Bots (Browser UA + Bot Behaviour)",
            "",
            f"**{disguised_count:,} requests** counted as human traffic are likely disguised bots.",
            "",
            "| IP | Requests | Scan ratio | Evidence |",
            "| --- | --- | --- | --- |",
        ]
        for d in disguised[:20]:
            lines.append(f"| `{d['ip']}` | {d['requests']:,} | {d['scan_ratio']:.0%} | {d['evidence']} |")
        lines.append("")

    # Suspicious subnets
    subnets = stats.get('suspicious_subnets', {})
    if subnets:
        lines += [
            "### Suspicious Subnets",
            "",
            "| Subnet | Unique IPs | Total Requests |",
            "| --- | --- | --- |",
        ]
        for subnet, sd in list(subnets.items())[:10]:
            lines.append(f"| `{subnet}` | {sd['unique_ips']} | {sd['total_requests']:,} |")
        lines.append("")

    # Blocking rules
    blocking = stats.get('blocking_rules', {})
    if blocking and (blocking.get('blocked_ips') or blocking.get('blocked_subnets')
                     or blocking.get('blocked_uas')):
        n_ips = len(blocking.get('blocked_ips', []))
        n_subnets = len(blocking.get('blocked_subnets', []))
        n_uas = len(blocking.get('blocked_uas', []))
        lines += [
            "### Blocking Rules",
            "",
            f"- **{n_ips} IPs** blocked (disguised bots)",
            f"- **{n_subnets} subnets** blocked (coordinated activity)",
            f"- **{n_uas} UA patterns** blocked (scrapers/scanners)",
            "",
            "nginx `.conf` and `.htaccess` files saved as artifacts.",
            "",
        ]

    # Google rate limiting
    grl = stats.get('google_rate_limit', {})
    if grl:
        lines += [
            "### Google Rate Limiting (429)",
            "",
            "| Bot | 429 rate | Max req/h | Status |",
            "| --- | --- | --- | --- |",
        ]
        for name, d in grl.items():
            lines.append(
                f"| {name} | {d['rate_429_pct']}% | {d['max_rph']:,} | {d['severity'].upper()} |"
            )
        lines.append("")

    # robots.txt
    robots = stats.get('robots_txt', {})
    if robots.get('content'):
        lines += ["### robots.txt Recommendations", "", "```", robots['content'], "```", ""]

    # Top 404s
    top_404 = stats.get('top_404_urls', {})
    if top_404:
        lines += [
            "### Top 404 URLs (crawl budget waste)",
            "",
            "| URL | Hits |",
            "| --- | --- |",
        ]
        for url, cnt in list(top_404.items())[:10]:
            lines.append(f"| `{url}` | {cnt:,} |")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by BotHunter v{meta['version']}*")

    return '\n'.join(lines)
