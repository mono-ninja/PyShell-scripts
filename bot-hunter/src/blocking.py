"""Generate nginx and .htaccess blocking rules from detection results.

The rules target three categories of bad traffic:

- **Disguised bots** — IPs with browser UAs but systematic scanning behaviour.
- **Suspicious subnets** — /24 (or consolidated /16) ranges with coordinated
  botnet-like activity.
- **Scraper/scanner UAs** — known patterns like ``curl``, ``python-requests``,
  ``Scrapy``, ``zgrab``, etc.  The UA patterns come from
  ``classifier.SCRAPER_BLOCK_PATTERNS`` (derived from ``BOT_SIGNATURES``) so
  adding a scraper signature automatically ships its blocking rule.
"""

import ipaddress
from collections import defaultdict
from pathlib import Path

from src.classifier import SCRAPER_BLOCK_PATTERNS


def _ht_comment(text: str) -> str:
    """Collapse whitespace in *text* so it stays on one comment line.

    Apache parses ``#`` only at the start of a line — a newline inside a
    log-derived reason/evidence would split the comment and leave a bare
    fragment that Apache tries to parse as a directive, breaking the site.
    """
    return ' '.join(text.split())


def _consolidate_subnets(block_subnets: list[dict]) -> list[dict]:
    """Merge 5+ entries from the same parent supernet into a single rule.

    IPv4 /24s are grouped under their /16; IPv6 /64s under their /48.
    Uses :mod:`ipaddress` so octet/CIDR boundaries are respected exactly.
    """
    parent_groups: dict = defaultdict(list)
    parent_keys: list[str | None] = []
    for e in block_subnets:
        cidr = e['cidr']
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            new_prefix = 16 if net.version == 4 else 48
            parent_key = str(net.supernet(new_prefix=new_prefix))
        except ValueError:
            parent_key = None
        parent_keys.append(parent_key)
        parent_groups[parent_key].append(e)

    result = []
    seen_parents: set = set()
    for e, key in zip(block_subnets, parent_keys):
        group = parent_groups.get(key, [])
        if key is not None and len(group) >= 5:
            if key not in seen_parents:
                seen_parents.add(key)
                result.append({
                    'cidr':       key,
                    'unique_ips': sum(x['unique_ips'] for x in group),
                    'requests':   sum(x['requests'] for x in group),
                    'confidence': 'HIGH',
                    'note':       f"merged {len(group)} subnets",
                })
        else:
            result.append(e)
    return result


def build_blocking_rules(
    bots_out: dict,
    disguised_bots: list[dict],
    suspicious_subnets: dict,
    domain: str = 'example.com',
    generated_at: str = '',
    conf_filename: str = '',
) -> dict:
    """Build nginx geo/map config and .htaccess rules from detection results."""
    ts = generated_at[:19] if generated_at else ''
    conf_fname = conf_filename or f"{domain}_block.conf"

    # ── Collect IPs to block (disguised bots) ──
    block_ips: list[dict] = []
    for d in disguised_bots:
        confidence = 'HIGH' if d['scan_ratio'] >= 0.70 else 'MEDIUM'
        block_ips.append({
            'ip':         d['ip'],
            'reason':     f"disguised bot - {d['evidence']}",
            'requests':   d['requests'],
            'confidence': confidence,
        })

    # ── Collect subnets to block ──
    # Include only subnets with BOTH 10+ IPs AND 100+ requests to avoid
    # false positives from shared-IP ISPs / corporate ranges.
    raw_subnets: list[dict] = []
    for subnet, sd in suspicious_subnets.items():
        if sd['unique_ips'] < 10 or sd['total_requests'] < 100:
            continue
        confidence = 'HIGH' if sd['unique_ips'] >= 25 else 'MEDIUM'
        raw_subnets.append({
            'cidr':       subnet,
            'unique_ips': sd['unique_ips'],
            'requests':   sd['total_requests'],
            'confidence': confidence,
        })
    block_subnets = _consolidate_subnets(raw_subnets)

    # Remove individual disguised-bot IPs already covered by a blocked subnet.
    # Build the list of blocked networks once (O3: single pass), then do one
    # membership test per candidate IP instead of the old O(subnets × all-IPs)
    # nested walk.  ipaddress handles octet/CIDR boundaries correctly (#2).
    blocked_networks: list = []
    for e in block_subnets:
        try:
            blocked_networks.append(ipaddress.ip_network(e['cidr'], strict=False))
        except ValueError:
            continue

    if blocked_networks:
        def _is_covered(ip: str) -> bool:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(addr in net for net in blocked_networks)

        block_ips = [x for x in block_ips if not _is_covered(x['ip'])]

    # ── Collect UA patterns to block ──
    # Patterns come straight from BOT_SIGNATURES via SCRAPER_BLOCK_PATTERNS —
    # no parallel list to keep in sync.  Exact key lookup is enough: bots_out
    # keys are signature display names, and the renamed "WordPress Cron
    # (curl)" entries are legitimate (filtered out above).
    block_uas: list[dict] = []
    for bot_name, data in bots_out.items():
        if data.get('legitimate') or data.get('category') not in ('scraper', 'scanner'):
            continue
        pattern = SCRAPER_BLOCK_PATTERNS.get(bot_name)
        if not pattern:
            # A scraper/scanner signature without a block_pattern — the
            # signature/blocking parity contract forbids this.
            continue
        block_uas.append({
            'name':    bot_name,
            'pattern': pattern,
            'count':   data['count'],
        })

    total_blocked_req = (
        sum(e['requests'] for e in block_ips) +
        sum(e['requests'] for e in block_subnets) +
        sum(e['count'] for e in block_uas)
    )

    # ── nginx config ──
    ng_lines = [
        f"# BotHunter - Auto-generated blocking rules",
        f"# Domain  : {domain}",
        f"# Created : {ts}",
        f"# Blocks  : {len(block_ips)} IPs  |  {len(block_subnets)} subnets  |  "
        f"{len(block_uas)} UA patterns  (~{total_blocked_req:,} req in analyzed period)",
        f"#",
        f"# INSTALL : copy to /etc/nginx/conf.d/{conf_fname}",
        f"#           add to nginx http{{}} block:  include /etc/nginx/conf.d/{conf_fname};",
        f"#           add to server{{}} block - see snippet at the bottom of this file.",
        f"# RELOAD  : nginx -t && systemctl reload nginx",
        f"",
        f"# -- Block by IP / subnet --",
        f"geo $bh_blocked_ip {{",
        f"    default 0;",
        f"",
    ]

    if block_ips:
        ng_lines.append("    # Disguised bots - browser UA + systematic scanning")
        for e in block_ips:
            pad = max(1, 22 - len(e['ip']) - 3)
            ng_lines.append(
                f"    {e['ip']}/32{' ' * pad}1;  "
                f"# [{e['confidence']}] {e['requests']:,} req | {e['reason']}"
            )
        ng_lines.append("")

    if block_subnets:
        ng_lines.append("    # Suspicious subnets - coordinated botnet activity")
        for e in block_subnets:
            note = f"  <- {e.get('note', '')}" if e.get('note') else ''
            pad = max(1, 22 - len(e['cidr']))
            ng_lines.append(
                f"    {e['cidr']}{' ' * pad}1;  "
                f"# [{e['confidence']}] {e['unique_ips']} IPs, {e['requests']:,} req{note}"
            )
        ng_lines.append("")

    ng_lines += [
        "}",
        "",
        "# -- Block by User-Agent --",
        "map $http_user_agent $bh_blocked_ua {",
        "    default 0;",
        "",
    ]
    if block_uas:
        ng_lines.append("    # Known scrapers and scanners")
        for e in sorted(block_uas, key=lambda x: -x['count']):
            pad = max(1, 28 - len(e['pattern']) - 4)
            ng_lines.append(
                f"    ~*{e['pattern']}{' ' * pad}1;  # {e['name']} ({e['count']:,} req)"
            )
        ng_lines.append("")
    ng_lines.append("}")

    ng_server_snippet = "\n".join([
        "# -- Paste this inside your server {} block --",
        "",
        "if ($bh_blocked_ip) {",
        "    return 444;  # close connection silently (no response to bot)",
        "}",
        "if ($bh_blocked_ua) {",
        "    return 444;",
        "}",
    ])

    # ── .htaccess config ──
    ht_lines = [
        f"# BotHunter - Auto-generated blocking rules",
        f"# Domain : {domain}",
        f"# Created: {ts}",
        f"# Place this block at the TOP of your .htaccess file",
        f"",
    ]

    if block_ips or block_subnets:
        ht_lines += [
            "# -- Block by IP / subnet --",
            "<RequireAll>",
            "    Require all granted",
            "",
        ]
        if block_ips:
            ht_lines.append("    # Disguised bots - browser UA + systematic scanning")
            for e in block_ips:
                ht_lines.append(
                    f"    # [{e['confidence']}] {e['requests']:,} req | "
                    f"{_ht_comment(e['reason'])}"
                )
                ht_lines.append(f"    Require not ip {e['ip']}")
            ht_lines.append("")

        if block_subnets:
            ht_lines.append("    # Suspicious subnets - coordinated botnet activity")
            for e in block_subnets:
                ht_lines.append(
                    f"    # [{e['confidence']}] {e['unique_ips']} IPs, "
                    f"{e['requests']:,} req"
                )
                ht_lines.append(f"    Require not ip {e['cidr']}")
            ht_lines.append("")

        ht_lines += ["</RequireAll>", ""]

    if block_uas:
        ht_lines += [
            "# -- Block by User-Agent --",
            "<IfModule mod_rewrite.c>",
            "    RewriteEngine On",
            "",
            "    # Known scrapers and scanners",
        ]
        last_idx = len(block_uas) - 1
        for i, e in enumerate(sorted(block_uas, key=lambda x: -x['count'])):
            flag = "[NC]" if i == last_idx else "[NC,OR]"
            # Comment on its own line BEFORE the directive: a trailing '#'
            # after [NC,OR] would be parsed as extra RewriteCond arguments.
            ht_lines.append(
                f"    # {_ht_comment(e['name'])} ({e['count']:,} req)"
            )
            ht_lines.append(
                f"    RewriteCond %{{HTTP_USER_AGENT}} {e['pattern']} {flag}"
            )
        ht_lines += [
            "    RewriteRule ^ - [F,L]",
            "</IfModule>",
        ]

    return {
        'nginx':           '\n'.join(ng_lines),
        'nginx_snippet':   ng_server_snippet,
        'htaccess':        '\n'.join(ht_lines),
        'blocked_ips':     block_ips,
        'blocked_subnets': block_subnets,
        'blocked_uas':     block_uas,
    }


def write_blocking_files(blocking: dict, base_path: Path) -> tuple[Path, Path]:
    """Write nginx .conf and .htaccess blocking files next to *base_path*.

    *base_path* is a stem like ``2026-08-28_wpmonitor.com`` (no extension).
    We append explicit suffixes rather than ``Path.with_suffix()``, which would
    treat the dotted domain's TLD as an existing suffix and replace it.
    """
    nginx_path = Path(str(base_path) + '.nginx.conf')
    htaccess_path = Path(str(base_path) + '.htaccess')

    nginx_full = blocking['nginx'] + '\n\n' + blocking['nginx_snippet']
    with open(nginx_path, 'w', encoding='utf-8') as f:
        f.write(nginx_full)
    with open(htaccess_path, 'w', encoding='utf-8') as f:
        f.write(blocking['htaccess'])

    return nginx_path, htaccess_path
