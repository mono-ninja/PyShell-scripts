"""Attack-pattern regexes and log-format definitions."""
import re

from src.config import Config

def build_patterns(cfg: Config) -> dict:
    # Patterns are matched against a pre-lowercased haystack of
    # ``path + referer + user_agent`` (see parse_line), so every literal here
    # MUST be written lowercase and the ``re.IGNORECASE`` flag is omitted for
    # speed (~3x over the full log). Do NOT mechanically ``.lower()`` these
    # strings — that would corrupt escapes such as ``\S`` / ``\W`` / ``\D``.
    # None of the patterns below use such escapes; keep it that way.
    # When the haystack contains '%', parse_line appends one URL-decoded copy
    # behind the raw text — patterns match either form, and must not assume
    # end-of-string semantics (the haystack never ends where the path ends).
    return {
        # (H2) `--` comment-out: matched when followed by whitespace, '&' or
        # end-of-string. The old `--\s*(?:&|$)` could only fire at the very end
        # of the combined haystack, i.e. never on a real line (referer + UA
        # always follow), so the classic `' OR 1=1--` technique slipped through.
        'SQL Injection':        re.compile(r"(union\s+select|select\s+\*|(?:or|and)\s+1=1|\bdrop\s+table\b|%27\s*(?:or|and|union|select)|--\s*(?:&|\s|$))"),
        'XSS':                  re.compile(r"(<script>|alert\(|javascript:|<img\s|onerror=|onload=)"),
        'Malicious Script':     re.compile(r"(shell\.php|cmd\.php|eval\(|base64_decode|system\(|passthru\()"),
        'Path Traversal':       re.compile(r"(\.\./|\.\.\\|%2e%2e)"),
        'LFI/RFI':              re.compile(r"(/etc/passwd|/etc/shadow|php://input|file://|/proc/self/environ|=https?://)"),
        'Log4Shell':            re.compile(r"\$\{jndi:(ldap|rmi|dns|iiop|rdm|cod)://"),
        'Command Injection':    re.compile(r"(;\s*(ls|id|whoami|cat|wget|curl|nc|bash|sh|python|perl)\b|\|\s*(cat|id|ls)\b|`[^`]+`|\$\([^)]+\))"),
        'XXE':                  re.compile(r"(<!entity|system\s+[\"']file://)"),
        'SSRF':                 re.compile(r"(localhost|127\.0\.0\.1|169\.254\.169\.254|metadata\.google\.internal|\[::1\])"),
        'CRLF Injection':       re.compile(r"%0d%0a"),
        'DNS Rebinding':        re.compile(r"(url=(10\.\d{1,3}\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.))"),
        'WP xmlrpc':            re.compile(r"xmlrpc\.php"),
        'WP Login Brute':       re.compile(r"wp-login\.php"),
        'WP User Enum':         re.compile(r"(\?author=\d+|/wp-json/wp/v2/users|/author/)"),
        'WP Email Enum':        re.compile(r"(wp-login\.php\?loggedout=true|action=lostpassword|wp-login\.php\?checkemail=)"),
        'WP Config Access':     re.compile(r"wp-config\.php"),
        'WP Admin Scan':        re.compile(r"/wp-admin/"),
        'WP Sensitive Files':   re.compile(r"(readme\.html|license\.txt|wp-config\.php\.(bak|old)|\.(sql|bak|old)(?:[/?&\s.]|$))"),
        'WP REST API Probe':    re.compile(r"/wp-json/"),
        'WP REST Auth Bypass':  re.compile(r"/wp-json/wp/v2/(?:posts|users|pages).*context=edit"),
        'WP Plugin Probe':      re.compile(r"/wp-content/plugins/(?!hseo)"),
        'WP Theme Probe':       re.compile(r"/wp-content/themes/"),
        'WP Plugin RCE':        re.compile(r"wp-content/plugins/.*\.(php|txt|bak)\?(?:cmd|exec|code|pass)="),
        'WP Theme RCE':         re.compile(r"wp-content/themes/.*\.php\?(?:action|cmd|code)="),
        'WP Webshell Upload':   re.compile(r"/wp-content/uploads/.*\.(php\d?|phtml|phar)\b"),
        'WP Admin AJAX':        re.compile(r"/wp-admin/admin-ajax\.php"),
        'WP Vuln Plugin Probe': re.compile(r"(revslider|timthumb\.php|wp-file-manager|slider-revolution|yuzo-related-post|wp-gdpr-compliance|duplicator/|backup-wd)"),
        'WP Version Leak':      re.compile(r"(wp-includes|wp-content)/.*\?ver=[\d.]+"),
        'WP Woo Probe':         re.compile(r"(/wp-json/wc/|\?add-to-cart=|\?post_type=product|/my-account/orders/)"),
        'WP Cron Abuse':        re.compile(r"wp-cron\.php"),
        'WP Scanner Probe':     re.compile(r"(wlwmanifest\.xml|wp-links-opml\.php|wp-app\.php|readme\.html|license\.txt)"),
        'WP Trackback Spam':    re.compile(r"wp-trackback\.php"),
        'WP Reg Spam':          re.compile(r"(wp-signup\.php|wp-register\.php|wp-login\.php\?action=register)"),
        'WP Comment Spam':      re.compile(r"wp-comments-post\.php"),
        'WP Feed Scrape':       re.compile(r"(\?feed=rss|/feed/(?:rss|atom|rss2)?|/atom/?$)"),
        'WP Debug Log':         re.compile(r"(wp-content/debug\.log|wp-content/upgrade/|/wp-admin/maint/)"),
        'WP Import/Export':     re.compile(r"(import\.php|export\.php|wp-migrate-db)"),
        'WP PHP Info':          re.compile(r"(phpinfo|info\.php|php\.info)"),
        'WP hseo Activation':   re.compile(r"(action=activate.*plugin=hseo|plugin=hseo.*action=activate)"),
        'WP hseo Install':      re.compile(r"(plugin-install\.php.*hseo|slug=hseo)"),
        'WP hseo File Access':  re.compile(r"wp-content/plugins/hseo/"),
    }


def build_wp_attack_vectors(patterns: dict) -> set:
    result = set()
    prefix = 'WP '
    for name in patterns:
        if name.startswith(prefix) and 'hseo' not in name:
            result.add(name)
    return result

SCANNER_UA_DEFINITE = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|hydra|metasploit|nessus|openvas|acunetix|burpsuite"
    r"|selenium|phantomjs|puppeteer|playwright|headlesschrome|headless\s*chrome|zgrab2|nuclei|httpx)",
    re.IGNORECASE
)

SCANNER_UA_SUSPICIOUS = re.compile(
    r"(python-requests|curl/|go-http-client|libwww-perl)",
    re.IGNORECASE
)

SUSPICIOUS_METHODS = {'PUT', 'DELETE', 'PATCH', 'PROPFIND', 'TRACE', 'CONNECT'}

# Combined Log Format: IP - - [timestamp] "METHOD PATH PROTO" STATUS SIZE "REFERER" "UA"
COMBINED_LOG_RE = re.compile(
    r'^(\S+)'                                  # IP (IPv4 or IPv6)
    r'\s+\S+'                                  # ident
    r'\s+\S+'                                  # authuser
    r'\s+\[([^\]]+)\]'                         # [timestamp]
    r'\s+"(\S+)\s+(\S+)\s+\S+"'               # "METHOD PATH PROTO"
    r'\s+(\d{3})'                              # status
    r'\s+(\d+|-)'                              # size
    r'(?:\s+"([^"]*)")?'                       # "referer" (optional)
    r'(?:\s+"([^"]*)")?'                       # "user-agent" (optional)
)

DATE_PATTERN = re.compile(r"(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})")

# Fast leading-IP extractor for the whitelist short-circuit (P3).
_LEADING_IP_RE = re.compile(r'^(\S+)')
