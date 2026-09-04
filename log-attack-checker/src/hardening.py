"""Static security data: vector sets, hardening fixes, cURL verification commands.

Pure data, no imports. Pattern names are the shared key between
``patterns.build_patterns`` and these maps; renaming a pattern here (or there)
silently drops the matching hardening entry.
"""

# --- Single WP_VECTORS definition (used by display + report) ---
WP_DISPLAY_VECTORS = {
    'WP Login Brute', 'WP xmlrpc', 'WP User Enum', 'WP Config Access',
    'WP Admin Scan', 'WP Sensitive Files', 'WP REST API Probe',
    'WP Plugin Probe', 'WP Theme Probe',
}

SENSITIVE_VECTORS = {
    'WP xmlrpc', 'WP Config Access', 'WP Sensitive Files', 'WP Cron Abuse',
    'WP Login Brute', 'WP Webshell Upload', 'WP Debug Log', 'WP PHP Info',
    'WP Vuln Plugin Probe', 'WP Plugin RCE', 'WP Theme RCE', 'WP Admin Scan',
    'WP REST Auth Bypass', 'WP Scanner Probe', 'LFI/RFI', 'SQL Injection',
    'Command Injection',
}

# --- Attack-chain tiers (C1) ---
# Reconnaissance vectors that ordinary WordPress traffic also triggers. They
# count toward the vector-count threshold only when paired with ≥1 hostile
# vector — on their own they are a normal admin/browsing session, not a chain.
CHAIN_RECON_VECTORS = {
    'WP Admin Scan', 'WP Admin AJAX', 'WP REST API Probe', 'WP Plugin Probe',
    'WP Theme Probe', 'WP Version Leak', 'WP Feed Scrape', 'WP Woo Probe',
    'WP Login Brute', 'WP Cron Abuse', 'WP Scanner Probe', 'WP Comment Spam',
}
# Hostile vectors that indicate a real attack attempt and count fully on their
# own. An IP must trip at least one of these to be eligible for a chain.
CHAIN_HOSTILE_VECTORS = {
    'WP Config Access', 'WP Webshell Upload', 'WP Plugin RCE', 'WP Theme RCE',
    'WP Vuln Plugin Probe', 'WP User Enum', 'WP Debug Log', 'WP Sensitive Files',
    'WP PHP Info', 'WP Import/Export', 'WP xmlrpc', 'WP Email Enum',
    'WP REST Auth Bypass', 'WP Trackback Spam', 'WP Reg Spam',
}

HARDENING_MAP = {
    'WP xmlrpc': {
        'priority': 'CRITICAL',
        'risk': 'Brute-force amplifier: one request = thousands of auth attempts via multicall',
        'nginx': 'location = /xmlrpc.php {\n    deny all;\n}',
        'apache': '<Files "xmlrpc.php">\n    Require all denied\n</Files>',
    },
    'WP Config Access': {
        'priority': 'CRITICAL',
        'risk': 'Exposes database credentials and secret keys',
        'nginx': 'location ~* wp-config\\.php {\n    deny all;\n}',
        'apache': '<Files "wp-config.php">\n    Require all denied\n</Files>',
    },
    'WP Webshell Upload': {
        'priority': 'CRITICAL',
        'risk': 'PHP execution in uploads directory = full server compromise',
        'nginx': 'location ~* /wp-content/uploads/.*\\.(php\\d?|phtml|phar)$ {\n    deny all;\n}',
        'apache': '<DirectoryMatch "/wp-content/uploads/">\n    <FilesMatch "\\.(php|php5|phtml|phar)$">\n        Require all denied\n    </FilesMatch>\n</DirectoryMatch>',
    },
    'WP Vuln Plugin Probe': {
        'priority': 'CRITICAL',
        'risk': 'Targets plugins with known public RCE / file-upload exploits',
        'nginx': 'location ~* /(revslider|timthumb\\.php|wp-file-manager|slider-revolution)/ {\n    deny all;\n}',
        'apache': '<LocationMatch "/(revslider|timthumb|wp-file-manager)/">\n    Require all denied\n</LocationMatch>',
        'extra': 'Remove or update these plugins immediately. Audit wp_options for malicious backdoors.',
    },
    'LFI/RFI': {
        'priority': 'CRITICAL',
        'risk': 'Arbitrary file read or remote code execution via file inclusion',
        'nginx': '# Use ModSecurity + OWASP CRS (recommended)\n# Quick pattern block:\nif ($request_uri ~* "(etc/passwd|proc/self|php://input|file://)") {\n    return 403;\n}',
        'apache': 'SecRule REQUEST_URI "@rx (?i:etc/passwd|proc/self|php://|file://)" \\\n    "id:1001,phase:1,deny,status:403,msg:\'LFI/RFI attempt\'"',
    },
    'SQL Injection': {
        'priority': 'CRITICAL',
        'risk': 'Database extraction, authentication bypass, or data destruction',
        'nginx': '# Enable ModSecurity with OWASP Core Rule Set:\nmodsecurity on;\nmodsecurity_rules_file /etc/nginx/modsec/main.conf;',
        'apache': 'SecRuleEngine On\nInclude modsecurity.d/activated_rules/*.conf',
    },
    'Command Injection': {
        'priority': 'CRITICAL',
        'risk': 'OS command execution leading to full server compromise',
        'nginx': '# ModSecurity + OWASP CRS is the correct fix here\nmodsecurity on;\nmodsecurity_rules_file /etc/nginx/modsec/main.conf;',
        'apache': 'SecRuleEngine On\nInclude modsecurity.d/activated_rules/*.conf',
    },
    'XSS': {
        'priority': 'HIGH',
        'risk': 'Cross-site scripting for session hijacking or defacement',
        'nginx': 'add_header X-XSS-Protection "1; mode=block" always;\nadd_header Content-Security-Policy "default-src \'self\'" always;\n# Also: ModSecurity + OWASP CRS',
        'apache': 'Header always set X-XSS-Protection "1; mode=block"\nHeader always set Content-Security-Policy "default-src \'self\'"',
    },
    'Path Traversal': {
        'priority': 'HIGH',
        'risk': 'Directory traversal to access files outside the web root',
        'nginx': '# Nginx normalises URIs and blocks ../ by default.\n# For encoded variants add ModSecurity.\n# Ensure merge_slashes on; (default) and use try_files.',
        'apache': 'SecRule REQUEST_URI "@rx \\.\\./" \\\n    "id:1002,phase:1,deny,status:403,msg:\'Path traversal\'"',
    },
    'WP Cron Abuse': {
        'priority': 'HIGH',
        'risk': 'External wp-cron.php requests consume PHP workers — DoS vector',
        'nginx': 'location = /wp-cron.php {\n    allow 127.0.0.1;\n    deny all;\n}',
        'apache': '<Files "wp-cron.php">\n    Require local\n</Files>',
        'extra': "Disable HTTP cron in wp-config.php:\n    define('DISABLE_WP_CRON', true);\nAdd real system cron:\n    */5 * * * * php /var/www/html/wp-cron.php",
    },
    'WP Login Brute': {
        'priority': 'HIGH',
        'risk': 'Credential stuffing and brute force against wp-login.php',
        'nginx': 'limit_req_zone $binary_remote_addr zone=wplogin:10m rate=5r/m;\n\nlocation = /wp-login.php {\n    limit_req zone=wplogin burst=3 nodelay;\n    # Optionally restrict to known admin IPs:\n    # allow YOUR_ADMIN_IP;\n    # deny all;\n}',
        'apache': '# Requires mod_ratelimit or mod_evasive\n<Location "/wp-login.php">\n    SetOutputFilter RATE_LIMIT\n    SetEnv rate-limit 400\n</Location>',
    },
    'WP Admin Scan': {
        'priority': 'HIGH',
        'risk': 'Admin panel reconnaissance and credential attacks',
        'nginx': '# Restrict wp-admin to known IPs:\nlocation /wp-admin/ {\n    allow YOUR_ADMIN_IP;\n    deny all;\n}',
        'apache': '<Directory "/var/www/html/wp-admin/">\n    Require ip YOUR_ADMIN_IP\n</Directory>',
    },
    'WP REST Auth Bypass': {
        'priority': 'HIGH',
        'risk': 'REST API context=edit parameter can expose private data or bypass auth',
        'nginx': 'if ($args ~* "context=edit") {\n    return 403;\n}',
        'apache': '<IfModule mod_rewrite.c>\n    RewriteCond %{QUERY_STRING} context=edit [NC]\n    RewriteRule .* - [F,L]\n</IfModule>',
    },
    'WP Debug Log': {
        'priority': 'HIGH',
        'risk': 'debug.log may expose credentials, stack traces, and internal paths',
        'nginx': 'location ~* /wp-content/debug\\.log {\n    deny all;\n}',
        'apache': '<Files "debug.log">\n    Require all denied\n</Files>',
        'extra': "Also in wp-config.php: define('WP_DEBUG_LOG', false); or move log outside web root.",
    },
    'WP PHP Info': {
        'priority': 'HIGH',
        'risk': 'phpinfo() exposes PHP version, server config, and environment variables',
        'nginx': 'location ~* (phpinfo\\.php|info\\.php|php\\.info) {\n    deny all;\n}',
        'apache': '<FilesMatch "(phpinfo\\.php|info\\.php|php\\.info)">\n    Require all denied\n</FilesMatch>',
    },
    'WP Sensitive Files': {
        'priority': 'HIGH',
        'risk': 'Backup files, SQL dumps and readme expose credentials and version info',
        'nginx': 'location ~* \\.(sql|bak|old|swp|log|gz|tar)$ {\n    deny all;\n}\nlocation ~* /(readme\\.html|license\\.txt) {\n    deny all;\n}',
        'apache': '<FilesMatch "\\.(sql|bak|old|swp|log|gz|tar)$">\n    Require all denied\n</FilesMatch>\n<FilesMatch "(readme\\.html|license\\.txt)">\n    Require all denied\n</FilesMatch>',
    },
    'WP Admin AJAX': {
        'priority': 'MEDIUM',
        'risk': 'admin-ajax.php abuse for privilege escalation or data extraction',
        'nginx': 'limit_req_zone $binary_remote_addr zone=adminajax:10m rate=30r/m;\n\nlocation = /wp-admin/admin-ajax.php {\n    limit_req zone=adminajax burst=10;\n}',
        'apache': '# Rate-limit via mod_ratelimit or use a WAF rule',
    },
    'WP Plugin Probe': {
        'priority': 'MEDIUM',
        'risk': 'Plugin enumeration and direct PHP execution via plugin files',
        'nginx': 'location ~* /wp-content/plugins/.*\\.php$ {\n    deny all;\n}',
        'apache': '<DirectoryMatch "/wp-content/plugins/">\n    <FilesMatch "\\.php$">\n        Require all denied\n    </FilesMatch>\n</DirectoryMatch>',
    },
    'WP Theme Probe': {
        'priority': 'MEDIUM',
        'risk': 'Theme file exposure and PHP execution attempts',
        'nginx': 'location ~* /wp-content/themes/.*\\.php$ {\n    deny all;\n}',
        'apache': '<DirectoryMatch "/wp-content/themes/">\n    <FilesMatch "\\.php$">\n        Require all denied\n    </FilesMatch>\n</DirectoryMatch>',
    },
    'WP REST API Probe': {
        'priority': 'MEDIUM',
        'risk': 'REST API scanning for user enumeration and data exposure',
        'nginx': '# Block user list endpoint:\nlocation ~* /wp-json/wp/v2/users {\n    deny all;\n}\n# Or restrict REST API entirely for non-logged-in users (in functions.php):\n# add_filter("rest_authentication_errors", fn($r) => is_user_logged_in() ? $r : new WP_Error("401","",["status"=>401]));',
        'apache': '<LocationMatch "/wp-json/wp/v2/users">\n    Require all denied\n</LocationMatch>',
    },
    'WP User Enum': {
        'priority': 'MEDIUM',
        'risk': 'Username harvesting via ?author= parameter for targeted brute force',
        'nginx': 'if ($args ~* "author=\\d+") {\n    return 403;\n}',
        'apache': '<IfModule mod_rewrite.c>\n    RewriteCond %{QUERY_STRING} author=\\d [NC]\n    RewriteRule .* - [F,L]\n</IfModule>',
    },
    'WP Scanner Probe': {
        'priority': 'MEDIUM',
        'risk': 'Universal scanner fingerprints confirm WordPress to automated attack tools',
        'nginx': 'location = /wlwmanifest.xml { deny all; }\nlocation = /wp-links-opml.php { deny all; }\nlocation = /wp-app.php { deny all; }',
        'apache': '<FilesMatch "(wlwmanifest\\.xml|wp-links-opml\\.php|wp-app\\.php)">\n    Require all denied\n</FilesMatch>',
    },
    'WP Version Leak': {
        'priority': 'LOW',
        'risk': 'WordPress and plugin version fingerprinting enables targeted exploits',
        'nginx': '# Handle at WordPress level (add to functions.php):\n# add_filter("style_loader_src", "remove_version_query", 9999);\n# add_filter("script_loader_src", "remove_version_query", 9999);\n# function remove_version_query($src) { return remove_query_arg("ver", $src); }',
        'apache': '# Same — handle at WordPress level or via CDN.',
        'extra': 'Remove readme.html from web root: rm /var/www/html/readme.html',
    },
}

CURL_MAP = {
    'WP xmlrpc': (
        '# GET probe — should return 403/404\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" https://SITE/xmlrpc.php\n\n'
        '# POST multicall — lists all methods if open\n'
        'curl -s -X POST https://SITE/xmlrpc.php \\\n'
        '  -H "Content-Type: text/xml" \\\n'
        "  -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>'\n"
        '# 200 + XML response = OPEN (bad);  403/404 = blocked (good)'
    ),
    'WP Config Access': (
        '# Check all common backup variants\n'
        'for f in wp-config.php wp-config.php.bak wp-config.php.old \\\n'
        '          wp-config.php~ .wp-config.php.swp wp-config.php.save; do\n'
        '  printf "%-32s " "$f"\n'
        '  curl -s -o /dev/null -w "HTTP %{http_code}\\n" "https://SITE/$f"\n'
        'done\n'
        '# HTTP 200 = CRITICAL: credentials are publicly readable'
    ),
    'WP Webshell Upload': (
        '# Find PHP files in uploads (run on server)\n'
        "find /var/www/html/wp-content/uploads/ \\\n"
        "  \\( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \\) 2>/dev/null\n\n"
        '# Test a path found in logs\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  "https://SITE/wp-content/uploads/shell.php"\n'
        '# HTTP 200 = webshell is live — CRITICAL'
    ),
    'WP Vuln Plugin Probe': (
        '# Check if known-vulnerable plugins exist\n'
        'for p in revslider slider-revolution timthumb.php wp-file-manager \\\n'
        '          duplicator backup-wd yuzo-related-post; do\n'
        '  printf "%-30s " "$p"\n'
        '  curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '    "https://SITE/wp-content/plugins/$p/"\n'
        'done\n'
        '# 200/301/302 = plugin present — update or remove immediately'
    ),
    'LFI/RFI': (
        '# Local file inclusion probe\n'
        "curl -s \"https://SITE/?page=../../../../etc/passwd\" | grep -c 'root:'\n\n"
        '# php:// wrapper probe\n'
        "curl -s -X POST \"https://SITE/?file=php://input\" \\\n"
        "  -d '<?php echo md5(\"lfi-test\"); ?>' | grep -c '8f8b8a'\n"
        '# Any match = CRITICAL: file inclusion is exploitable'
    ),
    'SQL Injection': (
        "# Error-based probe\n"
        "curl -s \"https://SITE/?s=1'\" | grep -iE 'sql|syntax|mysql|error'\n\n"
        "# UNION-based probe\n"
        "curl -s \"https://SITE/?id=1+UNION+SELECT+NULL,NULL--\" \\\n"
        "  | grep -i 'union'\n"
        '# SQL errors or data rows in response = injectable'
    ),
    'Command Injection': (
        '# Basic OS command probe\n'
        "curl -s \"https://SITE/?cmd=id\" | grep -E 'uid=|www-data|root'\n\n"
        '# Semicolon injection\n'
        "curl -s \"https://SITE/?host=127.0.0.1%3Bid\" | grep -E 'uid=|www-data'\n"
        '# Command output in response = CRITICAL RCE'
    ),
    'XSS': (
        '# Reflected XSS — check if tags pass through unescaped\n'
        "curl -s \"https://SITE/?s=%3Cscript%3Ealert(xss)%3C%2Fscript%3E\" \\\n"
        "  | grep -i '<script>alert'\n\n"
        '# img onerror variant\n'
        "curl -s \"https://SITE/?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E\" \\\n"
        "  | grep -i 'onerror='\n"
        '# Unescaped tag in response = reflected XSS'
    ),
    'Path Traversal': (
        '# Classic traversal probe\n'
        "curl -s \"https://SITE/../../../../etc/passwd\" | grep 'root:'\n\n"
        '# URL-encoded variant\n'
        "curl -s \"https://SITE/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd\" \\\n"
        "  | grep 'root:'\n"
        '# /etc/passwd content = traversal possible'
    ),
    'WP Cron Abuse': (
        '# Check external accessibility — should return 403\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  "https://SITE/wp-cron.php"\n\n'
        '# Measure response time (high time = heavy tasks triggered)\n'
        'curl -s -o /dev/null \\\n'
        '  -w "HTTP %{http_code}  time: %{time_total}s\\n" \\\n'
        '  "https://SITE/wp-cron.php?doing_wp_cron=1"\n'
        '# HTTP 200 = accessible externally (bad);  403 = protected (good)'
    ),
    'WP Login Brute': (
        '# POST login attempt — check response code and rate limiting\n'
        'curl -s -X POST https://SITE/wp-login.php \\\n'
        '  -d "log=admin&pwd=wrongpassword&wp-submit=Log+In&testcookie=1" \\\n'
        '  -H "Cookie: wordpress_test_cookie=WP+Cookie+check" \\\n'
        '  -o /dev/null -w "HTTP %{http_code}\\n"\n\n'
        '# Check for rate-limit headers\n'
        'curl -sI https://SITE/wp-login.php \\\n'
        '  | grep -i "x-ratelimit\\|retry-after\\|x-frame-options"\n'
        '# 302 = login succeeded;  200 = failed;  429 = rate limited (good)'
    ),
    'WP Admin Scan': (
        '# Check wp-admin accessibility\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  -L https://SITE/wp-admin/\n\n'
        '# POST to admin-ajax without auth\n'
        'curl -s -X POST https://SITE/wp-admin/admin-ajax.php \\\n'
        '  -d "action=query-attachments" \\\n'
        '  -w "\\nHTTP %{http_code}\\n"\n'
        '# wp-admin should 302→login;  admin-ajax 400 = ok;  200 = investigate'
    ),
    'WP REST Auth Bypass': (
        '# Check if context=edit leaks private fields without auth\n'
        'curl -s "https://SITE/wp-json/wp/v2/users?context=edit" \\\n'
        "  | python3 -m json.tool 2>/dev/null | grep -E '\"email\"|\"capabilities\"'\n\n"
        '# Check authenticated-only fields on posts\n'
        'curl -s "https://SITE/wp-json/wp/v2/posts?context=edit" \\\n'
        '  | python3 -m json.tool 2>/dev/null | head -30\n'
        '# Emails / capabilities visible = auth bypass present'
    ),
    'WP Debug Log': (
        '# Check if debug.log is publicly readable\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  "https://SITE/wp-content/debug.log"\n\n'
        '# Read first 1000 bytes\n'
        'curl -s --range 0-1000 \\\n'
        '  "https://SITE/wp-content/debug.log"\n'
        '# HTTP 200 + content = log exposed (HIGH risk)'
    ),
    'WP PHP Info': (
        '# Check common phpinfo filenames\n'
        'for f in phpinfo.php info.php php.info test.php php_info.php; do\n'
        '  printf "%-20s " "$f"\n'
        '  curl -s -o /dev/null -w "HTTP %{http_code}\\n" "https://SITE/$f"\n'
        'done\n'
        '# HTTP 200 = phpinfo exposed — delete the file immediately'
    ),
    'WP Sensitive Files': (
        '# Scan for exposed backup and config files\n'
        'for f in readme.html license.txt .env .env.bak .env.old .env.example \\\n'
        '          wp-config.php.bak database.sql backup.sql dump.sql db.sql; do\n'
        '  printf "%-28s " "$f"\n'
        '  curl -s -o /dev/null -w "HTTP %{http_code}\\n" "https://SITE/$f"\n'
        'done\n'
        '# HTTP 200 = file exposed;  403/404 = protected (good)'
    ),
    'WP Admin AJAX': (
        '# Test POST to admin-ajax without authentication\n'
        'curl -s -X POST https://SITE/wp-admin/admin-ajax.php \\\n'
        '  -d "action=heartbeat&_nonce=invalid" \\\n'
        '  -w "\\nHTTP %{http_code}\\n"\n\n'
        '# Test rate limiting — send 5 rapid requests\n'
        'for i in $(seq 1 5); do\n'
        '  curl -s -X POST https://SITE/wp-admin/admin-ajax.php \\\n'
        '    -d "action=heartbeat" -o /dev/null -w "HTTP %{http_code}\\n"\n'
        'done\n'
        '# All 200 with no slowdown = no rate limiting (bad)'
    ),
    'WP Plugin Probe': (
        '# Check if plugin PHP files are directly executable\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  "https://SITE/wp-content/plugins/hello.php"\n\n'
        '# Test a plugin file found in logs\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  "https://SITE/wp-content/plugins/PLUGIN_NAME/FILE.php"\n'
        '# 403 = PHP execution blocked (good);  200 = directly accessible (bad)'
    ),
    'WP Theme Probe': (
        '# Check if theme PHP files are directly callable\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  "https://SITE/wp-content/themes/THEME_NAME/functions.php"\n\n'
        '# Check for data files exposed in logs\n'
        'curl -s "https://SITE/wp-content/themes/THEME_NAME/data.json" \\\n'
        '  | python3 -m json.tool 2>/dev/null | head -20\n'
        '# 403 for .php = good;  data.json — review what it exposes'
    ),
    'WP REST API Probe': (
        '# Check user enumeration via REST API\n'
        'curl -s "https://SITE/wp-json/wp/v2/users" \\\n'
        "  | python3 -m json.tool 2>/dev/null | grep -E '\"slug\"|\"name\"'\n\n"
        '# Check general API accessibility\n'
        'curl -s -o /dev/null -w "HTTP %{http_code}\\n" \\\n'
        '  "https://SITE/wp-json/wp/v2/posts"\n'
        '# Username list visible = enumeration possible'
    ),
    'WP User Enum': (
        '# Enumerate users via ?author= redirect\n'
        'for i in 1 2 3 4 5; do\n'
        '  echo -n "?author=$i => "\n'
        '  curl -s -o /dev/null -w "%{redirect_url}\\n" \\\n'
        '    "https://SITE/?author=$i" | grep -oP "/author/\\K[^/]+"\n'
        'done\n\n'
        '# REST API user list\n'
        'curl -s "https://SITE/wp-json/wp/v2/users" \\\n'
        '  | python3 -c "import sys,json; [print(u[\'slug\']) for u in json.load(sys.stdin)]" 2>/dev/null\n'
        '# Usernames in output = enumeration possible'
    ),
    'WP Scanner Probe': (
        '# Check if scanner fingerprint files are accessible\n'
        'for f in wlwmanifest.xml wp-links-opml.php wp-app.php; do\n'
        '  printf "%-25s " "$f"\n'
        '  curl -s -o /dev/null -w "HTTP %{http_code}\\n" "https://SITE/$f"\n'
        'done\n'
        '# 403/404 = blocked (good);  200 = helps scanners confirm WordPress'
    ),
    'WP Version Leak': (
        '# Extract all ?ver= version strings from the homepage\n'
        "curl -s \"https://SITE/\" \\\n"
        "  | grep -oE 'ver=[0-9][0-9.]+' | sort -u\n\n"
        '# Check if readme.html reveals core version\n'
        'curl -s "https://SITE/readme.html" \\\n'
        '  | grep -i "version"\n'
        '# Output shows exact WP + plugin versions visible to attackers'
    ),
}
