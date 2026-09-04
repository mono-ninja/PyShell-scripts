"""Log file discovery and parsing for Apache/Nginx combined log formats.

Supports plain ``.log``/``.txt`` files, ``.gz``/``.bz2`` compressed archives,
and common rotation schemes (``access.log.1``, ``access_log-20260415``,
``error_log``).  The parser targets the Nginx/Apache *combined* log format,
which covers the overwhelming majority of real-world access logs::

    IP - - [date] "METHOD /path HTTP/x.y" status bytes "referrer" "user-agent"

The Apache **vhost_combined** format (the cPanel default, common in nginx
vhost setups) prepends the virtual host name and is also supported::

    vhost.example.com IP - - [date] "METHOD /path HTTP/x.y" status bytes ...

Lines that match neither format are classified by :func:`classify_skip` so
the report can distinguish a real regex regression from a foreign log format
interleaved in the same file.
"""

import bz2
import gzip
import ipaddress
import re
from datetime import datetime
from pathlib import Path

# Extension set kept for backward compatibility (used in the CLI "no files
# found" message).  Discovery now also matches by name pattern — see below.
LOG_EXTENSIONS = {'.log', '.txt', '.gz', '.bz2'}

# Name-based matching: catches rotated logs that have no recognised extension.
# Matches "access" or "error" followed by any separator/rotation suffix and
# "log" anywhere in the name (e.g. access.log.1, access_log-20260415, error_log).
_LOG_NAME_RE = re.compile(r'(access|error)[\w.-]*log', re.I)

# Apache/Nginx combined log format:
#   IP ident authuser [date] "request" status bytes "referrer" "user-agent"
_LOG_PATTERN = re.compile(
    r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+'
    r'"(\S+)\s+(\S+)\s+[^"]*"\s+'
    r'(\d{3})\s+(\S+)\s+'
    r'"([^"]*)"\s+"([^"]*)"'
)

# Apache vhost_combined format — one extra leading token (the vhost name)
# before the client IP; the rest is identical to combined.  Group numbering
# matches _LOG_PATTERN so both branches share the same extraction code.
_LOG_PATTERN_VHOST = re.compile(
    r'\S+\s+'                                  # vhost name, not captured
    r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+'    # IP ident authuser [date]
    r'"(\S+)\s+(\S+)\s+[^"]*"\s+'
    r'(\d{3})\s+(\S+)\s+'
    r'"([^"]*)"\s+"([^"]*)"'
)

# PHP-FPM access log format (interleaved in some Nginx configs):
#   - -  DD/Mon/YYYY:HH:MM:SS +ZZZZ  METHOD /path  STATUS /real/path  DURATION MEM CPU%
_PHP_FPM_PATTERN = re.compile(
    r'^-\s+-\s+\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\s+\S+\s+\d{3}\s+'
)


def _is_log_file(p: Path) -> bool:
    """Return True if *p* looks like a log file (by name pattern or extension)."""
    if _LOG_NAME_RE.search(p.name):
        return True
    suffixes = ''.join(p.suffixes)
    return p.suffix in LOG_EXTENSIONS or suffixes in LOG_EXTENSIONS


def find_log_files(logs_dir: Path) -> list[Path]:
    """Recursively find log files in *logs_dir* by name pattern or extension."""
    files: list[Path] = []
    if not logs_dir.exists() or not logs_dir.is_dir():
        return files
    for p in logs_dir.rglob('*'):
        if p.is_file() and _is_log_file(p):
            files.append(p)
    files.sort()
    return files


def discover_log_files(logs_dir: Path) -> tuple[list[Path], int]:
    """Like :func:`find_log_files` but also returns the count of non-log files skipped."""
    matched: list[Path] = []
    total_files = 0
    if not logs_dir.exists() or not logs_dir.is_dir():
        return matched, 0
    for p in logs_dir.rglob('*'):
        if not p.is_file():
            continue
        total_files += 1
        if _is_log_file(p):
            matched.append(p)
    matched.sort()
    return matched, total_files - len(matched)


def open_log_file(path: Path):
    """Open *path* for text reading, transparently decompressing .gz/.bz2."""
    suffixes = ''.join(path.suffixes)
    if path.suffix == '.gz' or suffixes.endswith('.gz'):
        return gzip.open(path, 'rt', encoding='utf-8', errors='replace')
    if path.suffix == '.bz2' or suffixes.endswith('.bz2'):
        return bz2.open(path, 'rt', encoding='utf-8', errors='replace')
    return open(path, 'r', encoding='utf-8', errors='replace')


def parse_log_line(line: str) -> dict | None:
    """Parse a single log line into a dict, or return ``None`` on mismatch.

    Tries the plain *combined* format first, then *vhost_combined* (leading
    virtual-host name).  Fields: ip, datetime, method, url (without query
    string), status, size, referrer, user_agent, format (which pattern
    matched).
    """
    stripped = line.strip()
    m = _LOG_PATTERN.match(stripped)
    if m:
        log_format = 'combined'
    else:
        m = _LOG_PATTERN_VHOST.match(stripped)
        if not m:
            return None
        # The vhost branch must not swallow foreign 4-token formats: the
        # token after the vhost name has to be a real IP address.
        try:
            ipaddress.ip_address(m.group(1))
        except ValueError:
            return None
        log_format = 'vhost_combined'
    ip, date_str, method, url, status, size, referrer, ua = m.groups()
    try:
        dt = datetime.strptime(date_str, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError:
        dt = None
    return {
        'ip':         ip,
        'datetime':   dt,
        'method':     method,
        'url':        url.split('?')[0],
        'status':     int(status),
        'size':       int(size) if size.isdigit() else 0,
        'referrer':   referrer,
        'user_agent': ua,
        'format':     log_format,
    }


def classify_skip(line: str) -> str:
    """Classify a line that :func:`parse_log_line` could not parse.

    Returns ``'php-fpm'`` for recognised PHP-FPM access log lines,
    ``'vhost-combined'`` for vhost_combined-shaped lines whose client field
    is not an IP address, or ``'no-match'`` for everything else.  This lets
    the report separate a real regex regression from a foreign log format
    interleaved in the same file.
    """
    stripped = line.strip()
    if _PHP_FPM_PATTERN.match(stripped):
        return 'php-fpm'
    if _LOG_PATTERN_VHOST.match(stripped):
        # Structurally vhost_combined; the only way it reached the skip path
        # is that the client field failed IP validation in parse_log_line.
        return 'vhost-combined'
    return 'no-match'
