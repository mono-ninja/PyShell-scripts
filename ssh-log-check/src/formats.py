"""src/formats.py — per-file format detection and line parsing.

Three container formats share one core: the sshd **message** parsers
(`parse_sshd_message`). The containers:

- **syslog text** — `Sep  4 10:11:12 host sshd[123]: <msg>` — Linux
  auth.log / secure and `journalctl` short output alike. Handles the
  ISO-timestamp rsyslog variant too.
- **journald JSON** — `journalctl -u ssh -o json` exports: one JSON
  object per line, the message in `MESSAGE`, the time in
  `__REALTIME_TIMESTAMP` (µs since epoch).
- **macOS log-show text** — `log show --predicate 'process == "sshd"'`:
  ISO timestamp, fixed columns, `sshd…: <msg>` at the tail.

OpenSSH ≥ 9.8 logs as `sshd-session`; the program matcher accepts the
whole `sshd…` family so fresh Ubuntu/Debian servers parse too.

Syslog timestamps carry no year — the standard month-rollover
heuristic (a month in the future means last year) is applied and the
period is reported per file honestly.
"""
from __future__ import annotations

import gzip
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime

from .analysis import Analyzer, Event, Kind

# --- container formats -----------------------------------------------------

SYSLOG_RE = re.compile(
    r"^(?:\w{3}\s+\d{1,2}\s+)?"            # Sep  4 (month optional)
    r"\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+"       # 10:00:01
    r"(\S+)\s+"                              # host
    r"(sshd[\w-]*)\[\d+\]:\s+(.*)$",        # prog[pid]: msg
)
SYSLOG_ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+"           # 2026-09-01T09:00:00.123+02:00
    r"(\S+)\s+"
    r"(sshd[\w-]*)\[\d+\]:\s+(.*)$",
)
MAC_LOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+[+-]\d{4}\s+"
    r"\S+\s+\S+\s+\S+\s+\d+\s+\d+\s+sshd\S*:\s+(.*)$"
)
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def syslog_datetime(line: str) -> datetime | None:
    """`Sep  4 10:11:12` (year-less — rollover heuristic) or an ISO
    timestamp. Best-effort: None when the prefix isn't a timestamp."""
    m = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if m and m.group(1) in MONTHS:
        now = datetime.now()
        year = now.year
        if MONTHS[m.group(1)] > now.month:
            year -= 1  # a month "in the future" means last year's log
        try:
            return datetime(year, MONTHS[m.group(1)], int(m.group(2)),
                            int(m.group(3)), int(m.group(4)), int(m.group(5)))
        except ValueError:
            return None
    m = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})", line)
    if m:
        try:
            return datetime.fromisoformat(m.group(0))
        except ValueError:
            return None
    return None


# --- the sshd message core ---------------------------------------------------

FAILED_PASSWORD_RE = re.compile(
    r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
ACCEPTED_RE = re.compile(
    r"Accepted (\S+) for (\S+) from (\S+) port (\d+)")
INVALID_USER_RE = re.compile(
    r"Invalid user (\S+) from (\S+) port (\d+)")
MAX_AUTH_RE = re.compile(
    r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)")
DISCONNECT_PREAUTH_RE = re.compile(
    r"Disconnected from (?:(?:authenticating|invalid) user (\S+) |user (\S+) )?(\S+) port (\d+) \[preauth\]")
CLOSED_PREAUTH_RE = re.compile(
    r"Connection closed by (?:(?:authenticating|invalid) user (\S+) )?(\S+) port (\d+) \[preauth\]")
PAM_FAILURE_RE = re.compile(
    r"authentication failure;.*rhost=(\S+)")


def parse_sshd_message(msg: str, ts: datetime | None) -> Event | None:
    """One sshd message → one typed Event. The shared core for every
    container format; new detections get added here, not per-format."""
    m = FAILED_PASSWORD_RE.search(msg)
    if m:
        return Event(kind=Kind.FAILED_PASSWORD, user=m.group(2),
                     ip=m.group(3), port=int(m.group(4)),
                     method=m.group(1), ts=ts, raw=msg)
    m = ACCEPTED_RE.search(msg)
    if m:
        return Event(kind=Kind.ACCEPTED, user=m.group(2), ip=m.group(3),
                     port=int(m.group(4)), method=m.group(1), ts=ts, raw=msg)
    m = INVALID_USER_RE.search(msg)
    if m:
        return Event(kind=Kind.INVALID_USER, user=m.group(1), ip=m.group(2),
                     port=int(m.group(3)), ts=ts, raw=msg)
    m = MAX_AUTH_RE.search(msg)
    if m:
        return Event(kind=Kind.MAX_AUTH, user=m.group(1), ip=m.group(2),
                     ts=ts, raw=msg)
    m = DISCONNECT_PREAUTH_RE.search(msg)
    if m:
        user = m.group(1) or m.group(2)
        return Event(kind=Kind.DISCONNECT_PREAUTH, user=user,
                     ip=m.group(3), port=int(m.group(4)), ts=ts, raw=msg)
    m = CLOSED_PREAUTH_RE.search(msg)
    if m:
        return Event(kind=Kind.CLOSED_PREAUTH, user=m.group(1),
                     ip=m.group(2), port=int(m.group(3)), ts=ts, raw=msg)
    m = PAM_FAILURE_RE.search(msg)
    if m:
        return Event(kind=Kind.PAM_FAILURE, ip=m.group(1), ts=ts, raw=msg)
    return None


# --- file iteration + per-file stats -------------------------------------------

@dataclass
class FileStats:
    path: str
    format: str = ""       # syslog | journald-json | mac-log | empty | text
    lines: int = 0
    matched: int = 0


def open_maybe_gz(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def sniff_format(path: str) -> str:
    """Read the first non-empty line and classify the container."""
    try:
        with open_maybe_gz(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and "MESSAGE" in obj:
                            return "journald-json"
                    except ValueError:
                        pass
                    return "text"
                if MAC_LOG_RE.match(line):
                    return "mac-log"
                if SYSLOG_RE.match(line) or SYSLOG_ISO_RE.match(line):
                    return "syslog"
                return "text"
    except OSError:
        return "error"
    return "empty"


def iter_log_files(logs_dir: str):
    """Every regular file in the folder (non-recursive) — the per-file
    sniff decides what's parseable; anything else reports as skipped."""
    for name in sorted(os.listdir(logs_dir)):
        path = os.path.join(logs_dir, name)
        if os.path.isfile(path) and not name.startswith("."):
            yield path


def parse_file(path: str, analyzer: Analyzer) -> FileStats:
    """One file into the analyzer, format detected by sniffing. Skipped
    files still count their lines so the report can show why."""
    fmt = sniff_format(path)
    stats = FileStats(path=path, format=fmt)
    if fmt in ("text", "error", "empty"):
        # Still count lines for the honest "0 events" report.
        try:
            with open_maybe_gz(path) as fh:
                stats.lines = sum(1 for _ in fh)
        except OSError:
            pass
        return stats

    with open_maybe_gz(path) as fh:
        for line in fh:
            stats.lines += 1
            event = None
            if fmt == "syslog":
                line = line.rstrip("\n")
                m_iso = SYSLOG_ISO_RE.match(line)
                m = m_iso or SYSLOG_RE.match(line)
                if m:
                    if m_iso:
                        # The ISO variant carries the full timestamp in
                        # group(1); the classic one needs the year
                        # heuristic on the bare month-day prefix.
                        ts = datetime.fromisoformat(m_iso.group(1))
                        msg = m_iso.group(4)
                    else:
                        ts = syslog_datetime(line)
                        msg = m.group(3)
                    event = parse_sshd_message(msg, ts)
            elif fmt == "mac-log":
                m = MAC_LOG_RE.match(line.rstrip("\n"))
                if m:
                    ts = None
                    try:
                        ts = datetime.fromisoformat(m.group(1))
                    except ValueError:
                        pass
                    event = parse_sshd_message(m.group(2), ts)
            elif fmt == "journald-json":
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(obj, dict):
                    continue
                msg = obj.get("MESSAGE")
                if not isinstance(msg, str):
                    continue
                ts = None
                raw_us = obj.get("__REALTIME_TIMESTAMP")
                if raw_us and str(raw_us).isdigit():
                    ts = datetime.fromtimestamp(int(raw_us) / 1_000_000)
                event = parse_sshd_message(msg, ts)
            if event is not None:
                analyzer.add(event, source=os.path.basename(path))
                stats.matched += 1
    return stats
