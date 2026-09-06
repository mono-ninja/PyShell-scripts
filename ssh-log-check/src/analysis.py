"""src/analysis.py — aggregation over parsed events.

The questions the operator brings to an sshd log:

- **Who is hammering us?** — failed attempts per IP (brute force),
  the usernames tried, invalid-user probes.
- **Did anyone get in?** — accepted logins, and the critical chain:
  failures from one IP *followed by* a success — a brute force that
  may have won.
- **What's the noise floor?** — preauth disconnects (probe scanners),
  the event period, per-user failure counts.

Findings are results: a riddled log is what the operator came to see,
never a run failure.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Kind(str, Enum):
    FAILED_PASSWORD = "failed_password"
    ACCEPTED = "accepted"
    INVALID_USER = "invalid_user"
    MAX_AUTH = "max_auth"
    DISCONNECT_PREAUTH = "disconnect_preauth"
    CLOSED_PREAUTH = "closed_preauth"
    PAM_FAILURE = "pam_failure"


@dataclass
class Event:
    kind: Kind
    ip: str = ""
    user: str = ""
    port: int = 0
    method: str = ""          # publickey / password / keyboard-interactive
    ts: datetime | None = None
    raw: str = ""
    source: str = ""          # file the event came from

    @property
    def is_failure(self) -> bool:
        return self.kind in (Kind.FAILED_PASSWORD, Kind.INVALID_USER,
                             Kind.MAX_AUTH, Kind.PAM_FAILURE)


@dataclass
class IPProfile:
    ip: str
    failures: int = 0
    accepted: list[Event] = field(default_factory=list)
    users_tried: Counter = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def brute_force(self) -> bool:
        return self.failures > 0

    def add(self, event: Event) -> None:
        if event.is_failure:
            self.failures += 1
            if event.user:
                self.users_tried[event.user] += 1
        elif event.kind == Kind.ACCEPTED:
            self.accepted.append(event)
        for attr in ("first_seen", "last_seen"):
            ref = getattr(self, attr)
            if event.ts is not None and (ref is None or
                                         (attr == "first_seen"
                                          and event.ts < ref) or
                                         (attr == "last_seen"
                                          and event.ts > ref)):
                setattr(self, attr, event.ts)


@dataclass
class UserStats:
    user: str
    failures: int = 0
    accepted: int = 0
    ips: set[str] = field(default_factory=set)
    invalid_user_probes: int = 0


class Analyzer:
    """The aggregate over every parsed file. Owns the per-IP and per-user
    views and the chain detection; pure logic, no I/O."""

    def __init__(self, whitelist: set[str] | None = None,
                 bruteforce_threshold: int = 5):
        self.whitelist = whitelist or set()
        self.bruteforce_threshold = bruteforce_threshold
        self.events = 0
        self.ips: dict[str, IPProfile] = {}
        self.users: dict[str, UserStats] = {}
        self.accepted_events: list[Event] = []
        self.preauth_noise = 0
        self.period: tuple[datetime | None, datetime | None] = (None, None)

    # -- ingestion ----------------------------------------------------------

    def add(self, event: Event, source: str = "") -> None:
        if event.ip and event.ip in self.whitelist:
            return  # excluded by the operator, not silently
        event.source = source
        self.events += 1

        if event.kind in (Kind.DISCONNECT_PREAUTH, Kind.CLOSED_PREAUTH):
            self.preauth_noise += 1

        if event.ip:
            profile = self.ips.setdefault(event.ip, IPProfile(event.ip))
            profile.add(event)

        if event.user:
            stats = self.users.setdefault(event.user, UserStats(event.user))
            if event.is_failure:
                stats.failures += 1
            if event.kind == Kind.ACCEPTED:
                stats.accepted += 1
            if event.kind == Kind.INVALID_USER:
                stats.invalid_user_probes += 1
            if event.ip:
                stats.ips.add(event.ip)

        if event.kind == Kind.ACCEPTED:
            self.accepted_events.append(event)

        # Mixed formats mix offset-aware (ISO, macOS) and naive (syslog,
        # journald-local) timestamps — normalize to wall-clock naive before
        # any comparison. Cross-timezone ordering isn't reconciled; logs
        # usually come from one server.
        ts = event.ts.replace(tzinfo=None) if event.ts and event.ts.tzinfo \
            else event.ts
        if ts is not None:
            event.ts = ts
            lo, hi = self.period
            self.period = (ts if lo is None or ts < lo else lo,
                           ts if hi is None or ts > hi else hi)

    # -- questions ------------------------------------------------------------

    def bruteforce_ips(self) -> list[IPProfile]:
        """IPs at or over the threshold, busiest first."""
        flagged = [p for p in self.ips.values()
                   if p.failures >= self.bruteforce_threshold]
        return sorted(flagged, key=lambda p: (-p.failures, p.ip))

    def top_offender_ips(self, limit: int) -> list[str]:
        """Busiest IPs by failure count (geo enrichment order)."""
        ordered = sorted(self.ips.values(),
                         key=lambda p: -p.failures)
        return [p.ip for p in ordered if p.failures > 0][:limit]

    def compromised_candidates(self) -> list[IPProfile]:
        """The critical chain: an IP that failed and then succeeded.
        Order of events matters — a success that came *after* the
        failures (by timestamp when available, file order otherwise)."""
        out = []
        for profile in self.ips.values():
            if not profile.accepted or profile.failures == 0:
                continue
            first_success = min((e.ts for e in profile.accepted
                                 if e.ts is not None), default=None)
            if first_success is not None and profile.last_seen \
                    and profile.last_seen > first_success:
                # Most activity is after the success — a legitimate user
                # who mistyped first. Still listed, but not a "won" case.
                if not any(e.ts < first_success for e in profile.accepted
                           if e.ts is not None) and \
                   profile.failures < self.bruteforce_threshold:
                    continue
            out.append(profile)
        return sorted(out, key=lambda p: (-p.failures, p.ip))

    def tried_usernames(self, limit: int) -> list[tuple[str, int]]:
        """The username wordlist the attackers used, most tried first —
        invalid-user probes plus failed passwords."""
        counter: Counter[str] = Counter()
        for profile in self.ips.values():
            counter.update(profile.users_tried)
        return counter.most_common(limit)
