"""Single measurement: phased connection timing for one HTTP(S) request.

Why stdlib socket/ssl/http.client instead of ``requests``: ``requests`` cannot
split the connect/TLS phases without hacking the adapter. Doing the connect by
hand fixes exact phase boundaries:

    t0            start
    t_dns         after getaddrinfo
    t_conn        after TCP connect
    t_tls         after TLS handshake (None for http://)
    t_ttfb        after response headers (getresponse returns)
    t_total       after the full body is read

``resp.read()`` is always called to completion — otherwise ``total`` would lie
about the transfer phase. ``TCP_NODELAY`` is set on the socket so Nagle does
not add ~40 ms of noise to small requests. ``Accept-Encoding: identity`` is
sent by default; ``--gzip`` switches it to ``gzip`` (compressed bytes are kept
as-is — that is a deliberately different measurement).
"""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from time import perf_counter
from urllib.parse import urlparse, urlunparse

from . import __version__
from .errors import InvalidURL, short_error

DEFAULT_USER_AGENT = f"srvtime/{__version__}"


# ── Data model ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Timing:
    """Phase durations in seconds. ``tls`` is None for plain http://."""

    dns: float
    connect: float
    tls: float | None
    ttfb: float
    total: float

    @property
    def server(self) -> float:
        """Pure server time: ttfb minus the network setup phases."""
        return self.ttfb - (self.dns + self.connect + (self.tls or 0.0))

    @property
    def transfer(self) -> float:
        """Body transfer: total minus ttfb."""
        return self.total - self.ttfb


@dataclass(frozen=True)
class Result:
    """One measurement. ``error`` is set instead of raising."""

    url: str
    status: int
    size: int
    timing: Timing
    server_timing: dict[str, float]
    started_at: datetime
    error: str | None = None


ZERO_TIMING = Timing(0.0, 0.0, None, 0.0, 0.0)


# ── Config ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ProbeConfig:
    timeout: float = 10.0
    insecure: bool = False
    ipv4: bool = False
    ipv6: bool = False
    gzip: bool = False
    user_agent: str = DEFAULT_USER_AGENT


# ── Prober ─────────────────────────────────────────────────────────────────


class Prober:
    """Measures one URL with phase breakdown, optionally reusing the connection.

    ``probe(..., reuse=True)`` keeps the underlying ``HTTPConnection`` alive
    between calls so DNS/TCP/TLS are ~0 from the second request on.
    A broken reused connection is discarded and rebuilt fresh for that one
    request, so a stale keep-alive never aborts the series.
    """

    def __init__(self, url: str, config: ProbeConfig):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise InvalidURL(f"unsupported scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise InvalidURL("URL is missing a host")

        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.base_path = parsed.path or "/"
        if parsed.query:
            self.base_path += "?" + parsed.query
        self.config = config

        if self.scheme == "https":
            ctx = ssl.create_default_context()
            if config.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._ssl_ctx: ssl.SSLContext | None = ctx
        else:
            self._ssl_ctx = None

        if config.ipv4 and config.ipv6:
            raise InvalidURL("--ipv4 and --ipv6 are mutually exclusive")
        if config.ipv4:
            self._family = socket.AF_INET
        elif config.ipv6:
            self._family = socket.AF_INET6
        else:
            self._family = socket.AF_UNSPEC

        self._conn: http.client.HTTPConnection | None = None

    def full_url(self, path: str) -> str:
        return urlunparse((self.scheme, f"{self.host}:{self.port}", path, "", "", ""))

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def probe(
        self,
        *,
        method: str = "GET",
        path: str | None = None,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        reuse: bool = False,
    ) -> Result:
        """Perform one measurement. Never raises — returns a Result with
        ``error`` set on failure."""
        path = path if path is not None else self.base_path
        url = self.full_url(path)
        started_at = datetime.now(timezone.utc)
        req_headers = self._build_headers(headers, reuse)
        conn: http.client.HTTPConnection | None = None
        reused = False
        dns = connect = 0.0
        tls: float | None = None

        try:
            t0 = perf_counter()

            if reuse and self._conn is not None and self._conn.sock is not None:
                conn = self._conn
                reused = True
                tls = 0.0 if self._ssl_ctx is not None else None
            else:
                # DNS
                addrs = socket.getaddrinfo(
                    self.host, self.port, self._family, socket.SOCK_STREAM
                )
                t_dns = perf_counter()
                dns = t_dns - t0

                # TCP — try the returned addresses until one connects
                sock = None
                last_exc: Exception | None = None
                for family, _, _, _, addr in addrs:
                    try:
                        s = socket.socket(family, socket.SOCK_STREAM)
                        s.settimeout(self.config.timeout)
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        s.connect(addr)
                        sock = s
                        break
                    except OSError as exc:
                        if s is not None:
                            try:
                                s.close()
                            except Exception:
                                pass
                        last_exc = exc
                if sock is None:
                    raise last_exc or ConnectionError("no address succeeded")
                t_conn = perf_counter()
                connect = t_conn - t_dns

                # TLS
                if self._ssl_ctx is not None:
                    sock = self._ssl_ctx.wrap_socket(sock, server_hostname=self.host)
                    t_tls = perf_counter()
                    tls = t_tls - t_conn
                else:
                    t_tls = t_conn

                conn = http.client.HTTPConnection(self.host, self.port, timeout=self.config.timeout)
                conn.sock = sock
                if reuse:
                    self._conn = conn

            # Request — getresponse blocks until the response headers arrive
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            t_ttfb = perf_counter()
            data = resp.read()
            t_total = perf_counter()

            status = resp.status
            server_timing = parse_server_timing(resp.getheader("Server-Timing"))

            if not reuse:
                try:
                    conn.close()
                except Exception:
                    pass
                if conn is self._conn:
                    self._conn = None

            timing = Timing(
                dns=dns,
                connect=connect,
                tls=tls,
                ttfb=t_ttfb - t0,
                total=t_total - t0,
            )
            return Result(
                url=url,
                status=status,
                size=len(data),
                timing=timing,
                server_timing=server_timing,
                started_at=started_at,
            )
        except Exception as exc:
            # A failed reused connection is dropped so the next probe rebuilds.
            if reused and conn is self._conn:
                try:
                    conn.close()
                except Exception:
                    pass
                self._conn = None
            elif conn is not None and conn is not self._conn:
                try:
                    conn.close()
                except Exception:
                    pass
            return Result(
                url=url,
                status=0,
                size=0,
                timing=ZERO_TIMING,
                server_timing={},
                started_at=started_at,
                error=short_error(exc),
            )

    def _build_headers(
        self, extra: dict[str, str] | None, reuse: bool
    ) -> dict[str, str]:
        headers: dict[str, str] = {
            "User-Agent": self.config.user_agent,
            "Accept-Encoding": "gzip" if self.config.gzip else "identity",
            "Connection": "keep-alive" if reuse else "close",
            "Host": self.host,
        }
        if extra:
            for key, value in extra.items():
                headers[key] = value
        return headers


# ── Server-Timing parser (W3C Server Timing spec) ───────────────────────────


def parse_server_timing(header: str | None) -> dict[str, float]:
    """Parse a ``Server-Timing`` header into ``{metric: dur_ms}``.

    Only metrics carrying a ``dur`` parameter are returned (others, like
    ``cache;desc="hit"``, convey no duration). ``dur`` is in milliseconds per
    the W3C Server Timing spec and is kept in that unit. Malformed values are
    skipped, not raised.
    """
    result: dict[str, float] = {}
    if not header:
        return result
    for metric in _split_top(header, ","):
        parts = _split_top(metric, ";")
        name = parts[0].strip()
        if not name:
            continue
        for param in parts[1:]:
            key, sep, val = param.partition("=")
            if not sep:
                continue
            if key.strip().lower() != "dur":
                continue
            value = val.strip().strip('"')
            try:
                result[name] = float(value)
            except ValueError:
                pass
    return result


def _split_top(text: str, sep: str) -> list[str]:
    """Split on ``sep`` ignoring separators inside double-quoted strings."""
    parts: list[str] = []
    buf: list[str] = []
    in_quotes = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == sep and not in_quotes:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts
