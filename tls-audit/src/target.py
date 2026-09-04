"""Target parsing — turn whatever the operator typed into host + port.

TLS speaks to a **host:port**, not a URL, so everything else in the
input is politely ignored: ``https://example.com/path?x=1``,
``example.com:8443`` and ``example.com`` all audit the same thing
(ports 443 and 8443 respectively). Bare IPs work too — SNI is skipped
for them, exactly as a browser would.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

DEFAULT_PORT = 443


class TargetError(ValueError):
    """The input cannot be read as a TLS target."""


def parse_target(raw: str) -> tuple[str, int]:
    """``host, port`` from any of: host, host:port, scheme://host[:port][/…].

    Raises :class:`TargetError` (the caller turns it into exit 2) on an
    empty input, a port that isn't 1–65535, or a host with no letters,
    digits, dots, or hyphens left in it.
    """
    text = (raw or "").strip()
    if not text:
        raise TargetError("empty target")

    # A scheme means URL-shaped input: let urlsplit take host and port,
    # and ignore everything after the authority.
    if "://" in text:
        try:
            parts = urlsplit(text)
        except ValueError as exc:
            raise TargetError(f"unparsable URL: {exc}") from exc
        host = parts.hostname or ""
        port = parts.port
        if parts.scheme not in ("http", "https"):
            raise TargetError(
                f"scheme {parts.scheme!r} ignored — this tool audits TLS "
                f"endpoints (host[:port])")
    else:
        # host[:port] — but mind an unbracketed IPv6 literal, which
        # carries colons of its own.
        host, port, had_brackets = _split_hostport(text)

    host = host.strip("[]").lower()
    if not host:
        raise TargetError("no host in the target")

    if port is None:
        port = DEFAULT_PORT
    if not 1 <= port <= 65535:
        raise TargetError(f"port {port} out of range 1–65535")

    is_ip = _is_ip_literal(host)
    if not is_ip and not _plausible_hostname(host):
        raise TargetError(f"{host!r} does not look like a hostname or IP")
    return host, port


def _split_hostport(text: str) -> tuple[str, int | None, bool]:
    """host, port, was-bracketed from ``host:port`` / ``[v6]:port`` / ``host``."""
    if text.startswith("["):                        # [::1]:8443 / [::1]
        host, _, rest = text[1:].partition("]")
        if not rest:
            return host, None, True
        if not rest.startswith(":"):
            raise TargetError(f"unexpected text after ]: {rest!r}")
        return host, _int_port(rest[1:]), True
    # Exactly one colon means host:port; more (and not bracketed) is a
    # bare IPv6 literal, which has no port part.
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        return host, _int_port(port), False
    if ":" in text:
        return text, None, False
    return text, None, False


def _int_port(raw: str) -> int:
    try:
        return int(raw)
    except ValueError as exc:
        raise TargetError(f"port {raw!r} is not a number") from exc


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _plausible_hostname(host: str) -> bool:
    if len(host) > 253 or not host:
        return False
    labels = host.split(".")
    return all(label and len(label) <= 63
               and all(ch.isalnum() or ch == "-" for ch in label)
               and not label.startswith("-") and not label.endswith("-")
               for label in labels)
