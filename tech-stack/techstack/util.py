"""Shared utilities: URL/hostname handling and eTLD+1.

Carried over from an earlier PyShell tool: ``normalize_url``,
``registrable_domain`` (critical for third-party grouping), ``hostname_of``
and ``resolve_url``. The DNS/subprocess helpers are intentionally NOT copied —
Tech Stack never runs ``dig`` and never resolves anything itself; it only reads
what the browser fetcher returns.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit, urljoin

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,62})?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62})?)*$"
)


def normalize_url(raw: str) -> str:
    s = raw.strip()
    if not re.match(r"^https?://", s, re.I):
        s = "https://" + s
    hash_idx = s.find("#")
    if hash_idx != -1:
        s = s[:hash_idx]
    try:
        parts = urlsplit(s)
        return urlunsplit(parts)
    except Exception:
        return s


def hostname_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except Exception:
        return ""


def is_valid_hostname(hostname: str) -> bool:
    """Strict DNS-name allowlist — guards against shell/URL injection."""
    return bool(_HOSTNAME_RE.match(hostname))


def resolve_url(maybe_relative: str, base: str) -> str:
    try:
        return urljoin(base, maybe_relative)
    except Exception:
        return maybe_relative


# ── eTLD+1 ──────────────────────────────────────────────────────────────────
# Pragmatic Public Suffix List subset for the common multi-label suffixes. For
# anything unknown we fall back to last-two-labels, which is correct for the
# overwhelming majority of registered domains. This avoids a runtime network
# fetch of the full PSL.
_MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
    "com.ua", "org.ua", "net.ua", "gov.ua", "in.ua", "at.ua", "kiev.ua",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "com.cn", "net.cn", "org.cn",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.in", "net.in", "org.in", "gov.in", "firm.in", "gen.in",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "org.mx", "net.mx", "gob.mx",
    "co.kr", "or.kr", "ne.kr",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.tw", "net.tw", "org.tw",
    "com.ar", "net.ar", "org.ar",
    "co.za", "net.za", "org.za", "web.za",
    "co.il", "net.il", "org.il", "gov.il",
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "info.pl", "biz.pl",
    "co.id", "net.id", "or.id", "web.id",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ph", "net.ph", "org.ph",
    "com.vn", "net.vn", "org.vn", "gov.vn",
    "co.th", "or.th", "in.th",
    "com.sa", "net.sa", "org.sa",
    "com.eg", "net.eg", "org.eg",
    "com.pk", "net.pk", "org.pk",
    "co.ke", "or.ke",
    "github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app",
    "pages.dev", "onrender.com", "fly.dev", "web.app", "firebaseapp.com",
    "pythonanywhere.com", "readthedocs.io", "surge.sh",
    "eu.org", "pp.ru",
}


def registrable_domain(hostname: str) -> str:
    """Compute eTLD+1 (registrable domain) from a hostname.

    Third-party grouping targets the apex even when the URL is a subdomain
    (e.g. ``www.googletagmanager.com`` -> ``googletagmanager.com``).
    """
    host = hostname.lower().rstrip(".")
    if not host:
        return hostname
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    for n in (3, 4):
        if len(labels) >= n + 1:
            suffix = ".".join(labels[-n:])
            if suffix in _MULTI_LABEL_TLDS:
                return ".".join(labels[-(n + 1):])
    return ".".join(labels[-2:])
