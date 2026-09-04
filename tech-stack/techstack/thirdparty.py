"""Third-party inventory: every external host a page pulls from.

Grouped by registrable domain (eTLD+1 from ``util.registrable_domain``), not by
full hostname: ``www.googletagmanager.com`` and ``googletagmanager.com`` are one
row. This is a network-request inventory, not a cookie/GDPR audit — without
simulating a consent mode, "the site leaks data to N hosts" is all we can
honestly say.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .evidence import Evidence, merge
from .util import hostname_of, registrable_domain

# Known domains → purpose. Unknown ones fall back to a TLD/host heuristic.
KNOWN_PURPOSES: dict[str, str] = {
    "googletagmanager.com": "Tag Manager",
    "google-analytics.com": "Analytics",
    "googletagmanager.com.gtag": "Analytics",
    "gstatic.com": "Google Fonts / static",
    "fonts.googleapis.com": "Fonts",
    "fonts.gstatic.com": "Fonts",
    "connect.facebook.net": "Advertising (Meta)",
    "facebook.net": "Advertising (Meta)",
    "doubleclick.net": "Advertising",
    "googlesyndication.com": "Advertising",
    "googleadservices.com": "Advertising",
    "googletagservices.com": "Advertising",
    "jsdelivr.net": "CDN (js)",
    "unpkg.com": "CDN (js)",
    "cdnjs.cloudflare.com": "CDN (js)",
    "cloudflare.com": "CDN",
    "cloudflareinsights.com": "Monitoring",
    "js.stripe.com": "Payments (Stripe)",
    "stripe.com": "Payments (Stripe)",
    "paypal.com": "Payments (PayPal)",
    "paypalobjects.com": "Payments (PayPal)",
    "sentry.io": "Monitoring (Sentry)",
    "sentry-cdn.com": "Monitoring (Sentry)",
    "browser.sentry-cdn.com": "Monitoring (Sentry)",
    "hotjar.com": "Analytics (Hotjar)",
    "clarity.ms": "Analytics (Clarity)",
    "mixpanel.com": "Analytics",
    "segment.io": "Analytics",
    "segment.com": "Analytics",
    "cdn.segment.com": "Analytics",
    "plausible.io": "Analytics",
    "matomo.org": "Analytics",
    "amplitude.com": "Analytics",
    "tiktok.com": "Advertising (TikTok)",
    "taboola.com": "Advertising",
    "outbrain.com": "Advertising",
    "criteo.com": "Advertising",
    "criteo.net": "Advertising",
    "amazon-adsystem.com": "Advertising (Amazon)",
    "aads.com": "Advertising",
    "linkedin.com": "Advertising (LinkedIn)",
    "licdn.com": "Advertising (LinkedIn)",
    "auth0.com": "Auth",
    "okta.com": "Auth",
    "oktacdn.com": "Auth",
    "firebaseio.com": "Auth / DB (Firebase)",
    "firebaseapp.com": "Auth (Firebase)",
    "googleapis.com": "Google API",
    "supabase.co": "Auth / DB",
    "shopify.com": "E-commerce (Shopify)",
    "cdn.shopify.com": "E-commerce (Shopify)",
    "bigcommerce.com": "E-commerce",
    "typekit.net": "Fonts (Adobe)",
    "p.typekit.net": "Fonts (Adobe)",
    "adobedtm.com": "Tag Manager (Adobe)",
    "ajax.googleapis.com": "CDN (Google)",
    "bootstrapcdn.com": "CDN (Bootstrap)",
    "maxcdn.bootstrapcdn.com": "CDN (Bootstrap)",
    "tailwindcss.com": "CDN (Tailwind)",
    "recaptcha.google.com": "Anti-bot (reCAPTCHA)",
    "gstatic.com.recaptcha": "Anti-bot",
    "hcaptcha.com": "Anti-bot (hCaptcha)",
    "challenges.cloudflare.com": "Anti-bot (Turnstile)",
    "gravatar.com": "Avatars",
    "wp.com": "WordPress.com",
    "youtube.com": "Video (YouTube)",
    "ytimg.com": "Video (YouTube)",
    "vimeo.com": "Video (Vimeo)",
    "player.vimeo.com": "Video (Vimeo)",
    "intercom.io": "Chat (Intercom)",
    "intercomcdn.com": "Chat (Intercom)",
    "zendesk.com": "Support (Zendesk)",
    "zopim.org": "Chat",
    "tawk.to": "Chat",
    "crisp.chat": "Chat",
    "jivosite.com": "Chat",
    "typeform.com": "Forms",
    "hsforms.net": "Forms (HubSpot)",
    "hubspot.com": "CRM/Marketing",
}

# Country-code TLD → ISO jurisdiction. Default (com/org/net/io/app) → "US/INTL".
JURISDICTION: dict[str, str] = {
    "ua": "UA", "ru": "RU", "by": "BY", "kz": "KZ",
    "de": "DE", "fr": "FR", "it": "IT", "es": "ES", "nl": "NL", "se": "SE",
    "pl": "PL", "cz": "CZ", "ro": "RO", "bg": "BG", "sk": "SK", "hu": "HU",
    "uk": "GB", "co.uk": "GB", "ie": "IE", "pt": "PT", "gr": "GR",
    "jp": "JP", "kr": "KR", "cn": "CN", "in": "IN", "br": "BR", "mx": "MX",
    "ca": "CA", "au": "AU", "nz": "NZ", "tr": "TR", "il": "IL", "ae": "AE",
    "ch": "CH", "at": "AT", "be": "BE", "dk": "DK", "fi": "FI", "no": "NO",
    "sg": "SG", "hk": "HK", "tw": "TW", "th": "TH", "id": "ID", "vn": "VN",
    "my": "MY", "ph": "PH", "sa": "SA", "eg": "EG", "za": "ZA", "ar": "AR",
    "cl": "CL", "pe": "PE", "ve": "VE", "ec": "EC",
}
DEFAULT_JURISDICTION = "US/INTL"

_FONT_EXTS = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
_IMG_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".avif"}


@dataclass
class ThirdParty:
    domain: str                 # registrable domain (eTLD+1)
    purpose: str
    count: int
    types: list[str] = field(default_factory=list)
    jurisdiction: str = DEFAULT_JURISDICTION
    hosts: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)


def _res_type(url: str, kind: str) -> str:
    path = (urlsplit(url).path or "").lower()
    if kind == "iframe":
        return "iframe"
    if kind == "preconnect":
        return "preconnect"
    if path.endswith(".js") or kind == "script":
        return "js"
    if path.endswith(".css") or kind == "stylesheet":
        return "css"
    if any(path.endswith(ext) for ext in _FONT_EXTS) or "font" in path:
        return "font"
    if any(path.endswith(ext) for ext in _IMG_EXTS) or kind == "image":
        return "image"
    if kind == "link":
        return "preconnect"
    return "other"


def _jurisdiction(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in JURISDICTION:
        return JURISDICTION[".".join(labels[-2:])]
    cctld = labels[-1]
    return JURISDICTION.get(cctld, DEFAULT_JURISDICTION)


def _purpose(reg_domain: str) -> str:
    if reg_domain in KNOWN_PURPOSES:
        return KNOWN_PURPOSES[reg_domain]
    # Heuristics on the domain string.
    d = reg_domain.lower()
    if re.search(r'\banalytic|\bstats?\b|\btrack', d):
        return "Analytics"
    if re.search(r'\bads?\b|advert|doubleclick|banner', d):
        return "Advertising"
    if "cdn" in d or "static" in d:
        return "CDN / static"
    if "font" in d:
        return "Fonts"
    if "cache" in d:
        return "Cache / CDN"
    return "other"


def inventory(evidences: list[Evidence], target_domain: str) -> list[ThirdParty]:
    """Build the third-party inventory across all sampled pages."""
    merged = merge(evidences)
    rows: list[tuple[str, str, str]] = []  # (url, host, kind)
    for src in merged.scripts:
        rows.append((src, hostname_of(src), "script"))
    for src in merged.stylesheets:
        rows.append((src, hostname_of(src), "stylesheet"))
    for src in merged.images:
        rows.append((src, hostname_of(src), "image"))
    for src in merged.iframes:
        rows.append((src, hostname_of(src), "iframe"))
    for src in merged.links:
        rows.append((src, hostname_of(src), "link"))

    groups: dict[str, ThirdParty] = {}
    for url, host, kind in rows:
        if not host:
            continue
        reg = registrable_domain(host)
        # Internal = same registrable domain as the target (incl. subdomains).
        if reg == target_domain:
            continue
        tp = groups.get(reg)
        if tp is None:
            tp = ThirdParty(
                domain=reg, purpose=_purpose(reg), count=0,
                jurisdiction=_jurisdiction(reg),
            )
            groups[reg] = tp
        tp.count += 1
        rtype = _res_type(url, kind)
        if rtype not in tp.types:
            tp.types.append(rtype)
        if host not in tp.hosts:
            tp.hosts.append(host)
        if len(tp.examples) < 3:
            tp.examples.append(url)

    result = sorted(groups.values(), key=lambda t: (-t.count, t.domain))
    return result


def purpose_summary(parties: list[ThirdParty]) -> dict[str, int]:
    """Total external requests grouped by purpose — for the bar chart."""
    out: dict[str, int] = {}
    for tp in parties:
        out[tp.purpose] = out.get(tp.purpose, 0) + tp.count
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))
