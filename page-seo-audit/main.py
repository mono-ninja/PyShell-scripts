#!/usr/bin/env python3
"""page-seo-audit/main.py — Page SEO Audit.

One URL in, one on-page SEO report out: fetch once, parse once, no
crawling. This is the independent, one-shot counterpart to the
``site-crawler`` + ``seo-checks`` pair — those two need a whole crawl to
say anything useful (duplicates, redirect reliance and indexability all
compare *across* pages); this one answers "is this single page any
good?" in seconds from a bare URL.

Deliberate boundaries, so it stays distinct from the sibling single-
target audit scripts: HTTP *security* headers belong to
``security-headers``, response timing to ``server-timing``, image bytes
to ``image-optimizer``. What's left — and what nothing else here checks
— is the on-page content and metadata layer: meta tags and
indexability, headings, image ``alt`` text, social preview tags,
hreflang, JSON-LD/microdata structured data, word count, the URL scheme
the page finally answers on, non-crawlable anchors, and (opt-in) the
page's own outbound links and canonical target.

No single weighted score: independent check families make defensible
relative weights hard to pick on paper (``security-headers`` needed a
live calibration pass after shipping one). The deliverable is a
per-category status table plus the findings, worst first.

Two network-touching steps beyond the page itself, both opt-in:
``--check-links`` (verifying links and the canonical target means
requests to hosts this script wouldn't otherwise touch — same reasoning
as ``seo-checks``' ``--check-external-links``) and ``--check-robots-txt``
(one request, to the *same* host, for the third indexability signal
alongside ``<meta name=robots>`` and ``X-Robots-Tag``).

Structured events are emitted on stderr so PyShell renders them
natively. Artifacts are written to PYSHELL_OUTPUT_DIR (or
``--output-dir``): ``page_facts.json`` (every raw extracted fact — the
evidence), ``findings.json`` (machine-readable, for CI — every finding
carries a stable ``code``), and ``report.md``.

Run from a terminal too — the events degrade to plain JSON log lines.
Exit codes: ``0`` — the page was fetched and audited and nothing crossed
``--fail-on``; ``1`` — no usable response (timeout, connection refused,
DNS failure, a non-HTML body, or a body that isn't parseable HTML);
``2`` — the audit ran but findings crossed the ``--fail-on`` threshold.
"""
import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Literal
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import lxml.html
import requests
from lxml import etree

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ

DEFAULT_UA = "PyShell-PageSeoAudit/1.0 (+on-page SEO audit)"
MAX_HOPS = 10
REDIRECT_STATUSES = (301, 302, 303, 307, 308)
# A page that doesn't fit in this much HTML is not a page this audit can
# say anything useful about — and reading it whole would be the one way
# a single fetch could exhaust memory.
MAX_BODY_BYTES = 10 * 1024 * 1024
HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")

# Same thresholds as seo-checks' meta_quality — deliberately duplicated,
# not imported: the two scripts share nothing by design (see their plans).
TITLE_MIN, TITLE_MAX = 50, 60
DESC_MIN, DESC_MAX = 120, 158
THIN_CONTENT_WORDS = 300
# Screen readers read alt text verbatim; past this it stops being a
# label and starts being a paragraph in the wrong place.
ALT_MAX_CHARS = 125
H1_MAX_CHARS = 70
# Below this the page is mostly markup — usually a shell that renders
# its content client-side, which is worth knowing before reading any
# other content finding.
MIN_TEXT_HTML_RATIO = 0.05

OG_REQUIRED = ("og:title", "og:description", "og:image", "og:type", "og:url")
TWITTER_CARD_TYPES = ("summary", "summary_large_image", "app", "player")
HEAD_TAGS = ("h1", "h2", "h3", "h4", "h5", "h6")

# `content="none"` is the exact equivalent of `noindex, nofollow` — a
# directive that is easy to miss precisely because it doesn't spell
# "noindex" out.
NOINDEX_TOKENS = frozenset({"noindex", "none"})
# Search engines read a bot-specific robots meta in preference to the
# generic one, so a `googlebot` noindex counts even when `robots` says
# index.
ROBOTS_META_NAMES = ("robots", "googlebot", "googlebot-news", "bingbot",
                     "yandex", "slurp", "msnbot", "duckduckbot")

# Elements that actually make the browser fetch something. `<link>` is
# the trap: rel=alternate (an RSS feed) and rel=preconnect (a DNS/TLS
# warm-up) are not subresources of this page, so a bare http:// there is
# not mixed content.
SRC_TAGS = frozenset({"img", "script", "iframe", "video", "audio",
                      "source", "embed", "track"})
SUBRESOURCE_LINK_RELS = frozenset({
    "stylesheet", "icon", "shortcut", "apple-touch-icon",
    "apple-touch-icon-precomposed", "mask-icon", "manifest",
    "preload", "modulepreload",
})
ICON_LINK_RELS = frozenset({"icon", "shortcut", "apple-touch-icon",
                            "apple-touch-icon-precomposed", "mask-icon"})

# text_content() concatenates adjacent text nodes with nothing between
# them, so `<p>one</p><p>two</p>` reads as "onetwo" — one word, not two.
# Every element that renders as its own box gets an explicit separator
# before the count.
BLOCK_TAGS = frozenset({
    "address", "article", "aside", "blockquote", "br", "caption",
    "dd", "details", "div", "dl", "dt", "fieldset", "figcaption",
    "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
    "header", "hr", "legend", "li", "main", "nav", "ol", "option", "p",
    "pre", "section", "summary", "table", "tbody", "td", "tfoot", "th",
    "thead", "tr", "ul",
})

# An alt attribute that says nothing a screen reader couldn't get from
# the filename.
JUNK_ALT = frozenset({"image", "img", "photo", "picture", "graphic",
                      "icon", "logo", "banner", "spacer", "untitled",
                      "alt", "alt text", "placeholder"})

HREFLANG_RE = re.compile(
    r"^(x-default|[a-zA-Z]{2,3}(-[a-zA-Z]{4})?(-([a-zA-Z]{2}|[0-9]{3}))?)$")

# A handful of offenders per finding — enough to make the fix findable
# without a product-photo grid dominating the report.
MAX_LISTED = 5
# Broken links are the one check that produces a finding per URL; past
# this the report stops being readable and the rest is aggregated.
MAX_LINK_FINDINGS = 20

CATEGORIES = ("Response", "Meta", "Headings", "Images", "Social",
              "Hreflang", "Structured Data", "Content", "Mixed Content",
              "Links")
# Worst-first when collapsing a category to one status, and when sorting
# findings for the report.
STATUS_ORDER = {"fail": 0, "warn": 1, "info": 2, "pass": 3}


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    """Send one structured event. One event, one line — never pretty-printed."""
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One check result within a category (Meta / Headings / Images / …).

    ``code`` is the stable identifier: ``detail`` is prose and gets
    reworded, so CI rules and allowlists key off the code instead.
    """
    category: str
    code: str
    status: Literal["pass", "warn", "fail", "info"]
    detail: str
    recommendation: str = ""


@dataclass
class Hop:
    """One response in the redirect chain (the only response when no chain)."""
    url: str
    status: int
    headers: list[list[str]]  # raw (name, value) pairs, duplicates preserved


@dataclass
class Options:
    """Everything the check phases need beyond the facts themselves."""
    min_words: int = THIN_CONTENT_WORDS
    check_links: bool = False
    link_scope: str = "all"          # all | internal | external
    max_links: int = 0               # 0 = no cap
    concurrency: int = 5
    link_timeout: int = 10
    user_agent: str = DEFAULT_UA
    verify: bool = True


@dataclass
class PageFacts:
    """Every raw fact extracted from the fetch + the HTML — the evidence
    artifact. HTTP-level fields are filled by the caller; everything else
    by parse_facts, which stays pure (tests parse fixtures offline)."""
    # HTTP layer
    requested_url: str = ""
    final_url: str = ""
    status: int | None = None
    content_type: str | None = None
    redirect_chain: list[dict] = field(default_factory=list)  # {url, status}
    redirect_no_location: bool = False   # a 3xx that never said where to
    body_truncated: bool = False         # body hit MAX_BODY_BYTES
    x_robots_tag: list[str] = field(default_factory=list)
    # A2 — meta & indexability
    title: str | None = None
    title_count: int = 0
    meta_description: str | None = None
    description_count: int = 0
    canonical_raw: str | None = None        # href exactly as written
    canonical: str | None = None            # resolved, or None if unresolvable
    canonical_count: int = 0
    meta_robots: str | None = None
    robots_directives: dict[str, str] = field(default_factory=dict)
    html_lang: str | None = None
    viewport: str | None = None
    charset: str | None = None
    meta_keywords: str | None = None
    icons: list[str] = field(default_factory=list)
    robots_txt_url: str | None = None
    # allowed | blocked | unavailable | None (not checked)
    robots_txt_verdict: str | None = None
    robots_txt_error: str | None = None
    # A3 — headings, in document order
    headings: list[dict] = field(default_factory=list)   # {level, text}
    # A4 — images; alt is None (attribute missing) vs "" (decorative) vs text
    images: list[dict] = field(default_factory=list)     # {src, alt, w, h, lazy}
    # A5 — social tags
    og: dict[str, str] = field(default_factory=dict)
    twitter: dict[str, str] = field(default_factory=dict)
    og_duplicates: list[str] = field(default_factory=list)
    twitter_duplicates: list[str] = field(default_factory=list)
    # A5b — hreflang alternates
    hreflang: list[dict] = field(default_factory=list)   # {lang, href, resolved}
    # A6 — structured data
    jsonld: list[dict] = field(default_factory=list)     # {raw, types, error, context}
    microdata_types: list[str] = field(default_factory=list)
    rdfa_types: list[str] = field(default_factory=list)
    # A7 — content & links
    word_count: int = 0
    html_bytes: int = 0
    text_bytes: int = 0
    has_main_landmark: bool = False
    links_internal: list[str] = field(default_factory=list)
    links_external: list[str] = field(default_factory=list)
    links_nofollow: list[str] = field(default_factory=list)
    # href="#" / "#fragment" / "javascript:…" — anchors a crawler can't
    # follow; the raw href values, not resolved URLs (they resolve to
    # nothing useful).
    links_uncrawlable: list[str] = field(default_factory=list)
    # A8 — mixed content
    resources: list[str] = field(default_factory=list)   # every subresource URL
    mixed_content: list[str] = field(default_factory=list)


class HeadersView:
    """Case-insensitive read access over a hop's raw header pairs."""

    def __init__(self, pairs: list[list[str]] | list[tuple[str, str]]):
        self.pairs = [[k, v] for k, v in pairs]

    def get(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.pairs:
            if k.lower() == low:
                return v
        return None

    def get_all(self, name: str) -> list[str]:
        low = name.lower()
        return [v for k, v in self.pairs if k.lower() == low]


# ---------------------------------------------------------------------------
# A1. Fetch — manual redirect chain, body of the final response
# ---------------------------------------------------------------------------

def _read_capped(resp, limit: int) -> tuple[bytes, bool]:
    """Body bytes, and whether the cap cut it short."""
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    body = b"".join(chunks)
    return body[:limit], total >= limit


def fetch_page(url: str, *, headers: dict[str, str], timeout: int,
               follow: bool, verify: bool) -> tuple[list[Hop], bytes, bool, bool]:
    """GET the URL hop by hop, returning every hop plus the final body.

    Manual redirect following (not ``allow_redirects=True``) for the same
    reason as ``security-headers``: a page audit should know whether it
    audited the URL it was given or something three hops away, and the
    X-Robots-Tag read must come from the response that actually carries
    the page.

    The body comes back as **bytes**, never ``resp.text``: for
    ``Content-Type: text/html`` with no ``charset``, requests decodes as
    ISO-8859-1 and ignores the document's own ``<meta charset>``, which
    turns every non-Latin page into mojibake and doubles the character
    counts the title/description length checks are built on. lxml reads
    the BOM and the meta charset itself when handed bytes.

    Returns ``(hops, body, truncated, no_location)``. Raises
    ``requests.RequestException`` on failure — the caller turns that into
    a single error report and exit code 1.
    """
    hops: list[Hop] = []
    current = url
    no_location = False
    for _ in range(MAX_HOPS):
        resp = requests.get(current, headers=headers, timeout=timeout,
                            allow_redirects=False, verify=verify, stream=True)
        hops.append(Hop(
            url=current,
            status=resp.status_code,
            headers=[[k, v] for k, v in resp.raw.headers.items()],
        ))
        is_redirect = resp.status_code in REDIRECT_STATUSES
        location = resp.headers.get("Location") if is_redirect else None
        if follow and is_redirect and location:
            resp.close()
            current = urljoin(current, location)
            continue
        if follow and is_redirect:
            # A 3xx with nowhere to go: the chain ends here, and the body
            # of the redirect response is all there is to audit.
            no_location = True
        try:
            body, truncated = _read_capped(resp, MAX_BODY_BYTES)
        finally:
            resp.close()
        return hops, body, truncated, no_location
    # Loop exhausted: the chain is longer than MAX_HOPS, or it loops. The
    # last hop is a redirect we deliberately didn't follow, so there is no
    # page body — the caller reports that instead of auditing nothing.
    return hops, b"", False, no_location


def fetch_robots_txt(page_url: str, *, headers: dict[str, str], timeout: int,
                     verify: bool) -> tuple[str, str, str | None]:
    """``(robots_url, verdict, error)`` for the page's own host.

    One request, to a host this audit already touched — the privacy
    reasoning that keeps ``--check-links`` off by default doesn't apply,
    but the extra request still earns its own opt-in flag.
    """
    parts = urlsplit(page_url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
    try:
        resp = requests.get(robots_url, headers=headers, timeout=timeout,
                            verify=verify, allow_redirects=True)
    except requests.RequestException as exc:
        return robots_url, "unavailable", type(exc).__name__
    if resp.status_code == 404:
        # No robots.txt is an explicit "everything is allowed".
        return robots_url, "allowed", None
    if resp.status_code >= 400:
        return robots_url, "unavailable", f"HTTP {resp.status_code}"

    parser = RobotFileParser()
    parser.parse(resp.text.splitlines())
    agent = headers.get("User-Agent", DEFAULT_UA)
    allowed = parser.can_fetch(agent, page_url) and parser.can_fetch("*", page_url)
    return robots_url, "allowed" if allowed else "blocked", None


# ---------------------------------------------------------------------------
# Fact extraction — one parse pass over the HTML
# ---------------------------------------------------------------------------

def _effective_base(doc: lxml.html.HtmlElement, base_url: str) -> str:
    for el in doc.iter("base"):
        href = el.get("href")
        if href:
            return urljoin(base_url, href)
    return base_url


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _rels(el) -> set[str]:
    return set((el.get("rel") or "").lower().split())


def _srcset_urls(value: str | None) -> list[str]:
    """URLs out of a srcset. Descriptors are dropped; data: entries are
    skipped rather than split on their own commas."""
    if not value:
        return []
    out = []
    for part in value.split(","):
        part = part.strip()
        if not part or part.lower().startswith("data:"):
            continue
        out.append(part.split()[0])
    return out


def _resource_refs(el) -> list[str]:
    """Every URL this element makes the browser fetch (or post to)."""
    tag = el.tag
    if not isinstance(tag, str):
        return []
    out: list[str | None] = []
    if tag == "link":
        if _rels(el) & SUBRESOURCE_LINK_RELS:
            out.append(el.get("href"))
    elif tag == "object":
        out.append(el.get("data"))
    elif tag == "form":
        out.append(el.get("action"))
    elif tag == "input":
        if (el.get("type") or "").lower() == "image":
            out.append(el.get("src"))
    elif tag in SRC_TAGS:
        out.append(el.get("src"))
    if tag in ("img", "source"):
        out.extend(_srcset_urls(el.get("srcset")))
    return [u for u in out if u]


def _visible_text(root) -> str:
    """The page's rendered text, with block boundaries preserved.

    Mutates the tree (separators are written into ``text``/``tail``), so
    this runs last — every other extraction has already read what it
    needs.
    """
    for el in root.iter():
        if not isinstance(el.tag, str) or el.tag not in BLOCK_TAGS:
            continue
        if el.text:
            el.text = " " + el.text
        el.tail = (el.tail or "") + " "
    return root.text_content()


def jsonld_types(data) -> list[str]:
    """@type values in a parsed JSON-LD payload — supports a single object,
    a top-level array, and a @graph wrapper (recursively)."""
    if isinstance(data, list):
        out: list[str] = []
        for item in data:
            out.extend(jsonld_types(item))
        return out
    if isinstance(data, dict):
        out = []
        t = data.get("@type")
        if isinstance(t, str):
            out.append(t)
        elif isinstance(t, list):
            out.extend(str(x) for x in t if isinstance(x, (str, int)))
        if "@graph" in data:
            out.extend(jsonld_types(data["@graph"]))
        return out
    return []


def jsonld_has_context(data) -> bool:
    """A block with no @context is ignored as silently as a broken one."""
    if isinstance(data, list):
        return any(jsonld_has_context(item) for item in data)
    if isinstance(data, dict):
        return "@context" in data
    return False


def parse_facts(html: str | bytes, base_url: str) -> PageFacts:
    """One HTML document → every fact the checks need. Pure — no network.

    Accepts bytes (the live path — lxml then honours the BOM and the
    document's own ``<meta charset>``) or str (the fixture path).

    Raises ``etree.LxmlError``/``ValueError`` when the body can't be
    parsed at all; partial garbage merely yields empty fields.
    """
    doc = lxml.html.document_fromstring(html)
    base = _effective_base(doc, base_url)
    facts = PageFacts(final_url=base_url)
    facts.html_bytes = len(html if isinstance(html, bytes)
                           else html.encode("utf-8", "replace"))

    # --- A2: meta & indexability ------------------------------------
    # <svg><title> is a tooltip, not the document title.
    titles = [el for el in doc.iter("title")
              if not any(a.tag == "svg" for a in el.iterancestors())]
    facts.title_count = len(titles)
    for el in titles:
        text = " ".join((el.text or "").split())
        if text:
            facts.title = text
            break

    for el in doc.iter("meta"):
        if el.get("charset"):
            facts.charset = facts.charset or el.get("charset").strip()
        equiv = (el.get("http-equiv") or "").strip().lower()
        content = (el.get("content") or "").strip()
        if equiv == "content-type" and "charset=" in content.lower():
            facts.charset = (facts.charset
                             or content.lower().split("charset=", 1)[1].strip())
        # Open Graph tags use `property`, Twitter tags use `name` — read
        # both so either spelling is found.
        key = (el.get("property") or el.get("name") or "").strip().lower()
        if not key or not content:
            continue
        if key.startswith("og:"):
            if key in facts.og:
                facts.og_duplicates.append(key)
            else:
                facts.og[key] = content
        elif key.startswith("twitter:"):
            if key in facts.twitter:
                facts.twitter_duplicates.append(key)
            else:
                facts.twitter[key] = content
        elif key == "description":
            facts.description_count += 1
            facts.meta_description = facts.meta_description or content
        elif key == "keywords":
            facts.meta_keywords = facts.meta_keywords or content
        elif key in ROBOTS_META_NAMES:
            facts.robots_directives.setdefault(key, content)
        elif key == "viewport":
            facts.viewport = facts.viewport or content
    facts.meta_robots = facts.robots_directives.get("robots")

    for el in doc.iter("link"):
        rel = _rels(el)
        href = (el.get("href") or "").strip()
        if "canonical" in rel and href:
            facts.canonical_count += 1
            if facts.canonical_raw is None:
                facts.canonical_raw = href
                resolved = urljoin(base, href)
                parts = urlsplit(resolved)
                if parts.scheme in ("http", "https") and parts.hostname:
                    facts.canonical = resolved
        if rel & ICON_LINK_RELS and href:
            facts.icons.append(urljoin(base, href))
        if "alternate" in rel and el.get("hreflang"):
            lang = el.get("hreflang").strip()
            resolved = urljoin(base, href) if href else ""
            parts = urlsplit(resolved)
            usable = parts.scheme in ("http", "https") and bool(parts.hostname)
            facts.hreflang.append({
                "lang": lang,
                "href": href,
                "resolved": resolved if usable else None,
                # Search engines require fully-qualified hreflang targets;
                # one that merely resolves is still rejected.
                "absolute": bool(href) and href.lower().startswith(
                    ("http://", "https://")),
            })

    facts.html_lang = ((doc.get("lang") or doc.get("xml:lang") or "").strip()
                       or None)

    # --- A3: headings, in document order -----------------------------
    for el in doc.iter(*HEAD_TAGS):
        facts.headings.append({
            "level": int(el.tag[1]),
            "text": " ".join(el.text_content().split()),
        })

    # --- A4: images. THE distinction to keep: img.get("alt") is None
    # when the attribute is missing (the finding) and "" when the image
    # is correctly marked decorative (never a finding).
    for el in doc.iter("img"):
        facts.images.append({
            "src": el.get("src"),
            "alt": el.get("alt"),
            "width": el.get("width"),
            "height": el.get("height"),
            "loading": (el.get("loading") or "").strip().lower() or None,
        })

    # --- A6: JSON-LD blocks -------------------------------------------
    for el in doc.iter("script"):
        if (el.get("type") or "").strip().lower() != "application/ld+json":
            continue
        raw = (el.text or "").strip()
        block: dict = {"raw": raw, "types": [], "error": None,
                       "has_context": False}
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            block["error"] = str(exc)
        else:
            block["types"] = jsonld_types(data)
            block["has_context"] = jsonld_has_context(data)
        facts.jsonld.append(block)

    # --- A6b: microdata / RDFa. Only JSON-LD used to be looked at, so a
    # fully marked-up microdata page reported "no structured data".
    for el in doc.iter():
        if not isinstance(el.tag, str):
            continue
        itemtype = el.get("itemtype")
        if itemtype:
            facts.microdata_types.extend(itemtype.split())
        typeof = el.get("typeof")
        if typeof:
            facts.rdfa_types.extend(typeof.split())
    facts.microdata_types = list(dict.fromkeys(facts.microdata_types))
    facts.rdfa_types = list(dict.fromkeys(facts.rdfa_types))

    # --- A7: links — internal vs external by exact host match, the same
    # comparison site-crawler's Scope uses by default (duplicated here,
    # not imported).
    base_host = _host(base)
    seen: set[str] = set()
    for el in doc.iter("a"):
        href = el.get("href")
        if not href:
            continue
        # A fragment or javascript: href is not a link a crawler can
        # follow. Collected for a finding rather than silently skipped —
        # and, importantly, before the scheme check below: urljoin()
        # resolves "#top" into this very page's URL, which used to count
        # an in-page fragment anchor as an internal link.
        if href.startswith("#") or href.strip().lower().startswith(
                "javascript:"):
            facts.links_uncrawlable.append(href)
            continue
        absolute = urljoin(base, href)
        parts = urlsplit(absolute)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            continue  # mailto:, tel:, javascript:, data:, …
        if absolute in seen:
            continue
        seen.add(absolute)
        target = (facts.links_internal if _host(absolute) == base_host
                  else facts.links_external)
        target.append(absolute)
        if _rels(el) & {"nofollow", "sponsored", "ugc"}:
            facts.links_nofollow.append(absolute)

    # --- A8: every subresource reference. rel=canonical is the page
    # itself and rel=alternate/preconnect are not subresources at all —
    # see SUBRESOURCE_LINK_RELS.
    seen_res: set[str] = set()
    for el in doc.iter():
        for src in _resource_refs(el):
            absolute = urljoin(base, src)
            if urlsplit(absolute).scheme.lower() not in ("http", "https"):
                continue
            if absolute not in seen_res:
                seen_res.add(absolute)
                facts.resources.append(absolute)

    facts.has_main_landmark = any(
        True for _ in doc.iter("main", "article"))

    # --- A7: word count, computed last — script/style/noscript content
    # is not words, the JSON-LD extraction above already copied what it
    # needs out of the script elements, and _visible_text mutates.
    body = doc.find("body")
    root = body if body is not None else doc
    for el in list(root.iter("script", "style", "noscript", "template")):
        el.drop_tree()
    text = _visible_text(root)
    words = text.split()
    facts.word_count = len(words)
    facts.text_bytes = len(" ".join(words))

    # --- A8: mixed content, only meaningful on an https page.
    if urlsplit(base_url).scheme == "https":
        facts.mixed_content = [u for u in facts.resources
                               if urlsplit(u).scheme == "http"]

    return facts


# ---------------------------------------------------------------------------
# A0. Response — the audited page is only as meaningful as the response
# ---------------------------------------------------------------------------

def audit_response(facts: PageFacts) -> list[Finding]:
    findings: list[Finding] = []
    code = facts.status

    if code is None:
        pass
    elif 200 <= code < 300:
        findings.append(Finding(
            "Response", "response.status.ok", "pass",
            f"HTTP {code} — a real page body was audited"))
    elif code in REDIRECT_STATUSES:
        findings.append(Finding(
            "Response", "response.status.redirect", "warn",
            f"HTTP {code} — the audited body is a redirect response, not a "
            "page; every finding below describes that body",
            "Re-run with redirect following on, or audit the redirect "
            "target directly"))
    else:
        findings.append(Finding(
            "Response", "response.status.error", "fail",
            f"HTTP {code} — this is an error response, not a page; every "
            "finding below describes the error body, not real content",
            "Audit a URL that returns 200 — an error page's SEO is not "
            "the page's SEO"))

    # The final URL's scheme. A 2xx over plain http means the server had
    # the chance to redirect to https and didn't; an unfollowed 3xx over
    # http might still redirect there, so that case stays silent rather
    # than guessing.
    scheme = urlsplit(facts.final_url).scheme if facts.final_url else ""
    if scheme == "https":
        findings.append(Finding(
            "Response", "response.scheme.https", "pass",
            "page is served over https"))
    elif scheme == "http" and (facts.status is None
                               or facts.status not in REDIRECT_STATUSES):
        findings.append(Finding(
            "Response", "response.scheme.http", "warn",
            "the final page is served over plain http — the server "
            "answered without redirecting to https",
            "Serve the page over https and redirect http to it — a light "
            "ranking signal and a browser-security baseline"))

    hops = len(facts.redirect_chain) - 1
    # A chain past MAX_HOPS never gets this far — main() reports it as a
    # failed run (exit 1) before any audit phase, so there is no
    # "truncated chain" finding to make here.
    if hops > 2:
        findings.append(Finding(
            "Response", "response.redirect.long", "info",
            f"{hops} redirects before the final page",
            "Point the first URL straight at the last one — every hop "
            "costs crawl budget and a little link equity"))
    elif hops > 0:
        findings.append(Finding(
            "Response", "response.redirect.followed", "info",
            f"{hops} redirect{'s' if hops != 1 else ''} followed from "
            f"{facts.requested_url}"))

    if facts.redirect_no_location:
        findings.append(Finding(
            "Response", "response.redirect.no_location", "warn",
            "a redirect response carried no Location header — the chain "
            "ends nowhere",
            "Send a Location header with every 3xx, or return the content "
            "directly"))

    if facts.body_truncated:
        findings.append(Finding(
            "Response", "response.body.truncated", "info",
            f"the response body is larger than "
            f"{MAX_BODY_BYTES // (1024 * 1024)} MB and was read only that "
            "far — findings below cover the part that was read",
            "A page this large is worth splitting for its own sake"))

    return findings


# ---------------------------------------------------------------------------
# A2. Meta & indexability
# ---------------------------------------------------------------------------

def robots_tokens(value: str) -> set[str]:
    return {t.strip().lower() for t in value.split(",") if t.strip()}


def meta_says_noindex(directives: dict[str, str]) -> list[str]:
    """The robots meta names that carry a noindex (or its `none` alias)."""
    return [name for name, value in directives.items()
            if robots_tokens(value) & NOINDEX_TOKENS]


def x_robots_says_noindex(values: list[str]) -> bool:
    """True when any X-Robots-Tag value carries a noindex directive —
    including user-agent-scoped ones like ``googlebot: noindex`` and the
    ``none`` alias, which means exactly ``noindex, nofollow``."""
    for value in values:
        for token in value.split(","):
            token = token.strip().lower()
            if ":" in token:
                token = token.split(":", 1)[1].strip()
            if token in NOINDEX_TOKENS:
                return True
    return False


def normalize_url(url: str) -> tuple[str, str, str, str]:
    """Scheme/host/path/query with the differences that never make two
    URLs different pages folded away (``www.``, a trailing slash)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    # "www.com" is a registrable domain in its own right, not a www
    # variant of "com" — fold the prefix only when something domain-like
    # is left under it.
    if host.startswith("www.") and "." in host[4:]:
        host = host[4:]
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return parts.scheme.lower(), host, path, parts.query


def audit_meta(facts: PageFacts) -> list[Finding]:
    findings: list[Finding] = []

    if not facts.title:
        findings.append(Finding(
            "Meta", "meta.title.missing", "fail", "no <title>",
            "Add a unique, descriptive title — the strongest on-page "
            "signal a page has"))
    elif not TITLE_MIN <= len(facts.title) <= TITLE_MAX:
        findings.append(Finding(
            "Meta", "meta.title.length", "info",
            f"title is {len(facts.title)} characters (~{TITLE_MIN}–"
            f"{TITLE_MAX} is the guideline; search engines truncate on "
            f"pixel width, so this is a rule of thumb): “{facts.title}”",
            "Longer titles may be truncated in search results; much "
            "shorter ones waste the space"))
    else:
        findings.append(Finding(
            "Meta", "meta.title.ok", "pass",
            f"title ({len(facts.title)} chars): “{facts.title}”"))
    if facts.title_count > 1:
        findings.append(Finding(
            "Meta", "meta.title.duplicate", "warn",
            f"{facts.title_count} <title> elements — only the first is "
            "used, the rest are dead weight",
            "Keep exactly one <title> in <head>"))

    if not facts.meta_description:
        findings.append(Finding(
            "Meta", "meta.description.missing", "warn", "no meta description",
            "Add one — search engines fall back to an arbitrary snippet "
            "from the page without it"))
    elif not DESC_MIN <= len(facts.meta_description) <= DESC_MAX:
        findings.append(Finding(
            "Meta", "meta.description.length", "info",
            f"meta description is {len(facts.meta_description)} characters "
            f"(~{DESC_MIN}–{DESC_MAX} is the guideline)",
            "Longer descriptions may be truncated in search results; "
            "shorter ones under-use the snippet"))
    else:
        findings.append(Finding(
            "Meta", "meta.description.ok", "pass",
            f"meta description ({len(facts.meta_description)} chars)"))
    if facts.description_count > 1:
        findings.append(Finding(
            "Meta", "meta.description.duplicate", "warn",
            f"{facts.description_count} meta description tags — only the "
            "first counts",
            "Keep exactly one <meta name=\"description\">"))

    findings.extend(_audit_canonical(facts))

    noindex_sources = [f'<meta name="{name}">'
                       for name in meta_says_noindex(facts.robots_directives)]
    if x_robots_says_noindex(facts.x_robots_tag):
        noindex_sources.append("X-Robots-Tag response header")
    if facts.robots_txt_verdict == "blocked":
        noindex_sources.append("robots.txt")
    if noindex_sources:
        findings.append(Finding(
            "Meta", "meta.robots.noindex", "warn",
            "this page is reachable but told not to be indexed — via "
            + " and ".join(noindex_sources)
            + "; confirm that's deliberate",
            "Remove noindex if the page should appear in search results"))
    else:
        findings.append(Finding(
            "Meta", "meta.robots.indexable", "pass",
            "indexable — no noindex in meta robots or X-Robots-Tag"))

    if facts.robots_txt_verdict == "unavailable":
        findings.append(Finding(
            "Meta", "meta.robots_txt.unavailable", "info",
            f"robots.txt could not be read ({facts.robots_txt_error}) — the "
            "crawl-level half of indexability is unknown",
            "Serve a robots.txt (an empty one is valid and means "
            "'crawl everything')"))
    elif facts.robots_txt_verdict == "allowed":
        findings.append(Finding(
            "Meta", "meta.robots_txt.allowed", "pass",
            "robots.txt allows this URL to be crawled"))

    if not facts.viewport:
        findings.append(Finding(
            "Meta", "meta.viewport.missing", "warn", "no viewport meta tag",
            "Add <meta name=viewport content=\"width=device-width, "
            "initial-scale=1\"> — a mobile-friendliness signal"))
    else:
        findings.append(Finding("Meta", "meta.viewport.ok", "pass",
                                f"viewport: {facts.viewport}"))

    if not facts.html_lang:
        findings.append(Finding(
            "Meta", "meta.lang.missing", "info",
            "no lang attribute on <html>",
            "Add one (<html lang=\"en\">) — primarily an accessibility "
            "signal"))
    else:
        findings.append(Finding("Meta", "meta.lang.ok", "pass",
                                f"html lang={facts.html_lang!r}"))

    if not facts.charset:
        findings.append(Finding(
            "Meta", "meta.charset.missing", "warn",
            "no character encoding declared in the document",
            "Add <meta charset=\"utf-8\"> as the first thing in <head> — "
            "without it a client that gets no charset in the HTTP header "
            "falls back to Latin-1 and mangles every non-ASCII character"))
    else:
        findings.append(Finding("Meta", "meta.charset.ok", "pass",
                                f"charset declared: {facts.charset}"))

    if not facts.icons:
        findings.append(Finding(
            "Meta", "meta.favicon.missing", "info",
            "no favicon or touch icon declared",
            "Add <link rel=\"icon\" href=\"/favicon.ico\"> — it shows up "
            "in tabs, bookmarks and some search results"))
    else:
        findings.append(Finding("Meta", "meta.favicon.ok", "pass",
                                f"{len(facts.icons)} icon link(s) declared"))

    if facts.meta_keywords:
        findings.append(Finding(
            "Meta", "meta.keywords.present", "info",
            "a <meta name=\"keywords\"> tag is present — no mainstream "
            "search engine has used it for well over a decade",
            "Harmless, but it can go"))

    return findings


def _audit_canonical(facts: PageFacts) -> list[Finding]:
    """Canonical presence *and* target — a canonical pointing somewhere
    else is the page asking to be dropped from the index, which is worth
    far more than 'the tag exists'."""
    findings: list[Finding] = []
    if facts.canonical_count > 1:
        findings.append(Finding(
            "Meta", "meta.canonical.duplicate", "warn",
            f"{facts.canonical_count} rel=canonical tags — search engines "
            "ignore all of them when they conflict",
            "Keep exactly one <link rel=\"canonical\">"))

    if not facts.canonical_raw:
        findings.append(Finding(
            "Meta", "meta.canonical.missing", "info", "no canonical tag",
            "Fine for a page reachable under exactly one URL; add one "
            "(<link rel=canonical>) if this content is reachable under "
            "several"))
        return findings
    if facts.canonical is None:
        findings.append(Finding(
            "Meta", "meta.canonical.unresolvable", "warn",
            f"canonical {facts.canonical_raw!r} does not resolve to an "
            "absolute http(s) URL",
            "Point rel=canonical at an absolute https:// URL"))
        return findings

    note = (" (relative href — kept, but an absolute URL is safer)"
            if not facts.canonical_raw.startswith(("http://", "https://"))
            else "")
    page = normalize_url(facts.final_url) if facts.final_url else None
    target = normalize_url(facts.canonical)
    if page is None or page == target:
        findings.append(Finding(
            "Meta", "meta.canonical.self", "pass",
            f"canonical is self-referencing: {facts.canonical}{note}"))
    elif page[1] != target[1]:
        findings.append(Finding(
            "Meta", "meta.canonical.cross_domain", "warn",
            f"canonical points at another domain ({facts.canonical}) — this "
            "page is asking to be dropped from the index in favour of that "
            "URL; confirm that's deliberate",
            "Point rel=canonical at this page unless it really is a "
            "syndicated copy"))
    else:
        findings.append(Finding(
            "Meta", "meta.canonical.differs", "info",
            f"canonical points at a different URL on this host "
            f"({facts.canonical}) — this URL is being consolidated into "
            "that one",
            "Expected on a filtered/paginated variant; a mistake anywhere "
            "else"))
    return findings


# ---------------------------------------------------------------------------
# A3. Headings
# ---------------------------------------------------------------------------

def audit_headings(facts: PageFacts) -> list[Finding]:
    findings: list[Finding] = []
    levels = [h["level"] for h in facts.headings]
    h1_count = levels.count(1)
    h1_texts = [h["text"] for h in facts.headings if h["level"] == 1]

    if h1_count == 0:
        findings.append(Finding(
            "Headings", "headings.h1.missing", "fail", "no <h1> on the page",
            "Add exactly one h1 describing the page — the main headline "
            "should not start at h2"))
    elif h1_count > 1:
        findings.append(Finding(
            "Headings", "headings.h1.multiple", "warn",
            f"{h1_count} <h1> elements — technically valid HTML5 in "
            "sectioned content, but every mainstream SEO tool flags it; "
            "check whether this is deliberate",
            "Keep one h1 per page and demote the rest to h2"))
    else:
        counts = {f"h{lvl}": levels.count(lvl) for lvl in range(1, 7)
                  if levels.count(lvl)}
        others = [f"{n} {tag}" for tag, n in counts.items() if tag != "h1"]
        findings.append(Finding(
            "Headings", "headings.h1.ok", "pass",
            "exactly one h1" + (" · " + " · ".join(others) if others else "")))

    empty = sum(1 for h in facts.headings if not h["text"])
    if empty:
        findings.append(Finding(
            "Headings", "headings.empty", "warn",
            f"{empty} heading element(s) with no text — they still create "
            "an entry in the document outline, pointing at nothing",
            "Give every heading text, or use a <div> if it's there for "
            "styling"))

    # A heading above h1 in the document: the outline starts mid-way.
    first_h1 = levels.index(1) if 1 in levels else None
    if first_h1 is not None and first_h1 > 0:
        findings.append(Finding(
            "Headings", "headings.before_h1", "info",
            f"{first_h1} heading(s) appear before the h1 "
            f"(first is h{levels[0]})",
            "Put the h1 first — an outline that opens below the top level "
            "reads as a fragment"))

    # A level skipped going down (h1 straight to h3, no h2 in between).
    skips: list[str] = []
    prev: int | None = None
    for level in levels:
        if prev is not None and level > prev + 1:
            skips.append(f"h{prev} → h{level}")
        prev = level
    if skips:
        findings.append(Finding(
            "Headings", "headings.skipped_level", "info",
            "heading level(s) skipped: " + ", ".join(skips)
            + " — an accessibility nit more than an SEO one",
            "Use the next level down (h2 before h3) so screen readers "
            "can build a sane outline"))

    if h1_count == 1:
        h1 = h1_texts[0]
        if len(h1) > H1_MAX_CHARS:
            findings.append(Finding(
                "Headings", "headings.h1.long", "info",
                f"the h1 is {len(h1)} characters — long enough that it "
                "reads as a sentence rather than a headline",
                f"Aim for under ~{H1_MAX_CHARS} characters"))
        if facts.title and h1.strip().lower() == facts.title.strip().lower():
            findings.append(Finding(
                "Headings", "headings.h1.equals_title", "info",
                "the h1 is character-for-character the <title>",
                "They serve different readers — the title is the search "
                "result, the h1 is the page. Two phrasings cover more "
                "queries than one repeated twice"))

    return findings


# ---------------------------------------------------------------------------
# A4. Images — alt text and the markup around it
# ---------------------------------------------------------------------------

def _listed(items: list[str]) -> str:
    shown = ", ".join(items[:MAX_LISTED])
    more = f" (+{len(items) - MAX_LISTED} more)" if len(items) > MAX_LISTED else ""
    return shown + more


def _img_label(img: dict) -> str:
    return img["src"] or "(no src)"


def audit_images(facts: PageFacts) -> list[Finding]:
    if not facts.images:
        return [Finding("Images", "images.none", "info",
                        "no <img> elements on the page")]

    findings: list[Finding] = []
    total = len(facts.images)
    missing = [i for i in facts.images if i["alt"] is None]
    blank = [i for i in facts.images
             if i["alt"] is not None and i["alt"] != "" and not i["alt"].strip()]

    if missing:
        findings.append(Finding(
            "Images", "images.alt.missing", "warn",
            f"{len(missing)} of {total} images missing the alt attribute "
            f"entirely: {_listed([_img_label(i) for i in missing])}",
            "Add alt=\"…\" describing content images; alt=\"\" is the "
            "correct, spec-sanctioned marking for decorative ones — but "
            "the attribute must exist"))
    else:
        decorative = sum(1 for i in facts.images if i["alt"] == "")
        described = total - decorative
        findings.append(Finding(
            "Images", "images.alt.ok", "pass",
            f"{total} images: {described} with alt text, {decorative} "
            f"correctly marked decorative (alt=\"\")"))

    if blank:
        findings.append(Finding(
            "Images", "images.alt.whitespace", "warn",
            f"{len(blank)} image(s) with a whitespace-only alt: "
            f"{_listed([_img_label(i) for i in blank])} — that is not the "
            "same as alt=\"\" to every screen reader",
            "Use a truly empty alt=\"\" for decorative images, or write "
            "real alt text"))

    long_alt = [i for i in facts.images
                if i["alt"] and len(i["alt"]) > ALT_MAX_CHARS]
    if long_alt:
        findings.append(Finding(
            "Images", "images.alt.long", "info",
            f"{len(long_alt)} image(s) with alt text over {ALT_MAX_CHARS} "
            f"characters: {_listed([_img_label(i) for i in long_alt])}",
            "Screen readers read alt verbatim with no way to skim — move "
            "the long version into a caption or nearby text"))

    junk = [i for i in facts.images if _is_junk_alt(i)]
    if junk:
        findings.append(Finding(
            "Images", "images.alt.uninformative", "info",
            f"{len(junk)} image(s) whose alt says nothing the filename "
            f"didn't: {_listed([_junk_alt_label(i) for i in junk])}",
            "Describe what the image shows, not that it is an image"))

    no_dims = [i for i in facts.images if not (i["width"] and i["height"])]
    if no_dims:
        findings.append(Finding(
            "Images", "images.dimensions.missing", "info",
            f"{len(no_dims)} of {total} images have no width/height "
            f"attributes: {_listed([_img_label(i) for i in no_dims])}",
            "Set both so the browser reserves the space before the file "
            "loads — this is the cheapest fix for layout shift (CLS)"))

    if facts.images and facts.images[0]["loading"] == "lazy":
        findings.append(Finding(
            "Images", "images.first.lazy", "info",
            f"the first image on the page ({_img_label(facts.images[0])}) is "
            "lazy-loaded",
            "If it's the largest thing above the fold, lazy loading delays "
            "the LCP it was supposed to speed up — load that one eagerly"))

    return findings


def _junk_alt_label(img: dict) -> str:
    return f"{_img_label(img)} (alt={(img['alt'] or '').strip()!r})"


def _is_junk_alt(img: dict) -> bool:
    alt = (img["alt"] or "").strip().lower()
    if not alt:
        return False
    if alt in JUNK_ALT:
        return True
    src = (img["src"] or "").strip().lower()
    if src:
        filename = src.rsplit("/", 1)[-1].split("?", 1)[0]
        if alt in (filename, filename.rsplit(".", 1)[0]):
            return True
    return bool(re.fullmatch(r"(image|img|photo|picture|dsc|pic)[\s_-]*\d*", alt))


# ---------------------------------------------------------------------------
# A5. Social tags (Open Graph + Twitter Card)
# ---------------------------------------------------------------------------

def audit_social(facts: PageFacts) -> list[Finding]:
    findings: list[Finding] = []

    # First-one-wins on duplicates would otherwise resolve silently —
    # same reasoning as the title/description/canonical duplicate checks.
    dupes = sorted(set(facts.og_duplicates) | set(facts.twitter_duplicates))
    if dupes:
        findings.append(Finding(
            "Social", "social.tags.duplicate", "warn",
            f"{len(dupes)} social tag(s) declared more than once: "
            f"{_listed(dupes)} — only the first of each is used",
            "Keep exactly one tag per property/name"))

    missing_og = [tag for tag in OG_REQUIRED if tag not in facts.og]
    og_absent = len(missing_og) == len(OG_REQUIRED)
    if og_absent:
        findings.append(Finding(
            "Social", "social.og.missing", "warn",
            "no Open Graph tags — shared links will show no rich preview "
            "at all",
            "Add at least og:title, og:description, og:image, og:type and "
            "og:url"))
    elif "og:image" in missing_og:
        others = [t for t in missing_og if t != "og:image"]
        detail = ("Open Graph partially present, but og:image is missing — "
                  "the most visually costly one")
        if others:
            detail += f" (also missing: {', '.join(others)})"
        findings.append(Finding(
            "Social", "social.og.image_missing", "warn", detail,
            "Add <meta property=\"og:image\" content=\"https://…\"> — a "
            "1200×630 image is the standard"))
    elif missing_og:
        findings.append(Finding(
            "Social", "social.og.partial", "pass",
            f"Open Graph present; non-critical tags missing: "
            f"{', '.join(missing_og)}"))
    else:
        findings.append(Finding(
            "Social", "social.og.complete", "pass",
            "Open Graph complete (og:title, og:description, og:image, "
            "og:type, og:url)"))

    findings.extend(_audit_og_values(facts))

    card = facts.twitter.get("twitter:card")
    if not card:
        if og_absent:
            # OG absent AND twitter:card absent: nothing anywhere would
            # render a preview.
            findings.append(Finding(
                "Social", "social.twitter.none", "warn",
                "no twitter:card either — with Open Graph also absent, no "
                "platform gets any preview data",
                "Add <meta name=\"twitter:card\" content=\"summary\"> at "
                "minimum; Open Graph is the bigger win"))
        else:
            # Platforms that support Twitter Cards fall back to Open Graph
            # when Twitter-specific tags are absent — not a finding.
            findings.append(Finding(
                "Social", "social.twitter.fallback", "info",
                "no twitter:card — platforms fall back to the Open Graph "
                "tags, which are present"))
    elif card.strip().lower() not in TWITTER_CARD_TYPES:
        findings.append(Finding(
            "Social", "social.twitter.card_invalid", "warn",
            f"twitter:card is {card!r}, which is not one of the defined "
            f"card types ({', '.join(TWITTER_CARD_TYPES)})",
            "Use summary or summary_large_image — an unknown value is "
            "ignored, the same as having no tag"))
    elif card.strip().lower() == "summary_large_image" \
            and "twitter:image" not in facts.twitter:
        findings.append(Finding(
            "Social", "social.twitter.image_missing", "warn",
            "twitter:card is summary_large_image but twitter:image is "
            "missing — that card mode specifically needs its own image tag",
            "Add <meta name=\"twitter:image\" content=\"https://…\"> "
            "(or drop to a plain summary card)"))
    else:
        findings.append(Finding(
            "Social", "social.twitter.ok", "pass", f"twitter:card = {card}"))

    return findings


def _audit_og_values(facts: PageFacts) -> list[Finding]:
    """Presence is only half of it — the ways a *present* social tag
    still produce no preview are a relative og:image/twitter:image and an
    og:url that disagrees with the canonical."""
    findings: list[Finding] = []

    for tag, code in (("og:image", "social.og.image_relative"),
                      ("twitter:image", "social.twitter.image_relative")):
        value = facts.og.get(tag) if tag.startswith("og:") \
            else facts.twitter.get(tag)
        if value and not value.lower().startswith(("http://", "https://")):
            findings.append(Finding(
                "Social", code, "warn",
                f"{tag} is a relative URL ({value!r}) — most crawlers "
                "(Facebook's included) require an absolute one and will "
                "show no image at all",
                "Use the full https://host/path form"))

    og_url = facts.og.get("og:url")
    if og_url and facts.canonical:
        if normalize_url(urljoin(facts.final_url or "", og_url)) \
                != normalize_url(facts.canonical):
            findings.append(Finding(
                "Social", "social.og.url_mismatch", "info",
                f"og:url ({og_url}) and rel=canonical ({facts.canonical}) "
                "point at different URLs",
                "Keep them identical — they answer the same question and "
                "sharing counts get split when they disagree"))

    for tag in ("og:title", "og:description"):
        value = facts.og.get(tag)
        if value is not None and not value.strip():
            findings.append(Finding(
                "Social", f"social.{tag.replace(':', '.')}.empty", "warn",
                f"{tag} is present but empty",
                "Give it real content or remove the tag"))

    return findings


# ---------------------------------------------------------------------------
# A5b. Hreflang — no findings at all on a single-language page
# ---------------------------------------------------------------------------

def audit_hreflang(facts: PageFacts) -> list[Finding]:
    if not facts.hreflang:
        return []

    findings: list[Finding] = []
    langs = [h["lang"] for h in facts.hreflang]

    bad = [h["lang"] for h in facts.hreflang
           if not HREFLANG_RE.match(h["lang"])]
    if bad:
        findings.append(Finding(
            "Hreflang", "hreflang.code_invalid", "warn",
            f"{len(bad)} hreflang value(s) are not valid language(-region) "
            f"codes: {_listed(bad)}",
            "Use ISO 639-1 language plus optional ISO 3166-1 Alpha-2 "
            "region (en, en-GB, zh-Hant), or x-default"))

    dupes = sorted({lang for lang in langs if langs.count(lang) > 1})
    if dupes:
        findings.append(Finding(
            "Hreflang", "hreflang.duplicate", "warn",
            f"the same hreflang value is declared more than once: "
            f"{_listed(dupes)} — conflicting entries invalidate the set",
            "Declare each language(-region) exactly once"))

    not_absolute = [h["href"] or "(empty)" for h in facts.hreflang
                    if not h.get("absolute")]
    if not_absolute:
        findings.append(Finding(
            "Hreflang", "hreflang.href_not_absolute", "warn",
            f"{len(not_absolute)} hreflang href(s) are not fully-qualified "
            f"http(s) URLs: {_listed(not_absolute)}",
            "hreflang targets must be absolute — a relative href is "
            "ignored even though a browser would resolve it"))

    page = normalize_url(facts.final_url) if facts.final_url else None
    self_refs = [h for h in facts.hreflang
                 if page is not None and h["resolved"]
                 and normalize_url(h["resolved"]) == page]
    if not self_refs:
        findings.append(Finding(
            "Hreflang", "hreflang.no_self_reference", "warn",
            "no hreflang entry points back at this page — a set without a "
            "self-reference is ignored wholesale",
            "Add an entry for this page's own language pointing at this "
            "URL"))
    elif facts.html_lang:
        # The page declares its language twice — on <html> and in the
        # self-referencing hreflang — and the two are read as one signal.
        # Compare primary subtags only: <html lang="en"> with a
        # self-referencing "en-GB" entry is agreement, not a conflict.
        # x-default is a fallback marker, not a language, so it never
        # conflicts with anything.
        page_lang = facts.html_lang.split("-")[0].strip().lower()
        mismatched = [h["lang"] for h in self_refs
                      if h["lang"].strip().lower() != "x-default"
                      and h["lang"].split("-")[0].strip().lower() != page_lang]
        if mismatched:
            findings.append(Finding(
                "Hreflang", "hreflang.lang_mismatch", "warn",
                f"<html lang={facts.html_lang!r}> but the self-referencing "
                f"hreflang entry declares {mismatched[0]!r} — the page's "
                "two language signals disagree, and one of them is wrong",
                "Make them say the same language — crawlers read both, and "
                "the disagreement is a coin flip for which one wins"))

    if "x-default" not in {lang.lower() for lang in langs}:
        findings.append(Finding(
            "Hreflang", "hreflang.no_x_default", "info",
            "no x-default entry",
            "Add one pointing at the page for users whose language "
            "matches none of the alternates"))

    if not findings:
        findings.append(Finding(
            "Hreflang", "hreflang.ok", "pass",
            f"{len(facts.hreflang)} hreflang alternates, self-referencing, "
            f"with x-default: {', '.join(dict.fromkeys(langs))}"))
    return findings


# ---------------------------------------------------------------------------
# A6. Structured data (JSON-LD, microdata, RDFa)
# ---------------------------------------------------------------------------

def audit_structured_data(facts: PageFacts) -> list[Finding]:
    findings: list[Finding] = []
    other = facts.microdata_types + facts.rdfa_types

    if not facts.jsonld:
        if other:
            findings.append(Finding(
                "Structured Data", "structured.non_jsonld_only", "info",
                "no JSON-LD, but the markup carries microdata/RDFa types: "
                + _listed([t.rsplit("/", 1)[-1] for t in other]),
                "Search engines read all three formats; JSON-LD is the one "
                "Google recommends and the easiest to keep correct"))
        else:
            findings.append(Finding(
                "Structured Data", "structured.none", "info",
                "no JSON-LD, microdata or RDFa structured data on the page",
                "Structured data is an enhancement, not a baseline "
                "requirement — add schema.org markup (e.g. Organization, "
                "Product, BreadcrumbList) if the page type benefits"))
        return findings

    types: list[str] = []
    valid = 0
    for block in facts.jsonld:
        if block["error"]:
            findings.append(Finding(
                "Structured Data", "structured.jsonld.malformed", "fail",
                f"malformed JSON-LD block ({block['error'][:120]}) — search "
                "engines silently ignore broken blocks, so this markup is "
                "pure waste",
                "Fix the JSON so the block parses; test it in Google's "
                "Rich Results Test"))
            continue
        valid += 1
        types.extend(block["types"])

    no_context = sum(1 for b in facts.jsonld
                     if not b["error"] and not b["has_context"])
    if no_context:
        findings.append(Finding(
            "Structured Data", "structured.jsonld.no_context", "fail",
            f"{no_context} JSON-LD block(s) parse but declare no @context — "
            "without it the vocabulary is undefined and the block is "
            "ignored just as silently as broken JSON",
            "Add \"@context\": \"https://schema.org\" to every block"))

    typeless = sum(1 for b in facts.jsonld
                   if not b["error"] and b["has_context"] and not b["types"])
    if typeless:
        findings.append(Finding(
            "Structured Data", "structured.jsonld.no_type", "warn",
            f"{typeless} JSON-LD block(s) declare no @type — nothing in "
            "them can be matched to a schema.org entity",
            "Add an @type naming what the block describes"))

    if valid:
        detail = f"{valid} valid JSON-LD block(s)"
        if types:
            detail += " — types: " + ", ".join(dict.fromkeys(types))
        else:
            detail += " (no @type found)"
        findings.append(Finding("Structured Data", "structured.jsonld.ok",
                                "pass", detail))

    if other:
        findings.append(Finding(
            "Structured Data", "structured.non_jsonld_also", "info",
            "microdata/RDFa types are also present: "
            + _listed([t.rsplit("/", 1)[-1] for t in other]),
            "Two formats describing the same thing can contradict each "
            "other — keep one as the source of truth"))

    return findings


# ---------------------------------------------------------------------------
# A7. Content & links
# ---------------------------------------------------------------------------

def audit_content(facts: PageFacts,
                  min_words: int = THIN_CONTENT_WORDS) -> list[Finding]:
    findings: list[Finding] = []

    if facts.word_count < min_words:
        findings.append(Finding(
            "Content", "content.thin", "info",
            f"{facts.word_count} words — under the ~{min_words}-word "
            "'thin content' heuristic (a heuristic, not a rule: a tool page "
            "or a contact page can legitimately be short)",
            "If this page is meant to rank for something, make sure it "
            "actually answers the query in depth"))
    else:
        findings.append(Finding("Content", "content.words.ok", "pass",
                                f"{facts.word_count} words of content"))

    if facts.html_bytes:
        ratio = facts.text_bytes / facts.html_bytes
        if ratio < MIN_TEXT_HTML_RATIO:
            findings.append(Finding(
                "Content", "content.text_ratio.low", "info",
                f"text is {ratio:.1%} of the HTML "
                f"({facts.text_bytes} chars of text in "
                f"{facts.html_bytes} bytes of markup)",
                "Usually a shell that renders its content client-side — "
                "check that a crawler without JavaScript sees the words a "
                "reader sees"))

    if not facts.has_main_landmark:
        findings.append(Finding(
            "Content", "content.landmark.missing", "info",
            "no <main> or <article> element",
            "Wrap the page's own content in one — it tells assistive "
            "technology and content extractors which part is the page and "
            "which is chrome"))

    if facts.links_nofollow:
        findings.append(Finding(
            "Content", "content.links.nofollow", "info",
            f"{len(facts.links_nofollow)} of "
            f"{len(facts.links_internal) + len(facts.links_external)} links "
            f"carry rel=nofollow/sponsored/ugc: "
            f"{_listed(facts.links_nofollow)}",
            "Expected on paid and user-generated links; on internal "
            "navigation it just wastes the link"))

    if facts.links_uncrawlable:
        findings.append(Finding(
            "Content", "content.links.uncrawlable", "warn",
            f"{len(facts.links_uncrawlable)} anchor(s) a crawler cannot "
            f"follow (href starts with # or javascript:): "
            f"{_listed(list(dict.fromkeys(facts.links_uncrawlable)))}",
            "Point them at real URLs, or use a <button> when they aren't "
            "navigation at all — a fragment or script href passes no link "
            "equity and can't be followed"))

    return findings


def needs_get_retry(code: int) -> bool:
    """Whether a HEAD response is worth a second (GET) request: many CDNs
    and WAFs refuse HEAD outright while GET works fine. 404/410 are honest
    answers — spending a second request on them proves nothing."""
    return code >= 400 and code not in (404, 410)


def default_probe(user_agent: str, verify: bool = True):
    """Build the network probe used by check_links — injectable so tests
    never touch the network (same pattern as seo-checks' external check).

    ``verify`` is threaded through deliberately: with --insecure the page
    itself is fetched without TLS verification, and a link check that
    still verified would fail every internal link on the staging host the
    flag exists for.
    """
    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    session.verify = verify

    def probe(url: str, timeout: int) -> tuple[int | None, str | None, str | None]:
        try:
            resp = session.head(url, timeout=timeout, allow_redirects=True)
            if needs_get_retry(resp.status_code):
                resp = session.get(url, timeout=timeout,
                                   allow_redirects=True, stream=True)
                resp.close()
            return resp.status_code, None, resp.url
        except requests.RequestException as exc:
            return None, type(exc).__name__, None

    return probe


def select_links(facts: PageFacts, scope: str = "all",
                 max_links: int = 0) -> list[str]:
    """The unique links a check pass should visit, in document order."""
    if scope == "internal":
        urls = list(facts.links_internal)
    elif scope == "external":
        urls = list(facts.links_external)
    else:
        urls = facts.links_internal + facts.links_external
    urls = list(dict.fromkeys(urls))
    return urls[:max_links] if max_links else urls


def check_links(facts: PageFacts, *, concurrency: int = 5, timeout: int = 10,
                user_agent: str = DEFAULT_UA, verify: bool = True,
                scope: str = "all", max_links: int = 0, probe=None,
                on_progress=None) -> list[Finding]:
    """Verify links on the page (opt-in — sends requests to hosts this
    script wouldn't otherwise touch). HEAD first, GET fallback where HEAD
    isn't allowed; non-2xx → one fail per broken URL, up to
    MAX_LINK_FINDINGS, then aggregated."""
    all_urls = select_links(facts, "all")
    urls = select_links(facts, scope, max_links)
    if not urls:
        return []

    if probe is None:
        probe = default_probe(user_agent, verify)

    internal = set(facts.links_internal)
    results: dict[str, tuple] = {}
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(probe, url, timeout): url for url in urls}
        # as_completed, not submission order: progress tracks what actually
        # finished, so one slow URL doesn't stall the counter at "3/50".
        for done, future in enumerate(as_completed(futures), 1):
            results[futures[future]] = future.result()
            if on_progress:
                on_progress(done, len(futures))

    findings: list[Finding] = []
    broken: list[tuple[str, str]] = []
    redirected: list[str] = []
    for url in sorted(results):
        code, error, final = _unpack_probe(results[url])
        if code is not None and 200 <= code < 300:
            if final and normalize_url(final) != normalize_url(url):
                redirected.append(f"{url} → {final}")
            continue
        reason = f"HTTP {code}" if code is not None else f"no response ({error})"
        broken.append((url, reason))

    for url, reason in broken[:MAX_LINK_FINDINGS]:
        where = "internal" if url in internal else "external"
        findings.append(Finding(
            "Links", "links.broken", "fail",
            f"{where} link {url} is unreachable — {reason}",
            "Fix or remove the link"))
    if len(broken) > MAX_LINK_FINDINGS:
        rest = len(broken) - MAX_LINK_FINDINGS
        findings.append(Finding(
            "Links", "links.broken.more", "fail",
            f"{rest} further unreachable link(s), not listed individually: "
            + _listed([u for u, _ in broken[MAX_LINK_FINDINGS:]]),
            "See findings.json for the full list"))

    if redirected:
        findings.append(Finding(
            "Links", "links.redirected", "info",
            f"{len(redirected)} link(s) reach their target only through a "
            f"redirect: {_listed(redirected)}",
            "Link straight at the final URL — each hop costs crawl budget"))

    if not broken:
        scope_note = "" if scope == "all" else f" ({scope} only)"
        capped = (f", capped from {len(all_urls)}"
                  if max_links and len(all_urls) > len(urls) else "")
        findings.append(Finding(
            "Links", "links.ok", "pass",
            f"{len(urls)} unique links verified{scope_note}{capped} "
            f"({len(facts.links_internal)} internal, "
            f"{len(facts.links_external)} external on the page), all "
            f"reachable"))
    return findings


def _unpack_probe(result) -> tuple[int | None, str | None, str | None]:
    """Probe results are (status, error, final_url); a two-tuple from an
    older stub still works."""
    if len(result) == 2:
        code, error = result
        return code, error, None
    return result


def check_canonical(facts: PageFacts, *, timeout: int = 10,
                    user_agent: str = DEFAULT_UA, verify: bool = True,
                    probe=None) -> list[Finding]:
    """Verify the canonical *target* when --check-links is on — one more
    request, folded into the same opt-in (a cross-domain canonical sends
    it to another host, which is exactly what that flag consents to).

    The presence checks only ever said the tag exists; this says whether
    it points at something. A canonical whose target errors or redirects
    is ignored, and the page consolidates into nothing.
    """
    if not facts.canonical:
        return []
    if probe is None:
        probe = default_probe(user_agent, verify)
    code, error, final = _unpack_probe(probe(facts.canonical, timeout))

    if code is None:
        return [Finding(
            "Meta", "meta.canonical.unreachable", "fail",
            f"canonical target {facts.canonical} — no response ({error})",
            "A canonical pointing at an unreachable URL is ignored; point "
            "it at a URL that answers 200")]
    if not 200 <= code < 300:
        return [Finding(
            "Meta", "meta.canonical.unreachable", "fail",
            f"canonical target {facts.canonical} returns HTTP {code}",
            "Point rel=canonical at a URL that answers 200 — one that "
            "errors is ignored, and the consolidation never happens")]
    if final and normalize_url(final) != normalize_url(facts.canonical):
        return [Finding(
            "Meta", "meta.canonical.redirects", "info",
            f"canonical target {facts.canonical} redirects to {final}",
            "Point rel=canonical straight at the final URL — every hop is "
            "a fresh chance for the signal to be dropped or re-read")]
    return [Finding(
        "Meta", "meta.canonical.reachable", "pass",
        f"canonical target answers 200: {facts.canonical}")]


# ---------------------------------------------------------------------------
# A8. Mixed content
# ---------------------------------------------------------------------------

def audit_mixed_content(facts: PageFacts) -> list[Finding]:
    if urlsplit(facts.final_url).scheme != "https":
        return [Finding(
            "Mixed Content", "mixed.not_applicable", "info",
            "page is served over plain http — the mixed-content check "
            "only applies to https pages")]

    if facts.mixed_content:
        return [Finding(
            "Mixed Content", "mixed.present", "warn",
            f"{len(facts.mixed_content)} resource(s) loaded over bare "
            f"http:// from an https page: {_listed(facts.mixed_content)}",
            "Serve every subresource over https — browsers block or flag "
            "mixed content, scripts and iframes most aggressively")]

    return [Finding(
        "Mixed Content", "mixed.none", "pass",
        f"no http:// subresources on an https page "
        f"({len(facts.resources)} checked)")]


# ---------------------------------------------------------------------------
# Report & artifacts
# ---------------------------------------------------------------------------

STATUS_ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌", "info": "ℹ️"}


def clip(val: str, max_len: int = 200) -> str:
    s = str(val).replace("\n", " ").replace("\r", " ")
    return s[:max_len] + "…" if len(s) > max_len else s


def esc_cell(val: str, max_len: int = 200) -> str:
    return clip(str(val).replace("|", "\\|"), max_len)


def category_status(findings: list[Finding], category: str) -> str:
    """Collapse a category's findings to one status for the summary table."""
    states = [f.status for f in findings if f.category == category]
    return min(states, key=lambda s: STATUS_ORDER[s]) if states else "—"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Highest-severity first, and within a tier in category order."""
    cat_rank = {c: i for i, c in enumerate(CATEGORIES)}
    return sorted(findings, key=lambda f: (STATUS_ORDER[f.status],
                                           cat_rank.get(f.category, 99)))


def count_statuses(findings: list[Finding]) -> dict[str, int]:
    return {s: sum(1 for f in findings if f.status == s)
            for s in ("fail", "warn", "info", "pass")}


def build_report(facts: PageFacts, findings: list[Finding]) -> str:
    counts = count_statuses(findings)
    # redirect_chain includes the originally requested hop, so the actual
    # number of redirects followed is one less than its length — a bare
    # 200 (no redirect) has exactly one entry, hop_count 0.
    hop_count = len(facts.redirect_chain) - 1
    head = f"`{facts.final_url or facts.requested_url}`"
    if facts.status is not None:
        head += f" · HTTP {facts.status}"
    if hop_count > 0:
        head += (f" · {hop_count} hop{'s' if hop_count != 1 else ''} from "
                 f"`{facts.requested_url}`")
    lines = [
        f"## Page SEO audit — {esc_cell(facts.final_url or facts.requested_url)}",
        "",
        head,
        "",
        (f"❌ {counts['fail']} fail · ⚠️ {counts['warn']} warn · "
         f"ℹ️ {counts['info']} info · ✅ {counts['pass']} pass"),
        "",
        (f"**{facts.word_count} words · {len(facts.links_internal)} internal "
         f"links · {len(facts.links_external)} external links**"),
        "",
        "### Category status", "",
        "| Category | Status |", "| --- | --- |",
    ]
    for category in CATEGORIES:
        st = category_status(findings, category)
        lines.append(f"| {category} | "
                     + (f"{STATUS_ICON[st]} {st}" if st in STATUS_ICON
                        else "—") + " |")

    lines += ["", "### Findings", "",
              "| Category | Status | Detail | Fix |",
              "| --- | --- | --- | --- |"]
    for f in sort_findings(findings):
        lines.append(f"| {f.category} | {STATUS_ICON[f.status]} {f.status} "
                     f"| {esc_cell(f.detail) or '—'} "
                     f"| {esc_cell(f.recommendation) or '—'} |")
    return "\n".join(lines)


def findings_payload(facts: PageFacts, findings: list[Finding]) -> dict:
    return {
        "url": facts.requested_url,
        "final_url": facts.final_url,
        "status": facts.status,
        "counts": count_statuses(findings),
        "category_status": {c: category_status(findings, c)
                            for c in CATEGORIES},
        "findings": [asdict(f) for f in findings],
    }


def write_artifacts(facts: PageFacts, findings: list[Finding], report: str,
                    out_dir: str | None = None) -> list[str]:
    out_dir = out_dir or os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return []
    os.makedirs(out_dir, exist_ok=True)

    written = []
    for name, payload in (("page_facts.json", asdict(facts)),
                          ("findings.json", findings_payload(facts, findings))):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        written.append(path)

    path = os.path.join(out_dir, "report.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(report + "\n")
    written.append(path)
    return written


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_checks(facts: PageFacts, options: Options) -> list[Finding]:
    """A0–A8 phase by phase, with progress events (the two network
    phases get their own sub-phases — they're the only slow ones)."""
    phases = [
        ("response", 10, 18, audit_response),
        ("meta", 18, 30, audit_meta),
        ("headings", 30, 40, audit_headings),
        ("images", 40, 50, audit_images),
        ("social tags", 50, 58, audit_social),
        ("hreflang", 58, 64, audit_hreflang),
        ("structured data", 64, 72, audit_structured_data),
        ("content", 72, 80,
         lambda f: audit_content(f, options.min_words)),
        ("mixed content", 80, 88, audit_mixed_content),
    ]
    findings: list[Finding] = []
    for name, lo, hi, fn in phases:
        emit({"type": "progress", "pct": lo, "message": f"Checking {name}"})
        findings.extend(fn(facts))
        emit({"type": "progress", "pct": hi, "message": f"{name} done"})

    if options.check_links:
        def on_progress(done: int, total: int) -> None:
            emit({"type": "progress",
                  "pct": round(90 + 10 * done / max(total, 1)),
                  "message": f"Links {done}/{total}"})
        emit({"type": "progress", "pct": 90, "message": "Verifying links"})
        # One shared probe session: the link pass and the canonical-target
        # check below are the same opt-in, so they share its connection
        # pool and its --insecure setting too.
        probe = default_probe(options.user_agent, options.verify)
        findings.extend(check_links(
            facts, concurrency=options.concurrency,
            timeout=options.link_timeout, user_agent=options.user_agent,
            verify=options.verify, scope=options.link_scope,
            max_links=options.max_links, on_progress=on_progress, probe=probe))
        findings.extend(check_canonical(facts, probe=probe,
                                        timeout=options.link_timeout))

    emit({"type": "progress", "pct": 100, "message": "Done"})
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Page SEO Audit — full on-page SEO audit of one URL "
                    "(meta, headings, alt text, social tags, hreflang, "
                    "structured data, mixed content)")
    parser.add_argument("--url", required=True,
                        help="URL of the page to audit")
    parser.add_argument("--follow-redirects", action="store_true",
                        help="Follow the redirect chain (PyShell passes the "
                             "flag when the toggle is on; a bare terminal "
                             "run audits exactly one response)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Per-request timeout in seconds")
    parser.add_argument("--user-agent", default=DEFAULT_UA,
                        help="User-Agent to send (some WAFs drop bare "
                             "python-requests)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS certificate verification "
                             "(internal/staging hosts)")

    checks = parser.add_argument_group("checks")
    checks.add_argument("--min-words", type=int, default=THIN_CONTENT_WORDS,
                        help=f"Thin-content threshold in words "
                             f"(default {THIN_CONTENT_WORDS})")
    checks.add_argument("--check-robots-txt", action="store_true",
                        help="Fetch the host's robots.txt and fold it into "
                             "the indexability verdict (one extra request, "
                             "same host)")
    checks.add_argument("--check-links", action="store_true",
                        help="Verify every link on the page and the "
                             "canonical target (extra requests to other "
                             "hosts — off by default)")
    checks.add_argument("--link-scope", choices=("all", "internal", "external"),
                        default="all",
                        help="Which links --check-links visits (default all)")
    checks.add_argument("--max-links", type=int, default=0,
                        help="Cap the number of links verified (0 = no cap)")
    checks.add_argument("--link-check-concurrency", type=int, default=5,
                        help="Link check concurrency (default 5)")
    checks.add_argument("--link-check-timeout", type=int, default=10,
                        help="Link check timeout in seconds (default 10)")
    checks.add_argument("--ignore", action="append", default=[],
                        metavar="CATEGORY",
                        help="Drop a category from the report entirely "
                             "(repeatable): " + ", ".join(CATEGORIES))

    out = parser.add_argument_group("output")
    out.add_argument("--output-dir",
                     help="Write the artifacts here (defaults to "
                          "PYSHELL_OUTPUT_DIR when running under PyShell)")
    out.add_argument("--format", choices=("markdown", "json"),
                     default="markdown",
                     help="What to print on stdout at the end")
    out.add_argument("--fail-on", choices=("none", "warn", "fail"),
                     default="none",
                     help="Exit 2 when a finding at this severity or worse "
                          "is present (default none — the audit's own "
                          "success is the exit code)")
    return parser


def _fail_threshold_hit(counts: dict[str, int], fail_on: str) -> bool:
    if fail_on == "fail":
        return counts["fail"] > 0
    if fail_on == "warn":
        return counts["fail"] > 0 or counts["warn"] > 0
    return False


def _report_failure(message: str, kind: str | None = None) -> int:
    print(f"✗ {message}", file=sys.stderr, flush=True)
    suffix = f" · _{kind}_" if kind else ""
    emit({"type": "markdown", "content":
          f"## Audit failed\n\n❌ **{esc_cell(message)}**{suffix}"})
    status(f"Failed: {kind or message}")
    return 1


def main() -> int:
    args = build_parser().parse_args()

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no request sent", flush=True)
        return 0

    unknown = [c for c in args.ignore if c not in CATEGORIES]
    if unknown:
        print(f"✗ unknown --ignore category: {', '.join(unknown)}",
              file=sys.stderr, flush=True)
        return 1

    verify = not args.insecure
    if not verify:
        # Otherwise urllib3 writes a non-JSON warning into the same stderr
        # stream the structured events go to, once per request.
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except (ImportError, AttributeError):  # pragma: no cover
            pass

    # An empty --user-agent (an untouched, defaultless PyShell field) is
    # exactly the bare-client signature the flag exists to avoid.
    user_agent = (args.user_agent or "").strip() or DEFAULT_UA
    headers = {"User-Agent": user_agent}

    url = args.url.strip()
    if "://" not in url:
        url = "https://" + url

    print(f"Auditing {url}", flush=True)
    status(f"Fetching {url}…")

    try:
        hops, body, truncated, no_location = fetch_page(
            url, headers=headers, timeout=args.timeout,
            follow=args.follow_redirects, verify=verify)
    except requests.RequestException as exc:
        kind = "timeout" if isinstance(exc, requests.Timeout) else "request error"
        return _report_failure(f"{type(exc).__name__}: {exc}", kind)

    for i, hop in enumerate(hops, 1):
        status(f"Hop {i}: {hop.status} {hop.url}")

    final = hops[-1]
    headers_view = HeadersView(final.headers)
    content_type = headers_view.get("Content-Type")
    print(f"← {final.status} {final.url} ({len(hops)} hop(s))", flush=True)

    # The chain ran past MAX_HOPS (or loops): there is no page body, so
    # there is nothing to audit — saying so beats reporting an empty page.
    if len(hops) >= MAX_HOPS and final.status in REDIRECT_STATUSES:
        return _report_failure(
            f"the redirect chain is still redirecting after {MAX_HOPS} hops "
            f"(last: {final.status} {final.url}) - it is too long or it "
            f"loops, so no page body was reached", "redirect chain")

    # A JSON API, a PDF or an image parses into "a page with no title and
    # no h1" — a report that looks like a catastrophically bad page
    # instead of saying this was never a page.
    base_type = (content_type or "").split(";", 1)[0].strip().lower()
    if base_type and base_type not in HTML_CONTENT_TYPES:
        return _report_failure(
            f"the response is {base_type}, not HTML — there is no on-page "
            f"SEO to audit here", "wrong content type")

    emit({"type": "progress", "pct": 5, "message": "Parsing HTML"})
    try:
        facts = parse_facts(body, final.url)
    except (etree.LxmlError, ValueError) as exc:
        return _report_failure(
            f"response arrived but is not parseable HTML: {exc}")

    facts.requested_url = url
    facts.final_url = final.url
    facts.status = final.status
    facts.content_type = content_type
    facts.redirect_chain = [{"url": h.url, "status": h.status} for h in hops]
    facts.redirect_no_location = no_location
    facts.body_truncated = truncated
    facts.x_robots_tag = headers_view.get_all("X-Robots-Tag")

    if args.check_robots_txt:
        status("Fetching robots.txt…")
        emit({"type": "progress", "pct": 8, "message": "Reading robots.txt"})
        (facts.robots_txt_url, facts.robots_txt_verdict,
         facts.robots_txt_error) = fetch_robots_txt(
            facts.final_url, headers=headers, timeout=args.timeout,
            verify=verify)

    options = Options(
        min_words=args.min_words,
        check_links=args.check_links,
        link_scope=args.link_scope,
        max_links=max(args.max_links, 0),
        concurrency=args.link_check_concurrency,
        link_timeout=args.link_check_timeout,
        user_agent=user_agent,
        verify=verify,
    )
    findings = run_checks(facts, options)
    if args.ignore:
        findings = [f for f in findings if f.category not in args.ignore]

    emit({"type": "table",
          "columns": ["Category", "Status", "Detail", "Fix"],
          "rows": [[f.category, f"{STATUS_ICON[f.status]} {f.status}",
                    clip(f.detail), clip(f.recommendation)]
                   for f in sort_findings(findings)]})

    report = build_report(facts, findings)
    emit({"type": "markdown", "content": report})
    write_artifacts(facts, findings, report, args.output_dir)

    counts = count_statuses(findings)
    summary = (f"{len(findings)} findings: {counts['fail']} fail · "
               f"{counts['warn']} warn · {counts['info']} info · "
               f"{counts['pass']} pass")
    status(summary)
    if args.format == "json":
        print(json.dumps(findings_payload(facts, findings), indent=2,
                         ensure_ascii=False), flush=True)
    else:
        print(f"\n{summary}", flush=True)

    # A page failing every check is still a successful audit — unless the
    # caller asked for a CI gate.
    return 2 if _fail_threshold_hit(counts, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
