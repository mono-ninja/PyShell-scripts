"""Extract title/meta/canonical/links from HTML (plan A5).

``lxml.html`` — lenient with malformed markup. A page whose body fails to
parse entirely raises (``lxml``'s ParserError etc.); the caller records
the page with the parse failure in ``error`` and moves on — one broken
page must not lose the rest of the crawl's data.

Link URLs come out already classified (internal = in scope) and
normalized exactly the way :mod:`src.frontier` normalizes them, so the
``links_internal`` lists written to the snapshot are the same strings the
snapshot uses as page keys — ``seo-checks``' reverse-link index matches
without any second normalization pass.

Head metadata is read from ``<head>`` only. Scanning the whole document
for ``<title>`` picks up the ``<title>`` inside an inline ``<svg>`` icon,
which would report a page that genuinely has no title as having one —
turning a finding into a false negative.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import lxml.html

from src.frontier import Scope, normalize_url

# <link rel=…> values that name a file to fetch. Everything else with an
# href is a *page* relationship (alternate/next/prev) or a connection hint
# (preconnect/dns-prefetch, which name an origin, not a document) and has
# no business being fetched as a status-only leaf.
RESOURCE_RELS = {"stylesheet", "icon", "shortcut icon", "apple-touch-icon",
                 "apple-touch-icon-precomposed", "mask-icon", "preload",
                 "manifest", "modulepreload"}

# Elements whose text is not page copy, for the word count.
_NON_TEXT_TAGS = ("script", "style", "noscript", "template", "svg")


@dataclass
class ParsedPage:
    title: str | None
    meta_description: str | None
    canonical: str | None
    meta_robots: str | None
    links_internal: list[str] = field(default_factory=list)
    links_external: list[str] = field(default_factory=list)
    link_rels: dict[str, str] = field(default_factory=dict)   # url -> rel tokens
    resources: list[str] = field(default_factory=list)        # img/link/script
    canonical_all: list[str] = field(default_factory=list)    # every rel=canonical
    hreflang: dict[str, str] = field(default_factory=dict)    # lang -> absolute url
    pagination: dict[str, str] = field(default_factory=dict)  # next/prev -> url
    h1: list[str] = field(default_factory=list)
    lang: str | None = None
    og_title: str | None = None
    og_description: str | None = None
    word_count: int = 0
    images_total: int = 0
    images_without_alt: int = 0
    images: list[str] = field(default_factory=list)          # deduped srcs
    images_missing_alt: list[str] = field(default_factory=list)
    nofollow_links: list[str] = field(default_factory=list)
    # --- schema 4 ---------------------------------------------------
    json_ld: list = field(default_factory=list)      # parsed ld+json blocks
    json_ld_broken: int = 0                          # ld+json that won't parse
    headings: list[dict] = field(default_factory=list)  # outline: {level, text}
    anchor_text: dict[str, list[str]] = field(default_factory=dict)
    charset: str | None = None                       # the document's own claim
    meta_viewport: str | None = None
    # --- schema 5 ---------------------------------------------------
    open_graph: dict[str, str] = field(default_factory=dict)   # every og:*
    twitter: dict[str, str] = field(default_factory=dict)      # every twitter:*
    meta_refresh: str | None = None                  # http-equiv=refresh content
    title_all: list[str] = field(default_factory=list)  # every <title>, empties too
    text_hash: str | None = None                     # sha256 of visible text
    base_href: str | None = None                     # effective <base href>
    iframes: list[str] = field(default_factory=list)  # embed srcs
    itemtypes: list[str] = field(default_factory=list)  # microdata tokens
    # --- schema 6 ---------------------------------------------------
    dir: str | None = None                           # ltr / rtl direction


def _effective_base(doc: lxml.html.HtmlElement, base_url: str) -> str:
    for el in doc.iter("base"):
        href = el.get("href")
        if href:
            return urljoin(base_url, href)
    return base_url


def _head_of(doc: lxml.html.HtmlElement) -> lxml.html.HtmlElement:
    """The ``<head>`` element, or the document itself when there is none.

    lxml's HTML parser synthesizes a ``<head>`` for almost any input, so
    the fallback only fires on fragments — where scanning everything is
    the right thing to do anyway.
    """
    head = doc.find("head")
    return doc if head is None else head


def _rel_tokens(el) -> set[str]:
    return set((el.get("rel") or "").lower().split())


def parse_page(html: str, base_url: str, scope: Scope, *,
               strip_tracking_params: bool = True,
               drop_params: tuple[str, ...] = (),
               drop_all_params: bool = False) -> ParsedPage:
    """Parse one HTML document.

    ``base_url`` should be the *final* URL of the page (after redirects)
    — relative links resolve against where the browser would actually be.
    Raises when the body can't be parsed at all; partial garbage merely
    yields empty fields.
    """
    norm_kw = dict(strip_tracking_params=strip_tracking_params,
                   drop_params=drop_params, drop_all_params=drop_all_params)
    doc = lxml.html.document_fromstring(html)
    base = _effective_base(doc, base_url)
    head = _head_of(doc)

    parsed = ParsedPage(title=None, meta_description=None, canonical=None,
                        meta_robots=None)

    # The base the links actually resolved against — recorded only when a
    # <base href> exists; without one it is just the page URL, no fact.
    # A base pointing at a CDN silently turns internal links external,
    # and this is the field that lets a check explain why.
    if any(el.get("href") for el in doc.iter("base")):
        parsed.base_href = base

    root_lang = doc.get("lang") if doc.tag == "html" else None
    parsed.lang = (root_lang or "").strip() or None
    # Direction matters as much as language for i18n audits: an Arabic or
    # Hebrew page without dir=rtl renders backwards, and hreflang alone
    # cannot tell you that.
    root_dir = doc.get("dir") if doc.tag == "html" else None
    parsed.dir = (root_dir or "").strip().lower() or None

    for el in head.iter("title"):
        text = (el.text or "").strip()
        # Every <title> is kept, empty ones included — a present-but-empty
        # title tag is a fact the first-non-empty `title` hides. Two
        # conflicting titles is the same finding two canonicals are
        # (see canonical_all).
        parsed.title_all.append(text)
        if text and parsed.title is None:
            parsed.title = text

    for el in head.iter("meta"):
        name = (el.get("name") or "").strip().lower()
        prop = (el.get("property") or "").strip().lower()
        http_equiv = (el.get("http-equiv") or "").strip().lower()
        if parsed.charset is None and (el.get("charset") or "").strip():
            parsed.charset = el.get("charset").strip()
        content = (el.get("content") or "").strip() or None
        if content is None:
            continue
        if parsed.charset is None and http_equiv == "content-type":
            # <meta http-equiv=content-type content="text/html; charset=…">
            _, _, declared = content.lower().partition("charset=")
            if declared:
                parsed.charset = declared.split(";")[0].strip()
        if name == "description" and parsed.meta_description is None:
            parsed.meta_description = content
        elif name == "viewport" and parsed.meta_viewport is None:
            parsed.meta_viewport = content
        elif name == "robots" and parsed.meta_robots is None:
            parsed.meta_robots = content
        elif http_equiv == "refresh" and parsed.meta_refresh is None:
            # An HTML-level redirect the redirect_chain cannot see: the
            # crawler does not act on it, it records it.
            parsed.meta_refresh = content
        if prop.startswith("og:") and prop not in parsed.open_graph:
            parsed.open_graph[prop] = content
        if name.startswith("twitter:") and name not in parsed.twitter:
            parsed.twitter[name] = content

    # The dedicated fields stay (schema 2); they are the first — and
    # only the first — of their property, same as before.
    parsed.og_title = parsed.open_graph.get("og:title")
    parsed.og_description = parsed.open_graph.get("og:description")

    for el in head.iter("link"):
        rels = _rel_tokens(el)
        href = el.get("href")
        if not href:
            continue
        absolute = urljoin(base, href)
        if "canonical" in rels:
            # Every canonical is kept: two conflicting ones on a page is
            # itself the finding, and collapsing them to "the last one
            # wins" would erase it before seo-checks ever sees it.
            parsed.canonical_all.append(absolute)
        if "alternate" in rels:
            lang = (el.get("hreflang") or "").strip()
            if lang:
                parsed.hreflang.setdefault(lang, absolute)
        for rel in ("next", "prev"):
            if rel in rels:
                parsed.pagination.setdefault(rel, absolute)

    parsed.canonical = parsed.canonical_all[0] if parsed.canonical_all else None

    seen_internal: set[str] = set()
    seen_external: set[str] = set()
    followed: set[str] = set()   # linked at least once *without* rel=nofollow

    for el in doc.iter("a"):
        href = el.get("href")
        if not href:
            continue
        absolute = urljoin(base, href)
        parts = urlsplit(absolute)
        if parts.scheme.lower() not in ("http", "https"):
            continue  # mailto:, tel:, javascript:, data:, …
        try:
            if scope.in_scope(absolute):
                url = normalize_url(absolute, **norm_kw)
                if url not in seen_internal:
                    seen_internal.add(url)
                    parsed.links_internal.append(url)
            else:
                url = normalize_url(absolute, strip_tracking_params=False)
                if url not in seen_external:
                    seen_external.add(url)
                    parsed.links_external.append(url)
        except ValueError:
            continue
        rels = _rel_tokens(el)
        if rels:
            parsed.link_rels[url] = " ".join(sorted(rels))
        # The visible link text, per target: unique texts in document
        # order. "Click here" as every anchor is a finding made from
        # exactly this fact.
        text = (el.text_content() or "").strip()
        if text:
            anchors = parsed.anchor_text.setdefault(url, [])
            if text not in anchors:
                anchors.append(text)
        if "nofollow" not in rels:
            # One plain link to a URL makes it followed, however many
            # nofollowed links also point at it — so a nofollow recorded
            # earlier must not outlive a bare link found later.
            followed.add(url)

    parsed.nofollow_links = [url for url in parsed.links_internal
                             if url not in followed]

    seen_resources: set[str] = set()
    for el in doc.iter("img", "script", "link", "source"):
        src = None
        if el.tag in ("img", "script", "source"):
            src = el.get("src")
        else:
            # rel=canonical has its own field; alternate/next/prev name
            # pages (queued as pages by the caller, not fetched as
            # leaves); preconnect/dns-prefetch name origins, not files.
            if not (_rel_tokens(el) & RESOURCE_RELS):
                continue
            src = el.get("href")
        if not src:
            continue
        absolute = urljoin(base, src)
        if urlsplit(absolute).scheme.lower() not in ("http", "https"):
            continue
        try:
            url = normalize_url(absolute, strip_tracking_params=False)
        except ValueError:
            continue
        if url not in seen_resources:
            seen_resources.add(url)
            parsed.resources.append(url)

    parsed.h1 = [text for text in
                 ((el.text_content() or "").strip() for el in doc.iter("h1"))
                 if text]

    # The full heading outline, empty headings included: a heading with
    # no text is itself a fact (an SEO finding), which the non-empty h1
    # list above deliberately hides. Document order is kept — it is the
    # hierarchy.
    for el in doc.iter("h1", "h2", "h3", "h4", "h5", "h6"):
        parsed.headings.append({"level": int(el.tag[1]),
                                "text": (el.text_content() or "").strip()})

    # Structured data, parsed: every <script type=application/ld+json>,
    # head or body. A block that won't parse as JSON is counted rather
    # than dropped — "ships ld+json but it's broken" is exactly the
    # finding a checker needs to be able to make. Both shapes a page can
    # legitimately use (a single object, or a list of them) are kept
    # as-is; interpreting @graph is the reader's job.
    for el in doc.iter("script"):
        if (el.get("type") or "").strip().lower() != "application/ld+json":
            continue
        raw = (el.text_content() or "").strip()
        if not raw:
            continue
        try:
            parsed.json_ld.append(json.loads(raw))
        except ValueError:
            parsed.json_ld_broken += 1

    # Third-party embeds: iframes are documents, not assets (resources
    # is img/script/css), and a check may well care about every YouTube
    # and map embed a page carries.
    seen_iframes: set[str] = set()
    for el in doc.iter("iframe"):
        src = el.get("src")
        if not src:
            continue
        absolute = urljoin(base, src)
        if urlsplit(absolute).scheme.lower() not in ("http", "https"):
            continue
        try:
            url = normalize_url(absolute, strip_tracking_params=False)
        except ValueError:
            continue
        if url not in seen_iframes:
            seen_iframes.add(url)
            parsed.iframes.append(url)

    # Microdata: the itemtype tokens in use. Sites that ship structured
    # data as microdata instead of JSON-LD are invisible to the json_ld
    # field; this is their visibility.
    seen_itemtypes: set[str] = set()
    for el in doc.iter():
        raw = (el.get("itemtype") or "").strip()
        for token in raw.split():
            if token not in seen_itemtypes:
                seen_itemtypes.add(token)
                parsed.itemtypes.append(token)

    body = doc.find("body")
    visible = _visible_text(doc if body is None else body)
    parsed.word_count = len(visible.split())
    # Exact-duplicate detection beyond templates: the hash of the same
    # whitespace-collapsed visible text the word count is made of, so
    # incidental whitespace cannot make two copies of one page differ.
    parsed.text_hash = hashlib.sha256(visible.encode("utf-8")).hexdigest()

    # ``images_total``/``images_without_alt`` count *elements*; ``images``
    # and ``images_missing_alt`` are the deduped absolute srcs, so a check
    # can name *which* images lack alt, not just how many. An src that
    # appears both with and without alt lands in both lists — that is a
    # fact of the markup, and judging it is seo-checks' job.
    seen_images: set[str] = set()
    seen_missing_alt: set[str] = set()
    for el in doc.iter("img"):
        parsed.images_total += 1
        missing_alt = el.get("alt") is None
        if missing_alt:
            # alt="" is a deliberate "decorative, skip me" marker, not a
            # missing alt — counting it would flag correct markup.
            parsed.images_without_alt += 1
        src = el.get("src")
        if not src:
            continue
        absolute = urljoin(base, src)
        if urlsplit(absolute).scheme.lower() not in ("http", "https"):
            continue
        try:
            url = normalize_url(absolute, strip_tracking_params=False)
        except ValueError:
            continue
        if url not in seen_images:
            seen_images.add(url)
            parsed.images.append(url)
        if missing_alt and url not in seen_missing_alt:
            seen_missing_alt.add(url)
            parsed.images_missing_alt.append(url)

    return parsed


def _visible_text(root: lxml.html.HtmlElement) -> str:
    """Whitespace-collapsed visible copy — the word count's source and
    the ``text_hash`` input, so the hash cannot differ on incidental
    whitespace.

    script/style/svg text is not page content. Text nodes are joined
    with a space rather than concatenated: block boundaries carry no
    character of their own, so ``<h1>One</h1><h1>Two</h1>`` would
    otherwise read as the single word "OneTwo".

    The tree is walked rather than deep-copied and stripped: a copy of a
    5 MB document just to drop a few ``<script>`` tags is the single most
    expensive thing this module could do per page. The walk reproduces
    ``strip_elements(..., with_tail=False)`` semantics exactly — the text
    that *followed* a removed element is kept, the element's own text is
    not.
    """
    def texts(el):
        if el.text:
            yield el.text
        for child in el:
            if isinstance(child.tag, str) and child.tag not in _NON_TEXT_TAGS:
                yield from texts(child)
            # comments / PIs (non-string tags) and non-text elements
            # contribute only their tail — the copy that followed them.
            if child.tail:
                yield child.tail
    return " ".join(" ".join(texts(root)).split())
