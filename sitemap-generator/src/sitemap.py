"""XML writing — urlset, xhtml:link alternates, 50k/50MB splitting, index.

The sitemap protocol (sitemaps.org, v0.9) caps one file at 50,000 URLs
and 50 MB uncompressed. This module never emits a file past either cap:
entries are chunked by count *and* by an estimated serialized size, with
a safety margin under the byte limit — an entry is ~``len(loc)`` bytes
plus fixed overhead plus one ``xhtml:link`` row per alternate.

When the URLs fit one file it is written as ``sitemap.xml`` (a plain
``<urlset>``). When they don't, ``sitemap.xml`` becomes a
``<sitemapindex>`` pointing at ``sitemap-1.xml`` … ``sitemap-N.xml``
next to it — the robots.txt ``Sitemap:`` line and every submission
bookmark keep pointing at the same URL, and the parts are referenced by
their absolute deployed location (``<scheme://host>/sitemap-i.xml``)
because an index must carry full URLs once uploaded.

``changefreq`` and ``priority`` are deliberately not written: Google has
ignored both for years, and emitting them would only date the file. The
report says so, so the omission reads as a decision, not an oversight.
"""
from __future__ import annotations

import io
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from src.eligibility import Entry

SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
XHTML_NS = "http://www.w3.org/1999/xhtml"

MAX_URLS_PER_FILE = 50_000
#: Margin under the protocol's 50 MB cap — the estimate is coarse, so the
#: real file lands well below the limit even when it guesses low.
MAX_BYTES_PER_FILE = 45 * 1024 * 1024

#: Serialized size of one <url> without its variable parts, measured on
#: an indented two-space document (opening/closing tags, newlines).
_ENTRY_OVERHEAD = 120
_ALTERNATE_OVERHEAD = 80


@dataclass
class WrittenSitemaps:
    """What write_sitemaps() produced, for the report and the summary."""
    files: list[str] = field(default_factory=list)   # filenames, ["sitemap.xml"] or index + parts
    total_urls: int = 0
    parts: int = 0                                   # 0 = single file
    indexed: bool = False                            # True = sitemap.xml is an index
    dirs: list[str] = field(default_factory=list)    # where the files landed


def _entry_bytes(entry: Entry) -> int:
    size = _ENTRY_OVERHEAD + len(entry.url.encode("utf-8"))
    if entry.lastmod:
        size += len(entry.lastmod) + 20
    size += sum(_ALTERNATE_OVERHEAD + len(href.encode("utf-8"))
                for _, href in entry.alternates)
    return size


def _chunk(entries: list[Entry]) -> list[list[Entry]]:
    """Split entries into file-sized chunks (count cap, byte cap, both)."""
    if not entries:
        return []
    chunks: list[list[Entry]] = []
    current: list[Entry] = []
    current_bytes = 0
    for entry in entries:
        size = _entry_bytes(entry)
        if current and (len(current) >= MAX_URLS_PER_FILE
                        or current_bytes + size > MAX_BYTES_PER_FILE):
            chunks.append(current)
            current, current_bytes = [], 0
        current.append(entry)
        current_bytes += size
    if current:
        chunks.append(current)
    return chunks


def _serialize(root: ET.Element) -> bytes:
    ET.indent(root, space="  ")
    # ET.register_namespace (done below) keeps the default namespace
    # xmlns=… instead of ns0: prefixes.
    buf = io.BytesIO()
    ET.ElementTree(root).write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue() + b"\n"


def build_urlset(entries: list[Entry]) -> bytes:
    """A complete <urlset> document for one chunk of entries."""
    ET.register_namespace("", SITEMAP_NS)
    has_alternates = any(e.alternates for e in entries)
    if has_alternates:
        ET.register_namespace("xhtml", XHTML_NS)
    root = ET.Element(f"{{{SITEMAP_NS}}}urlset")
    for entry in entries:
        url_el = ET.SubElement(root, f"{{{SITEMAP_NS}}}url")
        ET.SubElement(url_el, f"{{{SITEMAP_NS}}}loc").text = entry.url
        if entry.lastmod:
            ET.SubElement(url_el, f"{{{SITEMAP_NS}}}lastmod").text = entry.lastmod
        for lang, href in entry.alternates:
            link = ET.SubElement(url_el, f"{{{XHTML_NS}}}link")
            link.set("rel", "alternate")
            link.set("hreflang", lang)
            link.set("href", href)
    return _serialize(root)


def build_index(part_urls: list[str], generated_at: datetime | None = None) -> bytes:
    """A <sitemapindex> document pointing at the part files."""
    ET.register_namespace("", SITEMAP_NS)
    generated_at = generated_at or datetime.now(timezone.utc)
    root = ET.Element(f"{{{SITEMAP_NS}}}sitemapindex")
    for part_url in part_urls:
        sitemap_el = ET.SubElement(root, f"{{{SITEMAP_NS}}}sitemap")
        ET.SubElement(sitemap_el, f"{{{SITEMAP_NS}}}loc").text = part_url
        ET.SubElement(sitemap_el, f"{{{SITEMAP_NS}}}lastmod").text = \
            generated_at.astimezone(timezone.utc).isoformat(timespec="seconds")
    return _serialize(root)


def write_sitemaps(entries: list[Entry], out_dirs: list[str], site_origin: str,
                   generated_at: datetime | None = None) -> WrittenSitemaps:
    """Decide single-file vs index+parts and write every file to every dir.

    The caller has already refused the empty case — an empty sitemap
    deployed on top of a working one would drop the whole site, so this
    function raising on ``entries == []`` is a programming-error guard,
    not a user-facing path.
    """
    if not entries:
        raise ValueError("refusing to write an empty sitemap")
    if not out_dirs:
        raise ValueError("no output directories")

    chunks = _chunk(entries)
    written = WrittenSitemaps(total_urls=len(entries), dirs=list(out_dirs))

    def write_everywhere(name: str, data: bytes) -> None:
        for out_dir in out_dirs:
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, name), "wb") as fh:
                fh.write(data)
        written.files.append(name)

    if len(chunks) == 1:
        write_everywhere("sitemap.xml", build_urlset(chunks[0]))
        return written

    # Split case: sitemap.xml is the index, parts sit next to it. The
    # index references the parts by their deployed absolute URL — the
    # only form a live index may carry.
    written.indexed = True
    written.parts = len(chunks)
    for i, chunk in enumerate(chunks, start=1):
        write_everywhere(f"sitemap-{i}.xml", build_urlset(chunk))
    part_urls = [f"{site_origin}/sitemap-{i}.xml"
                 for i in range(1, len(chunks) + 1)]
    write_everywhere("sitemap.xml", build_index(part_urls, generated_at))
    # The index is the entry point — list it first so the report reads
    # "sitemap.xml (index) + N parts" in deployment order.
    written.files = ["sitemap.xml"] + [f for f in written.files if f != "sitemap.xml"]
    return written
