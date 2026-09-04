"""A6 — Dedupe IDs and classes.

This is where every competing sprite builder falls down. Once several icons are
inlined into one document, an ``id="a"`` on a gradient in icon 1 and an
``id="a"`` on a path in icon 2 collide, and an Illustrator ``<style>``
block's ``.st0`` silently restyles every other icon in the sprite. The fix is
mechanical but has to be total: every id and every class gets a per-symbol
prefix, and every reference to either gets rewritten — in attributes, in
inline ``style`` attributes, and inside ``<style>`` element CSS.

References rewritten:

* ``href`` / ``xlink:href`` (``#id`` fragments);
* ``url(#id)`` in ``fill``, ``stroke``, ``clip-path``, ``mask``, ``filter``,
  ``marker-start`` / ``-mid`` / ``-end``;
* ``url(#id)`` in ``style`` attributes;
* ``url(#id)`` and ``#id`` / ``.class`` selectors inside ``<style>`` CSS;
* ``begin`` / ``end`` on animation elements (``id.event`` references).

Classes are prefixed and CSS selectors rewritten with ``tinycss2`` (strategy 1
from the plan: prefix and rewrite, do not inline yet).
"""
from __future__ import annotations

import re

import tinycss2

from .model import Symbol
from .parse import XLINK_NS

# Attributes whose value may contain url(#id) paint-server references.
_URL_ATTRS = {
    "fill", "stroke", "clip-path", "mask", "filter",
    "marker-start", "marker-mid", "marker-end",
}
# Attributes that are bare #id (or path#id) fragment references.
_FRAG_ATTRS = {"href", f"{{{XLINK_NS}}}href"}
# Animation elements whose begin/end may reference another element's id.
_ANIM_TAGS = {"animate", "animateMotion", "animateTransform", "set", "animateColor"}

# url(#id) — optional quotes, captures the id. Also normalises away the quotes.
_URL_REF_RE = re.compile(r"url\(\s*['\"]?#([^'\"\s)]+)['\"]?\s*\)")


def _local(tag) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _iter_elements(body) -> list:
    """All element nodes (string tags) in body, top elements and descendants."""
    out = []
    for top in body:
        if not isinstance(top.tag, str):
            continue
        out.extend(el for el in top.iter() if isinstance(el.tag, str))
    return out


def _rewrite_url_refs(val: str, id_map: dict[str, str]) -> str:
    if not val or "url(" not in val:
        return val

    def repl(m: re.Match) -> str:
        frag = m.group(1)
        return f"url(#{id_map.get(frag, frag)})"

    return _URL_REF_RE.sub(repl, val)


def _rewrite_fragment(val: str, id_map: dict[str, str]) -> str:
    if not val or "#" not in val:
        return val
    pre, _, frag = val.partition("#")
    if frag in id_map:
        return f"{pre}#{id_map[frag]}"
    return val


def _rewrite_anim_refs(val: str, id_map: dict[str, str]) -> str:
    """Rewrite ``id.event`` (and ``id.event+offset``) in begin/end values."""
    if not val:
        return val
    out = []
    for token in val.split(";"):
        token = token.strip()
        m = re.match(r"^([A-Za-z_][\w-]*)\.(\w.*)$", token)
        if m and m.group(1) in id_map:
            token = f"{id_map[m.group(1)]}.{m.group(2)}"
        out.append(token)
    return ";".join(out)


# --- CSS rewriting (tinycss2) ----------------------------------------------

def _rewrite_selector_tokens(prelude: list, id_map: dict, class_map: dict) -> None:
    """Prefix ``.class`` and ``#id`` selectors in place on a prelude token list.

    tinycss2 parses ``.cls`` as a ``LiteralToken('.')`` followed by an
    ``IdentToken``, and ``#id`` as a single ``HashToken`` — so the two cases
    are handled differently. Tokens are mutated in place; their ``serialize()``
    methods read back from ``value``.
    """
    for i, tok in enumerate(prelude):
        if tok.type == "hash" and tok.is_identifier and tok.value in id_map:
            tok.value = id_map[tok.value]
        elif tok.type == "literal" and tok.value == ".":
            if i + 1 >= len(prelude):
                continue
            nxt = prelude[i + 1]
            if nxt.type == "ident" and nxt.value in class_map:
                nxt.value = class_map[nxt.value]


def _rewrite_decl_urls(decls: list, id_map: dict) -> None:
    """Rewrite url(#id) inside declaration values (in place).

    A ``URLToken`` serializes from its ``representation`` (the raw ``url(#a)``
    text), not its ``value`` — so both must be updated for the change to show
    up in :func:`tinycss2.serialize`.
    """
    for d in decls:
        if d.type != "declaration":
            continue
        for vt in d.value:
            if vt.type == "url" and vt.value.startswith("#"):
                frag = vt.value[1:]
                if frag in id_map:
                    new = f"#{id_map[frag]}"
                    vt.value = new
                    vt.representation = f"url({new})"


def _rewrite_css(css_text: str, id_map: dict, class_map: dict) -> str:
    """Prefix selectors and rewrite url(#id) inside a <style> element's CSS."""
    rules = tinycss2.parse_stylesheet(css_text, skip_comments=True, skip_whitespace=True)
    for rule in rules:
        if rule.type == "qualified-rule":
            _rewrite_selector_tokens(rule.prelude, id_map, class_map)
            decls = tinycss2.parse_declaration_list(rule.content)
            _rewrite_decl_urls(decls, id_map)
            rule.content = decls
        elif rule.type == "at-rule" and rule.content is not None:
            # Best-effort for flat at-rules (e.g. @font-face declarations).
            # Nested rule blocks (@media) keep their url() refs intact rather
            # than risk mis-serialising a re-parsed tree.
            decls = tinycss2.parse_declaration_list(rule.content)
            _rewrite_decl_urls(decls, id_map)
            rule.content = decls
    return tinycss2.serialize(rules)


def _rewrite_root_attrs(sym: Symbol, id_map: dict) -> None:
    carried = sym.meta.get("root_attrs", {})
    for k, v in carried.items():
        if v and "url(" in v:
            carried[k] = _rewrite_url_refs(v, id_map)


def dedupe(sym: Symbol) -> None:
    """Prefix ids/classes and rewrite every reference. Mutates ``sym`` in place."""
    sid = sym.id
    elements = _iter_elements(sym.body)

    # 1. Prefix every id; build old→new map.
    id_map: dict[str, str] = {}
    for el in elements:
        old = el.get("id")
        if old:
            new = f"{sid}__{old}"
            id_map[old] = new
            el.set("id", new)
    sym.meta["id_map"] = id_map

    # 2. Collect class names; build old→new map.
    class_map: dict[str, str] = {}
    for el in elements:
        cls = el.get("class")
        if cls:
            for token in cls.split():
                if token and token not in class_map:
                    class_map[token] = f"{sid}__{token}"
    sym.meta["class_map"] = class_map

    # 3. Per-element rewrites: url() attrs, fragment attrs, inline style,
    #    animation begin/end, and the class attribute itself.
    for el in elements:
        tag = _local(el.tag)
        for attr in list(el.attrib):
            val = el.get(attr)
            if val is None:
                continue
            if attr in _URL_ATTRS:
                el.set(attr, _rewrite_url_refs(val, id_map))
            elif attr in _FRAG_ATTRS:
                new = _rewrite_fragment(val, id_map)
                if new != val:
                    el.set(attr, new)
            elif attr == "style":
                el.set(attr, _rewrite_url_refs(val, id_map))
            elif tag in _ANIM_TAGS and attr in ("begin", "end"):
                el.set(attr, _rewrite_anim_refs(val, id_map))
        if class_map and el.get("class"):
            new_cls = " ".join(class_map.get(t, t) for t in el.get("class").split())
            el.set("class", new_cls)

    # 4. <style> element CSS text: selectors + declaration url() refs.
    for el in elements:
        if _local(el.tag) == "style" and el.text:
            el.text = _rewrite_css(el.text, id_map, class_map)

    # 5. Carried root attributes may carry url(#id) (e.g. fill="url(#grad)").
    _rewrite_root_attrs(sym, id_map)
