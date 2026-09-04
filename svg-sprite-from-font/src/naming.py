"""B4 — name resolution.

The single stage that decides whether the output is usable: codepoints like
``uniE900`` are useless as symbol ids. Sources, in priority order:

1. **names.json** — a previous run's output, hand-edited. Wins on re-run so a
   human edit is authoritative.
2. **The CSS file** — ``.icon-user:before { content: "\\e900" }``. The name the
   theme's markup already uses; the best source.
3. **glyph-name / post table** — meaningful in IcoMoon output, sometimes just
   ``glyph42`` (then skipped as not meaningful).
4. **Ligature names** — Material Icons and descendants, reconstructed from the
   ``GSUB`` ``liga`` feature (done in :mod:`binfont`).
5. **Fallback** — ``uniE900``, always logged as unnamed so the gaps are visible.

The CSS class prefix (``fa-``, ``icon-`` ...) is detected as the longest common
prefix of the classes found in the CSS, so the bare name is ``user`` whether
the class was ``fa-user`` or ``icon-user``. The sprite prefix (``icon-`` by
default) is then prepended to form the symbol id.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from tinycss2 import parse_declaration_list, parse_stylesheet

from .model import RawGlyph

_MEANINGLESS = re.compile(
    r"^(\.notdef|\.null|glyph\d+|\d+|nonmarkingreturn|uni[0-9A-Fa-f]{1,6})$"
)


@dataclass
class NameBinding:
    sprite_id: str            # final, prefix-included, collision-free id
    name: str                 # bare, slugified name (e.g. "user")
    source: str               # names.json | css | post | gsub | fallback
    class_name: str | None    # primary legacy CSS class (e.g. "fa-user")
    aliases: list[str] = field(default_factory=list)  # other classes → same cp
    ligature: str | None = None
    unnamed: bool = False     # True for the fallback case


@dataclass
class NameResolution:
    bindings: list[NameBinding]          # parallel to the input glyphs
    names_json: dict                     # {key: {name, source, ...}}
    class_to_sprite: dict[str, str]      # every legacy CSS class -> sprite id
    css_prefix: str = ""
    sprite_prefix: str = "icon-"


def slugify(name: str) -> str:
    """Make a name safe as an SVG/CSS id fragment, preserving case."""
    name = name.strip()
    if not name:
        return "unnamed"
    out = re.sub(r"[^A-Za-z0-9_-]+", "-", name)
    out = re.sub(r"-+", "-", out).strip("-")
    return out or "unnamed"


def parse_css_classes(css_path: str) -> tuple[dict[int, str], dict[int, list[str]]]:
    """Read an icon-font CSS into ``(cp -> primary class, cp -> all classes)``.

    Matches ``.icon-user:before { content: "\\e900" }``. The StringToken value
    is already escape-decoded by tinycss2, so ``ord(value)`` is the codepoint.
    """
    with open(css_path, encoding="utf-8") as fh:
        css = fh.read()
    primary: dict[int, str] = {}
    all_classes: dict[int, list[str]] = {}
    for rule in parse_stylesheet(css, skip_comments=True, skip_whitespace=True):
        if rule.type != "qualified-rule":
            continue
        classes, has_before = _parse_selector(rule.prelude)
        if not has_before or not classes:
            continue
        cp = _content_codepoint(rule.content)
        if cp is None:
            continue
        all_classes.setdefault(cp, [])
        for cls in classes:
            if cls not in all_classes[cp]:
                all_classes[cp].append(cls)
        if cp not in primary:
            primary[cp] = classes[-1]  # last class is the icon-specific one
    return primary, all_classes


def _parse_selector(prelude) -> tuple[list[str], bool]:
    """Split a prelude on commas; for each group collect class names and detect
    a ``:before``/``::before`` pseudo-element."""
    classes: list[str] = []
    has_before = False
    group: list = []
    for tok in prelude:
        if tok.type == "literal" and tok.value == ",":
            c, b = _parse_group(group)
            classes.extend(c)
            has_before = has_before or b
            group = []
        else:
            group.append(tok)
    if group:
        c, b = _parse_group(group)
        classes.extend(c)
        has_before = has_before or b
    return classes, has_before


def _parse_group(tokens) -> tuple[list[str], bool]:
    classes: list[str] = []
    has_before = False
    after_dot = False
    after_colon = 0  # count consecutive ':'
    for tok in tokens:
        if tok.type == "literal" and tok.value == ".":
            after_dot = True
            continue
        if after_dot and tok.type == "ident":
            classes.append(tok.value)
            after_dot = False
            continue
        after_dot = False
        if tok.type == "literal" and tok.value == ":":
            after_colon += 1
            continue
        if after_colon and tok.type == "ident":
            if tok.value.lower() == "before":
                has_before = True
            after_colon = 0
            continue
        after_colon = 0
    return classes, has_before


def _content_codepoint(content_tokens) -> int | None:
    decls = parse_declaration_list(content_tokens)
    for d in decls:
        if d.type == "declaration" and d.name == "content":
            for tok in d.value:
                if tok.type == "string" and tok.value:
                    ch = tok.value[0]
                    return ord(ch)
    return None


def _common_class_prefix(classes: list[str]) -> str:
    if not classes:
        return ""
    pre = classes[0]
    for s in classes[1:]:
        while not s.startswith(pre):
            pre = pre[:-1]
            if not pre:
                return ""
    if "-" in pre:
        return pre[: pre.rindex("-") + 1]
    return ""


def _meaningful(name: str | None) -> bool:
    if not name:
        return False
    if _MEANINGLESS.match(name):
        return False
    return any(c.isalpha() for c in name)


def _cp_key(cp: int) -> str:
    return f"{cp:04x}"


def resolve_names(
    glyphs: list[RawGlyph],
    css_path: str | None,
    existing_names: dict | None,
    sprite_prefix: str = "icon-",
) -> NameResolution:
    primary_cls: dict[int, str] = {}
    all_cls: dict[int, list[str]] = {}
    if css_path:
        try:
            primary_cls, all_cls = parse_css_classes(css_path)
        except OSError:
            pass

    css_prefix = _common_class_prefix(list(primary_cls.values()))

    bindings: list[NameBinding] = []
    names_json: dict = {}
    used_ids: set[str] = set()
    class_to_sprite: dict[str, str] = {}

    def unique_id(bare: str) -> str:
        sid = slugify(bare)
        candidate = sprite_prefix + sid
        n = 2
        while candidate in used_ids:
            candidate = f"{sprite_prefix}{sid}-{n}"
            n += 1
        used_ids.add(candidate)
        return candidate

    for g in glyphs:
        name: str | None = None
        source = "fallback"
        class_name: str | None = None
        aliases: list[str] = []
        unnamed = False
        key: str
        if g.codepoint is not None:
            key = _cp_key(g.codepoint)
        else:
            key = f"lig:{g.ligature}" if g.ligature else f"gn:{g.glyph_name}"

        # 1. Hand-edited names.json.
        if existing_names and key in existing_names:
            ed = existing_names[key]
            if isinstance(ed, dict) and ed.get("name"):
                name = ed["name"]
                source = "names.json"
                class_name = ed.get("class")
                aliases = ed.get("aliases", []) or []

        # 2. CSS.
        if name is None and g.codepoint is not None and g.codepoint in primary_cls:
            cls = primary_cls[g.codepoint]
            class_name = cls
            aliases = [c for c in all_cls.get(g.codepoint, []) if c != cls]
            bare = cls[len(css_prefix):] if cls.startswith(css_prefix) else cls
            name = bare
            source = "css"

        # 3. post / glyph-name.
        if name is None and _meaningful(g.glyph_name):
            name = g.glyph_name
            source = "post"

        # 4. Ligature.
        if name is None and g.ligature:
            name = g.ligature
            source = "gsub"

        # 5. Fallback.
        if name is None:
            unnamed = True
            if g.codepoint is not None:
                name = f"uni{g.codepoint:04X}"
            elif g.ligature:
                name = g.ligature
            else:
                name = slugify(g.glyph_name or "unnamed")
            source = "fallback"

        bare = name
        sprite_id = unique_id(bare)
        b = NameBinding(
            sprite_id=sprite_id, name=slugify(bare), source=source,
            class_name=class_name, aliases=aliases, ligature=g.ligature,
            unnamed=unnamed,
        )
        bindings.append(b)

        # names.json entry.
        entry: dict = {"name": b.name, "source": source}
        if class_name:
            entry["class"] = class_name
        if aliases:
            entry["aliases"] = aliases
        if g.ligature:
            entry["ligature"] = g.ligature
        if g.codepoint is not None:
            entry["codepoint"] = f"U+{g.codepoint:04X}"
        names_json[key] = entry

        # Legacy class → sprite id (for migration.css).
        if class_name:
            class_to_sprite[class_name] = sprite_id
        for a in aliases:
            class_to_sprite[a] = sprite_id

    return NameResolution(
        bindings=bindings, names_json=names_json,
        class_to_sprite=class_to_sprite, css_prefix=css_prefix,
        sprite_prefix=sprite_prefix,
    )


def load_names_json(path: str) -> dict | None:
    """Read a hand-edited names.json, or None if missing/invalid."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None
