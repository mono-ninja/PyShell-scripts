#!/usr/bin/env python3
"""a11y-check/main.py — the accessibility pass, statically and honestly.

Accessibility was the biggest gap in the collection after 48 scripts,
and this fills it the collection's way: one fetch (the Page SEO Audit
principle), everything computed from the HTML and the CSS that can be
read statically.  The checks:

- **Contrast** (WCAG 1.4.3) — text color × background color wherever
  the pairing is unambiguous: inline styles, `<style>` blocks and
  fetched stylesheets, simple tag/class/id selectors only.  The color
  parser is the one written for **color-palette** (every CSS syntax →
  RGB), the ratio is the WCAG relative-luminance formula, the
  threshold knows large text (24px, or 19px bold → 3:1 instead of
  4.5:1).  Where CSS cannot be paired statically — JS-computed
  styles, descendant selectors, inheritance chains — the report says
  "not checked", never "passed".
- **Forms** — inputs/selects/textareas without a `<label for>`, an
  aria-label/labelledby, a wrapping label or a title;
  placeholder-only is flagged as a warning (it is not a label).
- **Headings** — level skips (h2 → h4), no h1, several h1.
- **Language** — `lang` on `<html>` (WCAG 3.1.1, level A), invalid
  codes, foreign-language inserts.
- **ARIA misuse** — roles without their required state
  (checkbox/slider/…), `aria-hidden` or `role=presentation` on
  focusable elements.
- **Focus** — `tabindex` above 0 (the DOM order is the right order).
- **Links** — empty links, "click here" generic text.
- **Tables** — no `<th>`, `<th>` without `scope`.
- **Landmarks & skip link** — main/nav/header, the first `#` link.

Image `alt` is **Page SEO Audit's** column — this script counts them
for context and points there, it does not double-audit.

Exit codes: 0 = ran (findings are results), 1 = unreachable, 2 = bad
arguments.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field

import lxml.html
import requests

USER_AGENT = "PyShell-a11y-check/1 (+accessibility diagnostics)"

# ── the color parser written for color-palette, carried over ─────────────

CSS_NAMED_COLORS = {
    "black": "#000000", "white": "#FFFFFF", "red": "#FF0000",
    "green": "#008000", "blue": "#0000FF", "yellow": "#FFFF00",
    "gray": "#808080", "grey": "#808080", "silver": "#C0C0C0",
    "maroon": "#800000", "olive": "#808000", "lime": "#00FF00",
    "aqua": "#00FFFF", "teal": "#008080", "navy": "#000080",
    "fuchsia": "#FF00FF", "purple": "#800080", "orange": "#FFA500",
    "pink": "#FFC0CB", "brown": "#A52A2A", "beige": "#F5F5DC",
    "gold": "#FFD700", "cyan": "#00FFFF", "magenta": "#FF00FF",
    "darkgray": "#A9A9A9", "darkgrey": "#A9A9A9", "lightgray": "#D3D3D3",
    "lightgrey": "#D3D3D3", "dimgray": "#696969", "dimgrey": "#696969",
    "whitesmoke": "#F5F5F5", "gainsboro": "#DCDCDC", "lightyellow": "#FFFFE0",
    "lightcyan": "#E0FFFF", "lightgoldenrodyellow": "#FAFAD2",
}


def parse_color(value: str) -> str | None:
    """Any CSS color value → normalized #RRGGBB (color-palette's
    parser; alpha dropped — the contrast wants the color)."""
    value = (value or "").strip().lower()
    if not value:
        return None
    if value in CSS_NAMED_COLORS:
        return CSS_NAMED_COLORS[value]
    if re.match(r"^#[0-9a-f]{3}$", value):
        return "#" + "".join(c * 2 for c in value[1:]).upper()
    if re.match(r"^#[0-9a-f]{6}$", value):
        return value.upper()
    if re.match(r"^#[0-9a-f]{8}$", value):
        return ("#" + value[1:7]).upper()
    m = re.match(r"^rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", value)
    if m:
        return "#{:02X}{:02X}{:02X}".format(*(min(255, int(g))
                                              for g in m.groups()))
    m = re.match(r"^rgba?\(\s*([\d.]+)%\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%",
                 value)
    if m:
        return "#{:02X}{:02X}{:02X}".format(
            *(round(float(g) * 2.55) for g in m.groups()))
    m = re.match(r"^hsla?\(\s*([\d.]+)(?:deg|turn)?\s*,\s*([\d.]+)%"
                 r"\s*,\s*([\d.]+)%", value)
    if m:
        h = float(m.group(1)) * 360 if "turn" in value else float(m.group(1))
        return _hsl_to_hex(h, float(m.group(2)), float(m.group(3)))
    return None


def _hsl_to_hex(h: float, s: float, l: float) -> str:
    s, l = s / 100, l / 100
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = l - c / 2
    seg = int(h // 60) % 6
    rgb = [(c, x, 0), (x, c, 0), (0, c, x),
           (0, x, c), (x, 0, c), (c, 0, x)][seg]
    return "#{:02X}{:02X}{:02X}".format(*(round((v + m) * 255)
                                          for v in rgb))


def _hex_rgb(hex_color: str) -> tuple[int, int, int]:
    return (int(hex_color[1:3], 16), int(hex_color[3:5], 16),
            int(hex_color[5:7], 16))


def _wcag_channel(v: int) -> float:
    c = v / 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def wcag_contrast(fg: str, bg: str) -> float:
    """The WCAG relative-luminance ratio, 1..21."""
    def lum(hex_color: str) -> float:
        r, g, b = _hex_rgb(hex_color)
        return (0.2126 * _wcag_channel(r) + 0.7152 * _wcag_channel(g)
                + 0.0722 * _wcag_channel(b))
    l1, l2 = lum(fg), lum(bg)
    if l1 < l2:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)


# ── events ───────────────────────────────────────────────────────────────

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ── findings model ───────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # error | warning | info
    check: str             # contrast | forms | headings | …
    message: str
    where: str = ""
    fix: str = ""

    def as_dict(self) -> dict:
        return {"severity": self.severity, "check": self.check,
                "message": self.message, "where": self.where,
                "fix": self.fix}


ORDER = {"error": 0, "warning": 1, "info": 2}
ICON = {"error": "🔴", "warning": "🟠", "info": "ℹ️"}


def _el_label(el) -> str:
    """A short human pointer to an element: tag#id.class — text…"""
    tag = el.tag if isinstance(el.tag, str) else "?"
    parts = [tag]
    if el.get("id"):
        parts.append("#" + el.get("id"))
    classes = (el.get("class") or "").split()
    if classes:
        parts.append("." + ".".join(classes[:3]))
    label = "".join(parts)
    text = " ".join(el.text_content().split())[:40]
    return f"{label} — “{text}”" if text else label


# ── fetch ────────────────────────────────────────────────────────────────

def fetch(url: str, timeout: int) -> requests.Response:
    resp = requests.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    return resp


def stylesheet_urls(doc, base_url: str) -> list[str]:
    out = []
    for el in doc.iter("link"):
        rels = (el.get("rel") or "").lower().split()
        if "stylesheet" in rels and el.get("href"):
            out.append(el.get("href"))
    return out


def absolutize(url: str, base_url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    if url.startswith("//"):
        return "https:" + url
    return base_url.rstrip("/") + "/" + url.lstrip("/")


# ── the static CSS engine ────────────────────────────────────────────────

RULE_RE = re.compile(r"([^{}]+)\{([^{}]*)\}", re.S)


def css_color_rules(css_text: str) -> list[tuple[str, str, str]]:
    """(selector, color, background) from every rule whose selector is
    a *single simple* tag/class/id selector — the static scope."""
    out = []
    for m in RULE_RE.finditer(css_text or ""):
        sel = m.group(1).strip()
        if not re.fullmatch(r"([a-zA-Z][\w-]*|\.[\w-]+|#[\w-]+)", sel):
            continue
        color = bg = ""
        for decl in m.group(2).split(";"):
            prop, _, value = decl.partition(":")
            prop = prop.strip().lower()
            value = value.strip()
            if prop == "color" and not color:
                color = parse_color(value) or ""
            elif prop in ("background", "background-color") and not bg:
                bg = parse_color(value.split()[0] if value else "") or ""
        if color or bg:
            out.append((sel, color, bg))
    return out


def rule_matches(el, sel: str) -> bool:
    if sel.startswith("."):
        return sel[1:] in (el.get("class") or "").split()
    if sel.startswith("#"):
        return el.get("id") == sel[1:]
    return el.tag == sel


def resolve_colors(el, rules, doc) -> tuple[str, str]:
    """(color, background) that static CSS can pin on an element: the
    last matching rule's declarations, falling back to html/body for
    the background."""
    color = bg = ""
    for sel, c, b in rules:
        if rule_matches(el, sel):
            color = c or color
            bg = b or bg
    style = el.get("style") or ""
    for decl in style.split(";"):
        prop, _, value = decl.partition(":")
        prop, value = prop.strip().lower(), value.strip()
        if prop == "color":
            color = parse_color(value) or color
        elif prop in ("background", "background-color") and value:
            bg = parse_color(value.split()[0]) or bg
    if not bg:
        for host in (doc.find("body"), doc.find("html")):
            if host is None:
                continue
            for sel, _c, b in rules:
                if b and rule_matches(host, sel):
                    bg = b
        for host in (doc.find("body"), doc.find("html")):
            if host is not None:
                style = host.get("style") or ""
                m = re.search(r"background(?:-color)?\s*:\s*([^;]+)",
                              style)
                if m:
                    bg = parse_color(m.group(1).split()[0]) or bg
    if not bg:
        # nothing declared anywhere → the browser's white canvas
        # (documented assumption; transparent layers on white)
        bg = "#FFFFFF"
    return color, bg


def font_is_large(el, rules) -> bool | None:
    """True/False/None (unknown) — 24px+, or 19px+ bold."""
    size = weight = None
    for sel, c, b in rules:
        pass  # sizes in style blocks are out of the simple scope
    style = el.get("style") or ""
    m = re.search(r"font-size\s*:\s*([\d.]+)px", style)
    if m:
        size = float(m.group(1))
    if re.search(r"font-weight\s*:\s*(bold|[7-9]00)", style):
        weight = "bold"
    if size is None:
        return None
    if size >= 24:
        return True
    return weight == "bold" and size >= 18.66


# ── the audits ───────────────────────────────────────────────────────────

def audit_contrast(doc, rules) -> list[Finding]:
    findings: list[Finding] = []
    checked = 0
    for el in doc.iter():
        if el.tag in ("script", "style", "head", "meta", "link"):
            continue
        text = (el.text or "").strip()
        if not text:
            continue
        color, bg = resolve_colors(el, rules, doc)
        if not color or not bg:
            continue
        checked += 1
        ratio = wcag_contrast(color, bg)
        large = font_is_large(el, rules)
        threshold = 3.0 if large else 4.5
        kind = "large text" if large else \
            ("text (size unknown — 4.5 assumed)" if large is None
             else "text")
        if ratio < threshold:
            findings.append(Finding(
                "error", "contrast",
                f"{ratio:.2f}:1 {color} on {bg} — needs "
                f"{threshold}:1 for {kind}",
                where=_el_label(el),
                fix="darken the text or lighten the background until "
                    "the pair reaches the ratio"))
    if not checked:
        findings.append(Finding(
            "info", "contrast",
            "no statically-pairable color/background pairs on this "
            "page — contrast not checked (JS-computed styles, "
            "compound selectors and inheritance chains are beyond "
            "the static scope; a contrast spot-check in DevTools "
            "covers them)"))
    return findings


def audit_forms(doc) -> list[Finding]:
    findings: list[Finding] = []
    ids_with_label = {el.get("for") for el in doc.iter("label")
                      if el.get("for")}
    for el in doc.iter("input", "select", "textarea"):
        itype = (el.get("type") or "text").lower()
        if itype in ("hidden", "submit", "reset", "button"):
            continue
        el_id = el.get("id") or ""
        labelled = (el_id and el_id in ids_with_label) \
            or el.get("aria-label") or el.get("aria-labelledby") \
            or el.get("title") \
            or any(a.tag == "label" for a in el.iterancestors("label"))
        if not labelled:
            if el.get("placeholder"):
                findings.append(Finding(
                    "warning", "forms",
                    "control has only a placeholder — it disappears on "
                    "input and is not a label",
                    where=_el_label(el),
                    fix="add a <label for=…>, aria-label or title"))
            else:
                findings.append(Finding(
                    "error", "forms",
                    f"{el.tag} has no label at all",
                    where=_el_label(el),
                    fix="give it an id and a <label for=…>, or an "
                        "aria-label"))
    return findings


def audit_headings(doc) -> list[Finding]:
    findings: list[Finding] = []
    levels = [(int(h.tag[1]), h) for h in doc.iter(*[f"h{i}"
                                                     for i in range(1, 7)])]
    if not levels:
        findings.append(Finding("warning", "headings",
                                "no headings on the page",
                                fix="structure the content with h1…h6"))
        return findings
    if levels[0][0] != 1:
        findings.append(Finding(
            "info", "headings",
            f"the first heading is h{levels[0][0]}, not h1"))
    h1s = [h for lv, h in levels if lv == 1]
    if len(h1s) > 1:
        findings.append(Finding("info", "headings",
                                f"{len(h1s)} h1 elements — one per page "
                                "is the clean shape"))
    for (prev, _el), (nxt, el) in zip(levels, levels[1:]):
        if nxt > prev + 1:
            findings.append(Finding(
                "warning", "headings",
                f"level skip: h{prev} → h{nxt}",
                where=_el_label(el),
                fix="don't skip levels — the outline is the "
                    "screen-reader navigation"))
    return findings


def audit_lang(doc) -> list[Finding]:
    findings: list[Finding] = []
    html_el = doc if doc.tag == "html" else doc.find("html")
    lang = (html_el.get("lang") if html_el is not None else "") or ""
    if not lang:
        findings.append(Finding(
            "error", "lang", "<html> has no lang attribute",
            fix="lang tells screen readers which pronunciation engine "
                "to load (WCAG 3.1.1, level A)"))
    elif not re.match(r"^[a-z]{2,3}(-[A-Za-z0-9]+)*$", lang):
        findings.append(Finding("warning", "lang",
                                f"lang={lang!r} is not a valid BCP-47 "
                                "code"))
    if lang:
        for el in doc.iter():
            el_lang = el.get("lang")
            if el_lang and el_lang != lang and el.tag != "html":
                findings.append(Finding(
                    "info", "lang",
                    f"foreign-language insert lang={el_lang!r} inside "
                    f"a lang={lang!r} page (fine if intentional)",
                    where=_el_label(el)))
    return findings


ROLE_REQUIRED_STATE = {
    "checkbox": "aria-checked", "switch": "aria-checked",
    "radio": "aria-checked",
    "slider": "aria-valuenow", "progressbar": "aria-valuenow",
    "spinbutton": "aria-valuenow", "scrollbar": "aria-valuenow",
}


def audit_aria(doc) -> list[Finding]:
    findings: list[Finding] = []
    for el in doc.iter():
        role = (el.get("role") or "").strip()
        if role in ROLE_REQUIRED_STATE \
                and not el.get(ROLE_REQUIRED_STATE[role]):
            findings.append(Finding(
                "error", "aria",
                f"role={role!r} without {ROLE_REQUIRED_STATE[role]} — "
                "the state is the whole point of the role",
                where=_el_label(el)))
        focusable = (el.tag in ("a", "button", "input", "select",
                                "textarea")
                     and (el.tag != "a" or el.get("href"))) \
            or el.get("tabindex") is not None
        if focusable and (el.get("aria-hidden") == "true"
                          or role in ("presentation", "none")):
            findings.append(Finding(
                "error", "aria",
                "focusable element hidden from assistive tech — "
                "keyboard users can still tab into the void",
                where=_el_label(el),
                fix="remove aria-hidden/role=presentation from "
                    "focusable elements"))
    return findings


def audit_focus(doc) -> list[Finding]:
    findings: list[Finding] = []
    for el in doc.iter():
        tabindex = el.get("tabindex")
        if tabindex and tabindex.lstrip("-").isdigit() \
                and int(tabindex) > 0:
            findings.append(Finding(
                "warning", "focus",
                f"tabindex={tabindex} — positive values reorder the "
                "tab sequence away from the DOM order and trap users",
                where=_el_label(el),
                fix="tabindex=\"0\" to make it focusable in DOM order"))
    return findings


GENERIC_LINK_TEXT = {"click here", "here", "read more", "more", "this",
                     "link", "details", "learn more"}


def audit_links(doc) -> list[Finding]:
    findings: list[Finding] = []
    for el in doc.iter("a"):
        if not el.get("href"):
            continue
        text = " ".join(el.text_content().split()).lower()
        has_img_alt = any(img.get("alt")
                          for img in el.iter("img"))
        if not text and not has_img_alt and not el.get("aria-label") \
                and not el.get("title"):
            findings.append(Finding(
                "error", "links", "empty link — no text, no image alt, "
                "no label",
                where=_el_label(el),
                fix="give the link text (screen readers announce it)"))
        elif text in GENERIC_LINK_TEXT:
            findings.append(Finding(
                "warning", "links",
                f"generic link text “{text}” — out of context, in a "
                "link list, it tells a screen-reader user nothing",
                where=_el_label(el),
                fix="link text should name the destination"))
    return findings


def audit_tables(doc) -> list[Finding]:
    findings: list[Finding] = []
    for table in doc.iter("table"):
        rows = list(table.iter("tr"))
        if len(rows) < 2:
            continue  # layout tables / single-row oddities
        ths = list(table.iter("th"))
        if not ths:
            findings.append(Finding(
                "warning", "tables",
                "data table without header cells",
                where=_el_label(table),
                fix="mark the header row/column with <th> so the "
                    "relationships are announced"))
        else:
            bare = [th for th in ths if not th.get("scope")
                    and not th.get("headers") and not th.get("id")]
            if bare:
                findings.append(Finding(
                    "info", "tables",
                    f"{len(bare)} <th> without scope — in tables "
                    "beyond 2×2, scope=col/row removes the ambiguity"))
    return findings


def audit_landmarks(doc) -> list[Finding]:
    findings: list[Finding] = []
    body = doc.find("body")
    for tag, why in (("main", "the one place screen-reader users jump "
                               "to for content"),
                     ("nav", "the skip target for the menu"),
                     ("header", "the banner landmark")):
        if not list(doc.iter(tag)):
            findings.append(Finding(
                "info", "landmarks",
                f"no <{tag}> landmark — {why}"))
    first_link = None
    if body is not None:
        for el in body.iter("a"):
            first_link = el
            break
    if first_link is not None \
            and (first_link.get("href") or "").startswith("#"):
        findings.append(Finding(
            "info", "landmarks",
            "skip link present — the keyboard path starts at the "
            "content, good"))
    else:
        findings.append(Finding(
            "info", "landmarks",
            "no skip link before the navigation — keyboard users tab "
            "through the whole menu on every page"))
    return findings


def run_audits(doc, rules) -> list[Finding]:
    findings: list[Finding] = []
    for audit in (audit_contrast, audit_forms, audit_headings,
                  audit_lang, audit_aria, audit_focus, audit_links,
                  audit_tables, audit_landmarks):
        findings.extend(audit(*( (doc, rules) if audit is audit_contrast
                                 else (doc,) )))
    return sorted(findings, key=lambda f: (ORDER[f.severity], f.check))


# ── report ───────────────────────────────────────────────────────────────

def build_table_event(findings: list[Finding]) -> dict:
    rows = [{
        "severity": ICON[f.severity] + " " + f.severity,
        "check": f.check,
        "finding": f.message,
        "where": f.where,
    } for f in findings[:60]]
    return {"type": "table",
            "columns": ["severity", "check", "finding", "where"],
            "rows": rows}


def build_markdown(url: str, findings: list[Finding],
                   images_without_alt: int | None) -> str:
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    infos = sum(1 for f in findings if f.severity == "info")
    verdict = "🔴 errors" if errors else ("🟠 warnings" if warnings
                                          else "🟢 clean")
    out = [f"# A11y Check — Report\n",
           f"URL: `{url}` · {len(findings)} finding(s): "
           f"**{errors} errors, {warnings} warnings, {infos} notes** · "
           f"verdict: **{verdict}**\n",
           "Static pass: one fetch, the HTML and the CSS that can be "
           "read without running the page. What static analysis cannot "
           "see is reported as not checked — never as passed.\n"]
    current = None
    for f in findings:
        if f.check != current:
            out.append(f"\n## {f.check}\n")
            current = f.check
        out.append(f"- {ICON[f.severity]} {f.message}"
                   + (f" — `{f.where}`" if f.where else ""))
        if f.fix:
            out.append(f"  - fix: {f.fix}")
    if images_without_alt is not None:
        out.append(f"\n## images\n")
        out.append(f"- {images_without_alt} image(s) without alt — the "
                   "alt audit lives in **Page SEO Audit** (it is an "
                   "SEO signal as much as an accessibility one); run "
                   "it on the same URL.")
    out.append("\n## Where this fits\n")
    out.append("- **Page SEO Audit** — the same one-fetch pass for "
               "title/meta/headings/alt as search-visibility signals.")
    out.append("- **Color Palette** — the color engine this script's "
               "contrast math grew out of; useful when picking an "
               "accessible palette.")
    out.append("- **Site Crawler → SEO Checks** — the whole-site pass; "
               "this script is the deep single-page one.")
    return "\n".join(out)


def write_artifacts(url: str, findings: list[Finding], report: str,
                    images_without_alt: int | None) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {"url": url,
               "findings": [f.as_dict() for f in findings],
               "images_without_alt": images_without_alt}
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ── main ─────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A11y Check — the static accessibility pass: "
                    "contrast, forms, headings, ARIA, focus, links")
    parser.add_argument("--url", required=True,
                        help="the page to check")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds (default 15)")
    parser.add_argument("--max-stylesheets", type=int, default=3,
                        help="stylesheets fetched for the contrast pass")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no pages are fetched", flush=True)
        return 0

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        print("✗ the URL must start with http:// or https://",
              file=sys.stderr, flush=True)
        return 2

    log(f"Checking the accessibility of {url}")
    status("fetching the page")
    try:
        resp = fetch(url, args.timeout)
    except requests.RequestException as exc:
        print(f"✗ cannot reach {url}: {exc}", file=sys.stderr,
              flush=True)
        return 1
    emit({"type": "progress", "pct": 30, "message": "parsing"})

    doc = lxml.html.document_fromstring(resp.content)
    base_url = resp.url
    rules: list[tuple[str, str, str]] = []
    for style in doc.iter("style"):
        rules.extend(css_color_rules(style.text or ""))
    fetched_css = 0
    for href in stylesheet_urls(doc, base_url)[:max(args.max_stylesheets,
                                                    0)]:
        try:
            css_resp = fetch(absolutize(href, base_url), args.timeout)
            rules.extend(css_color_rules(css_resp.text or ""))
            fetched_css += 1
        except requests.RequestException:
            continue
    emit({"type": "progress", "pct": 60,
          "message": f"{len(rules)} contrast rule(s), "
                     f"{fetched_css} stylesheet(s) fetched"})

    findings = run_audits(doc, rules)
    images_without_alt = sum(
        1 for img in doc.iter("img") if not (img.get("alt") or "").strip())

    report = build_markdown(url, findings, images_without_alt)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(findings))
    emit({"type": "markdown", "content": report})
    write_artifacts(url, findings, report, images_without_alt)

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    summary = f"{len(findings)} finding(s) · {errors} errors · " \
              f"{warnings} warnings"
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
