#!/usr/bin/env python3
"""schema-check/main.py — is the structured data valid, and is it
worth anything?

Page SEO Audit **extracts** the JSON-LD (presence as a signal);
this script **validates** it — and adds the verdict no official
validator gives: *valid but no rich result*.  Google renders rich
results for a bounded list of types (31 as of March 2026, and the
FAQ listing left the SERP in May 2026); a perfectly valid
`WebPage` block earns nothing in Google and still feeds Bing,
Perplexity and every other consumer.  That distinction — valid ≠
valuable — is the report's spine.

The checks, one fetch, everything else offline:

- **JSON-LD parses** — invalid JSON in a `<script type=
  "application/ld+json">` is the most common failure in the wild;
  a `@graph` is walked, `@type` arrays are flattened.
- **Types against the curated schema.org shapes** (YAML data): the
  required and recommended properties per type, with nesting
  understood — `Product` → `offers` → `Offer` with its own
  required `price`/`priceCurrency`; a URL-shaped value in a URL
  property; a date-shaped value in a date property.
- **Microdata and RDFa alongside** — `itemscope`/`itemtype` and
  `typeof=`/`vocab=` spotted and counted; mixing three syntaxes is
  a maintenance smell, said as such.
- **The schema-vs-page cross-check** — the `Product.offers.price`
  that appears nowhere in the visible text (the price the visitor
  sees is the one the markup must carry); the same for the headline
  name of the main entity.

Exit codes: 0 = ran (findings are results), 1 = unreachable or no
structured data, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from pathlib import Path

import lxml.html
import requests
import yaml

DATA_PATH = Path(__file__).resolve().parent / "schema_types.yaml"
USER_AGENT = "PyShell-schema-check/1 (+structured data diagnostics)"

URL_PROPS = {"url", "image", "logo", "sameAs", "thumbnailUrl",
             "contentUrl", "embedUrl", "mainEntityOfPage",
             "potentialAction"}
DATE_PROPS = {"datePublished", "dateModified", "uploadDate",
              "datePosted", "validThrough", "priceValidUntil",
              "startDate", "endDate"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


def load_data() -> dict:
    return yaml.safe_load(DATA_PATH.read_text(encoding="utf-8")) \
        or {}


# ------------------------------------------------------------- extraction

def extract_jsonld_blocks(doc) -> list[tuple[str, str]]:
    out = []
    for i, script in enumerate(doc.iter("script"), 1):
        if (script.get("type") or "").lower() \
                == "application/ld+json":
            out.append((f"script #{i}", script.text or ""))
    return out


def iter_entities(node, parent_type: str = "", is_root: bool = True):
    """Yield every entity object in a JSON-LD tree: the root(s),
    @graph members, and nested typed objects (offers,
    aggregateRating…). Fragments without @type are NOT entities —
    they are properties of their parent; @graph is walked though
    (it IS the entity carrier)."""
    if isinstance(node, list):
        for item in node:
            yield from iter_entities(item, parent_type, False)
    elif isinstance(node, dict):
        t = node.get("@type")
        types = t if isinstance(t, list) else ([t] if t else [])
        label = "/".join(str(x) for x in types)
        if label:
            yield label, node
        elif is_root:
            yield "(no @type)", node
        for key, value in node.items():
            if key == "@graph":
                graph = value if isinstance(value, list) else [value]
                for item in graph:
                    yield from iter_entities(item, "", False)
            elif key.startswith("@"):
                continue
            elif isinstance(value, (dict, list)):
                yield from iter_entities(value,
                                         label or parent_type,
                                         False)


def extract_microdata(doc) -> dict:
    scopes = [el for el in doc.iter()
              if el.get("itemscope") is not None]
    types = []
    for el in scopes:
        t = el.get("itemtype") or ""
        types.append(t.rsplit("/", 1)[-1] if t else "?")
    return {"count": len(scopes), "types": types}


def extract_rdfa(doc) -> dict:
    items = [el for el in doc.iter() if el.get("typeof")]
    return {"count": len(items),
            "types": sorted({(el.get("typeof") or "").split()[0]
                             for el in items})}


# ------------------------------------------------------------- validation

def is_url(value) -> bool:
    return isinstance(value, str) \
        and re.match(r"^https?://", value) is not None


def is_date(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def validate_entity(label: str, node: dict, data: dict) -> list[dict]:
    """One entity against the curated shape; findings are
    {severity, check, detail, entity}."""
    findings: list[dict] = []
    types = data.get("types") or {}

    def add(sev, check, detail):
        findings.append({"severity": sev, "check": check,
                         "detail": detail, "entity": label})

    shape = None
    matched = None
    for t in label.split("/"):
        if t in types:
            shape, matched = types[t], t
            break
    if shape is None:
        return findings        # unknown type: no shape to enforce

    for prop in shape.get("required") or []:
        val = node.get(prop)
        if val in (None, "", [], {}):
            add("error", "required",
                f"{matched}: required `{prop}` missing")
        elif prop in URL_PROPS and not is_url(val) \
                and not isinstance(val, (dict, list)):
            add("warning", "shape",
                f"{matched}.{prop} should be a URL, got "
                f"{str(val)[:40]!r}")
        elif prop in DATE_PROPS and not (is_date(val)
                                         or isinstance(val,
                                                       (dict, list))):
            add("warning", "shape",
                f"{matched}.{prop} should be an ISO date, got "
                f"{str(val)[:40]!r}")
    for prop in shape.get("recommended") or []:
        if node.get(prop) in (None, "", [], {}):
            add("info", "recommended",
                f"{matched}: recommended `{prop}` missing")
    return findings


def cross_check_page(entities: list[tuple[str, dict]],
                     visible_text: str) -> list[dict]:
    """The schema-vs-page contradictions: the price and the name
    the visitor sees must carry the markup's values."""
    findings: list[dict] = []
    for label, node in entities:
        if "Product" not in label.split("/"):
            continue
        offers = node.get("offers")
        if isinstance(offers, dict):
            price = offers.get("price")
            if price is not None and str(price) not in visible_text:
                findings.append({
                    "severity": "warning", "check": "vs-page",
                    "detail": f"the markup's price {price} appears "
                              "nowhere in the visible text — the "
                              "visitor sees a different number (or "
                              "none); markup and page must agree",
                    "entity": label})
        name = node.get("name")
        if isinstance(name, str) and len(name) > 8 \
                and name not in visible_text:
            findings.append({
                "severity": "info", "check": "vs-page",
                "detail": f"the markup's name “{name[:50]}” is not "
                          "the page's visible text — often fine "
                          "(a shorter title shown), worth a look",
                "entity": label})
    return findings


# -------------------------------------------------------------------- report

ICON = {"error": "🔴", "warning": "🟠", "info": "ℹ️"}


def build_table_event(findings: list[dict]) -> dict:
    rows = [[ICON[f["severity"]] + " " + f["severity"],
             f["check"], f["entity"], f["detail"][:70]]
            for f in findings]
    return {"type": "table",
            "columns": ["severity", "check", "entity", "detail"],
            "rows": rows[:60]}


def build_markdown(url: str, entities: list[tuple[str, dict]],
                   findings: list[dict], microdata: dict,
                   rdfa: dict, google: list[str]) -> str:
    errors = sum(1 for f in findings if f["severity"] == "error")
    out = [f"# Schema Check — Report\n",
           f"URL: `{url}` · {len(entities)} schema.org "
           f"entit(ies) · {len(findings)} finding(s), "
           f"{errors} error(s)\n"]

    top_types = sorted({label.split("/")[0]
                        for label, _ in entities})
    out.append("## The verdict validators don't give\n")
    for t in top_types:
        in_google = t in google
        out.append(f"- {'🟢' if in_google else '⚪'} **{t}** — "
                   + (f"in Google's rich-result list"
                      if in_google else
                      "**valid but no rich result**: outside "
                      "Google's supported list — still useful for "
                      "Bing, Perplexity and other consumers"))
    out.append("")

    current = None
    for f in findings:
        if f["check"] != current:
            out.append(f"\n## {f['check']}\n")
            current = f["check"]
        out.append(f"- {ICON[f['severity']]} {f['detail']}"
                   + (f" ({f['entity']})" if f["entity"] else ""))

    if microdata["count"] or rdfa["count"]:
        out.append("\n## Other syntaxes on the page\n")
        if microdata["count"]:
            out.append(f"- microdata: {microdata['count']} "
                       "itemscope(s) — " + ", ".join(
                           microdata["types"][:6]))
        if rdfa["count"]:
            out.append(f"- RDFa: {rdfa['count']} typeof element(s)")
        out.append("- mixing JSON-LD with microdata/RDFa works but "
                   "is a maintenance smell — one syntax, one page.")
    if not findings:
        out.append("\nNo validation findings — the curated shapes "
                   "are satisfied. The rich-result verdict above is "
                   "the value question.")
    out.append("\n## Related\n")
    out.append("- **Page SEO Audit** — extracts the same JSON-LD "
               "as a presence signal; this script validates it.")
    out.append("- **AI Crawler Check** — the policy side; good "
               "schema is what AI answers cite.")
    out.append("- **Site Crawler → SEO Checks** — the whole-site "
               "pass.")
    return "\n".join(out)


def write_artifacts(url: str, entities: list[tuple[str, dict]],
                    findings: list[dict], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "url": url,
        "entities": [{"type": label,
                      "keys": sorted(node.keys())}
                     for label, node in entities],
        "findings": findings,
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Schema Check — structured data validated, and "
                    "the valid-but-no-rich-result verdict")
    parser.add_argument("--url", required=True,
                        help="the page to check")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no pages are fetched",
              flush=True)
        return 0

    url = args.url.strip()
    if not re.match(r"^https?://", url):
        print("✗ the URL must start with http:// or https://",
              file=sys.stderr, flush=True)
        return 2

    log(f"Validating the structured data of {url}")
    status("one fetch")
    try:
        resp = requests.get(url, timeout=args.timeout,
                            allow_redirects=True,
                            headers={"User-Agent": USER_AGENT})
    except requests.RequestException as exc:
        print(f"✗ cannot reach {url}: {exc}", file=sys.stderr,
              flush=True)
        return 1
    doc = lxml.html.document_fromstring(resp.content)
    emit({"type": "progress", "pct": 40, "message": "parsing"})

    data = load_data()
    google = data.get("google_rich_results") or []
    findings: list[dict] = []
    entities: list[tuple[str, dict]] = []

    for where, text in extract_jsonld_blocks(doc):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            findings.append({"severity": "error", "check": "jsonld",
                             "detail": f"invalid JSON in {where}: "
                                       f"{exc}", "entity": where})
            continue
        found = list(iter_entities(parsed))
        entities.extend(found)
        for label, node in found:
            findings.extend(validate_entity(label, node, data))
    visible = " ".join(doc.text_content().split())
    findings.extend(cross_check_page(entities, visible))

    microdata = extract_microdata(doc)
    rdfa = extract_rdfa(doc)
    emit({"type": "progress", "pct": 100, "message": "Done"})

    if not entities and not findings and not microdata["count"] \
            and not rdfa["count"]:
        print(f"✗ no structured data found on {url} — nothing to "
              "validate (Page SEO Audit grades the absence)",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(url, entities, findings, microdata,
                            rdfa, google)
    emit(build_table_event(findings))
    emit({"type": "markdown", "content": report})
    write_artifacts(url, entities, findings, report)

    errors = sum(1 for f in findings if f["severity"] == "error")
    summary = (f"{len(entities)} entit(ies) · {len(findings)} "
               f"finding(s) · {errors} error(s)")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
