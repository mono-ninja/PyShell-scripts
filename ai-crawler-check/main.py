#!/usr/bin/env python3
"""ai-crawler-check/main.py — what your site gives AI crawlers.

Bot Hunter classifies the AI crawlers that already *visited* (the
log side); this script reads the **policy** side — what the site
tells them, before they ever arrive:

- **robots.txt** — the rules for the known AI crawlers (GPTBot,
  ClaudeBot, PerplexityBot, CCBot, Google-Extended, Bytespider…):
  blocked, partially blocked, allowed — or simply **not mentioned**,
  which robots.txt means as *allowed by default*. The `*` group is
  read too, with its trap named: a blanket Disallow hits normal
  search engines just as hard.
- **llms.txt** — the `/llms.txt` and `/llms-full.txt` convention: a
  markdown file describing the site for LLM consumption. It is a
  **convention, not a standard** — the report treats it exactly as
  that: presence, reachability and shape (a first `#` heading), no
  invented normativity.
- **noai markers** — `X-Robots-Tag: noai, noimageai` headers and
  the `<meta name="robots">` family on the page itself.

Three fetches, plain words. Nothing here judges the *choice* to
allow or block — that is an editorial decision; the script makes
the current state visible.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

import requests

USER_AGENT = "PyShell-ai-crawler-check/1 (+AI crawler policy)"

# the AI crawler census — product, operator, and what the agent name
# covers. Unmentioned in robots.txt = allowed by default.
AI_CRAWLERS = [
    ("GPTBot", "OpenAI — model training"),
    ("OAI-SearchBot", "OpenAI — search results"),
    ("ChatGPT-User", "OpenAI — user-triggered fetches"),
    ("ClaudeBot", "Anthropic — model training"),
    ("Claude-Web", "Anthropic — user-triggered fetches"),
    ("CCBot", "Common Crawl — the open corpus many models train on"),
    ("Google-Extended", "Google — Gemini training (does not affect search)"),
    ("PerplexityBot", "Perplexity — search answers"),
    ("Amazonbot", "Amazon — Alexa/AI training"),
    ("Applebot-Extended", "Apple — AI training (Applebot itself is search)"),
    ("meta-externalagent", "Meta — AI training"),
    ("Bytespider", "ByteDance — training, famously ignores robots.txt"),
    ("YouBot", "You.com — search/AI"),
    ("cohere-ai", "Cohere — training"),
]


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ------------------------------------------------------------------ robots

def parse_robots_groups(text: str) -> dict[str, dict]:
    """{agent-lower: {"disallow": [...], "allow": [...]}} — the last
    group an agent appears in wins (robots.txt semantics for groups
    with the same agent are merged; the simple reading used here)."""
    groups: dict[str, dict] = {}
    current: list[str] = []
    group_closed = False       # a rule line after UAs closes the group
    for raw in (text or "").splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if not value and field != "user-agent":
            continue
        if field == "user-agent":
            if group_closed:
                current = []
                group_closed = False
            current.append(value.lower())
            for a in current:
                groups.setdefault(a, {"disallow": [], "allow": []})
        elif current:
            group_closed = True
            for a in current:
                if field in ("disallow", "allow"):
                    groups[a][field].append(value)
    return groups


def crawler_status(groups: dict[str, dict], agent: str) -> dict:
    """{mentioned, verdict, detail} for one crawler."""
    g = groups.get(agent.lower())
    star = groups.get("*")
    if g is not None:
        dis = g["disallow"]
        if "/" in dis or dis == [""]:
            return {"mentioned": True, "verdict": "blocked",
                    "detail": "Disallow: / — fully blocked"}
        if dis:
            return {"mentioned": True, "verdict": "partial",
                    "detail": f"Disallow: {', '.join(dis[:3])}"}
        return {"mentioned": True, "verdict": "allowed",
                "detail": "mentioned with no Disallow — explicitly "
                          "welcomed"}
    if star and ("/" in star["disallow"] or star["disallow"] == [""]):
        return {"mentioned": False, "verdict": "blocked via *",
                "detail": "not mentioned, but the * group blocks "
                          "everything — including normal search "
                          "engines"}
    if star and star["disallow"]:
        return {"mentioned": False, "verdict": "partial via *",
                "detail": f"not mentioned; * disallows "
                          f"{', '.join(star['disallow'][:3])}"}
    return {"mentioned": False, "verdict": "allowed by default",
            "detail": "not mentioned — robots.txt silence means "
                      "allowed"}


# ----------------------------------------------------------------- llms.txt

def check_llms(url: str, timeout: int) -> dict:
    """The /llms.txt convention — presence and shape, honestly."""
    out = {}
    for key, path in (("llms_txt", "/llms.txt"),
                      ("llms_full_txt", "/llms-full.txt")):
        entry = {"url": path, "status": None, "shape": ""}
        try:
            r = requests.get(url.rstrip("/") + path, timeout=timeout,
                             headers={"User-Agent": USER_AGENT},
                             allow_redirects=True)
            entry["status"] = r.status_code
            if r.status_code == 200 and r.text.strip():
                first = r.text.strip().splitlines()[0].strip()
                if first.startswith("#"):
                    entry["shape"] = "markdown with a # heading — " \
                                     "the convention's shape"
                else:
                    entry["shape"] = f"200 but starts with " \
                                     f"{first[:30]!r} — not the " \
                                     "convention's markdown shape"
            elif r.status_code == 200:
                entry["shape"] = "200 but empty"
        except requests.RequestException as exc:
            entry["status"] = None
            entry["shape"] = f"unreachable: {exc}"
        out[key] = entry
    return out


# ---------------------------------------------------------------- noai tags

def check_noai(url: str, timeout: int) -> dict:
    """X-Robots-Tag headers + the meta robots family on the page."""
    out = {"x_robots_tag": [], "meta_robots": []}
    try:
        r = requests.get(url, timeout=timeout,
                         headers={"User-Agent": USER_AGENT},
                         allow_redirects=True)
    except requests.RequestException as exc:
        out["error"] = str(exc)
        return out
    for value in r.headers.get("X-Robots-Tag", "").split(","):
        value = value.strip().lower()
        if value:
            out["x_robots_tag"].append(value)
    meta = re.search(
        r'<meta\s+[^>]*name=["\']robots["\'][^>]*content=["\']([^"\']*)',
        r.text, re.I)
    if meta:
        out["meta_robots"] = [v.strip().lower()
                              for v in meta.group(1).split(",")
                              if v.strip()]
    return out


# -------------------------------------------------------------------- report

def build_table_event(crawlers: list[dict]) -> dict:
    # rows are arrays of cell values aligned with columns — PyShell's
    # table renderer maps over each row; dict rows crash it
    rows = [[c["agent"], c["operator"], c["status"]["verdict"]]
            for c in crawlers]
    return {"type": "table",
            "columns": ["crawler", "operator", "robots.txt"],
            "rows": rows}


def build_markdown(url: str, robots_status: int, crawlers: list[dict],
                   llms: dict, noai: dict) -> str:
    blocked = sum(1 for c in crawlers
                  if c["status"]["verdict"] == "blocked")
    partial = sum(1 for c in crawlers
                  if "partial" in c["status"]["verdict"])
    out = [f"# AI Crawler Check — Report\n",
           f"Site: `{url}` · robots.txt: "
           f"{'present' if robots_status == 200 else f'HTTP {robots_status}'}"
           f" · **{blocked} of {len(crawlers)} known AI crawlers "
           f"blocked**, {partial} partial\n",
           "The policy side of the AI question: what the site "
           "*tells* the crawlers. The visit side — who actually came "
           "— is **Bot Hunter**'s log analysis; the two reports read "
           "well together.\n"]

    out.append("## robots.txt — the AI crawler census\n")
    for c in crawlers:
        s = c["status"]
        mark = {"blocked": "🚫", "partial": "◐",
                "allowed": "✅"}.get(s["verdict"], "⚪")
        out.append(f"- {mark} **{c['agent']}** ({c['operator']}): "
                   f"{s['verdict']} — {s['detail']}")
    out.append("")
    unmentioned = [c for c in crawlers if not c["status"]["mentioned"]]
    if unmentioned:
        out.append(f"{len(unmentioned)} crawler(s) are not mentioned "
                   "at all — robots.txt silence means *allowed*. If "
                   "that is not the intent, each needs its own group "
                   "(a bare `Disallow` under `*` also hits normal "
                   "search engines).")
    out.append("")

    out.append("## llms.txt — the convention (not a standard)\n")
    l = llms["llms_txt"]
    if l["status"] == 200 and l["shape"].startswith("markdown"):
        out.append(f"- `/llms.txt` present, the convention's shape — "
                   "a markdown brief of the site for LLM consumption")
    elif l["status"] == 200:
        out.append(f"- `/llms.txt` answers 200 but {l['shape']}")
    else:
        out.append(f"- `/llms.txt`: HTTP {l['status']} — absent. "
                   "Nothing is broken: llms.txt is a **convention "
                   "several AI tooling vendors read, not a "
                   "standard**; the site simply doesn't offer the "
                   "brief.")
    lf = llms["llms_full_txt"]
    if lf["status"] == 200:
        out.append(f"- `/llms-full.txt`: present ({lf['shape'][:60]})")
    out.append("")

    out.append("## noai markers\n")
    x = [v for v in noai.get("x_robots_tag", [])
         if v in ("noai", "noimageai")]
    m = [v for v in noai.get("meta_robots", [])
         if v in ("noai", "noimageai")]
    if x:
        out.append(f"- `X-Robots-Tag` on the page: "
                   f"{', '.join(x)} — the noai family is set at the "
                   "header level")
    if m:
        out.append(f"- `<meta name=robots>` on the page: "
                   f"{', '.join(m)}")
    if not x and not m:
        out.append("- no noai/noimageai markers on the page (header "
                   "or meta) — content is offered to AI consumers "
                   "the same as to everyone else")
    if noai.get("x_robots_tag"):
        out.append(f"- full X-Robots-Tag value: "
                   f"{', '.join(noai['x_robots_tag'])}")
    out.append("")
    out.append("## Reading it\n")
    out.append("- Blocking model training but keeping search: "
               "GPTBot/ClaudeBot/CCBot groups with `Disallow: /`; "
               "**Google-Extended** is the Gemini-only knob and does "
               "not touch Google Search.")
    out.append("- The reverse (welcoming AI while staying unindexed) "
               "is also expressible — explicit Allow groups for the "
               "agents you want.")
    out.append("- robots.txt is a **request**, not a fence: "
               "Bytespider is the famous non-complier; enforcement "
               "is a firewall/WAF job (**Port Check**, **FW Audit**).")
    out.append("\n## Related\n")
    out.append("- **Robots Audit** — the robots.txt validator (the "
               "rules' syntax and sanity); this script adds the "
               "AI-crawler reading.")
    out.append("- **Bot Hunter** — the log side: who actually "
               "crawled, classified by agent.")
    return "\n".join(out)


def write_artifacts(url: str, robots_status: int, crawlers: list[dict],
                    llms: dict, noai: dict, report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "url": url, "robots_status": robots_status,
        "crawlers": [{"agent": c["agent"], "operator": c["operator"],
                      **c["status"]} for c in crawlers],
        "llms_txt": llms,
        "noai": noai,
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
        description="AI Crawler Check — what the site tells AI "
                    "crawlers: robots.txt rules, llms.txt, noai "
                    "markers")
    parser.add_argument("--url", required=True,
                        help="the site to check")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no requests are made", flush=True)
        return 0

    url = args.url.strip()
    if not re.match(r"^https?://", url):
        print("✗ the URL must start with http:// or https://",
              file=sys.stderr, flush=True)
        return 2
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"

    log(f"Reading the AI-crawler policy of {origin}")
    status("robots.txt → llms.txt → the page")
    emit({"type": "progress", "pct": 10, "message": "robots.txt"})
    try:
        robots = requests.get(origin + "/robots.txt",
                              timeout=args.timeout,
                              headers={"User-Agent": USER_AGENT})
    except requests.RequestException as exc:
        print(f"✗ cannot reach {origin}: {exc}", file=sys.stderr,
              flush=True)
        return 1
    robots_text = robots.text if robots.status_code == 200 else ""

    emit({"type": "progress", "pct": 40, "message": "parsing groups"})
    groups = parse_robots_groups(robots_text)
    crawlers = [{"agent": a, "operator": o,
                 "status": crawler_status(groups, a)}
                for a, o in AI_CRAWLERS]

    emit({"type": "progress", "pct": 70, "message": "llms.txt"})
    llms = check_llms(origin, args.timeout)
    noai = check_noai(url, args.timeout)
    emit({"type": "progress", "pct": 100, "message": "Done"})

    report = build_markdown(url, robots.status_code, crawlers, llms,
                            noai)
    emit(build_table_event(crawlers))
    emit({"type": "markdown", "content": report})
    write_artifacts(url, robots.status_code, crawlers, llms, noai,
                    report)

    blocked = sum(1 for c in crawlers
                  if c["status"]["verdict"] == "blocked")
    summary = (f"{blocked}/{len(crawlers)} AI crawler(s) blocked · "
               f"llms.txt "
               + ("present" if llms["llms_txt"]["status"] == 200
                  else "absent"))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
