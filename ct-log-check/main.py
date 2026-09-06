#!/usr/bin/env python3
"""ct-log-check/main.py — every certificate ever issued for a domain.

TLS Audit inspects the **live** certificate — the one your server
serves right now.  This script reads the **history**: the
certificate transparency logs (via the crt.sh feed — the same
client pattern as Subdomain Search, which found *names* there; this
finds *issuances*).  Nobody has to be probed: every public CA
submits every issuance to the logs, and the logs are public.

The picture:

- **The timeline** — issuances per month (a chart), with the recent
  acceleration or silence visible at a glance.
- **The issuers** — grouped by CA: your main issuer and *everyone
  else who ever issued for the domain* — the headline of this
  report.  A CA you don't recognize in that list is either history
  (a rotation) or a question (who ordered that cert?).
- **Wildcards** — the `*.domain` certificates, each covering
  everything below it.
- **Names** — every name the certs cover, with the ones still
  *valid now* (not_before ≤ today ≤ not_after) separated from the
  expired history.  Which names still exist is a DNS question —
  the report says so and points at Subdomain Search instead of
  guessing.
- **CAA vs the actual issuers** — the policy half nobody reads:
  the domain's CAA records (who is *allowed* to issue, fetched via
  DNS-over-HTTPS) compared with the CAs holding *live* certificates
  in the logs.  Allowed ✅ · a CA outside the list 🔴 · an issuer
  the curated mapping doesn't recognize ⚪ (check by hand).  The
  nuance is said aloud: CAA governs from the moment it was
  published — a live certificate may legitimately predate your own
  policy.

Passive: one feed fetch plus a couple of DNS-over-HTTPS lookups —
the same answers anyone gets.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from collections import Counter

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

HEADERS = {"User-Agent": "PyShell-ct-log-check/1 (+CT history)"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    retry = Retry(total=2, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    return s


SESSION = make_session()


# ------------------------------------------------------------------ the feed

def fetch_crtsh(domain: str, timeout: int) -> list[dict]:
    """The raw crt.sh JSON rows (caller shapes them)."""
    r = SESSION.get(f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=timeout)
    r.raise_for_status()
    try:
        payload = r.json()
    except ValueError:
        raise ValueError("crt.sh answered a non-JSON page — it "
                         "does that under load; retry shortly")
    if not isinstance(payload, list):
        raise ValueError("unexpected crt.sh payload shape")
    return payload


def parse_rows(rows: list[dict], domain: str) -> list[dict]:
    """crt.sh rows → one record per unique (id, name) with issuer,
    validity and wildcard flag — names filtered to the domain."""
    out = []
    seen: set[tuple[str, str]] = set()
    suffix = "." + domain.lower()
    for row in rows:
        cert_id = str(row.get("id", ""))
        names_raw = (row.get("name_value") or "")
        names = [n.strip().lower() for n in names_raw.splitlines()
                 if n.strip()]
        # crt.sh sometimes packs names into common_name too
        cn = (row.get("common_name") or "").strip().lower()
        if cn and cn not in names:
            names.append(cn)
        issuer = (row.get("issuer_name") or "").strip()
        try:
            not_before = dt.datetime.fromisoformat(
                (row.get("not_before") or "").replace("Z", "+00:00"))
            not_after = dt.datetime.fromisoformat(
                (row.get("not_after") or "").replace("Z", "+00:00"))
        except ValueError:
            continue
        # crt.sh timestamps carry no zone — they are UTC
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=dt.timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=dt.timezone.utc)
        for name in names:
            if name != domain.lower() and not name.endswith(suffix):
                continue  # a deeper name not under this domain
            if (cert_id, name) in seen:
                continue
            seen.add((cert_id, name))
            out.append({
                "cert_id": cert_id, "name": name, "issuer": issuer,
                "not_before": not_before, "not_after": not_after,
                "wildcard": name.startswith("*."),
            })
    return out


# --------------------------------------------------------------------- CAA

# The curated issuer → CAA-domain mapping. crt.sh speaks full
# distinguished names ("CN=Let's Encrypt R11, O=Let's Encrypt"); CAA
# speaks registrable domains ("letsencrypt.org"). An issuer that
# matches nothing here is reported as unrecognized — never guessed
# into either verdict.
ISSUER_CAA_MAP = [
    (r"let'?s encrypt|letsencrypt|isrg", "letsencrypt.org"),
    (r"google trust services|pki\.goog", "pki.goog"),
    (r"\bamazon\b|^aws|aws corp", "amazon.com"),
    (r"digicert|symantec|thawte|rapidssl|geotrust|quovadis",
     "digicert.com"),
    (r"sectigo|comodo", "sectigo.com"),
    (r"globalsign", "globalsign.com"),
    (r"godaddy", "godaddy.com"),
    (r"entrust|affirmtrust", "entrust.net"),
    (r"\bssl\.com\b", "ssl.com"),
    (r"buypass", "buypass.com"),
    (r"zerossl", "zerossl.com"),
    (r"harica", "harica.gr"),
    (r"swisssign", "swisssign.com"),
    (r"trustwave", "trustwave.com"),
    (r"cloudflare", "cloudflare.com"),
]

# Second-level suffixes for the CAA tree-climb bound (the walk stops
# at the registrable domain — a public suffix's own CAA never applies).
CAA_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
    "com.br", "com.ua", "net.ua", "org.ua", "co.jp", "com.mx",
    "co.in", "co.nz", "co.za", "com.sg", "com.tr", "com.cn",
    "com.tw", "com.hk", "com.pl", "com.ar", "co.kr",
}


def caa_climb_chain(domain: str) -> list[str]:
    """The domain and its ancestors up to the registrable domain —
    the order a CA checks CAA in (RFC 8659: the first record found
    climbing up governs)."""
    labels = domain.strip().rstrip(".").split(".")
    if len(labels) < 3:
        return [domain]
    chain = [domain]
    while len(labels) > 2:
        labels.pop(0)
        chain.append(".".join(labels))
        if len(labels) == 3 and \
                ".".join(labels[1:]) in CAA_SUFFIXES:
            break
    return chain


def fetch_caa(domain: str, timeout: int) -> dict:
    """CAA via DNS-over-HTTPS (Google JSON, Cloudflare fallback),
    climbing the tree the way a CA does.

    Returns {"status": "ok"|"no policy"|"failed", "records": [...],
    "from": <the zone the policy was found in>}.
    """
    for name in caa_climb_chain(domain):
        records = _doh_caa(name, timeout)
        if records is None:
            return {"status": "failed", "records": [],
                    "from": domain}
        if records:
            return {"status": "ok", "records": records,
                    "from": name}
    return {"status": "no policy", "records": [], "from": domain}


def _doh_caa(name: str, timeout: int) -> list[str] | None:
    """One DoH question; None = both resolvers failed (not 'no
    records' — an unanswered question is never an empty policy)."""
    for url in (
        f"https://dns.google/resolve?name={name}&type=CAA",
        f"https://cloudflare-dns.com/dns-query?name={name}"
        f"&type=CAA",
    ):
        try:
            r = SESSION.get(url, timeout=timeout,
                            headers={"accept":
                                     "application/dns-json"})
            data = r.json()
        except (requests.RequestException, ValueError):
            continue
        if data.get("Status") == 0:
            return [a.get("data", "") for a in
                    data.get("Answer", [])
                    if a.get("type") == 257]
        if data.get("Status") == 3:      # NXDOMAIN: an answer
            return []
    return None


def parse_caa(records: list[str]) -> dict:
    """{issue, issuewild, iodef} — CAA domains before any ';' params,
    lowercased; an empty issue value is the forbid-all shape."""
    out = {"issue": [], "issuewild": [], "iodef": []}
    for rec in records or []:
        m = re.match(r'\s*\d+\s+(\w+)\s+"([^"]*)"', rec or "")
        if not m:
            continue
        tag = m.group(1).lower()
        value = m.group(2).split(";")[0].strip().lower()
        if tag in out:
            out[tag].append(value)
    return out


def map_issuer_to_caa(issuer: str) -> str | None:
    """The CAA domain a crt.sh issuer name maps to, or None."""
    low = (issuer or "").lower()
    for pattern, caa in ISSUER_CAA_MAP:
        if re.search(pattern, low):
            return caa
    return None


def caa_verdicts(records: list[dict], caa: dict) -> list[dict]:
    """Per CA holding a live certificate: allowed / outside the
    list / unrecognized. The comparison covers **valid-now** certs
    — CAA governs from publication, and a live cert may predate
    the policy; the report says the nuance, the verdict names the
    shape."""
    if caa["status"] == "failed":
        return [{"kind": "failed"}]
    policy = parse_caa(caa["records"])
    allowed = {d for d in policy["issue"] + policy["issuewild"]
               if d}
    forbid_all = (policy["issue"] == [""] or
                  (not policy["issue"] and
                   policy["issuewild"] == [""]))
    now = dt.datetime.now(dt.timezone.utc)
    live = [r for r in records
            if r["not_before"] <= now <= r["not_after"]]
    by_issuer: Counter = Counter(r["issuer"] for r in live)
    if not by_issuer:
        return [{"kind": "no live certs"}]
    verdicts = []
    for issuer, count in by_issuer.most_common():
        caa_domain = map_issuer_to_caa(issuer)
        if caa_domain is None:
            verdicts.append({"kind": "unrecognized", "issuer": issuer,
                             "certs": count})
        elif not allowed or forbid_all:
            verdicts.append({"kind": "outside", "issuer": issuer,
                             "caa": caa_domain, "certs": count})
        elif caa_domain in allowed:
            verdicts.append({"kind": "allowed", "issuer": issuer,
                             "caa": caa_domain, "certs": count})
        else:
            verdicts.append({"kind": "outside", "issuer": issuer,
                             "caa": caa_domain, "certs": count})
    return verdicts


# ----------------------------------------------------------------- analysis

def analyze(records: list[dict]) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    by_issuer: Counter = Counter(r["issuer"] for r in records)
    months: Counter = Counter(
        r["not_before"].strftime("%Y-%m") for r in records)
    wildcards = [r for r in records if r["wildcard"]]
    valid_now = [r for r in records
                 if r["not_before"] <= now <= r["not_after"]]
    names = {r["name"] for r in records}
    valid_names = {r["name"] for r in valid_now}
    main_issuer, main_count = (by_issuer.most_common(1)[0]
                               if by_issuer else ("", 0))
    others = [(i, c) for i, c in by_issuer.most_common()
              if i != main_issuer]
    # a burst: more issuances in the last 30 days than the monthly
    # median of the last year
    recent = [r for r in records
              if (now - r["not_before"]).days <= 30]
    year = [r for r in records
            if (now - r["not_before"]).days <= 365]
    med = len(year) / 12 if year else 0
    burst = len(recent) > 3 * max(1.0, med)
    # the crt.sh JSON cap: for very large domains the feed returns
    # only the oldest ~5000 rows — detect and name it instead of
    # reporting a misleading "valid now: 0"
    newest = max((r["not_before"] for r in records), default=now)
    stale_days = (now - newest).days
    feed_stale = stale_days > 90
    return {
        "records": len(records), "names": len(names),
        "valid_names": sorted(valid_names),
        "by_issuer": dict(by_issuer),
        "main_issuer": main_issuer, "main_issuer_count": main_count,
        "other_issuers": others,
        "months": dict(sorted(months.items())),
        "wildcards": wildcards,
        "valid_now_count": len(valid_now),
        "recent_30d": len(recent),
        "burst": burst,
        "feed_stale": feed_stale,
        "feed_stale_days": stale_days,
    }


# -------------------------------------------------------------------- report

def build_table_event(a: dict) -> dict:
    rows = [{"issuer": issuer, "certs": count}
            for issuer, count in a["by_issuer"].items()]
    rows.sort(key=lambda r: -r["certs"])
    return {"type": "table", "columns": ["issuer", "certs"],
            "rows": rows[:15]}


def build_chart_event(a: dict) -> dict:
    months = a["months"]
    return {"type": "chart", "chart_type": "bar",
            "title": "Certificate issuances by month",
            "labels": list(months),
            "series": [{"name": "issuances",
                        "values": list(months.values())}]}


def build_markdown(domain: str, a: dict, caa: dict | None = None,
                   verdicts: list[dict] | None = None) -> str:
    out = [f"# CT Log Check — Report\n",
           f"Domain: **{domain}** · {a['records']} issuance record(s) "
           f"over {a['names']} name(s) · "
           f"{a['valid_now_count']} valid right now\n"]
    out.append("Certificate transparency is public by law of the "
               "ecosystem: every public CA reports every issuance. "
               "This is what the logs say about your domain — "
               "nobody was probed.\n")

    out.append("## Issuers\n")
    out.append(f"- main: **{a['main_issuer']}** "
               f"({a['main_issuer_count']} record(s))")
    if a["other_issuers"]:
        out.append(f"- everyone else who ever issued for "
                   f"`{domain}`:")
        for issuer, count in a["other_issuers"][:10]:
            out.append(f"  - {issuer}: {count}")
        out.append("")
        out.append("A CA you don't recognize in this list is either "
                   "history (an old rotation) or a question — who "
                   "ordered that certificate? Cross-check with your "
                   "ACME accounts and your DNS provider's API log.")
    else:
        out.append("- no other CA ever issued for this domain — "
                   "the tidy single-issuer shape")
    out.append("")

    out.append("## Timeline\n")
    months = a["months"]
    if months:
        first, last = next(iter(months)), list(months)[-1]
        out.append(f"- first issuance in the feed: **{first}**, "
                   f"latest: **{last}**")
        out.append(f"- last 30 days: {a['recent_30d']} issuance(s)")
        if a["burst"]:
            out.append("- ⚠️ the recent pace is a burst against the "
                       "last year's monthly average — renewal churn, "
                       "or something new being provisioned")
        if a["feed_stale"]:
            out.append(f"- ⚫ the newest issuance in this feed is "
                       f"{a['feed_stale_days']} days old — crt.sh "
                       "**caps its JSON output for very large "
                       "domains**, and the cap hits the old rows "
                       "first; the recent history (and every "
                       "'valid now' count) is missing. For a domain "
                       "this size, watch issuances via the crt.sh "
                       "web UI or a dedicated CT monitor.")
    out.append("")

    if a["wildcards"]:
        out.append("## Wildcards\n")
        for w in sorted({w["name"] for w in a["wildcards"]}):
            out.append(f"- `{w}` — covers everything below it")
        out.append("")

    out.append("## Names\n")
    out.append(f"- {a['names']} distinct name(s) in the certs; "
               f"{len(a['valid_names'])} still covered by a valid "
               "certificate.")
    for name in sorted(a["valid_names"])[:15]:
        out.append(f"  - valid now: `{name}`")
    if len(a["valid_names"]) > 15:
        out.append(f"  - … +{len(a['valid_names']) - 15} more")
    out.append("- Which of these names still *exist* is a DNS "
               "question — **Subdomain Search** answers it from the "
               "same feed plus DNS; **Fleet Check** tests them over "
               "HTTP.")
    out.append("")

    if verdicts is not None:
        out.append("## CAA — who is allowed vs who actually issued\n")
        if caa["status"] == "failed":
            out.append("- ⚫ the CAA lookup failed on both resolvers "
                       "— the policy side is **not checked**, never "
                       "'no policy'; re-run when DNS-over-HTTPS "
                       "answers.")
        elif caa["status"] == "no policy":
            out.append(f"- ⚪ no CAA record on `{domain}` or its "
                       "parents — **any CA in the world may issue** "
                       "for the domain. A one-line record naming "
                       "your CA closes that door.")
        else:
            policy = parse_caa(caa["records"])
            allowed = ", ".join(sorted(
                {d for d in policy["issue"] + policy["issuewild"]
                 if d})) or "forbid all (';')"
            out.append(f"- policy (found on `{caa['from']}`): "
                       f"**{allowed}**"
                       + (f" · iodef: {', '.join(policy['iodef'])}"
                          if policy["iodef"] else ""))
        for v in verdicts:
            if v["kind"] == "failed":
                break
            if v["kind"] == "no live certs":
                out.append("- no live certificates right now — "
                           "nothing to compare against the policy")
                break
            if v["kind"] == "allowed":
                out.append(f"- ✅ **{v['issuer']}** ({v['certs']} "
                           f"live cert(s)) → `{v['caa']}` — allowed")
            elif v["kind"] == "outside":
                out.append(f"- 🔴 **{v['issuer']}** ({v['certs']} "
                           f"live cert(s)) → `{v['caa']}` — "
                           "**outside the CAA list**: issued before "
                           "the policy was set, or a gap in it")
            else:
                out.append(f"- ⚪ **{v['issuer']}** ({v['certs']} "
                           "live cert(s)) — an issuer the curated "
                           "mapping doesn't recognize; check by "
                           "hand (`dig CAA {dom}` + the cert's "
                           "issuer)".format(dom=domain))
        if verdicts and verdicts[0]["kind"] not in ("failed",
                                                    "no live certs"):
            out.append("- the nuance, said aloud: CAA governs "
                       "*issuance from the moment it was "
                       "published* — a live certificate may "
                       "legitimately predate your own policy; the "
                       "rotation schedule is yours to set.")
        out.append("")

    out.append("## Related\n")
    out.append("- **TLS Audit** — the live certificate this history "
               "feeds: grade, chain, expiry of what's served now.")
    out.append("- **Subdomain Search** — the names, from the same "
               "crt.sh feed plus passive sources.")
    out.append("- **Fleet Check** — the whole portfolio's live TLS "
               "in one table.")
    return "\n".join(out)


def write_artifacts(domain: str, records: list[dict], a: dict,
                    report: str, caa: dict | None = None,
                    verdicts: list[dict] | None = None) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "domain": domain,
        "records": [{**r, "not_before": r["not_before"].isoformat(),
                     "not_after": r["not_after"].isoformat()}
                    for r in records],
        "summary": {k: v for k, v in a.items()
                    if k != "wildcards"},
        "wildcards": sorted({w["name"] for w in a["wildcards"]}),
        "caa": caa,
        "caa_verdicts": verdicts,
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
        description="CT Log Check — every certificate ever issued "
                    "for a domain: timeline, issuers, wildcards, "
                    "valid-now names, and CAA vs the actual issuers")
    parser.add_argument("--domain", required=True,
                        help="the registrable domain")
    parser.add_argument("--timeout", type=int, default=45,
                        help="crt.sh timeout in seconds (default 45)")
    parser.add_argument("--skip-caa", action="store_true",
                        help="skip the CAA-vs-issuers comparison "
                             "(no DNS-over-HTTPS lookups)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no lookups are made", flush=True)
        return 0

    domain = args.domain.strip().lower().rstrip(".")
    if not re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", domain) \
            or "." not in domain:
        print(f"✗ {args.domain!r} is not a domain name",
              file=sys.stderr, flush=True)
        return 2

    log(f"Fetching the CT history of {domain} from crt.sh")
    status("querying crt.sh")
    emit({"type": "progress", "pct": 20, "message": "crt.sh"})
    try:
        rows = fetch_crtsh(domain, args.timeout)
    except requests.RequestException as exc:
        print(f"✗ crt.sh unreachable: {exc}", file=sys.stderr,
              flush=True)
        return 1
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 1
    emit({"type": "progress", "pct": 60,
          "message": f"{len(rows)} raw rows"})

    records = parse_rows(rows, domain)
    if not records:
        print(f"✗ no certificate records found for {domain} in the "
              "transparency logs", file=sys.stderr, flush=True)
        return 1
    a = analyze(records)

    caa: dict | None = None
    verdicts: list[dict] | None = None
    if not args.skip_caa:
        log("Fetching the CAA policy (DNS-over-HTTPS)")
        status("querying CAA")
        emit({"type": "progress", "pct": 80, "message": "CAA"})
        caa = fetch_caa(domain, min(args.timeout, 20))
        verdicts = caa_verdicts(records, caa)
    emit({"type": "progress", "pct": 100, "message": "Done"})

    report = build_markdown(domain, a, caa, verdicts)
    emit(build_table_event(a))
    emit(build_chart_event(a))
    emit({"type": "markdown", "content": report})
    write_artifacts(domain, records, a, report, caa, verdicts)

    others = len(a["other_issuers"])
    summary = (f"{a['records']} issuance(s) · "
               f"{a['names']} name(s) · "
               f"{others + 1} issuer(s) · "
               f"{a['valid_now_count']} valid now")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
