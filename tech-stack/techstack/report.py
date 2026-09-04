"""Report assembly: table event, markdown, CSV, snapshot, diff.

Three views from one run, all built here so they cannot disagree:
  * the **stack** — one row per technology: version, confidence, evidence, status;
  * the **third-party** inventory — one row per external registrable domain;
  * the **snapshot** — ``stack.json``, the input to ``--baseline`` and to a future
    portfolio-review column.

Exit code stays 0 on a successful scan: an EOL PHP is a finding in the report,
not a script failure — findings are results, never failures.
"""
from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from .advisories import Advisory
from .detect import Detection
from .signatures import categories as sig_categories, category_label
from .thirdparty import ThirdParty, purpose_summary
from .versions import VersionResult


def _cat_order() -> dict[str, int]:
    return {c.id: c.order for c in sig_categories()}


def order_detections(detections: dict[str, Detection]) -> list[Detection]:
    """By category order, then confidence desc, then name."""
    order = _cat_order()

    def key(d: Detection) -> tuple:
        primary = d.categories[0] if d.categories else "zzz"
        return (order.get(primary, 999), -d.confidence, d.name.lower())

    return sorted(detections.values(), key=key)


def _status(d: Detection, ver: VersionResult, adv: Optional[Advisory]) -> tuple[str, str]:
    """Return (icon, text) for the Status column."""
    if d.note:
        return ("?", d.note)
    if d.derived:
        return ("→", "derived")
    if adv and adv.status == "vulnerable":
        return ("✖", "vulnerable: " + (", ".join(adv.cves) if adv.cves else adv.detail))
    if adv and adv.status == "eol":
        return ("⚠", adv.detail)
    if ver and ver.note:
        return ("?", ver.note)
    return ("—", "")


def _ver_display(ver: Optional[VersionResult]) -> str:
    if ver is None:
        return "unknown"
    return ver.display()


def build_table_event(
    detections: dict[str, Detection],
    versions: dict[str, VersionResult],
    advisories: dict[str, Advisory],
) -> dict:
    rows: list[list[str]] = []
    for d in order_detections(detections):
        ver = versions.get(d.slug)
        adv = advisories.get(d.slug)
        icon, text = _status(d, ver, adv)
        status = f"{icon} {text}".strip()
        rows.append([
            d.name,
            category_label(d.categories[0]) if d.categories else "—",
            _ver_display(ver),
            f"{d.confidence:.0f}%",
            "; ".join(d.evidence[:2]) if d.evidence else "",
            status,
        ])
    return {
        "type": "table",
        "columns": ["Technology", "Category", "Version", "Confidence", "Evidence", "Status"],
        "rows": rows,
    }


def build_markdown(
    url: str,
    detections: dict[str, Detection],
    versions: dict[str, VersionResult],
    advisories: dict[str, Advisory],
    parties: list[ThirdParty],
    *,
    rendered: bool,
    pages: int,
    sig_date: str,
    adv_date: str,
    warnings: list[str],
) -> str:
    lines: list[str] = []
    lines.append(f"# 🧱 Tech Stack — {url}")
    lines.append("")
    lines.append("**Scan:** " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                 + f" · pages: {pages} · rendered: {'yes' if rendered else 'no'}")
    lines.append("")

    n_tech = len(detections)
    n_domains = len(parties)
    n_reqs = sum(p.count for p in parties)
    n_vuln = sum(1 for s, d in detections.items() if advisories.get(s) and advisories[s].status == "vulnerable")
    n_eol = sum(1 for s, d in detections.items() if advisories.get(s) and advisories[s].status == "eol")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Technologies | {n_tech} |")
    lines.append(f"| External domains | {n_domains} |")
    lines.append(f"| External requests | {n_reqs} |")
    lines.append(f"| EOL / vulnerable | {n_eol} / {n_vuln} |")
    lines.append("")

    # Stack grouped by category.
    lines.append("## Stack")
    lines.append("")
    lines.append("| Technology | Version | Conf. | Evidence | Status |")
    lines.append("|---|---|---|---|---|")
    for d in order_detections(detections):
        ver = versions.get(d.slug)
        adv = advisories.get(d.slug)
        icon, text = _status(d, ver, adv)
        status = f"{icon} {text}".strip() or "—"
        ev = "; ".join(d.evidence[:2]) if d.evidence else ("← " + d.implied_by if d.derived else "—")
        lines.append(f"| {d.name} | {_ver_display(ver)} | {d.confidence:.0f}% | {ev} | {status} |")
    lines.append("")

    # Third parties.
    if parties:
        lines.append("## Third parties")
        lines.append("")
        lines.append("_A network-request inventory, not a GDPR audit._")
        lines.append("")
        lines.append("| Domain | Purpose | Requests | Types | Jurisdiction |")
        lines.append("|---|---|---|---|---|")
        for tp in parties[:50]:
            lines.append(f"| {tp.domain} | {tp.purpose} | {tp.count} | {', '.join(tp.types)} | {tp.jurisdiction} |")
        if len(parties) > 50:
            lines.append(f"| … | {len(parties) - 50} more domains | | | |")
        lines.append("")

    # Stale / vulnerable detail.
    stale = [(s, d) for s, d in detections.items() if advisories.get(s)]
    if stale:
        lines.append("## Stale / vulnerable")
        lines.append("")
        for slug, d in stale:
            adv = advisories[slug]
            ver = versions.get(slug)
            icon = "✖" if adv.status == "vulnerable" else "⚠"
            lines.append(f"- {icon} **{d.name}** {_ver_display(ver)} — {adv.detail}"
                         + (f" ({', '.join(adv.cves)})" if adv.cves else ""))
        lines.append("")

    if warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"Signature base: `{sig_date}` · EOL/CVE lookup: `{adv_date}`. "
                 "Tech Stack changes nothing on the target — it only reads.")
    return "\n".join(lines)


def build_snapshot(
    url: str,
    detections: dict[str, Detection],
    versions: dict[str, VersionResult],
    advisories: dict[str, Advisory],
    parties: list[ThirdParty],
    *,
    rendered: bool,
    pages: int,
    sig_date: str,
    scope: dict | None = None,
) -> dict:
    techs = []
    for d in order_detections(detections):
        ver = versions.get(d.slug)
        adv = advisories.get(d.slug)
        techs.append({
            "slug": d.slug,
            "name": d.name,
            "categories": list(d.categories),
            "version": _ver_display(ver),
            "version_source": ver.source if ver else "unknown",
            "confidence": d.confidence,
            "derived": d.derived,
            "implied_by": d.implied_by,
            "evidence": d.evidence[:3],
            "status": adv.status if adv else "",
            "cves": adv.cves if adv else [],
            "cpe": d.cpe,
            "note": d.note,
        })
    return {
        "schema": 1,
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signature_db": sig_date,
        "rendered": rendered,
        "pages": pages,
        # What this run actually measured. Without it a diff cannot tell
        # "disappeared" from "never looked" (see build_diff).
        "scope": scope or {},
        "technologies": techs,
        "third_party": [
            {"domain": tp.domain, "purpose": tp.purpose, "count": tp.count,
             "types": tp.types, "jurisdiction": tp.jurisdiction}
            for tp in parties
        ],
    }


def build_chart_event(parties: list[ThirdParty]) -> Optional[dict]:
    """Bar chart: external requests by purpose. One event, at the end."""
    summary = purpose_summary(parties)
    if not summary:
        return None
    labels = list(summary)
    return {
        "type": "chart",
        "chart_type": "bar",
        "title": "External requests by purpose",
        "labels": labels,
        "series": [{"name": "requests", "values": [summary[l] for l in labels]}],
    }


def write_artifacts(
    output_dir: str,
    markdown: str,
    snapshot: dict,
    detections: dict[str, Detection],
    versions: dict[str, VersionResult],
    advisories: dict[str, Advisory],
    parties: list[ThirdParty],
    diff_md: Optional[str],
) -> list[str]:
    written: list[str] = []

    def _write(name: str, content: str) -> None:
        path = os.path.join(output_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(path)

    _write("techstack-report.md", markdown)

    with open(os.path.join(output_dir, "stack.json"), "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2, ensure_ascii=False)
    written.append(os.path.join(output_dir, "stack.json"))

    # technologies.csv
    csv_path = os.path.join(output_dir, "technologies.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["slug", "name", "category", "version", "confidence",
                    "derived", "evidence", "status", "cves"])
        for d in order_detections(detections):
            ver = versions.get(d.slug)
            adv = advisories.get(d.slug)
            w.writerow([
                d.slug, d.name,
                d.categories[0] if d.categories else "",
                _ver_display(ver), f"{d.confidence:.0f}",
                "yes" if d.derived else "",
                "; ".join(d.evidence[:3]),
                adv.status if adv else "",
                "|".join(adv.cves) if adv else "",
            ])
    written.append(csv_path)

    # third-party.csv
    tp_path = os.path.join(output_dir, "third-party.csv")
    with open(tp_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["domain", "purpose", "count", "types", "jurisdiction", "hosts"])
        for tp in parties:
            w.writerow([tp.domain, tp.purpose, tp.count, "|".join(tp.types),
                        tp.jurisdiction, "|".join(tp.hosts)])
    written.append(tp_path)

    if diff_md is not None:
        _write("diff.md", diff_md)

    return written


def _scope_of(snapshot: dict) -> dict:
    """Scan scope of a snapshot, with a fallback for pre-scope stack.json files.

    Legacy files carry no ``scope``. Inferring "third-party was measured" from a
    non-empty list is deliberately conservative: an empty list is ambiguous
    (measured and found nothing vs. never measured), and guessing "measured"
    there is what produced phantom "disappeared" rows in the first place.
    """
    scope = snapshot.get("scope") or {}
    if scope:
        return {
            "categories": set(scope.get("categories") or ()),
            "third_party": bool(scope.get("third_party")),
            "versions": bool(scope.get("versions")),
            "min_confidence": scope.get("min_confidence"),
        }
    return {
        "categories": set(),                                  # [] = all
        "third_party": bool(snapshot.get("third_party")),
        "versions": any(t.get("version", "unknown") != "unknown"
                        for t in snapshot.get("technologies", [])),
        "min_confidence": None,
    }


def _comparable_categories(base: dict, cur: dict) -> Optional[set]:
    """Categories measured by BOTH runs. ``None`` means "no restriction"."""
    b, c = base["categories"], cur["categories"]
    if not b and not c:
        return None
    if not b:
        return set(c)
    if not c:
        return set(b)
    return b & c


def _in_scope(tech: dict, cats: Optional[set]) -> bool:
    if cats is None:
        return True
    return bool(set(tech.get("categories") or ()) & cats)


def build_diff(baseline: dict, current: dict) -> str:
    """Compare a previous stack.json to the current snapshot.

    A diff is only worth reading if it never cries wolf: a technology absent
    because the run filtered it out, or a third party absent because
    ``--third-party`` was off, must not be reported as *gone*. Each dimension is
    compared only when both runs actually measured it; the rest is stated as
    not compared, which is the honest answer and keeps the real changes visible.
    """
    b_scope, c_scope = _scope_of(baseline), _scope_of(current)
    cats = _comparable_categories(b_scope, c_scope)

    base_tech = {t["slug"]: t for t in baseline.get("technologies", [])
                 if _in_scope(t, cats)}
    cur_tech = {t["slug"]: t for t in current.get("technologies", [])
                if _in_scope(t, cats)}

    tp_comparable = b_scope["third_party"] and c_scope["third_party"]
    base_tp = {t["domain"]: t for t in baseline.get("third_party", [])}
    cur_tp = {t["domain"]: t for t in current.get("third_party", [])}

    added = sorted(set(cur_tech) - set(base_tech))
    removed = sorted(set(base_tech) - set(cur_tech))
    common = set(cur_tech) & set(base_tech)
    changed = []
    for s in sorted(common):
        bv = base_tech[s].get("version", "unknown")
        cv = cur_tech[s].get("version", "unknown")
        if bv != cv and bv != "unknown" and cv != "unknown":
            changed.append((s, bv, cv))

    tp_added = sorted(set(cur_tp) - set(base_tp)) if tp_comparable else []
    tp_removed = sorted(set(base_tp) - set(cur_tp)) if tp_comparable else []

    lines = ["# diff · Tech Stack", ""]
    lines.append(f"baseline: {baseline.get('url', '?')} · "
                 f"{baseline.get('timestamp', '?')}")
    lines.append(f"current:  {current.get('url', '?')} · "
                 f"{current.get('timestamp', '?')}")
    lines.append("")

    # ── What could not be compared, and why ──────────────────────────────────
    not_compared: list[str] = []
    if not tp_comparable:
        which = "baseline" if not b_scope["third_party"] else "current run"
        not_compared.append(
            f"**Third parties** — not compared: {which} ran without `--third-party`.")
    if cats is not None:
        not_compared.append(
            "**Categories** — compared only: `" + "`, `".join(sorted(cats)) +
            "` (the rest was not measured in one of the runs).")

    caveats: list[str] = []
    if baseline.get("rendered") != current.get("rendered"):
        caveats.append(
            "rendering was enabled in only one of the runs — technologies visible "
            "only through JS may have appeared/disappeared because of that, not "
            "because of changes on the site")
    bp, cp = baseline.get("pages"), current.get("pages")
    if bp and cp and bp != cp:
        caveats.append(f"different number of pages ({bp} → {cp}) — the stack of "
                       f"internal pages differs from the homepage's")
    bmc, cmc = b_scope["min_confidence"], c_scope["min_confidence"]
    if bmc is not None and cmc is not None and bmc != cmc:
        caveats.append(f"different confidence threshold ({bmc}% → {cmc}%)")
    if not (b_scope["versions"] and c_scope["versions"]):
        caveats.append("versions were not detected in both runs — version changes are incomplete")

    if not_compared:
        lines.append("> **Not compared**")
        lines.append(">")
        for n in not_compared:
            lines.append(f"> - {n}")
        lines.append("")
    if caveats:
        lines.append("> **Note:** the scan scope differed — " +
                     "; ".join(caveats) + ".")
        lines.append("")

    def _name(slug: str, src: dict) -> str:
        return src.get(slug, {}).get("name", slug)

    if added:
        lines.append("## Added")
        lines.append("")
        for s in added:
            v = cur_tech[s].get("version", "unknown")
            lines.append(f"- **{_name(s, cur_tech)}** {v}")
        lines.append("")
    if removed:
        lines.append("## Removed")
        lines.append("")
        for s in removed:
            v = base_tech[s].get("version", "unknown")
            lines.append(f"- **{_name(s, base_tech)}** {v}")
        lines.append("")
    if changed:
        lines.append("## Version changes")
        lines.append("")
        for s, bv, cv in changed:
            lines.append(f"- **{_name(s, cur_tech)}**: {bv} → {cv}")
        lines.append("")

    if tp_added:
        lines.append("## New third parties")
        lines.append("")
        for d in tp_added:
            lines.append(f"- {d} — {cur_tp[d].get('purpose', '?')}")
        lines.append("")
    if tp_removed:
        lines.append("## Gone third parties")
        lines.append("")
        for d in tp_removed:
            lines.append(f"- {d}")
        lines.append("")

    if not (added or removed or changed or tp_added or tp_removed):
        scope_note = " in the compared dimensions" if (not_compared or caveats) else ""
        lines.append(f"_No stack changes found{scope_note}._")
    return "\n".join(lines)
