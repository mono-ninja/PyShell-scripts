"""src/report.py — the results table, the markdown report, the artifact
writer. The strip/compress report tells the privacy story: what the
metadata would have leaked."""
from __future__ import annotations

import json
import os

from .events import emit
from .inspection import human_size


OP_HEADLINE = {
    "merge": "🔗 Merged",
    "split": "✂️ Split",
    "extract": "📄 Extracted",
    "rotate": "🔁 Rotated",
    "strip": "🧼 Stripped",
    "compress": "🗜️ Compressed",
}


def build_table_event(operation: str, results) -> dict:
    rows = []
    for r in results:
        rows.append([r.source, {"ok": "✓", "error": "✗"}[r.status],
                     r.detail or r.note or "—"])
    return {
        "type": "table",
        "columns": ["File", "Status", "Result"],
        "rows": rows,
    }


def build_markdown(operation: str, results, written, leaks) -> str:
    ok = sum(1 for r in results if r.status == "ok")
    head = f"## {OP_HEADLINE.get(operation, '')} {ok}/{len(results)} file(s)"
    lines = [head, ""]

    for r in results:
        icon = "✓" if r.status == "ok" else "✗"
        lines.append(f"- {icon} **{r.source}** — "
                     f"{r.detail or r.note or '—'}")
    lines.append("")

    if written:
        lines.append(f"**{len(written)} file(s) written** to "
                     f"`{os.path.dirname(written[0]) or '.'}` — the "
                     f"originals were never touched.")
        lines.append("")

    if leaks:
        any_leak = any(desc for _name, desc in leaks)
        lines.append("### What the metadata would have leaked")
        lines.append("")
        if not any_leak:
            lines.append("_Nothing — these files carried no info-dict "
                         "metadata, XMP or attachments. (Their content "
                         "can still leak: text, images, visible "
                         "watermarks.)_")
        else:
            for name, desc in leaks:
                lines.append(f"- **{name}**: " + (
                    "; ".join(f"{label}: {value}"
                              for label, value in desc.items())
                    if desc else "nothing"))
        lines.append("")
        lines.append("_The clean copies carry none of it: the document "
                     "is rebuilt from pages only. Before sending a PDF "
                     "anywhere, run strip on it — see also "
                     "[EXIF Inspect](../exif-inspect) for the same "
                     "story in your photos._")
        lines.append("")

    if operation == "compress":
        lines.append("_Compression here = metadata removal + duplicate-"
                     "object dedupe. Image streams are never re-encoded — "
                     "a scanned PDF won't shrink much; the honest way to "
                     "shrink scans is re-encoding, which loses quality "
                     "and isn't done silently._")
        lines.append("")

    total_in = sum(r.source_bytes for r in results)
    total_out = sum(r.output_bytes for r in results)
    if operation in ("strip", "compress") and total_in:
        delta = 100 * (total_in - total_out) / total_in
        lines.append(f"_{human_size(total_in)} → {human_size(total_out)} "
                     f"({delta:+.1f}%) — size changes are a side effect, "
                     f"never the goal of strip._")
        lines.append("")
    return "\n".join(lines)


def write_artifacts(operation: str, results, leaks) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "operation": operation,
        "results": [{"source": r.source, "status": r.status,
                     "detail": r.detail, "note": r.note,
                     "source_bytes": r.source_bytes,
                     "output_bytes": r.output_bytes}
                    for r in results],
        "metadata_removed": {name: desc for name, desc in leaks},
    }
    with open(os.path.join(out_dir, "pdf_toolkit_results.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
