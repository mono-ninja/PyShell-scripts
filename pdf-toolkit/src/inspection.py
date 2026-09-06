"""src/inspection.py — opening PDFs safely and describing what they leak."""
from __future__ import annotations

from pypdf import PdfReader
from pypdf.errors import PdfReadError, DependencyError as PypdfDependencyError


def read_pdf(path: str) -> tuple[PdfReader | None, str]:
    """(reader, problem). Encrypted files get one empty-password try —
    most "encrypted" PDFs in the wild are owner-locked, not
    password-locked. The problem string is human, for the log."""
    try:
        reader = PdfReader(path)
    except FileNotFoundError:
        return None, "file not found"
    except PermissionError:
        return None, "not readable (permissions)"
    except (PdfReadError, PypdfDependencyError) as exc:
        return None, f"not a readable PDF ({type(exc).__name__})"
    if reader.is_encrypted:
        try:
            if not reader.decrypt(""):
                return None, "encrypted — a password is required"
        except (PdfReadError, ValueError):
            return None, "encrypted — a password is required"
    return reader, ""


# The metadata keys that leak identity, in display order. Everything
# else in the info dict is still shown if present (never invented).
LEAK_FIELDS = [
    ("/Title", "Title"),
    ("/Author", "Author"),
    ("/Subject", "Subject"),
    ("/Keywords", "Keywords"),
    ("/Creator", "Created with"),
    ("/Producer", "Produced by"),
    ("/CreationDate", "Created"),
    ("/ModDate", "Modified"),
]


def describe_metadata(reader: PdfReader) -> dict[str, str]:
    """The metadata that would leak, as a {label: value} dict — the
    privacy story strip/compress reports before removing it."""
    out: dict[str, str] = {}
    md = reader.metadata
    if md:
        for key, label in LEAK_FIELDS:
            value = md.get(key)
            if value:
                out[label] = str(value)
    try:
        if reader.xmp_metadata:
            # XMP is a second, parallel metadata stream (Adobe's) — even
            # files with a "clean" info dict often carry one.
            out["XMP"] = "present (Adobe metadata stream)"
    except Exception:
        pass
    try:
        if reader.attachments:
            names = ", ".join(sorted(reader.attachments)[:5])
            out["Attachments"] = f"{len(reader.attachments)}: {names}"
    except Exception:
        pass
    return out


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.0f} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"
