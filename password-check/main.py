#!/usr/bin/env python3
"""password-check/main.py — is a password already in a known breach?

Two modes. **Check**: one password (a secret field — Keychain, env,
never argv) is analyzed locally — length, character classes, entropy,
obvious patterns — and looked up in
[Have I Been Pwned](https://haveibeenpwned.com/Passwords)' breach
database using **k-anonymimity**: the password is SHA-1-hashed locally,
only the first **5 characters of the hash** are sent, and the server
answers with the whole range so the match happens on this machine. The
password itself never leaves the machine in any recoverable form, and
no API key is needed.

**Generate**: cryptographically strong passwords (`secrets` module),
tunable length and alphabet, shown in the Results tab.

Privacy contract: **no artifacts are written** — nothing lands on disk.
The checked password is masked everywhere it appears (length and first
character only); generated passwords are printed to the run log and the
Results tab, because copying them is the point, but never to a file.

Exit codes: 0 = the check/generation ran (a pwned password is a
finding, not a failure; an unreachable HIBP server degrades the report
with a warning, it doesn't fail the run), 1 = unusable input (check
mode without a password), 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import secrets
import string
import sys

import requests

USER_AGENT = "PyShell-password-check/1.0"
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

LOWER, UPPER, DIGITS, SYMBOLS = string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%^&*()-_=+[]{};:,.?/"

# Entropy buckets (bits) — the vocabulary the report speaks.
VERY_WEAK, WEAK, FAIR, STRONG = 28, 36, 60, 128
STRENGTH_ICON = {"very weak": "🔴", "weak": "🟠", "fair": "🟡",
                 "strong": "🟢", "very strong": "🟢"}


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# ---------------------------------------------------------------------------
# Local analysis (pure — tests live on these)
# ---------------------------------------------------------------------------

def charset_classes(password: str) -> list[str]:
    """Which character classes the password draws from."""
    classes = []
    if any(c in LOWER for c in password):
        classes.append("lowercase")
    if any(c in UPPER for c in password):
        classes.append("uppercase")
    if any(c in DIGITS for c in password):
        classes.append("digits")
    if any(not c.isalnum() for c in password):
        classes.append("symbols")
    other = [c for c in password
             if not c.isascii() and not c.isspace()]
    if other:
        classes.append("non-ASCII")
    return classes


def pool_size(classes: list[str]) -> int:
    """The alphabet the password could have been drawn from, given the
    classes it actually uses."""
    size = 0
    if "lowercase" in classes:
        size += 26
    if "uppercase" in classes:
        size += 26
    if "digits" in classes:
        size += 10
    if "symbols" in classes:
        size += 32  # printable ASCII punctuation+symbols, rounded honest
    if "non-ASCII" in classes:
        size += 100  # unicode is huge; a conservative floor
    return size


def entropy_bits(password: str) -> float:
    """Shannon-style entropy of a *random* password with this length and
    these classes: len × log2(pool). The honest ceiling for what it
    could be — patterns below say why reality is often lower."""
    classes = charset_classes(password)
    size = pool_size(classes)
    if size <= 1:
        return 0.0
    return round(len(password) * math.log2(size), 1)


def strength_label(bits: float) -> str:
    if bits < VERY_WEAK:
        return "very weak"
    if bits < WEAK:
        return "weak"
    if bits < FAIR:
        return "fair"
    if bits < STRONG:
        return "strong"
    return "very strong"


# Keyboard/sequence detectors: reported as warnings, never silently
# folded into the entropy number (the deduction would be a guess).
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789",
             "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def pattern_warnings(password: str) -> list[str]:
    """Human warnings for patterns entropy math can't see."""
    warnings = []
    low = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in low:
                warnings.append(f"contains the sequence “{chunk}”")
                break
            rev = chunk[::-1]
            if rev in low:
                warnings.append(f"contains the reversed sequence “{rev}”")
                break
    run, run_len = "", 1
    for c in password:
        if c == run:
            run_len += 1
        else:
            run, run_len = c, 1
        if run_len == 3:
            warnings.append(f"contains a triple repeat (“{c}{c}{c}”)")
            break
    if len(set(password)) == 1 and len(password) > 1:
        warnings.append("is a single repeated character")
    return warnings


def mask_password(password: str) -> str:
    """What the log may show: the first character, the length, nothing
    else. An empty/1-char password shows as dots only."""
    if not password:
        return "(empty)"
    if len(password) == 1:
        return "•"
    return f"{password[0]}{'•' * (len(password) - 1)}"


# ---------------------------------------------------------------------------
# HIBP k-anonymimity lookup
# ---------------------------------------------------------------------------

def sha1_upper(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def parse_range_body(body: str) -> dict[str, int]:
    """The range server answers with `SUFFIX:COUNT` lines — every hash
    that starts with the requested prefix. The match happens here, on
    this machine."""
    counts: dict[str, int] = {}
    for line in body.splitlines():
        if ":" in line:
            suffix, _, count = line.partition(":")
            try:
                counts[suffix.strip()] = int(count)
            except ValueError:
                continue
    return counts


def lookup_hibp(password: str, timeout: int
                ) -> tuple[int | None, str]:
    """(breach_count, error). count is None only when the range server
    couldn't be reached — a network fact, not a verdict."""
    digest = sha1_upper(password)
    prefix, suffix = digest[:5], digest[5:]
    try:
        resp = requests.get(HIBP_RANGE_URL.format(prefix=prefix),
                            timeout=timeout,
                            headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
    except requests.RequestException as exc:
        return None, type(exc).__name__
    counts = parse_range_body(resp.text)
    return counts.get(suffix, 0), ""


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def generate_password(length: int, symbols: bool) -> str:
    """A `secrets`-random password over the chosen alphabet, guaranteed
    to use every selected class at least once."""
    alphabet = LOWER + UPPER + DIGITS + (SYMBOLS if symbols else "")
    classes = [LOWER, UPPER, DIGITS] + ([SYMBOLS] if symbols else [])
    while True:
        chars = [secrets.choice(cls) for cls in classes]
        chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
        # Fisher–Yates on secrets randomness — random.shuffle is not
        # cryptographic; building our own keeps the whole path in secrets.
        for i in range(len(chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            chars[i], chars[j] = chars[j], chars[i]
        candidate = "".join(chars)
        # Reject pathological all-same-class draws (already prevented by
        # the seed chars; the check is cheap insurance).
        if charset_classes(candidate) == charset_classes("".join(classes)):
            return candidate


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def build_check_markdown(password: str, breach_count: int | None,
                         error: str) -> str:
    bits = entropy_bits(password)
    label = strength_label(bits)
    classes = charset_classes(password)
    warnings = pattern_warnings(password)

    if breach_count is None:
        head = f"## ⚠️ {STRENGTH_ICON[label]} {label.capitalize()} — breach status unknown"
    elif breach_count > 0:
        head = (f"## 🔴 Pwned — seen **{breach_count:,} time(s)** in known "
                f"breaches")
    else:
        head = f"## 🟢 Not found in known breaches — {label} ({bits} bits)"
    lines = [head, "",
             f"- Password (masked): `{mask_password(password)}` — "
             f"{len(password)} character(s)",
             f"- Character classes: {', '.join(classes) if classes else 'none'}",
             f"- Entropy: **{bits} bits** ({label})"]
    if warnings:
        lines.append("- ⚠️ Patterns: " + "; ".join(f"it {w}" for w in warnings))
    lines.append("")

    if breach_count is None:
        lines += [f"**The HIBP range server couldn't be reached ({error}).**",
                  "The entropy analysis stands; the breach lookup does not.",
                  "Re-run when the network allows — `api.pwnedpasswords.com`",
                  "is free and keyless.", ""]
    elif breach_count > 0:
        lines += ["**Change it everywhere it's used.** A password in a",
                  "breach corpus is in every credential-stuffing wordlist;",
                  "no amount of entropy saves it. If it's reused, each site",
                  "using it inherits the breach.", ""]
    else:
        lines += ["Not appearing here is good but local: it says nothing",
                  "about reuse, phishing, or a breach not yet indexed.",
                  "Unique-per-site + a password manager remains the rule.",
                  ""]
    if bits < FAIR:
        lines.append("_Length beats cleverness: 4 random common words or "
                     "20+ random characters is where entropy becomes "
                     "comfortable. Generate mode makes those._")
        lines.append("")
    lines.append("_Only a 5-character SHA-1 prefix left this machine; the "
                 "match ran locally. No files were written._")
    lines.append("")
    return "\n".join(lines)


def build_check_table(password: str, breach_count: int | None) -> dict:
    bits = entropy_bits(password)
    return {
        "type": "table",
        "columns": ["Metric", "Value"],
        "rows": [
            ["Length", len(password)],
            ["Character classes", ", ".join(charset_classes(password))
             or "—"],
            ["Entropy", f"{bits} bits"],
            ["Strength", strength_label(bits)],
            ["Breach count (HIBP)", breach_count if breach_count is not None
             else "unreachable"],
        ],
    }


def build_generate_markdown(passwords: list[str]) -> str:
    lines = [f"## 🔑 {len(passwords)} password(s) generated", ""]
    for p in passwords:
        lines.append(f"- `{p}` — {entropy_bits(p)} bits, "
                     f"{strength_label(entropy_bits(p))}")
    lines += ["",
              "_Generated with the `secrets` module (os.urandom) — shown "
              "here and in the run log, **never written to a file**. "
              "Pick one, store it in a password manager, and clear this "
              "run from history when PyShell grows that button._",
              ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Password Check — HIBP k-anonymimity breach lookup, "
                    "entropy analysis, strong generation")
    parser.add_argument("--mode", choices=["check", "generate"],
                        default="check",
                        help="check one password, or generate new ones")
    parser.add_argument("--generate-length", type=int, default=20,
                        help="characters per generated password (default 20)")
    parser.add_argument("--generate-count", type=int, default=3,
                        help="how many passwords to generate (default 3)")
    parser.add_argument("--include-symbols",
                        action=argparse.BooleanOptionalAction, default=True,
                        help="include symbols in generated passwords "
                             "(default on)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HIBP request timeout in seconds (default 10)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no lookups, no generation",
              flush=True)
        return 0

    if args.mode == "generate":
        if not (8 <= args.generate_length <= 128):
            print("✗ --generate-length must be 8–128", file=sys.stderr,
                  flush=True)
            return 2
        if not (1 <= args.generate_count <= 20):
            print("✗ --generate-count must be 1–20", file=sys.stderr,
                  flush=True)
            return 2
        status(f"Generating {args.generate_count} password(s) of "
               f"{args.generate_length} characters")
        passwords = [generate_password(args.generate_length,
                                       args.include_symbols)
                     for _ in range(args.generate_count)]
        for p in passwords:
            log(f"  {p}")
        emit({"type": "progress", "pct": 100, "message": "Done"})
        emit({"type": "table", "columns": ["Password", "Entropy", "Strength"],
              "rows": [[p, f"{entropy_bits(p)} bits",
                        strength_label(entropy_bits(p))]
                       for p in passwords]})
        emit({"type": "markdown",
              "content": build_generate_markdown(passwords)})
        status(f"{len(passwords)} password(s) generated — copy from Results")
        return 0

    # --- check mode ---
    password = os.environ.get("PASSWORD", "")
    if not password:
        print("✗ no password to check: the Password field is empty (it "
              "arrives via the PASSWORD env var — set it or fill the "
              "secret field in PyShell)", file=sys.stderr, flush=True)
        return 1

    masked = mask_password(password)
    log(f"Checking a {len(password)}-character password ({masked}) — "
        f"hashing locally")
    bits = entropy_bits(password)
    log(f"  Entropy: {bits} bits ({strength_label(bits)}) · "
        f"classes: {', '.join(charset_classes(password))}")
    for w in pattern_warnings(password):
        log(f"  ⚠️ it {w}")

    status("Asking HIBP for the hash-prefix range (k-anonymimity)")
    emit({"type": "progress", "pct": 40, "message": "Local analysis done"})
    breach_count, error = lookup_hibp(password, args.timeout)
    emit({"type": "progress", "pct": 100, "message": "Done"})

    if breach_count is None:
        log(f"  ⚠️ HIBP unreachable ({error}) — local analysis only")
    elif breach_count > 0:
        log(f"  🔴 found in known breaches: {breach_count:,} occurrence(s)")
    else:
        log("  🟢 not found in known breaches")

    emit(build_check_table(password, breach_count))
    emit({"type": "markdown",
          "content": build_check_markdown(password, breach_count, error)})

    if breach_count is None:
        verdict = f"{bits} bits · breach status unknown (HIBP unreachable)"
    elif breach_count > 0:
        verdict = f"{bits} bits · pwned ({breach_count:,}× in breaches)"
    else:
        verdict = f"{bits} bits · not found in known breaches"
    status(f"{masked} · {verdict}")
    # A pwned password is a finding, not a run failure.
    return 0


if __name__ == "__main__":
    sys.exit(main())
