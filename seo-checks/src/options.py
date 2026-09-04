"""Tunables every check receives, so ``main.py`` keeps dispatching
generically instead of growing a keyword argument per check.

One object, one signature — ``run(snapshot, options)`` — which is what
makes the registry in :mod:`src.checks` a plain dict lookup. Defaults here
are the same numbers the CLI advertises; the CLI overrides them, tests
construct :class:`Options` directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Options:
    # --- duplicates ---------------------------------------------------
    duplicates_mode: str = "exact"        # exact | normalized
    # Filled in by main.py only when both `canonical` and `duplicates`
    # are selected — canonical's cross-check is skipped, not half-run,
    # when the user didn't ask for duplicate detection.
    duplicate_groups: list | None = None

    # --- meta quality -------------------------------------------------
    # "Too short" is deliberately far below the ~50-60 guideline: a title
    # of 45 characters is fine, and flagging it turns every page on the
    # site into an info-level finding that buries the real ones.
    title_min: int = 30
    title_max: int = 60
    desc_min: int = 70
    desc_max: int = 158

    # --- orphans ------------------------------------------------------
    max_depth: int = 3

    # --- canonical ----------------------------------------------------
    flag_missing_canonical: bool = False

    # --- external links (read by external_links.run only) -------------
    external_ignore_hosts: frozenset[str] = field(default_factory=frozenset)
