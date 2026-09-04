"""The Symbol dataclass — the contract every pipeline stage produces/consumes.

One ``Symbol`` is one icon's worth of state. Stages do not hand each other
free-floating dicts or ad-hoc tuples: they mutate (or rebuild) this object so
the shape of the data flowing through the pipeline stays legible.

Fields
------
id
    Final symbol id, prefix included (e.g. ``icon-arrow-left``). Empty until
    A3 naming runs.
view_box
    The ``viewBox`` string for the ``<symbol>`` (``"0 0 24 24"``). Empty until
    A4 normalize synthesises it.
body
    lxml elements, ready to nest under ``<symbol>``. After A4 this is the
    deep-copied inner content of the source ``<svg>``; A6 and A5 mutate it in
    place. Empty until A4.
source
    Source file path (as given on the command line / discovered), kept for
    warnings and the result table.
warnings
    Human-readable strings, surfaced in the PyShell result table.
meta
    Anything a later stage needs to remember but that is not itself XML
    content: the original ``<svg>`` root, carried root attributes, the
    old→new id/class maps, whether currentColor was substituted, etc.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Symbol:
    id: str = ""
    view_box: str = ""
    body: list = field(default_factory=list)
    source: str = ""
    warnings: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
