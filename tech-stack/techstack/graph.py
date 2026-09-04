"""Implication / exclusion graph.

Half the useful conclusions are derivative, not direct: Next.js ⇒ React ⇒
Node.js, WooCommerce ⇒ WordPress ⇒ PHP, Elementor ⇒ WordPress. These are
transitively closed over ``implies`` after the main pass, flagged ``derived`` so
the table distinguishes a conclusion from evidence, with confidence no higher
than its source.

``excludes`` is rarer but stops nonsense like Apache + IIS + nginx at once: on a
conflict the weaker signal is dropped and the winner gets a note. Without this,
a CDN rewriting ``Server:`` would let two webservers coexist in the report.

``note_cdn_hidden_origin``: behind Cloudflare ``Server: cloudflare`` and
the real web server is invisible. The honest answer is "unknown (behind
Cloudflare)", not silence — an empty row reads as "no server", which is absurd.
"""
from __future__ import annotations

from .detect import Detection
from .signatures import Technology

# Derived technologies cap below direct evidence — a conclusion is never more
# certain than the signal it rests on, and a bit lower to stay honest.
DERIVED_CAP = 85

# CDN slugs that hide the origin server.
_CDN_SLUGS = {"cloudflare", "fastly", "akamai", "sucuri", "imperva", "incapsula", "section"}


def apply_implies(
    detections: dict[str, Detection], by_slug: dict[str, Technology]
) -> dict[str, Detection]:
    """Transitively close ``implies``. Mutates and returns ``detections``."""
    queue = list(detections.values())
    while queue:
        src = queue.pop()
        tech = by_slug.get(src.slug)
        if not tech:
            continue
        for imp in tech.implies:
            implied_tech = by_slug.get(imp)
            if not implied_tech:
                continue
            new_conf = min(src.confidence, DERIVED_CAP)
            existing = detections.get(imp)
            if existing is not None:
                # Only upgrade a *derived* tech if the new source is stronger.
                # A directly-detected tech is never overwritten by an implication.
                if existing.derived and new_conf > existing.confidence:
                    existing.confidence = new_conf
                    existing.implied_by = src.slug
                    existing.evidence = [f"← {src.name}"]
                continue
            derived = Detection(
                slug=implied_tech.slug,
                name=implied_tech.name,
                categories=implied_tech.categories,
                confidence=new_conf,
                derived=True,
                implied_by=src.slug,
                evidence=[f"← {src.name}"],
                cpe=implied_tech.cpe,
                website=implied_tech.website,
            )
            detections[imp] = derived
            queue.append(derived)
    return detections


def resolve_excludes(
    detections: dict[str, Detection], by_slug: dict[str, Technology]
) -> dict[str, Detection]:
    """On a conflict, keep the stronger signal; drop the weaker with a note."""
    for slug in list(detections):
        if slug not in detections:
            continue
        tech = by_slug.get(slug)
        if not tech:
            continue
        for ex in tech.excludes:
            if slug not in detections:
                break
            if ex not in detections or ex == slug:
                continue
            a = detections[slug]
            b = detections[ex]
            winner, loser = (a, b) if a.confidence >= b.confidence else (b, a)
            detections.pop(loser.slug, None)
            if winner.note:
                winner.note += f"; conflict with {loser.name}"
            else:
                winner.note = f"conflict with {loser.name} ({loser.confidence:.0f}%)"
    return detections


def note_cdn_hidden_origin(
    detections: dict[str, Detection], by_slug: dict[str, Technology]
) -> dict[str, Detection]:
    """If a CDN is detected but no web server, add a placeholder.

    Behind Cloudflare ``Server: cloudflare`` and the origin is invisible.
    "Unknown (behind Cloudflare)" is honest; silence reads as "no server".
    """
    has_server = any(
        "server" in d.categories for d in detections.values()
    )
    if has_server:
        return detections
    cdn_names = [d.name for s, d in detections.items() if s in _CDN_SLUGS]
    if not cdn_names:
        return detections
    detections["__cdn_hidden_server"] = Detection(
        slug="__cdn_hidden_server",
        name="Web server",
        categories=("server",),
        confidence=0,
        derived=True,
        evidence=[f"behind {', '.join(cdn_names)}"],
        note=f"unknown (behind {', '.join(cdn_names)})",
    )
    return detections


def apply_graph(
    detections: dict[str, Detection], by_slug: dict[str, Technology]
) -> dict[str, Detection]:
    detections = apply_implies(detections, by_slug)
    detections = resolve_excludes(detections, by_slug)
    return detections
