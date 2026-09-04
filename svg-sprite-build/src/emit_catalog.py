"""Emit catalog.html — a self-contained preview of every symbol in the sprite.

The sprite defs are inlined into the page (hidden by the same zero-size
technique as ``sprite.svg``) and each icon is rendered with
``<svg><use href="#id"/></svg>``. Inlining — rather than
``<use href="sprite.svg#id">`` — keeps the catalog working when opened
directly from ``file://``, where external references can be blocked.
"""
from __future__ import annotations

from jinja2 import Environment
from markupsafe import Markup

from .emit_sprite import write_artifact

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SVG Sprite Catalog</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; margin: 24px; color: #222; }
  h1 { font-size: 1.15rem; margin: 0 0 4px; }
  .meta { color: #666; font-size: 0.85rem; margin-bottom: 18px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 12px; }
  .card { border: 1px solid #e6e6e6; border-radius: 8px; padding: 12px 10px;
          display: flex; flex-direction: column; align-items: center; gap: 8px; }
  .preview { width: 48px; height: 48px; color: #222; }
  .preview svg { width: 100%; height: 100%; }
  .id { font: 0.72rem ui-monospace, Menlo, monospace; word-break: break-all; text-align: center; }
  .warn { color: #b00020; font-size: 0.68rem; text-align: center; }
</style>
</head>
<body>
<h1>SVG Sprite Catalog</h1>
<div class="meta">{{ count }} icon{{ 's' if count != 1 else '' }}</div>
{{ sprite_svg }}
<div class="grid">
{% for s in symbols %}
  <div class="card">
    <div class="preview"><svg><use href="#{{ s.id }}"/></svg></div>
    <div class="id">{{ s.id }}</div>
    {% if s.warnings %}<div class="warn">{{ s.warnings | join('; ') }}</div>{% endif %}
  </div>
{% endfor %}
</div>
</body>
</html>
"""


def render_catalog(symbols, sprite_svg: str) -> str:
    env = Environment(autoescape=True)
    tmpl = env.from_string(_TEMPLATE)
    return tmpl.render(
        count=len(symbols),
        symbols=symbols,
        sprite_svg=Markup(sprite_svg),
    )


def emit_catalog(symbols, sprite_svg: str, out_dir: str) -> str:
    html = render_catalog(symbols, sprite_svg)
    return write_artifact(out_dir, "catalog.html", html)
