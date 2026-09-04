"""B7 — write catalog.html, the verification grid.

Each icon is shown in two columns side by side: the converted sprite rendered
via ``<use>``, and the same glyph rendered from the original font (embedded as
a base64 ``@font-face``). That comparison is the only honest way to spot a
geometry defect at a glance, and it is what exposes B5 problems immediately.

For SVG-font inputs the original-font column cannot be rendered — browsers
removed SVG-font support — so a note replaces it instead of a silent blank.
"""
from __future__ import annotations

import base64
import os

from jinja2 import Environment

from .util import atomic_write_text

# src format() and the data: MIME type per container.
_FONT_FORMATS = {
    "ttf": ("truetype", "font/ttf"),
    "otf": ("opentype", "font/otf"),
    "woff": ("woff", "font/woff"),
    "woff2": ("woff2", "font/woff2"),
}

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SVG sprite catalog — {{ family }}</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  .meta { color: #666; margin: 0 0 1.5rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; }
  .card { border: 1px solid #ddd; border-radius: 8px; padding: .75rem; background: #fff; }
  @media (prefers-color-scheme: dark) { .card { background: #1c1c1e; border-color: #333; } }
  .cols { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; margin-bottom: .5rem; }
  .col { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 56px; border-radius: 4px; padding: .25rem; }
  .col .lbl { font-size: 10px; color: #888; margin-top: .25rem; }
  .col.sprite { background: #f4f4f6; color: #111; }
  .col.orig   { background: #eef6ff; color: #111; }
  @media (prefers-color-scheme: dark) { .col.sprite { background: #2a2a2c; } .col.orig { background: #16223a; } }
  .sprite svg, .mn-icon { width: 32px; height: 32px; fill: currentColor; }
  .orig i { font-size: 32px; line-height: 1; }
  .id { font-weight: 600; word-break: break-all; }
  .row { font-size: 12px; color: #555; }
  .row b { color: #222; }
  code { background: #f4f4f6; padding: 1px 4px; border-radius: 3px; font-size: 11px; word-break: break-all; }
  @media (prefers-color-scheme: dark) { code { background: #2a2a2c; } .row b { color: #ddd; } }
  .copy { cursor: pointer; border: 1px solid #ccc; background: transparent; border-radius: 3px; font-size: 11px; padding: 1px 6px; }
  .copy:hover { background: #eee; }
  .warn { color: #c0392b; font-size: 11px; }
  .note { color: #888; font-size: 11px; font-style: italic; }
</style>
{% if font_face %}
<style>
  @font-face { font-family: 'mn-orig'; src: url({{ font_src }}) format('{{ font_fmt }}'); font-display: block; }
  .orig i { font-family: 'mn-orig'; }
  .mn-lig { font-feature-settings: "liga" 1; -webkit-font-feature-settings: "liga" 1; }
  {% for row in rows %}{% if row.cp_escape %}.orig-{{ loop.index0 }}::before { content: "{{ row.cp_escape }}"; }
  {% endif %}{% endfor %}
</style>
{% endif %}
</head>
<body>
<h1>SVG sprite catalog — {{ family }}</h1>
<p class="meta">{{ stats.total }} icons · source: <code>{{ font_format }}</code>{% if stats.unnamed %} · <span class="warn">{{ stats.unnamed }} unnamed</span>{% endif %}</p>
{{ sprite_body | safe }}
<div class="grid">
{% for row in rows %}
  <div class="card">
    <div class="cols">
      <div class="col sprite">
        <svg viewBox="{{ row.view_box }}"><use href="#{{ row.sprite_id }}"></use></svg>
        <span class="lbl">sprite</span>
      </div>
      <div class="col orig">
        {% if font_face %}
          {% if row.cp_escape %}<i class="orig-{{ loop.index0 }}"></i>
          {% elif row.ligature %}<i class="mn-lig">{{ row.ligature }}</i>
          {% else %}<span class="note">no codepoint</span>
          {% endif %}
        {% else %}
          <span class="note">SVG font: not renderable in browsers</span>
        {% endif %}
        <span class="lbl">original font</span>
      </div>
    </div>
    <div class="id">{{ row.sprite_id }}</div>
    <div class="row"><b>cp</b> {{ row.codepoint or "—" }} · <b>class</b> {{ row.class_name or "—" }} · <b>name</b> {{ row.name_source }}</div>
    {% if row.ligature %}<div class="row"><b>ligature</b> {{ row.ligature }}</div>{% endif %}
    {% if row.warnings %}<div class="warn">{{ row.warnings | join("; ") }}</div>{% endif %}
    <div class="row" style="margin-top:.25rem">
      <code>&lt;svg class="mn-icon"&gt;&lt;use href="#{{ row.sprite_id }}"&gt;&lt;/use&gt;&lt;/svg&gt;</code>
      <button class="copy" data-snippet='&lt;svg class="mn-icon"&gt;&lt;use href="#{{ row.sprite_id }}"&gt;&lt;/use&gt;&lt;/svg&gt;'>copy</button>
    </div>
  </div>
{% endfor %}
</div>
<script>
  document.querySelectorAll('.copy').forEach(function(b){
    b.addEventListener('click', function(){
      var s = b.getAttribute('data-snippet');
      navigator.clipboard.writeText(s).then(function(){ b.textContent='copied'; setTimeout(function(){b.textContent='copy';},1000); });
    });
  });
</script>
</body>
</html>
"""


def emit_catalog(
    out_path: str,
    rows: list[dict],
    sprite_body: str,
    font_path: str | None,
    font_format: str,
    family: str,
    stats: dict,
) -> str:
    """Render the catalog HTML and write it atomically.

    ``rows`` are plain dicts (see :func:`main._catalog_rows`) with keys:
    sprite_id, view_box, codepoint, cp_escape, class_name, name_source,
    ligature, warnings.
    """
    font_face = False
    font_src = ""
    font_fmt = "truetype"
    if font_path and font_format in _FONT_FORMATS and os.path.isfile(font_path):
        try:
            with open(font_path, "rb") as fh:
                b64 = base64.b64encode(fh.read()).decode("ascii")
            fmt, mime = _FONT_FORMATS[font_format]
            font_src = f"data:{mime};base64,{b64}"
            font_fmt = fmt
            font_face = True
        except OSError:
            font_face = False

    env = Environment(autoescape=True, keep_trailing_newline=True)
    tpl = env.from_string(_TEMPLATE)
    html = tpl.render(
        rows=rows, sprite_body=sprite_body, family=family,
        font_format=font_format, stats=stats,
        font_face=font_face, font_src=font_src, font_fmt=font_fmt,
    )
    atomic_write_text(out_path, html)
    return out_path
