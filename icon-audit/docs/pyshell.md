# Icon Audit

QA of an icon set **before the sprite is built** — while fixing is
still cheap. SVG Optimize minifies whatever it finds; SVG Sprite
Build silently renames non-conventional filenames, synthesizes
missing viewBoxes, prefixes ids — and dies only on the one
collision it cannot survive. This script is the gate before both.

The checks:

- **viewBox diversity** — the 24/20/16 mix that renders as
  inconsistent sizing; no viewBox at all (the build will synthesize
  one from width/height — noted, since synthesis is a guess).
- **Naming vs the sprite's own convention** — every file whose stem
  differs from its slug will be renamed **silently** (listed as the
  rename it becomes); two stems collapsing to one slug is the
  collision the build dies on.
- **Fill vs stroke** — a set half solid, half outline reads as two
  sets on the page.
- **Stroke-width outliers** — inconsistent weights in one outline
  set.
- **Geometry duplicates** — identical path data (paint excluded
  from the hash) under different names.
- **Embedded rasters** — `<image>` or `data:image/` inside an
  "SVG": raster bloat, immune to currentColor theming.
- **The a11y shape** — icons carrying `<title>` (stripped at
  build: the description belongs at the `<use>` site), the
  `aria-hidden` reminder for use time.
- **Unused icons** — with a code folder given, every icon's symbol
  id (`icon-<slug>`) and slug is grepped against the codebase;
  never-referenced icons are named. Dead weight in the sprite is
  bytes every visitor pays for.

The conveyor this gates: **Figma Export** → **this** → **SVG
Optimize** → **SVG Sprite Build**.

---

## Before running

1. Pick the **Icon folder** — the folder the sprite would be built
   from (non-recursive, like the build itself).
2. Optionally point **Code folder** at your project for the
   unused-icons check.
3. **Prepare Env** — installs lxml. Press **Run** (⌘↩).

## Fields

### Input

- **Icon folder** — the `.svg` files (hidden files skipped, like
  the build's discover step).
- **Code folder (for the unused check)** — optional: your project
  folder. Every icon's symbol id and slug is grepped here;
  never-referenced icons are named. `.git`, `node_modules`,
  dependency dirs and non-text files are skipped by design.

---

## Result

- **Results tab** — the summary table (check · count · detail) and
  the report: every section with the named icons and the fix.
- **Artifacts** — `report.md`, `findings.json` (every icon's facts
  and every check's raw output).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the audit ran; findings are results |
| 1 | no `.svg` files in the folder |
| 2 | bad arguments (folder not found) |

## Related

- **SVG Sprite Build** — the build this audit gates; its slug
  convention is mirrored here, change it there first.
- **SVG Optimize** — the minify step after the gate.
- **Figma Export** — the fresh export worth running through this
  gate.
