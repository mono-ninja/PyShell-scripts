# Figma Export

The bridge from the design tool to the icon conveyor. The
collection's conveyor ends in a sprite; its start was always
"somehow the SVGs appear in a folder" — this is that somehow: the
**components** of a Figma file (or one frame of it) exported as
SVG, named by the sprite's own convention, ready for **Icon Audit
→ SVG Optimize → SVG Sprite Build**.

- **Token** — a Figma personal access token, through the Keychain
  (the token field stores it; standalone: `FIGMA_TOKEN` in the
  environment). Without it: an honest exit with the
  where-to-get-one line, never an imitated export.
- **Scope** — the whole file, or the frame in the URL's
  `?node-id=`; every component under the scope is collected
  (component sets walk to their variants — each state exports
  separately, named "set variant").
- **Names** — Figma's names ("icon/home", "Home Icon") slugified
  exactly the way SVG Sprite Build does it, so nothing renames
  twice; collisions get a `-2` suffix and are said aloud.
- **PNG** — optional, at 1x or 2x, for the places SVG cannot go.

The honest limit, surfaced live: Figma's **Variables API is
Enterprise-only**. The script asks; a 403 is reported as "not
checked — Enterprise-only", never as "no variables". Nodes and
published styles — what icons need — are available on every plan.

---

## Before running

1. Get a personal access token: Figma → Settings → Security →
   Personal access tokens (read-only scope is enough). Paste it
   into the token field once — PyShell stores it in the Keychain.
2. Copy the file's URL (or the frame's — with `?node-id=`).
3. **Prepare Env** — installs requests. Press **Run** (⌘↩).

## Fields

### Target

- **Figma URL** — `https://www.figma.com/design/<key>/Name`,
  optionally with `?node-id=…` to scope one frame.

### Export

- **Also export PNG** — SVG is the conveyor's currency; PNG at 1x
  or 2x is optional.
- **Per-request timeout (s)** — 5–120, default 30.

---

## Result

- **Results tab** — the exports table (component · exported as ·
  svg · png) and the report: the name normalizations, the
  collision suffixes, the variables limit note, the conveyor
  steps from here.
- **Artifacts** — `<slug>.svg` (and `.png` when chosen),
  `findings.json`, `report.md`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | exported |
| 1 | no token / nothing to export / every download failed |
| 2 | bad arguments (not a figma.com URL, no file key) |

## Related

- **Icon Audit / SVG Optimize / SVG Sprite Build** — the three
  steps this export feeds.
- **Color Palette** — the design-tokens side (colors) of the same
  handoff.
