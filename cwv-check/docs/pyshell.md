# CWV Check

What real Chrome users experience — the **field** side of the perf
line: LCP / INP / CLS **p75 per form factor** (phone and desktop
separately, against the official bands), the **URL-or-origin
fallback** said aloud (thin pages have no record; origin numbers
are site-wide), the **25-week trend** (line chart), and the
**lab-vs-field headline** — the divergence between this report and
the lab tools (Server Timing, HAR Analyze) is the actionable
conclusion.

The lab tools say *what* is slow; this says *whether the field
sees it*.

---

## Before running

1. Enter the **URL** — a page for page-level data; a site root
   reads the origin record either way.
2. Set the **CrUX API key** — free: Google Cloud Console → enable
   the *Chrome UX Report API* → Credentials → Create API key. Via
   `CRUX_API_KEY` (the Keychain in PyShell); without it the script
   exits with instructions, never an imitated number.
3. **Prepare Env** — installs `requests`. Press **Run** (⌘↩).

## Fields

### Target

- **URL** — the page or origin to look up.

### Feed

- **CrUX API key** — the free Google key (env secret).
- **Per-request timeout (s)** — 5–60, default 30.

---

## Result

- **Results tab** — the table (form factor · metric · p75 ·
  assessment: 🟢 good ≤ LCP 2.5 s / INP 200 ms / CLS 0.10, 🟠
  needs improvement, 🔴 poor), the 25-week p75 trend (line chart),
  and the report:
  - **The data level** — page or origin, in the header; the
    origin fallback carries its note ("site-wide, not this
    page's").
  - **The lab-vs-field headline** — field red + lab green = the
    lab missed the visitors' conditions; field green + lab red =
    trust the field for ranking, the lab for diagnosing.
  - The history absence is a note ("not guessed"), never a flat
    line.
- **Artifacts** — `report.md`, `findings.json` (per-form-factor
  p75s and the history, machine-readable).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; the report is the field picture |
| 1 | no API key, or no CrUX data for the URL nor the origin |
| 2 | bad arguments: no http(s) URL |

## Related

- **Server Timing / HAR Analyze / Cache Check** — the lab side:
  what is slow and why.
- **Load Test** — degradation under load.
- **SEO Checks** — the whole-site pass.
