# PyShell Script Authoring Guide

This document describes how to create Python scripts that PyShell recognizes, builds forms for, streams output from, and displays results.

---

## Contents

1. [Three ways to describe a script](#three-ways-to-describe-a-script)
2. [Project structure](#project-structure)
3. [The pyshell.yaml manifest](#the-pyshellyaml-manifest)
4. [PEP 723 inline manifest](#pep-723-inline-manifest)
5. [Introspection (without a manifest)](#introspection-without-a-manifest)
6. [Form field types](#form-field-types)
7. [Bindings](#bindings)
8. [Argument styles](#argument-styles)
9. [Conditional visibility (visible_if)](#conditional-visibility-visible_if)
10. [Field grouping](#field-grouping)
11. [Operator documentation (Docs panel)](#operator-documentation-docs-panel)
12. [Secrets](#secrets)
13. [Structured events](#structured-events)
    - [Why not rich, tqdm, and ANSI](#why-not-rich-tqdm-and-ansi)
    - [Progress](#progress)
    - [Table](#table)
    - [Markdown result](#markdown-result)
    - [Chart](#chart)
    - [Status](#status)
14. [Artifacts (output files)](#artifacts-output-files)
15. [Dependencies (requirements.txt)](#dependencies-requirementstxt)
16. [Environment access](#environment-access)
17. [Complete examples](#complete-examples)

---

## Three ways to describe a script

PyShell supports three ways to describe a script's parameters (in priority order):

| Method | Where | When to use |
|---|---|---|
| `pyshell.yaml` | Separate file next to the script | Many parameters, complex configuration |
| PEP 723 | Inline TOML in `.py` comments | Single file, simple scripts |
| Introspection | Automatic via `argparse`/`click`/`typer` | Quick start, prototyping |

If no manifest is present, PyShell creates a minimal schema and shows a **Guessed** badge. Click **Introspect** to automatically detect arguments.

---

## Project structure

PyShell itself does not impose a layout: `runtime.entry` and `runtime.requirements`
in `pyshell.yaml` are paths, so you can organize the folder however you like. But this
is the structure that the scripts in this repository (`curl/`, `image-converter/`)
follow — stick to it for new ones too, so all projects look consistent.

### Single file, no folder

The simplest case is a PEP 723 inline manifest or a script designed for
introspection. No folder or `pyshell.yaml` needed:

```
my-script.py
```

See [PEP 723 inline manifest](#pep-723-inline-manifest) and
[Introspection](#introspection-without-a-manifest); working examples are `_reference/single-file.py`
and `_reference/no-manifest.py`.

### Script with pyshell.yaml (recommended structure)

```
my-script/
├── pyshell.yaml           # manifest: form fields, runtime, outputs
├── main.py                 # entry point — path specified in runtime.entry
├── requirements.txt        # dependencies, if any — path in runtime.requirements
└── docs/
    ├── pyshell.md            # operator documentation, Docs panel (⌘D)
    └── pyshell_ua.md          # translation, optional (_<code> suffix)
```

`docs/pyshell.md` is optional, but this exact path takes priority over
`pyshell.md` in the root of the script's folder — see
[Operator documentation](#operator-documentation-docs-panel).

### Multi-module script

When there is more logic than fits in a single `main.py`, move it into a package
next to it and keep `main.py` a thin entry point that only parses arguments and
calls code from the package:

```
my-script/
├── pyshell.yaml
├── requirements.txt
├── main.py                 # thin entry point
├── src/
│   ├── __init__.py
│   ├── core.py
│   └── ...
└── docs/
    └── pyshell.md
```

None of the scripts in this repository need this yet — `curl/` and
`image-converter/` are still a single `main.py` each — but reach for it as soon
as one file stops being manageable rather than letting `main.py` grow past a
few hundred lines.

### Several single-script files in one folder

If a folder contains several independent `.py` files without a shared
`pyshell.yaml`, name the Docs panel document after the script (`report-demo.md`
next to `report-demo.py`) rather than a shared `pyshell.md` — otherwise it will
mix up the scripts. Example: `progress-demo.py`/`progress-demo.md` and
`report-demo.py`/`report-demo.md` in `_reference/` in this repository. File name
priorities are described in [Operator documentation](#operator-documentation-docs-panel).

---

## The pyshell.yaml manifest

Create a `pyshell.yaml` file next to the script:

```yaml
schema: 1
id: com.mycompany.my-script        # unique identifier
name: My Script                     # display name
version: 1.0
description: Script description     # optional
icon: lucide:wrench                 # vector icon or emoji, optional
category: Tools                     # optional

runtime:
  entry: main.py                    # entry point (relative to pyshell.yaml)
  python: ">=3.11,<3.14"           # Python version constraint
  requirements: requirements.txt    # dependencies file, optional
  timeout: 60                       # timeout in seconds, optional

inputs:
  - key: url
    type: url
    label: URL
    help: URL to check
    required: true
    binding:
      kind: arg
      flag: "--url"
      style: space

outputs:
  artifacts:
    - "*.csv"
    - "report.html"
  result: table                     # table | markdown | none
```

### Top-level fields

| Field | Required | Description |
|---|---|---|
| `schema` | yes | Schema version, always `1` |
| `id` | no | Unique ID; if missing — `local.<first 16 hex chars of sha256(path)>` |
| `name` | yes | Display name |
`version` | no | Script version (arbitrary string), shown in UI as `v<version>` |
| `description` | no | Description |
| `icon` | no | `lucide:<name>`, emoji, or a symbol |
| `category` | no | Category for grouping |
| `runtime` | yes | Run configuration |
| `inputs` | yes | List of form fields (may be empty) |
| `outputs` | no | Output description |

#### icon

`icon` accepts either an arbitrary emoji/symbol (`icon: 🔧`) or a vector icon in
the format `lucide:<name>`, where `<name>` is one of the identifiers listed
below (a subset of [lucide.dev/icons](https://lucide.dev/icons)):

```
activity, alert-triangle, archive, bar-chart, bell, bot, brain, bug,
calculator, calendar, camera, check, check-circle, clock, cloud,
cloud-download, cloud-upload, code, compass, copy, cpu, database,
dollar-sign, download, eye, file, file-code, file-json, file-text, filter,
flag, flask-conical, folder, folder-open, git-branch, git-commit, globe,
grid, hard-drive, hash, heart, help-circle, home, image, info, key,
layers, line-chart, link, list, lock, mail, map, map-pin, message-square,
mic, monitor, music, package, pause, pie-chart, play, printer,
refresh-cw, rocket, rotate-cw, save, search, send, server, settings,
shield, shield-check, sliders, smartphone, sparkles, square, star, table,
target, terminal, timer, trash, trending-down, trending-up, upload, user,
users, video, webhook, wifi, wrench, x-circle, zap
```

An unknown name after `lucide:` (like any value without this prefix) is shown
as plain text — same as before with emoji — so old manifests with `icon: 🔧`
keep working unchanged.

### runtime

| Field | Required | Description |
|---|---|---|
| `entry` | yes | Path to the `.py` file (relative to `pyshell.yaml`) |
| `python` | yes | Version constraint (PEP 440): `">=3.11"`, `">=3.11,<3.14"` |
| `requirements` | no | Path to `requirements.txt` |
| `timeout` | no | Timeout in seconds; `null` = no limit |

---

## PEP 723 inline manifest

For single-file scripts — a TOML block in comments at the top:

```python
#!/usr/bin/env python3
# /// script
# [tool.pyshell]
# id = "com.example.my-script"
# name = "My Script"
# python = ">=3.11"
#
# [[tool.pyshell.inputs]]
# key = "url"
# type = "url"
# label = "URL"
# required = true
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--url"
# style = "space"
#
# [[tool.pyshell.inputs]]
# key = "count"
# type = "int"
# label = "Count"
# default = 10
# min = 1
# max = 100
# [tool.pyshell.inputs.binding]
# kind = "arg"
# flag = "--count"
# style = "space"
# ///

import argparse
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--count", type=int, default=10)
    args = parser.parse_args()
    print(f"URL: {args.url}, Count: {args.count}")

if __name__ == "__main__":
    main()
```

**PEP 723 rules:**
- Start: `# /// script` (exactly this)
- End: `# ///`
- Every line starts with `# ` (hash + space); a blank line may be written
  as just `#`, without the space
- TOML syntax, section `[tool.pyshell]`

---

## Introspection (without a manifest)

If a script has no manifest, PyShell can automatically detect its arguments by monkey-patching `argparse`/`click`/`typer`.

**What is detected:**
- Flags (`--flag`)
- Types (`str`, `int`, `float`, `bool`, `choices`)
- Default values
- Help text
- Positional arguments

**Limitations:**
- Runs arbitrary code from the module (gated behind a consent dialog)
- 10-second timeout
- `os.fork`, `subprocess.Popen`, `time.sleep` are blocked (so scripts with infinite loops don't hang)
- `PYSHELL_INTROSPECT=1` is passed in the env

**What a script needs for introspection:**

```python
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", type=str, default="World", help="Name to greet")
    parser.add_argument("--count", type=int, default=1, help="Number of greetings")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--mode", choices=["fast", "slow"], default="fast")
    args = parser.parse_args()
    # ...

if __name__ == "__main__":
    main()
```

After introspection you can save the result as `pyshell.yaml` with the **Save Manifest** button.

---

## Form field types

| `type` | YAML | Description | Extra fields |
|---|---|---|---|
| `string` | `type: string` | Text string | `pattern` (regex), `max_len` |
| `multiline` | `type: multiline` | Multi-line text | — |
| `int` | `type: int` | Integer | `min`, `max` |
| `float` | `type: float` | Floating-point number | `min`, `max` |
| `bool` | `type: bool` | Yes/no (checkbox) | — |
| `choice` | `type: choice` | Dropdown list | `options: [{value: a, label: A}]` |
| `multi_choice` | `type: multi_choice` | Multiple choice | `options: [...]` |
| `file` | `type: file` | File picker | `extensions: [csv, json]` |
| `files` | `type: files` | Multiple file picker | `extensions: [...]` |
| `dir` | `type: dir` | Directory picker | — |
| `save_path` | `type: save_path` | Save path | `default_name: output.txt` |
| `secret` | `type: secret` | Password (Keychain) | — |
| `date` | `type: date` | Date | — |
| `url` | `type: url` | URL address | — |

### Examples

```yaml
inputs:
  # Text field with validation
  - key: username
    type: string
    label: Username
    pattern: "^[a-zA-Z0-9_]+$"
    max_len: 50
    required: true
    binding: {kind: arg, flag: "--username", style: space}

  # Integer with constraints
  - key: retries
    type: int
    label: Retries
    min: 0
    max: 10
    default: 3
    binding: {kind: arg, flag: "--retries", style: space}

  # Dropdown list
  - key: format
    type: choice
    label: Output Format
    options:
      - value: json
        label: JSON
      - value: csv
        label: CSV
      - value: xml
        label: XML
    default: json
    binding: {kind: arg, flag: "--format", style: space}

  # Multiple choice
  - key: tags
    type: multi_choice
    label: Tags
    options:
      - {value: alpha}
      - {value: beta}
      - {value: gamma}
    binding: {kind: arg, flag: "--tag", style: repeat}

  # File with extension filter
  - key: input_file
    type: file
    label: Input File
    extensions: [csv, tsv]
    required: true
    binding: {kind: arg, flag: "--input", style: space}

  # Password (stored in Keychain)
  - key: api_key
    type: secret
    label: API Key
    required: true
    binding: {kind: env, name: API_KEY}
```

---

## Bindings

A binding defines how a field's value is passed to the script:

| `kind` | Description | Example |
|---|---|---|
| `arg` | Command-line argument | `--url https://example.com` |
| `env` | Environment variable | `API_KEY=secret` |
| `positional` | Positional argument | `script.py input.csv` |
| `stdin` | Standard input (text) | `echo "data" \| script.py` |
| `temp_file` | Written to a temp file, path is passed | `--data /tmp/xxx.tmp` |

### Examples

```yaml
# Argument
- key: url
  type: url
  binding:
    kind: arg
    flag: "--url"
    style: space

# Environment variable
- key: api_key
  type: secret
  binding:
    kind: env
    name: API_KEY

# Positional argument (order via index)
- key: input_file
  type: file
  binding:
    kind: positional
    index: 0

- key: output_file
  type: save_path
  binding:
    kind: positional
    index: 1

# Standard input
- key: data
  type: multiline
  binding:
    kind: stdin

# Temp file (for large data)
- key: config
  type: multiline
  binding:
    kind: temp_file
    flag: "--config"
```

### What this looks like at runtime

| Binding | What PyShell passes |
|---|---|
| `arg` + `space` | `script.py --url https://example.com` |
| `arg` + `equals` | `script.py --url=https://example.com` |
| `arg` + `flag` | `script.py --verbose` (only when `true`) |
| `env` | `API_KEY=secret script.py` |
| `positional` | `script.py input.csv output.csv` |
| `stdin` | `echo "data" \| script.py` |
| `temp_file` | `script.py --config /tmp/pyshell_abc123.tmp` |

---

## Argument styles

For `binding.kind: arg`:

| `style` | Example | When to use |
|---|---|---|
| `space` | `--url https://example.com` | Standard style |
| `equals` | `--url=https://example.com` | Script requires `=` |
| `flag` | `--verbose` | For `bool` (only when `true`) |
| `repeat` | `--tag a --tag b` | For `multi_choice` |
| `joined` | `--tags a,b` | For `multi_choice` with a separator |

```yaml
# Repeat (each value as a separate flag)
- key: tags
  type: multi_choice
  options: [{value: a}, {value: b}, {value: c}]
  binding:
    kind: arg
    flag: "--tag"
    style: repeat
# → python script.py --tag a --tag b

# Joined (values with a separator)
- key: tags
  type: multi_choice
  options: [{value: a}, {value: b}, {value: c}]
  binding:
    kind: arg
    flag: "--tags"
    style: joined
    sep: ","
# → python script.py --tags a,b
```

---

## Conditional visibility (visible_if)

Fields can appear depending on the values of other fields:

```yaml
inputs:
  - key: mode
    type: choice
    label: Mode
    options:
      - {value: simple}
      - {value: advanced}
    default: simple
    binding: {kind: arg, flag: "--mode", style: space}

  # Visible only when mode = advanced
  - key: batch_size
    type: int
    label: Batch Size
    min: 1
    max: 1000
    default: 100
    visible_if:
      op: eq
      key: mode
      value: advanced
    binding: {kind: arg, flag: "--batch-size", style: space}

  # Visible only when mode != simple
  - key: verbose
    type: bool
    label: Verbose
    visible_if:
      op: ne
      key: mode
      value: simple
    binding: {kind: arg, flag: "--verbose", style: flag}

  # Visible when the field is non-empty / true
  - key: debug_level
    type: int
    label: Debug Level
    visible_if:
      op: truthy
      key: verbose
    binding: {kind: arg, flag: "--debug", style: space}
```

**Operators:**
- `eq` — equals (string, number, bool)
- `ne` — not equals
- `truthy` — non-empty / true / non-zero

---

## Field grouping

Fields can be grouped into (collapsible) sections:

```yaml
inputs:
  - key: url
    type: url
    label: URL
    group: Connection
    binding: {kind: arg, flag: "--url", style: space}

  - key: timeout
    type: int
    label: Timeout
    group: Connection
    default: 30
    binding: {kind: arg, flag: "--timeout", style: space}

  - key: format
    type: choice
    label: Format
    group: Output
    options: [{value: json}, {value: csv}]
    binding: {kind: arg, flag: "--format", style: space}

  - key: output_file
    type: save_path
    label: Output File
    group: Output
    binding: {kind: arg, flag: "--output", style: space}
```

Fields without a `group` are shown in the main section.

---

## Operator documentation (Docs panel)

If a document sits next to the script, PyShell shows a **Docs** button (⌘D) and
renders it in a side panel. This is what the person about to run the script
reads: what it does, what the fields mean, what the consequences will be.

**Where it is looked up.** First — in the **`docs/`** subfolder next to the
script; if there is no document there, PyShell falls back to the script's own
folder (the old layout, still supported). That is, `docs/pyshell.md` overrides
`pyshell.md` in the project root.

**Languages.** Next to the base file you can place translations with a `_<code>`
suffix: `pyshell.md` + `pyshell_ua.md` + `pyshell_de.md`. If there is more than
one variant, the panel shows a language switcher; the file without a suffix is
the one opened by default. The language code is not checked against a list of
locales — `ua`, `uk`, or `pt-br` all work. Only variants of **one and the same**
priority level count as translations: `README.md` will never appear in the
switcher alongside `pyshell.md`, because it is a different document, not a
different language.

The file is looked up in the script's folder, and the most specific one wins:

| File | Priority |
|---|---|
| `<script name>.md` — e.g. `report-demo.md` next to `report-demo.py` | 1 — taken first |
| `pyshell.md` (or `pyshell.markdown`) | 2 |
| `README.md` / `README.markdown` | 3 |
| `README.txt` | 4 |
| `README` without extension | 5 |

Case does not matter: `PyShell.MD` works too.

The first row matters when **several single-script files live in one folder**:
`pyshell.md` there would be shared by all of them, whereas a document named
after the script belongs to it alone. That is how it is done in `_reference/`,
where `progress-demo.py` and `report-demo.py` sit next to their own
`progress-demo.md` and `report-demo.md`. For a folder that *is* the project
(like `curl/` or `image-converter/` in this repository), `pyshell.md` is more
natural.

**Why a separate file and not just README.** A README is written for someone
cloning the repository: installation, license, development. The Docs panel is
read by a different person — one already looking at the form and wanting to
know what to enter in the `--depth` field and whether it will wipe prod. These
are different documents for different audiences. `pyshell.md` gives a place
for the second without spoiling the first, and it sits next to `pyshell.yaml`,
so its purpose is clear from the file listing alone. If there is none, the
README is shown, so for a simple script there is nothing extra to do.

The file is not stored in the schema: it is read every time a script is
selected, so edits are visible immediately, without re-importing.

### What can be written

A CommonMark subset: headings, paragraphs, lists, fenced and indented code
blocks, blockquotes, horizontal rules, tables with `|`, and inline `code`,
**bold**, *italic*, and links.

Limitations worth knowing in advance:

- **HTML is not rendered** — tags are escaped and shown as text. The document
  is written by the script's author, while the panel lives in a webview that
  has access to application commands, so no "raw" HTML can be allowed here.
- **Links open in the system browser**, and only the `http`, `https`, and
  `mailto` schemes. A relative link (`./docs/usage.md`) remains plain text —
  there is nowhere to navigate inside the panel.
- **Images are not shown.**
- **Table alignment** (`---:`) is parsed but ignored.
- **Nested lists** are flattened to a single level.
- The size limit is **512 KB**; a larger file yields an error instead of the panel.

### Example

```markdown
# NinjaScan

Passive audit of a WordPress site. Changes nothing on the target, read-only.

## Before running

- **Target URL** — the full address with `https://`. Only this host is checked,
  without going to subdomains.
- **Depth** — how many pages to crawl. 50 is enough for a typical blog;
  beyond 500 the scan will take tens of minutes.
- **API token** — needed only for CVE checks; without it those 6 checks
  are skipped, the other 80 work.

## Result

A findings table in the Results tab and `report.sarif` in the artifacts tab.
A non-zero exit code means the scan failed, not that problems were found —
findings are always in the table.
```

---

## Secrets

For passwords, API keys, etc., use `type: secret` with `binding: env`:

```yaml
- key: api_key
  type: secret
  label: API Key
  required: true
  binding:
    kind: env
    name: API_KEY
```

**How it works:**
1. The value is stored in macOS Keychain / Windows Credential Manager
2. It is never returned to the frontend
3. It is not written to `state.json` or logs
4. It is passed via an environment variable **(not via argv)** — `ps aux` does not show env to other processes on macOS
5. In the script it is available as `os.environ["API_KEY"]`

```python
import os

api_key = os.environ.get("API_KEY")
if not api_key:
    print("API_KEY not set", file=sys.stderr)
    sys.exit(1)
```

---

## Structured events

PyShell parses JSON strings from **stderr** and renders them as native UI elements: a progress bar, a table, a status line. This is the standard way to show progress — and a replacement for `rich`/`tqdm`, which do not work here (see below).

**Important:** a JSON event must contain the field `"pyshell": true` — otherwise the line is treated as a regular log. This prevents the loss of lines that a script logs as JSON to stderr (e.g. `{"error": "..."}`).

```python
import json, sys

def emit(event):
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)
```

The examples below use this `emit`.

---

### Why not rich, tqdm, and ANSI

PyShell runs the script through **pipes, not a PTY** (this is a fixed decision for v1). The consequences are concrete:

| What the library does | What happens in PyShell |
|---|---|
| ANSI colors, bold, italic | Escape sequences are **stripped** from the line. No color, but no garbage either. |
| Redrawing the line via `\r` (`tqdm` progress bars) | Output is split **only on `\n`**. A bar without a newline accumulates into one huge line and appears only when the script finishes — i.e. you will see no progress at all. |
| Spinners, `Live`, `Progress` from `rich` | Same thing: either one bloated line, or thousands of nearly identical lines in the log. |
| `rich` frames, tables, panels | They will be drawn with characters, but the alignment falls apart, because this is not a fixed-width terminal. |

Most of these libraries detect on their own that they are not printing to a terminal (`sys.stderr.isatty()` → `False`) and switch to a flat mode. But not all, and not always — so it is more reliable to disable them explicitly.

To detect "I am running under PyShell", use the environment variable **`PYSHELL_OUTPUT_DIR`** — PyShell always sets it:

```python
import os, sys

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ
PLAIN = UNDER_PYSHELL or not sys.stderr.isatty()
```

How to silence specific libraries:

```python
# tqdm — disable animation, keep the logic
from tqdm import tqdm
for item in tqdm(items, disable=PLAIN):
    ...

# rich — no color and no animation
from rich.console import Console
console = Console(no_color=PLAIN, force_terminal=False, highlight=False)

# rich.progress — do not use Live/Progress under PyShell,
# replace with emit({"type": "progress", ...})

# click / colorama
import click
click.echo(click.style("text", fg="green"), color=not PLAIN)
```

If a library still draws a bar, it is better to remove it from that code path and emit `progress` events instead.

---

### Progress

```python
emit({
    "type": "progress",
    "pct": 42.5,                    # 0–100
    "message": "Scanning plugins",  # optional
})
```

**`pct` is a percentage 0–100, not a fraction 0–1.** If you send `0.42`, the bar will be stuck near zero.

**The event replaces the previous one, it does not accumulate.** The UI keeps only the last progress state, so send them frequently — that is normal, no history is built up.

#### Rate-limit yourself

Every structured event flies to the UI as **a separate IPC message, with no batching** (plain log lines, on the contrary, are grouped in ~50 ms chunks). Moreover, structured events **count toward the same output limit** as regular logs (50 MB / 500k lines per run). If you emit an event for every item in a 10-million-iteration loop, they will exhaust the limit — PyShell will start dropping the middle of the output, keeping the head and the tail.

So emit an event only when something visible to a human has changed:

```python
def progress_reporter(total):
    """Emits progress no more often than once per whole percent."""
    last = -1

    def report(done, message=""):
        nonlocal last
        pct = int(done * 100 / total) if total else 0
        if pct != last:
            last = pct
            emit({"type": "progress", "pct": pct, "message": message})

    return report

report = progress_reporter(len(urls))
for i, url in enumerate(urls, 1):
    check(url)
    report(i, f"{i}/{len(urls)} · {url}")
```

For very fast loops it is more reliable to rate-limit by time:

```python
import time

last_sent = 0.0

def report(done, total, message=""):
    global last_sent
    now = time.monotonic()
    # Always pass the first and last frame, the rest — no more than 10/s
    if done in (0, total) or now - last_sent >= 0.1:
        last_sent = now
        emit({"type": "progress", "pct": done * 100 / total, "message": message})
```

#### Multiple phases

There is one progress bar. If a script has several phases, map them onto a single 0–100 scale and put the phase name into `message`:

```python
PHASES = [("Resolving DNS", 0, 15),
          ("Fetching pages", 15, 70),
          ("Analyzing", 70, 100)]

def phase_progress(name, lo, hi):
    def report(done, total):
        pct = lo + (hi - lo) * (done / total if total else 1)
        emit({"type": "progress", "pct": pct, "message": name})
    return report

for name, lo, hi in PHASES:
    report = phase_progress(name, lo, hi)
    ...
```

#### When the total is unknown

Do not invent a fake percentage — it will go backwards and look like a bug. Use `status` for indeterminate progress and switch to `progress` once the total becomes known:

```python
emit({"type": "status", "message": "Enumerating subdomains…"})
found = enumerate_subdomains()          # how many there will be is unknown upfront
emit({"type": "status", "message": f"Found {len(found)} subdomains"})

report = progress_reporter(len(found))  # now progress is determinate
for i, host in enumerate(found, 1):
    scan(host)
    report(i, host)
```

#### Working example

Everything above is assembled in `_reference/progress-demo.py` — you can import and run it. At the end it prints how many events were sent over how many iterations: 2000 (and 50,000 too) iterations yield ~95 events.

#### Finish at 100

The bar does not reset itself upon completion. Send `100` as the last frame, otherwise a successful run will be left with the bar at 97%:

```python
emit({"type": "progress", "pct": 100, "message": "Done"})
```

---

### Table

```python
emit({
    "type": "table",
    "columns": ["URL", "Status", "Time (ms)"],
    "rows": [
        ["https://example.com", "OK", "123"],
        ["https://fail.com", "Error", "5000"],
    ],
})
```

**The table is also replaced wholesale.** Do not send it row by row in a loop — only the last row will be shown. Accumulate results in a list and send the table once at the end (or re-send the full list if a live update is needed).

```python
rows = []
for url in urls:
    rows.append([url, check(url)])
emit({"type": "table", "columns": ["URL", "Status"], "rows": rows})
```

It is better to convert cell values to strings yourself: anything that is not a string or a number is shown as JSON.

---

### Markdown result

Shows formatted markdown in the Results tab. Replaced wholesale on every event.

```python
emit({
    "type": "markdown",
    "content": "## Scan complete\n\nFound **3** vulnerabilities:\n\n- CVE-2024-1234\n- CVE-2024-5678\n- CVE-2024-9012",
})
```

A CommonMark subset is supported: headings, lists, code blocks, tables, links, **bold**, *italic*. There are no HTML tags — all text is escaped. Table alignment (`---:`) is parsed but ignored, and nested lists are flattened to a single level. A working example is `_reference/report-demo.py`.

```python
# Collecting results into markdown
lines = ["## Results\n"]
for url, status in results:
    icon = "✅" if status == 200 else "❌"
    lines.append(f"- {icon} `{url}` — {status}")
emit({"type": "markdown", "content": "\n".join(lines)})
```

---

### Chart

Shows an SVG chart in the Results tab. Supports line and bar charts.

```python
emit({
    "type": "chart",
    "chart_type": "line",  # "line" | "bar"
    "title": "Response time by endpoint",
    "labels": ["/", "/api", "/login", "/search"],
    "series": [
        {"name": "p50", "values": [12, 45, 80, 120]},
        {"name": "p99", "values": [50, 180, 350, 600]},
    ],
})
```

- `labels` — labels along the X axis (shared by all series)
- `series` — an array of `{name, values}` objects; `values[i]` corresponds to `labels[i]`
- The palette has 10 colors and cycles: the 11th series is drawn in the first color
- The chart is **replaced wholesale** on every event — do not send it point by point in a loop
- For real-time updates, send the full chart with the new data (but no more than once per second)
- X-axis labels are thinned out automatically to avoid overlap — but all points are drawn, so for a long timeline still send a window of the last N (see `_reference/report-demo.py`)

```python
# Multi-phase chart with updates
import time

phases = ["Phase 1", "Phase 2", "Phase 3"]
for phase_idx, phase in enumerate(phases):
    values = []
    for step in range(10):
        values.append(measure(step))
        # Re-send the full chart at every step
        emit({
            "type": "chart",
            "chart_type": "line",
            "title": f"{phase} — step {step}/10",
            "labels": [f"step {i}" for i in range(step + 1)],
            "series": [{"name": phase, "values": values}],
        })
        time.sleep(0.5)
```

---

### Status

One line below the progress. Also replaced.

```python
emit({"type": "status", "message": "Connecting to database…"})
# ... later ...
emit({"type": "status", "message": "Connected"})
```

---

### Full example

```python
#!/usr/bin/env python3
"""Script with structured events."""
import json
import os
import sys
import time

UNDER_PYSHELL = "PYSHELL_OUTPUT_DIR" in os.environ


def emit(event):
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def main():
    items = [f"item-{i}" for i in range(1, 51)]

    print(f"Checking {len(items)} items…", flush=True)
    emit({"type": "status", "message": "Initializing"})

    rows = []
    last_pct = -1

    for i, name in enumerate(items, 1):
        time.sleep(0.02)

        pct = int(i * 100 / len(items))
        if pct != last_pct:                     # no more than once per percent
            last_pct = pct
            emit({"type": "progress", "pct": pct, "message": f"{i}/{len(items)} · {name}"})

        rows.append([name, "OK" if i % 3 else "SKIP"])

    # Table — once, with the full contents
    emit({"type": "table", "columns": ["Item", "Status"], "rows": rows})
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit({"type": "status", "message": f"Checked {len(rows)} items"})

    print("Finished", flush=True)


if __name__ == "__main__":
    main()
```

---

### Rules

- JSON events go to **stderr**, regular output to stdout (`print()` → LogView)
- The field `"pyshell": true` is mandatory
- **One event — one line.** `json.dumps(..., indent=2)` will break parsing: multi-line JSON falls apart into separate log lines
- `flush=True` is mandatory (PyShell additionally sets `PYTHONUNBUFFERED=1`, but do not rely on that alone)
- `pct` — 0–100
- `progress`, `table`, `markdown`, `chart`, and `status` **replace** the previous value, they do not accumulate
- An unknown `type` is silently ignored — if nothing appeared, check the spelling
- Rate-limit event frequency: they are not batched and count toward the output limit
- Do not use `rich`/`tqdm` for progress — pipes, not a PTY

---

## Artifacts (output files)

Artifacts are files the script creates and PyShell shows as cards with **Show** and **Save** buttons:

```yaml
outputs:
  artifacts:
    - "*.csv"           # glob pattern
    - "report.html"
    - "output/*.json"
  result: table         # table | markdown | none
```

Files are looked up in `PYSHELL_OUTPUT_DIR` (see below).

```python
import os

output_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
with open(os.path.join(output_dir, "results.csv"), "w") as f:
    f.write("name,value\n")
    f.write("alpha,1\n")
```

---

## Dependencies (requirements.txt)

Create a `requirements.txt` next to the script:

```
requests>=2.28
beautifulsoup4>=4.12
rich>=13.0
```

Specify the path in the manifest:

```yaml
runtime:
  entry: main.py
  python: ">=3.11"
  requirements: requirements.txt
```

**Installation:**
1. Click **Prepare Env**
2. PyShell shows the dependency list and asks for confirmation
3. Installs via `uv pip install -r requirements.txt` (with sdist fallback support)
4. Each script gets an isolated venv

When `requirements.txt` changes, the environment is only marked stale (Stale) —
it is **not** rebuilt on its own. Running a script with a stale environment
fails with an "environment not ready" error; click **Prepare Env** again to
reinstall the dependencies.

### Dependencies on other scripts (`needs`)

A script can depend not on a Python package but on **another PyShell
script**. Four variants of that dependency:

| Variant | What it is | How PyShell supports it |
|---|---|---|
| **Data (pipeline)** | Script B reads script A's artifacts — the user runs A, then B with a `dir`/`files` field pointing at A's output | Nothing extra: a form field + `PYSHELL_OUTPUT_DIR` in A |
| **Invocation (subprocess)** | B runs A's entry point as a child process | The path to A's folder arrives in `PYSHELL_DEPS` |
| **Code (import)** | B imports a module from A's folder (`sys.path` + PYSHELL_DEPS) | The path is in `PYSHELL_DEPS`; but A's Python dependencies must be duplicated into B's `requirements.txt` — each script has its own venv |
| **Soft synergy** | A improves B's work but isn't required | Text in `pyshell.md` only |

The dependency is **declared** in the manifest — by the other script's id:

```yaml
schema: 1
id: com.pyshell.pageseoaudit
name: Page SEO Audit
needs:
  - com.pyshell.sitecrawler   # the id from that script's pyshell.yaml
```

What follows from it:

- The script's **header** shows a yellow `Needs: …` pill when a
  depended-on script is missing from the list (satisfied dependencies
  are not shown — that would be noise).
- The **Store** pulls missing dependencies as a chain on install
  (recursively, cycle-safe). Installed ones are not updated — updating
  is a separate action.
- **At run time** PyShell passes the installed dependencies via the
  `PYSHELL_DEPS` environment variable — a JSON map
  `{"<id>": "<folder path>"}`:

```python
import json, os, subprocess, sys

deps = json.loads(os.environ.get("PYSHELL_DEPS", "{}"))
crawler = deps.get("com.pyshell.sitecrawler")

if crawler:
    # the "invocation" variant: a child process
    subprocess.run([sys.executable, f"{crawler}/main.py", "--url", url], check=True)
    # the "code" variant: import from the dependency's folder
    # sys.path.insert(0, crawler) — and don't forget its dependencies
    # in your own requirements.txt
```

`needs` is an **expectation, not a block**: the run is not forbidden
when a dependency is missing (the script can handle that itself, as in
the example above). A missing id simply never appears in
`PYSHELL_DEPS`.

**For humans**, the chain is described in `pyshell.md` — in a
`## Dependencies` section:

```markdown
## Dependencies

Requires **Site Crawler** (`com.pyshell.sitecrawler`):

1. Run Site Crawler on the domain — it saves `urls.csv` to its artifacts
2. Point this script's "URL list" field at that file

Without Site Crawler, the script accepts its own URL list in the "URL
list (manual)" field.
```

The manifest is for the machine (ids that can be verified and
installed); `pyshell.md` is for the operator (what to run first, and
why). Keep the two in agreement.

---

## Environment access

PyShell passes the following environment variables to the script:

| Variable | Value |
|---|---|
| `PYSHELL_OUTPUT_DIR` | Directory for writing artifacts |
| `PYSHELL_INTROSPECT` | `1` during introspection (can be checked) |
| `<env binding>` | Values from `binding: {kind: env, name: ...}` |
| `<secret binding>` | Secrets from Keychain |

```python
import os

# Where to write output files
output_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")

# A script can skip dangerous actions during introspection
if os.environ.get("PYSHELL_INTROSPECT") == "1":
    print("Introspection mode, skipping real work")
    sys.exit(0)

# Secrets
api_key = os.environ.get("API_KEY")
```

---

## Complete examples

### Minimal script (no manifest)

```python
#!/usr/bin/env python3
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--name", default="World")
args = parser.parse_args()
print(f"Hello, {args.name}!")
```

Import via **+ File** → **Introspect** → the form appears automatically.

### Script with pyshell.yaml

Structure:
```
my-script/
├── pyshell.yaml
├── main.py
└── requirements.txt
```

`pyshell.yaml`:
```yaml
schema: 1
id: com.example.scraper
name: Web Scraper
icon: 🕷
category: Tools

runtime:
  entry: main.py
  python: ">=3.11"
  requirements: requirements.txt
  timeout: 120

inputs:
  - key: url
    type: url
    label: Target URL
    required: true
    group: Connection
    binding: {kind: arg, flag: "--url", style: space}

  - key: depth
    type: int
    label: Crawl Depth
    min: 1
    max: 10
    default: 2
    group: Connection
    binding: {kind: arg, flag: "--depth", style: space}

  - key: format
    type: choice
    label: Output Format
    options:
      - {value: json, label: JSON}
      - {value: csv, label: CSV}
    default: json
    group: Output
    binding: {kind: arg, flag: "--format", style: space}

  - key: verbose
    type: bool
    label: Verbose
    default: false
    visible_if:
      op: eq
      key: format
      value: json
    binding: {kind: arg, flag: "--verbose", style: flag}

  - key: api_key
    type: secret
    label: API Key
    group: Auth
    binding: {kind: env, name: API_KEY}

outputs:
  artifacts:
    - "results.json"
    - "results.csv"
  result: table
```

`main.py`:
```python
#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time

def emit(event):
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--format", default="json")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    api_key = os.environ.get("API_KEY", "")
    print(f"Scraping {args.url} (depth={args.depth})", flush=True)
    emit({"type": "status", "message": f"API key: {'✓' if api_key else '✗'}"})

    pages = []
    total = args.depth * 5
    for i in range(total):
        time.sleep(0.1)
        emit({"type": "progress", "pct": ((i+1)/total)*100, "message": f"Page {i+1}/{total}"})
        pages.append([f"page-{i+1}", f"https://example.com/{i+1}", "200 OK"])

    emit({
        "type": "table",
        "columns": ["Page", "URL", "Status"],
        "rows": pages,
    })

    output_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    results = {"url": args.url, "pages": len(pages)}

    with open(os.path.join(output_dir, "results.json"), "w") as f:
        json.dump(results, f, indent=2)

    with open(os.path.join(output_dir, "results.csv"), "w") as f:
        f.write("page,url,status\n")
        for p in pages:
            f.write(",".join(p) + "\n")

    emit({"type": "status", "message": f"Done: {len(pages)} pages"})
    print("Finished!", flush=True)

if __name__ == "__main__":
    main()
```

`requirements.txt`:
```
requests>=2.28
beautifulsoup4>=4.12
```

Import via **+ Folder** → select the `my-script/` folder.
