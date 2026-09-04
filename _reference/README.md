# Reference

Everything needed to **write** a script for this collection — the format guide
plus small working examples — in one place. Nothing here is part of the
collection itself: the leading underscore keeps this folder sorted above the
scripts and marks it as supporting material, not a script you can import.

For what the collection *is* and how to run a script from it, see the root
[`README.md`](../README.md).

## The authoring guide

[`authoring-guide.md`](authoring-guide.md) is the PyShell script-authoring
guide — what a manifest may contain, field types, bindings, argument styles,
secrets, structured events, artifacts, dependencies. It is the format's
source of truth: every script in this collection only adds conventions on
top of the spec, and never contradicts it.

## The examples

Small scripts copied from the
[PyShell](https://github.com/mono-ninja/PyShell) repo, each one demonstrating
a specific section of the guide:

| Example | Demonstrates | Guide section |
|---|---|---|
| [`hello/`](hello) | the minimal `pyshell.yaml`: three fields of three types, and how the manifest turns into the form | [The pyshell.yaml manifest](authoring-guide.md#the-pyshellyaml-manifest) |
| [`single-file.py`](single-file.py) | a PEP 723 inline manifest in `.py` comments — no `pyshell.yaml` at all | [PEP 723 inline manifest](authoring-guide.md#pep-723-inline-manifest) |
| [`no-manifest.py`](no-manifest.py) | a pure-argparse script, and PyShell's **Introspect** building a form from it | [Introspection (without a manifest)](authoring-guide.md#introspection-without-a-manifest) |
| [`progress-demo.py`](progress-demo.py) | progress done right: `status` for an unknown-size phase, one event per whole percent, phases sharing the single 0–100 bar, a summary table, an artifact | [Progress](authoring-guide.md#progress) |
| [`report-demo.py`](report-demo.py) | the other result kinds: a live throttled chart with a scrolling window, a final bar-or-line chart, and a markdown report | [Chart](authoring-guide.md#chart) · [Markdown result](authoring-guide.md#markdown-result) |

Each `.py` sits next to its own `.md` — a Docs-panel document named after the
script rather than a shared `pyshell.md`. That per-script naming is itself
part of the demo: several single-file scripts live in this one folder, and
the guide's [Operator
documentation](authoring-guide.md#operator-documentation-docs-panel) explains why a
shared `pyshell.md` would mix them up.

They are teaching demos — deliberately tiny, standard-library-only, no
network — **not** collection scripts. Don't add them to the root README's
"Available scripts" table.

## Trying one

In PyShell: **+ Folder** (⇧⌘O) for `hello/`, **+ File** (⌘O) for the single
`.py` files, then **Prepare Env** (nothing to install) and **Run** (⌘↩).

From a terminal they work too — the structured events degrade to single-line
JSON on stderr:

```bash
python3 hello/main.py --name PyShell --count 3 --uppercase
python3 single-file.py --url https://example.com --timeout 30
python3 no-manifest.py input.txt --count 5 --mode turbo
python3 progress-demo.py --items 50000        # ~95 progress events, not 50000
python3 report-demo.py --samples 500 --final-chart line
```

`progress-demo.py` writes its `report.csv` artifact into
`PYSHELL_OUTPUT_DIR` only — without that variable (i.e. in a terminal) it
skips the file and says so.

## Syncing with PyShell

Both halves come from the
[PyShell](https://github.com/mono-ninja/PyShell) app repo:

- `authoring-guide.md` — the English translation of PyShell's
  `docs/scripting.md` (Ukrainian original), with the example paths adjusted
  to this folder and one section added: **Project structure** (the folder
  conventions of this collection, absent from the upstream guide).
- the examples — verbatim copies of its `examples/` folder.

When the originals change upstream, re-copy them — and re-check the path
mentions afterwards: two of the example `.md` docs name this folder.
