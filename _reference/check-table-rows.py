#!/usr/bin/env python3
"""_reference/check-table-rows.py — collection guard for table events.

PyShell's Results pane renders a `table` event by mapping over each
row (`row.map((cell, j) => <td>…)`), so **every row must be an array
of cell values aligned with `columns`** — see authoring-guide.md
§Table. A dict row has no `.map`: the whole Results pane dies with
`TypeError: g.map is not a function` and the table never renders.

This script AST-scans every script's `main.py` / `src/*.py`, finds
each `{"type": "table", …}` event, traces what its `rows` expression
produces (list literals, comprehensions, appends, slices, `or`
fallbacks — resolved within the enclosing function's scope) and
fails if any table is fed dict rows.

Run from the repo root:

    python3 _reference/check-table-rows.py

Exit 0 = every table event emits array rows. Any output = offenders.
"""
from __future__ import annotations

import ast
import glob
import sys


def is_table_event(node: ast.AST) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for k, v in zip(node.keys, node.values):
        if (isinstance(k, ast.Constant) and k.value == "type"
                and isinstance(v, ast.Constant) and v.value == "table"):
            return True
    return False


def classify(expr: ast.AST) -> str:
    """What an expression produces: 'dict', 'array' or 'other'."""
    if isinstance(expr, ast.ListComp):
        return "dict" if isinstance(expr.elt, ast.Dict) else "array"
    if isinstance(expr, ast.List):
        elts = [e for e in expr.elts if not isinstance(e, ast.Starred)]
        if not elts:
            return "array"
        return "dict" if all(isinstance(e, ast.Dict) for e in elts) \
            else "array"
    if isinstance(expr, ast.Subscript):        # rows[:60]
        return classify(expr.value)
    if isinstance(expr, ast.BoolOp):           # rows or [[…]]
        kinds = {classify(v) for v in expr.values}
        if "dict" in kinds:
            return "dict"
        return "array" if kinds == {"array"} else "other"
    if (isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id in ("list", "sorted", "reversed")
            and expr.args):
        return classify(expr.args[0])
    return "other"


def table_is_dict(tree: ast.Module, table: ast.Dict) -> bool:
    # resolve names only inside the enclosing function — different
    # functions may reuse the name `rows` for unrelated lists
    scope = tree
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(sub is table for sub in ast.walk(node)):
                scope = node
                break

    assigns: dict[str, list[ast.AST]] = {}
    appends: dict[str, list[ast.AST]] = {}
    for n in ast.walk(scope):
        if (isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name)):
            assigns.setdefault(n.targets[0].id, []).append(n.value)
        elif (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "append"
                and isinstance(n.func.value, ast.Name)):
            appends.setdefault(n.func.value.id, []).append(
                n.args[0] if n.args else None)

    def trace(expr: ast.AST, seen: tuple[str, ...] = ()) -> set[str]:
        out: set[str] = set()
        if isinstance(expr, ast.Name):
            if expr.id in seen:
                return out
            for a in assigns.get(expr.id, []):
                out |= trace(a, seen + (expr.id,))
            for a in appends.get(expr.id, []):
                if a is not None:
                    out.add("dict" if isinstance(a, ast.Dict)
                            else "array")
        else:
            kind = classify(expr)
            out.add(kind)
            if kind == "other" and isinstance(expr, (ast.Call, ast.BoolOp)):
                parts = (expr.args if isinstance(expr, ast.Call)
                         else expr.values)
                for p in parts:
                    out |= trace(p, seen)
        return out

    for k, v in zip(table.keys, table.values):
        if isinstance(k, ast.Constant) and k.value == "rows":
            if "dict" in trace(v):
                return True
    return False


def main() -> int:
    offenders = []
    for path in sorted(glob.glob("*/main.py") + glob.glob("*/src/*.py")):
        folder = path.split("/")[0]
        if folder.startswith(("_", "tests", ".")):
            continue
        try:
            tree = ast.parse(open(path, encoding="utf-8").read())
        except (OSError, SyntaxError) as exc:
            offenders.append(f"{path}: unparseable ({exc})")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict) and is_table_event(node) \
                    and table_is_dict(tree, node):
                offenders.append(path)
                break

    if offenders:
        print("dict-row table events (PyShell cannot render these):")
        for o in offenders:
            print(f"  {o}")
        print("fix: rows must be arrays of cells aligned with "
              "columns — see _reference/authoring-guide.md §Table")
        return 1
    print("table events: all rows are arrays")
    return 0


if __name__ == "__main__":
    sys.exit(main())
