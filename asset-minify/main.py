#!/usr/bin/env python3
"""asset-minify/main.py — minify CSS and JS, stdlib first.

Two engines, one contract:

- **built-in** (pure stdlib, always available): a scanner-based CSS
  minifier and a token-based JS minifier. No npm, no network, no
  dependencies — the script runs anywhere Python does.
- **system** ([terser](https://terser.org) for JS,
  [clean-css-cli](https://github.com/clean-css/clean-css-cli) for CSS):
  used when the binaries are on PATH, because they compress harder —
  terser mangles names and drops dead code, which a safe stripper
  cannot.

`--engine auto` (the default) picks the system binary per kind when it
exists and falls back to the built-in one when it doesn't: a missing
binary is no longer a dead end, only a weaker result. `--engine
builtin` never shells out; `--engine system` demands the binaries and
exits 1 with the exact `npm install -g …` line if they are absent.

Contracts, inherited from the collection:

- **The originals are never touched** — results land in the output
  folder as `<stem>.min.css` / `<stem>.min.js`.
- **A file that won't shrink isn't written**: when the minified
  candidate comes out bigger or equal (an already-minified source),
  the row is marked `already minimal` and no `.min` file is produced —
  a byte-identical copy would be a lie.
- `*.min.css` / `*.min.js` inputs are skipped (minifying the minified
  is churn), and files already present in the output are skipped
  unless **Overwrite** is on.

Exit codes: 0 = the batch ran (skips and no-savings rows are
results), 1 = missing prerequisite binary under `--engine system` /
unusable output folder / every file failed, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

# The system binaries the wrapper can drive. Keys match --only values.
REQUIRED_BINARIES = {
    "css": ["cleancss"],
    "js": ["terser"],
}
BUILTIN = "built-in"  # the engine name reported for the pure-Python path

# A GUI host (PyShell included) starts with a minimal PATH that misses
# the npm global bin — the binary is installed and shutil.which still
# says no. These are the usual places to look before believing it.
EXTRA_BIN_DIRS = (
    "/opt/homebrew/bin",                       # Homebrew on Apple silicon
    "/usr/local/bin",                          # Homebrew on Intel, plain npm
    os.path.expanduser("~/.npm-global/bin"),
    os.path.expanduser("~/.volta/bin"),
    os.path.expanduser("~/.local/bin"),
)


# ---------------------------------------------------------------------------
# Structured-event plumbing
# ---------------------------------------------------------------------------

def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.0f} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Result:
    source: str            # path as given
    rel: str               # output-relative name
    kind: str              # css | js
    status: str            # minified | already minimal | skipped | error
    original_bytes: int = 0
    output_bytes: int = 0
    engine: str = ""       # built-in | terser | cleancss | —
    note: str = ""


# ---------------------------------------------------------------------------
# Engine selection (the curl-precedent check, now a preference not a demand)
# ---------------------------------------------------------------------------

def which(binary: str) -> str | None:
    """`shutil.which`, then the usual npm bin folders — a run launched
    from an app menu must not conclude that terser is missing when it
    is sitting in /opt/homebrew/bin."""
    found = shutil.which(binary)
    if found:
        return found
    prefix = os.environ.get("NPM_CONFIG_PREFIX")
    folders = EXTRA_BIN_DIRS
    if prefix:
        folders += (os.path.join(prefix, "bin"),)
    for folder in folders:
        candidate = os.path.join(folder, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def resolve_engine(kind: str, choice: str) -> str:
    """The engine name for this kind: BUILTIN or the system binary.
    `auto` prefers the binary when it is installed — it compresses
    harder — and falls back to the built-in minifier when it is not."""
    binary = REQUIRED_BINARIES[kind][0]
    if choice == "builtin":
        return BUILTIN
    if choice == "system":
        return binary
    return binary if which(binary) else BUILTIN


def missing_binaries(only: str) -> list[str]:
    """The system binaries `--engine system` needs and doesn't have.
    Per-kind: a CSS-only run doesn't demand terser. Used by tests;
    main() rechecks against the kinds actually collected."""
    needed: list[str] = []
    kinds = ["css", "js"] if only == "both" else [only]
    for kind in kinds:
        needed += REQUIRED_BINARIES[kind]
    return [b for b in dict.fromkeys(needed) if which(b) is None]


def install_hint(missing: list[str]) -> str:
    return ("npm install -g "
            + " ".join({"cleancss": "clean-css-cli"}.get(b, b)
                       for b in missing))


# ---------------------------------------------------------------------------
# Input collection (pure)
# ---------------------------------------------------------------------------

def is_minified(name: str) -> bool:
    return name.endswith(".min.css") or name.endswith(".min.js")


def kind_of(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith(".css"):
        return "css"
    if lower.endswith(".js"):
        return "js"
    return None


def collect_inputs(args) -> list[tuple[str, str, str]]:
    """(source, rel, kind) triples for the chosen mode. Raises
    ValueError with a human message."""
    pairs: list[tuple[str, str]] = []
    if args.mode == "single":
        if not args.single_asset:
            raise ValueError("--single-asset is required in single mode")
        src = os.path.abspath(args.single_asset)
        if not os.path.isfile(src):
            raise ValueError(f"{args.single_asset} is not a file")
        pairs.append((src, os.path.basename(src)))
    elif args.mode == "multiple":
        if not args.input_file:
            raise ValueError("--input-file (one or more) is required in multiple mode")
        for given in args.input_file:
            src = os.path.abspath(given)
            if not os.path.isfile(src):
                raise ValueError(f"{given} is not a file")
            pairs.append((src, os.path.basename(src)))
    else:
        if not args.input_folder:
            raise ValueError("--input-folder is required in folder mode")
        root = os.path.abspath(args.input_folder)
        if not os.path.isdir(root):
            raise ValueError(f"{args.input_folder} is not a folder")
        walk = os.walk(root) if args.recursive else [next(os.walk(root))]
        for dirpath, _dirs, files in walk:
            for name in sorted(files):
                if is_minified(name):
                    continue  # never minify the minified
                if kind_of(name) is None:
                    continue
                if args.only != "both" and kind_of(name) != args.only:
                    continue
                src = os.path.join(dirpath, name)
                pairs.append((src, os.path.relpath(src, root)))

    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for src, rel in pairs:
        if rel in seen:  # same-name collision across folders
            stem, ext = os.path.splitext(rel)
            i = 2
            while f"{stem}-{i}{ext}" in seen:
                i += 1
            rel = f"{stem}-{i}{ext}"
        seen.add(rel)
        out.append((src, rel, kind_of(rel)))
    if not out:
        raise ValueError("no .css/.js files to minify"
                         + (" (already-minified files are skipped)" if
                            args.mode == "folder" else ""))
    return out


# ---------------------------------------------------------------------------
# The built-in CSS minifier (pure stdlib)
# ---------------------------------------------------------------------------
#
# A single-pass scanner, not a parser: strings, url() and comments are
# copied or dropped whole, and whitespace is only removed where CSS
# cannot tell the difference. The conservative calls are deliberate —
# a byte saved is worthless if the stylesheet stops working:
#
#   * inside ( ) the spaces around + - * / are load-bearing (calc,
#     clamp, min, max), so nothing is packed there;
#   * a space is removed AFTER a colon, never before — `a :hover` and
#     `a:hover` are different selectors;
#   * #aabbcc collapses to #abc only inside a declaration block, so an
#     `#aabbcc` ID selector is never touched.

_CSS_URL = re.compile(r"url\(", re.IGNORECASE)
_CSS_HEX = re.compile(r"#([0-9a-fA-F]{8}|[0-9a-fA-F]{6})(?![0-9a-fA-F])")
_CSS_NUM = re.compile(r"\d*\.\d+|\d+\.?")
# At-rules whose block holds rules, not declarations.
_CSS_RULE_BLOCK_AT = ("@media", "@supports", "@container", "@layer",
                      "@scope", "@document", "@-moz-document",
                      "@keyframes", "@-webkit-keyframes", "@-moz-keyframes")


def _css_needs_space(prev: str, nxt: str, depth: int, bracket: int) -> bool:
    """Whether a run of whitespace between these two characters carries
    meaning. `depth` is the ( ) nesting, `bracket` the [ ] nesting."""
    if prev in "{};,:([!" or nxt in "{};,)]!":
        return False
    if bracket:                     # [attr ~= "v"] — operators pack tight
        return False
    if prev in ">~" or nxt in ">~":
        return False
    if not depth and (prev == "+" or nxt == "+"):
        return False                # a selector combinator; in ( ) it is maths
    return True


def _css_token_char(ch: str) -> bool:
    """Whether this character can be part of an ident, number or hex —
    the test for whether two neighbours would fuse into one token if
    nothing were put between them."""
    return ch.isalnum() or ch in "_-%#\\"


def _css_shorten_number(raw: str) -> str:
    if "." not in raw:
        return raw
    trimmed = raw.rstrip("0").rstrip(".") or "0"
    if trimmed.startswith("0.") and len(trimmed) > 2:
        trimmed = trimmed[1:]
    return trimmed


def minify_css(text: str) -> str:
    text = text.removeprefix("\ufeff")
    out: list[str] = []
    ctx: list[bool] = []       # one flag per open brace: True = declarations
    prelude: list[str] = []    # what was read since the last { } or ;
    depth = bracket = 0
    space = False        # real whitespace was here
    sep = False          # only a comment was here — a weaker separator
    i, n = 0, len(text)

    def put(token: str) -> None:
        nonlocal space, sep
        if out:
            prev = out[-1][-1]
            if space:
                if _css_needs_space(prev, token[0], depth, bracket):
                    out.append(" ")
            elif sep and _css_token_char(prev) and _css_token_char(token[0]):
                # A comment is not whitespace: `.a/*x*/.b` is the
                # compound `.a.b`, not a descendant. It does still keep
                # `1px/*x*/2px` from fusing into one token.
                out.append(" ")
        space = sep = False
        out.append(token)
        prelude.append(token)

    def custom() -> bool:
        """Inside a `--custom-property` value: its content is an opaque
        token stream, so leave the colours and numbers exactly as
        written — clean-css keeps its hands off these too."""
        return "".join(prelude).lstrip().startswith("--")

    while i < n:
        c = text[i]
        if c in " \t\r\n\f":
            space = True
            i += 1
        elif text.startswith("/*", i):
            # Every comment goes, banners and `/*!` licence headers
            # included; it leaves a separator behind, because CSS does
            # not glue the tokens a comment sat between.
            end = text.find("*/", i + 2)
            i = end + 2 if end != -1 else n
            sep = True
        elif c in "\"'":
            j, quote = i + 1, c
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            put(text[i:j])
            i = j
        elif (c in "uU") and _CSS_URL.match(text, i):
            j = i + 4              # url( — copied verbatim, quotes and all
            while j < n and text[j] != ")":
                if text[j] in "\"'":
                    quote, j = text[j], j + 1
                    while j < n and text[j] != quote:
                        j += 2 if text[j] == "\\" else 1
                j += 1
            j = min(j + 1, n)
            put(text[i:j])
            i = j
        elif c == "{":
            head = "".join(prelude).strip().lower()
            ctx.append(not head.startswith(_CSS_RULE_BLOCK_AT))
            put("{")
            prelude.clear()
            i += 1
        elif c == "}":
            while out and out[-1] == ";":
                out.pop()          # the last declaration needs no semicolon
            if ctx:
                ctx.pop()
            put("}")
            prelude.clear()
            i += 1
        elif c in ";()[]":
            # put() first, then the counters: the space before `[` is
            # judged OUTSIDE the bracket it opens, or `[a] [b]` (a
            # descendant) would collapse into `[a][b]` (one element).
            put(c)
            if c == "(":
                depth += 1
            elif c == ")":
                depth = max(0, depth - 1)
            elif c == "[":
                bracket += 1
            elif c == "]":
                bracket = max(0, bracket - 1)
            elif c == ";":
                prelude.clear()
            i += 1
        elif c == "#" and ctx and ctx[-1] and not bracket and not custom():
            match = _CSS_HEX.match(text, i)
            after = text[match.end()] if match and match.end() < n else ""
            if match and after != "{":     # never an ID selector, then
                digits = match.group(1).lower()
                if all(digits[k] == digits[k + 1]
                       for k in range(0, len(digits), 2)):
                    digits = digits[0::2]
                put("#" + digits)
                i = match.end()
            else:
                put(c)
                i += 1
        elif (c.isdigit()
              or (c == "." and i + 1 < n and text[i + 1].isdigit())) \
                and ((ctx and ctx[-1]) or depth) and not bracket \
                and not custom() \
                and not (out and not space
                         and (out[-1][-1].isalnum()
                              or out[-1][-1] in "-_#.%\\")):
            match = _CSS_NUM.match(text, i)
            put(_css_shorten_number(match.group(0)))
            i = match.end()
        else:
            put(c)
            i += 1
    return "".join(out).strip()


# ---------------------------------------------------------------------------
# The built-in JS minifier (pure stdlib)
# ---------------------------------------------------------------------------
#
# A tokenizer, not a parser: comments and whitespace go, tokens are
# repacked as tightly as the lexical grammar allows. It does NOT mangle
# names or drop dead code — that needs scope analysis, which is what
# terser is for. What it does do, it does safely:
#
#   * regex literals are told apart from division by the preceding
#     token, template literals (with nested ${…}) are copied verbatim;
#   * a newline present in the source is KEPT wherever automatic
#     semicolon insertion could depend on it — `return\nx` never
#     becomes `return x`.

_JS_PUNCT = sorted(
    [">>>=", "...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=",
     "??=", "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--",
     "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
     "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/",
     "%", "&", "|", "^", "!", "~", "?", ":", "=", ".", "#", "@"],
    key=len, reverse=True)
# After these, a slash opens a regex literal, not a division.
_JS_REGEX_AFTER = {"return", "typeof", "instanceof", "in", "of", "new",
                   "delete", "void", "throw", "case", "do", "else", "yield",
                   "await"}
# Punctuators that CAN end a statement — a newline after them is ASI-relevant.
_JS_STATEMENT_END = (")", "]", "}", "++", "--")
_JS_WS = " \t\r\n\f\v\xa0\u2028\u2029\ufeff"


def _js_scan_string(s: str, i: int) -> int:
    quote, j, n = s[i], i + 1, len(s)
    while j < n:
        if s[j] == "\\":
            j += 2
            continue
        if s[j] == quote:
            return j + 1
        if s[j] == "\n":
            break
        j += 1
    raise ValueError("unterminated string literal")


def _js_scan_template(s: str, i: int) -> int:
    j, n = i + 1, len(s)
    while j < n:
        if s[j] == "\\":
            j += 2
            continue
        if s[j] == "`":
            return j + 1
        if s.startswith("${", j):
            j = _js_scan_braces(s, j + 1)
            continue
        j += 1
    raise ValueError("unterminated template literal")


def _js_scan_braces(s: str, i: int) -> int:
    """From the `{` at i to just past its match, skipping every literal
    a `}` could hide in — strings, nested templates, comments and regex
    literals (`${x.replace(/\\*\\//g, "")}` is why the last one matters)."""
    depth, j, n = 0, i, len(s)
    prev = "{"          # last significant char: tells regex from division
    while j < n:
        c = s[j]
        if c in " \t\r\n\f\v":
            j += 1
            continue
        if c in "\"'":
            j = _js_scan_string(s, j)
            prev = "x"
            continue
        if c == "`":
            j = _js_scan_template(s, j)
            prev = "x"
            continue
        if s.startswith("//", j):      # comments first: // is never a regex
            end = s.find("\n", j)
            j = n if end == -1 else end
            continue
        if s.startswith("/*", j):
            end = s.find("*/", j + 2)
            j = n if end == -1 else end + 2
            continue
        if c == "/" and not (prev.isalnum() or prev in "_$)]}"):
            j = _js_scan_regex(s, j)
            prev = "x"
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        prev = c
        j += 1
    raise ValueError("unterminated template expression")


def _js_scan_regex(s: str, i: int) -> int:
    j, n, in_class = i + 1, len(s), False
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            break
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "/":
            j += 1
            while j < n and (s[j].isalpha() or s[j] == "$"):
                j += 1
            return j
        j += 1
    raise ValueError("unterminated regular expression")


def _js_regex_allowed(kind: str, value: str) -> bool:
    if kind == "":
        return True
    if kind == "name":
        return value in _JS_REGEX_AFTER
    return kind == "punct" and value not in _JS_STATEMENT_END


def _js_needs_space(pk: str, pv: str, k: str, v: str) -> bool:
    """Whether two adjacent tokens would lex as one without a space."""
    wordy = ("name", "number")
    if pk in wordy and k in wordy:
        return True
    if pk == "number" and k == "punct" and v.startswith("."):
        return True          # 1 .toString() must not become 1.toString()
    if pk == "name" and k == "regex":
        return True
    if pk == "punct" and k == "punct":
        a, b = pv[-1], v[0]
        if a in "+-" and a == b:
            return True      # a + +b  /  a - --b
        if a == "/" and b in "/*":
            return True      # never let two operators open a comment
        if a == "<" and b == "!":
            return True
    return False


def _js_keep_newline(pk: str, pv: str, k: str, v: str) -> bool:
    """A newline that was in the source is kept unless it provably
    cannot matter — that is the whole ASI safety net."""
    if pk == "":
        return False
    if pk == "punct" and pv not in _JS_STATEMENT_END:
        return False         # the statement is unfinished: no ASI possible
    if k == "punct" and v in (")", "]", "}", ",", ";", ":"):
        return False
    return True


def minify_js(text: str) -> str:
    text = text.removeprefix("\ufeff")
    head = ""
    if text.startswith("#!"):        # a shebang survives, first line intact
        cut = text.find("\n")
        head = (text if cut == -1 else text[:cut]) + "\n"
        text = "" if cut == -1 else text[cut + 1:]

    out: list[str] = []
    pk = pv = ""
    newline = False
    line_start = True    # only whitespace/comments seen on this line so far
    i, n = 0, len(text)

    def put(kind: str, value: str) -> None:
        nonlocal pk, pv, newline, line_start
        if value == "}":
            while out and out[-1] == ";":
                out.pop()            # ;} is just }
        if out:
            if newline and _js_keep_newline(pk, pv, kind, value):
                out.append("\n")
            elif _js_needs_space(pk, pv, kind, value):
                out.append(" ")
        newline = line_start = False
        out.append(value)
        pk, pv = kind, value

    while i < n:
        c = text[i]
        if c in _JS_WS:
            if c in "\r\n\u2028\u2029":
                newline = line_start = True
            i += 1
        elif text.startswith("//", i) or text.startswith("<!--", i) \
                or (text.startswith("-->", i) and line_start):
            # `<!--` and a line-leading `-->` are HTML-like comments: a
            # legacy inline script must not come out as `< !--`.
            end = text.find("\n", i)
            i = n if end == -1 else end
            newline = True
        elif text.startswith("/*", i):
            # Every comment goes, `/*!` licence banners included. Two
            # tokens a comment sat between still get their space from
            # _js_needs_space, so nothing fuses.
            end = text.find("*/", i + 2)
            body = text[i + 2:end if end != -1 else n]
            i = end + 2 if end != -1 else n
            if "\n" in body:
                newline = True
        elif c in "\"'":
            j = _js_scan_string(text, i)
            put("string", text[i:j])
            i = j
        elif c == "`":
            j = _js_scan_template(text, i)
            put("template", text[i:j])
            i = j
        elif c == "/" and _js_regex_allowed(pk, pv):
            j = _js_scan_regex(text, i)
            put("regex", text[i:j])
            i = j
        elif c.isdigit() or (c == "." and i + 1 < n and text[i + 1].isdigit()):
            j = i
            if c == "0" and i + 1 < n and text[i + 1] in "xXoObB":
                j = i + 2
                while j < n and (text[j].isalnum() or text[j] == "_"):
                    j += 1
            else:
                while j < n and (text[j].isdigit() or text[j] in "._"):
                    j += 1
                if j < n and text[j] in "eE":
                    k = j + 1
                    if k < n and text[k] in "+-":
                        k += 1
                    if k < n and text[k].isdigit():
                        j = k
                        while j < n and text[j].isdigit():
                            j += 1
                if j < n and text[j] == "n":
                    j += 1
            put("number", text[i:j])
            i = j
        elif (c.isalpha() or c in "_$" or ord(c) > 127
              or (c == "#" and i + 1 < n
                  and (text[i + 1].isalpha() or text[i + 1] in "_$"))):
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_$"
                             or ord(text[j]) > 127):
                j += 1
            put("name", text[i:j])
            i = j
        else:
            for punct in _JS_PUNCT:
                if text.startswith(punct, i):
                    put("punct", punct)
                    i += len(punct)
                    break
            else:
                put("punct", c)
                i += 1
    return head + "".join(out).strip()


# ---------------------------------------------------------------------------
# The minifier runs (built-in call, or one subprocess per file)
# ---------------------------------------------------------------------------

def run_builtin(kind: str, src: str) -> tuple[bytes | None, str]:
    """The pure-Python path. Any hiccup is one error row, never a
    crashed batch."""
    try:
        with open(src, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return None, str(exc)[:200]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, ("not valid UTF-8 — the built-in engine needs text "
                      "(install terser/clean-css-cli for this file)")
    try:
        minified = minify_css(text) if kind == "css" else minify_js(text)
    except (ValueError, RecursionError, IndexError) as exc:
        return None, f"built-in {kind} minifier: {exc}"[:200]
    return minified.encode("utf-8"), ""


def run_system(kind: str, src: str, dst: str,
               timeout: int) -> tuple[bytes | None, str]:
    """One file through the system binary. The candidate goes to a
    `.part` temp first: a failed run never leaves half a `.min` file."""
    tmp = dst + ".part"
    try:
        if os.path.dirname(tmp):
            os.makedirs(os.path.dirname(tmp), exist_ok=True)
        name = REQUIRED_BINARIES[kind][0]
        binary = which(name) or name
        # `--comments false` / `specialComments:0` — the built-in engine
        # keeps no comment, so neither may these, or the same input
        # would come out differently depending on what is installed.
        if kind == "js":
            cmd = [binary, src, "--compress", "--mangle",
                   "--comments", "false", "-o", tmp]
        else:
            cmd = [binary, "-O1", "specialComments:0", "-o", tmp, src]
        # terser and cleancss are `#!/usr/bin/env node` scripts: finding
        # them outside PATH is useless unless node comes along too, and
        # it lives in the same folder.
        env = dict(os.environ)
        folder = os.path.dirname(binary)
        if folder and folder not in env.get("PATH", "").split(os.pathsep):
            env["PATH"] = folder + os.pathsep + env.get("PATH", "")
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=True,
                       env=env)
        with open(tmp, "rb") as fh:
            return fh.read(), ""
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode("utf-8", "replace").strip()
        first = stderr.splitlines()[0] if stderr else "no error output"
        return None, first[:200]
    except subprocess.TimeoutExpired:
        return None, f"{kind} minifier timed out after {timeout}s"
    except OSError as exc:
        return None, str(exc)[:200]
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def run_minifier(kind: str, src: str, dst: str, engine: str,
                 timeout: int) -> tuple[bytes | None, str]:
    """(candidate_bytes, note) — the candidate is compared to the source
    by the caller before anything is written."""
    if engine == BUILTIN:
        return run_builtin(kind, src)
    return run_system(kind, src, dst, timeout)


def minified_name(rel: str) -> str:
    stem, ext = os.path.splitext(rel)
    return f"{stem}.min{ext}"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_table_event(results: list[Result]) -> dict:
    rows = []
    for r in results:
        saved = ""
        if r.status == "minified" and r.original_bytes:
            saved = f"{100 * (r.original_bytes - r.output_bytes) / r.original_bytes:.1f}%"
        rows.append([r.rel, r.kind, r.engine or "—", r.status, saved or "—",
                     r.note or ""])
    return {
        "type": "table",
        "columns": ["File", "Kind", "Engine", "Status", "Saved", "Note"],
        "rows": rows,
    }


def build_markdown_event(results: list[Result]) -> dict:
    minified = [r for r in results if r.status == "minified"]
    saved = sum(r.original_bytes - r.output_bytes for r in minified)
    total_in = sum(r.original_bytes for r in results)
    pct = f" ({100 * saved / total_in:.1f}% of {human_size(total_in)})" \
        if total_in else ""
    engines = sorted({r.engine for r in results if r.engine
                      and r.status != "skipped"})
    lines = [
        f"## {'🗜️' if saved else '⚪'} {human_size(saved)} saved{pct}",
        "",
        f"- Minified: **{len(minified)}** · already minimal: "
        f"{sum(1 for r in results if r.status == 'already minimal')} · "
        f"skipped: {sum(1 for r in results if r.status == 'skipped')} · "
        f"errors: {sum(1 for r in results if r.status == 'error')}",
        "",
    ]
    if any(r.status == "already minimal" for r in results):
        lines.append("_`already minimal` rows produced no `.min` file — a "
                     "byte-identical copy would be a lie. The sources "
                     "stayed as they are._")
        lines.append("")
    if any(r.engine == BUILTIN and r.kind == "js" and r.status != "skipped"
           for r in results):
        lines.append("_The built-in JS engine strips comments and "
                     "whitespace only — it does not mangle names. "
                     "`npm install -g terser` for the harder squeeze._")
        lines.append("")
    lines.append(f"_{len(results)} file(s) through "
                 f"{', '.join(engines) if engines else 'no engine'}; "
                 f"originals never touched._")
    lines.append("")
    return {"type": "markdown", "content": "\n".join(lines)}


def write_report_csv(results: list[Result]) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR")
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "minification_report.csv"), "w",
              newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["file", "kind", "engine", "status", "original_bytes",
                         "minified_bytes", "saved_percent", "note"])
        for r in results:
            saved = 0.0
            if r.status == "minified" and r.original_bytes:
                saved = round(100 * (r.original_bytes - r.output_bytes)
                              / r.original_bytes, 1)
            writer.writerow([r.rel, r.kind, r.engine, r.status,
                             r.original_bytes, r.output_bytes, saved, r.note])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Asset Minify — CSS/JS through the built-in Python "
                    "minifier or the system terser/clean-css binaries; "
                    "originals never touched")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-asset", help="the .css/.js to minify")
    parser.add_argument("--input-file", action="append", default=[],
                        help="a file to minify; repeatable")
    parser.add_argument("--input-folder", help="folder of .css/.js files")
    parser.add_argument("--only", choices=["both", "css", "js"],
                        default="both",
                        help="folder mode: process CSS, JS or both")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    parser.add_argument("--engine", choices=["auto", "builtin", "system"],
                        default="auto",
                        help="auto: system binaries when installed, the "
                             "built-in Python minifier otherwise (default); "
                             "builtin: never shell out; system: require "
                             "terser/cleancss")
    parser.add_argument("--output-folder", required=True,
                        help="where the .min files land")
    parser.add_argument("--overwrite", action="store_true",
                        help="overwrite existing .min files")
    parser.add_argument("--binary-timeout", type=int, default=120,
                        help="per-file system-minifier timeout (default 120s)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no binaries run, no files written",
              flush=True)
        return 0

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2
    kinds_needed = {kind for _s, _r, kind in sources}

    # --engine system is the only mode that can lack a prerequisite, and
    # it is checked per kind actually collected, AFTER collection: a
    # CSS-only run never demands terser, and nothing crashes mid-batch.
    if args.engine == "system":
        missing = sorted({b for kind in kinds_needed
                          for b in REQUIRED_BINARIES[kind]
                          if which(b) is None})
        if missing:
            print(f"✗ missing system binaries: {', '.join(missing)}\n"
                  f"  install them with:\n"
                  f"    {install_hint(missing)}\n"
                  f"  or drop --engine system to use the built-in "
                  f"Python minifier",
                  file=sys.stderr, flush=True)
            return 1

    engines = {kind: resolve_engine(kind, args.engine)
               for kind in kinds_needed}

    output_folder = os.path.abspath(args.output_folder)
    try:
        os.makedirs(output_folder, exist_ok=True)
    except OSError as exc:
        print(f"✗ cannot create the output folder: {exc}",
              file=sys.stderr, flush=True)
        return 1

    total = len(sources)
    used = ", ".join(f"{kind}: {engines[kind]}" for kind in sorted(engines))
    log(f"Minifying {total} file(s) — {used}")
    status(f"{total} file(s) · {used}")

    results: list[Result] = []
    for i, (src, rel, kind) in enumerate(sources, 1):
        engine = engines[kind]
        target = os.path.join(output_folder, minified_name(rel))
        fallback_note = ""
        original_size = os.path.getsize(src)
        if os.path.exists(target) and not args.overwrite:
            results.append(Result(src, rel, kind, "skipped", original_size,
                                  note="exists in output (--overwrite)"))
            log(f"  ⏭ {minified_name(rel)}: exists, skipped")
        else:
            candidate, note = run_minifier(kind, src, target, engine,
                                           args.binary_timeout)
            if (candidate is None and engine != BUILTIN
                    and args.engine == "auto"):
                retry, retry_note = run_builtin(kind, src)
                if retry is not None:
                    fallback_note = f"{engine} failed ({note}); built-in used"
                    candidate, note, engine = retry, retry_note, BUILTIN
                    log(f"  ↩ {rel}: {fallback_note}")
            if candidate is None:
                results.append(Result(src, rel, kind, "error", original_size,
                                      engine=engine, note=note))
                log(f"  ✗ {rel}: {note}")
            elif len(candidate) >= original_size:
                results.append(Result(src, rel, kind, "already minimal",
                                      original_size, len(candidate),
                                      engine=engine,
                                      note=fallback_note
                                      or "minifier output not smaller"))
                log(f"  〰 {rel}: already minimal "
                    f"({human_size(original_size)})")
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(candidate)
                results.append(Result(src, rel, kind, "minified",
                                      original_size, len(candidate),
                                      engine=engine, note=fallback_note))
                pct = 100 * (original_size - len(candidate)) / original_size
                log(f"  ✓ {minified_name(rel)}: "
                    f"{human_size(original_size)} → "
                    f"{human_size(len(candidate))} ({pct:.1f}%)")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    if results and all(r.status == "error" for r in results):
        print("✗ every file failed — nothing was minified",
              file=sys.stderr, flush=True)
        return 1

    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(results))
    emit(build_markdown_event(results))
    write_report_csv(results)

    minified_n = sum(1 for r in results if r.status == "minified")
    saved = sum(r.original_bytes - r.output_bytes
                for r in results if r.status == "minified")
    status(f"{human_size(saved)} saved over {minified_n} file(s)")
    log(f"← {human_size(saved)} saved · {minified_n} minified · "
        f"{sum(1 for r in results if r.status == 'already minimal')} "
        f"already minimal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
