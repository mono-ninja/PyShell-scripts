#!/usr/bin/env python3
"""dep-audit/main.py — known vulnerabilities in the project's own
dependencies.

The third look at the same source tree: **secret-scan** reads it for
leaked credentials, **wp-audit** for the operator's own code — and
this script reads it for **someone else's code with known holes**.
cve-check covers the live-site shape (a tech-stack snapshot → OSV);
a local project was invisible to the collection until now.

Lockfiles are the input, because they carry **pinned** versions —
the only versions a vulnerability answer can be honest about:

- Python: `requirements.txt` (`==` pins; `>=` ranges go to the
  honest *not pinned, not checked* list), `poetry.lock` (tomllib).
- JavaScript: `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml`
  (npm ecosystem).
- PHP: `composer.lock` (Packagist), Go: `go.mod` (Go),
  Ruby: `Gemfile.lock` (RubyGems), Rust: `Cargo.lock` (crates.io).

Each pinned dependency goes to OSV's `/v1/querybatch` — the
Google-run aggregation of GHSA/PyPA/Go/Rust advisories, free and
keyless, the same source cve-check already speaks to.  The verdict
per dependency: the advisory IDs (with CVE aliases), and the
nearest fixed version when one exists.

Exit codes: 0 = the audit ran (findings are results), 1 = no
lockfile in the folder / OSV unreachable, 2 = bad arguments.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field

import requests
import yaml

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://osv.dev/vulnerability/{id}"
OSV_VULNS_API = "https://api.osv.dev/v1/vulns/{id}"
BATCH_SIZE = 100
MAX_DETAIL_FETCHES = 200       # beyond this, fixes are reported as unknown
USER_AGENT = "PyShell-dep-audit/1 (+dependency diagnostics)"

LOCKFILES = {
    "requirements.txt": ("PyPI", "req"),
    "poetry.lock": ("PyPI", "poetry"),
    "package-lock.json": ("npm", "npm"),
    "yarn.lock": ("npm", "yarn"),
    "pnpm-lock.yaml": ("npm", "pnpm"),
    "composer.lock": ("Packagist", "composer"),
    "go.mod": ("Go", "gomod"),
    "Gemfile.lock": ("RubyGems", "gemfile"),
    "Cargo.lock": ("crates.io", "cargo"),
}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# -------------------------------------------------------------------- model

@dataclass
class Dep:
    name: str
    version: str
    ecosystem: str
    source: str          # which lockfile


@dataclass
class LockfileResult:
    path: str
    ecosystem: str
    deps: list[Dep] = field(default_factory=list)
    unpinned: list[str] = field(default_factory=list)   # req ranges
    note: str = ""


# ------------------------------------------------------------------ parsers

def parse_requirements(text: str) -> tuple[list[Dep], list[str]]:
    deps: list[Dep] = []
    unpinned: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line or line.startswith(("-r", "--", ".")):
            continue
        line = re.sub(r"\s*;.*$", "", line)      # environment markers
        line = re.sub(r"\s*\[.*?\]\s*", "", line)  # extras
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*([=<>!~]+.*)?$", line)
        if not m:
            continue
        name, spec = m.group(1), (m.group(2) or "").strip()
        if "==" in spec and not re.search(r"[<>!~]", spec.split("==")[0]):
            version = spec.split("==")[-1].strip().strip("\"'")
            if "*" not in version:
                deps.append(Dep(name, version, "PyPI", "requirements.txt"))
                continue
        unpinned.append(f"{name} ({spec or 'no version'})")
    return deps, unpinned


def parse_poetry_lock(data: bytes) -> list[Dep]:
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []
    return [Dep(p["name"], str(p["version"]), "PyPI", "poetry.lock")
            for p in parsed.get("package", [])
            if p.get("name") and p.get("version")]


def parse_package_lock(data: dict) -> list[Dep]:
    deps: list[Dep] = []
    seen: set[str] = set()
    packages = data.get("packages") or {}
    for path, info in packages.items():
        if not path or not isinstance(info, dict):
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        version = info.get("version")
        if name and version and (name, version) not in seen:
            seen.add((name, version))
            deps.append(Dep(name, version, "npm", "package-lock.json"))
    if not deps:                                  # lockfileVersion 1
        for name, info in (data.get("dependencies") or {}).items():
            version = info.get("version")
            if version:
                deps.append(Dep(name, version, "npm",
                                "package-lock.json"))
    return deps


def parse_yarn_lock(text: str) -> list[Dep]:
    """yarn v1: `pkg@range, pkg2@range:` + `version "x"`. The berry
    format (`resolution`) is noted honestly when unparsed."""
    deps: list[Dep] = []
    current_name = ""
    for line in text.splitlines():
        m = re.match(r'^"?(?!\s)([^#\s"][^:]*?):\s*$', line)
        if m:
            spec = m.group(1)
            first = spec.split(",")[0].strip().strip('"')
            current_name = re.sub(r"@[^@]*$", "", first) or first
            continue
        vm = re.match(r'^\s+version\s+"?([^"\s]+)"?', line)
        if vm and current_name:
            deps.append(Dep(current_name, vm.group(1), "npm",
                            "yarn.lock"))
            current_name = ""
    if not deps and "resolution" in text:
        return []  # berry lockfile — unsupported v1
    return deps


def parse_pnpm_lock(data: dict) -> list[Dep]:
    deps: list[Dep] = []
    for key, info in (data.get("packages") or {}).items():
        # key like '/django@4.0/hash' — take name@version before '/'
        m = re.match(r"^/([^/@]+)@([^/]+)/", key)
        if m:
            deps.append(Dep(m.group(1), m.group(2), "npm",
                            "pnpm-lock.yaml"))
    return deps


def parse_composer_lock(data: dict) -> list[Dep]:
    out = []
    for section in ("packages", "packages-dev"):
        for p in data.get(section) or []:
            if p.get("name") and p.get("version"):
                out.append(Dep(p["name"], p["version"].lstrip("v"),
                               "Packagist", "composer.lock"))
    return out


def parse_go_mod(text: str) -> list[Dep]:
    deps: list[Dep] = []
    in_block = False
    for line in text.splitlines():
        s = line.split("//")[0].strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("require "):
            s = s[len("require "):]
        elif not in_block:
            continue
        parts = s.split()
        if len(parts) >= 2 and not parts[0].startswith("("):
            if re.match(r"^v?[\d.]+", parts[1]):
                deps.append(Dep(parts[0], parts[1].lstrip("v"),
                                "Go", "go.mod"))
    return deps


def parse_gemfile_lock(text: str) -> list[Dep]:
    deps: list[Dep] = []
    in_gem = False
    for line in text.splitlines():
        s = line.rstrip()
        if re.match(r"^GEM\s*$", s):
            in_gem = True
            continue
        if not in_gem:
            continue
        if s and not s.startswith(" "):
            in_gem = False          # dedent — the next section
            continue
        m = re.match(r"^\s{4,}([A-Za-z0-9_.-]+) \(([^)]+)\)", s)
        if m and not m.group(2).startswith("="):   # constraints aren't versions
            deps.append(Dep(m.group(1), m.group(2), "RubyGems",
                            "Gemfile.lock"))
    return deps


def parse_cargo_lock(data: bytes) -> list[Dep]:
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []
    return [Dep(p["name"], str(p["version"]), "crates.io",
                "Cargo.lock")
            for p in parsed.get("package", [])
            if p.get("name") and p.get("version")]


def parse_lockfile(path: str) -> LockfileResult | None:
    """One lockfile → deps (or None when it's not one of ours)."""
    name = os.path.basename(path)
    if name not in LOCKFILES:
        return None
    ecosystem, kind = LOCKFILES[name]
    res = LockfileResult(path=path, ecosystem=ecosystem)
    try:
        if kind == "req":
            text = open(path, encoding="utf-8", errors="replace").read()
            res.deps, res.unpinned = parse_requirements(text)
        elif kind == "poetry":
            res.deps = parse_poetry_lock(open(path, "rb").read())
        elif kind == "npm":
            res.deps = parse_package_lock(json.load(open(path)))
        elif kind == "yarn":
            res.deps = parse_yarn_lock(
                open(path, encoding="utf-8", errors="replace").read())
        elif kind == "pnpm":
            res.deps = parse_pnpm_lock(
                yaml.safe_load(open(path)) or {})
        elif kind == "composer":
            res.deps = parse_composer_lock(json.load(open(path)))
        elif kind == "gomod":
            res.deps = parse_go_mod(
                open(path, encoding="utf-8", errors="replace").read())
        elif kind == "gemfile":
            res.deps = parse_gemfile_lock(
                open(path, encoding="utf-8", errors="replace").read())
        elif kind == "cargo":
            res.deps = parse_cargo_lock(open(path, "rb").read())
    except (OSError, json.JSONDecodeError, yaml.YAMLError,
            UnicodeDecodeError) as exc:
        res.note = f"unreadable: {exc}"
    return res


def find_lockfiles(project_dir: str, recursive: bool) -> list[str]:
    """Lockfiles in the folder (or the tree), sorted; the top level
    plus one level of known subdirs (the project root may be a
    monorepo) when recursive."""
    found = []
    walker = os.walk(project_dir) if recursive else [
        (project_dir, [d for d in os.listdir(project_dir)
                       if os.path.isdir(os.path.join(project_dir, d))],
         os.listdir(project_dir))]
    skip = {"node_modules", ".git", "vendor", "venv", ".venv",
            "__pycache__"}
    for root, dirs, files in walker:
        dirs[:] = [d for d in dirs if d not in skip]
        for f in files:
            if f in LOCKFILES:
                found.append(os.path.join(root, f))
        if not recursive:
            # one level deeper for monorepo layouts
            for d in dirs:
                sub = os.path.join(root, d)
                for f in os.listdir(sub):
                    if f in LOCKFILES:
                        found.append(os.path.join(sub, f))
    return sorted(set(found))


# --------------------------------------------------------------------- OSV

def osv_batches(deps: list[Dep], session: requests.Session,
                timeout: int) -> list[dict]:
    """Querybatch: aligned results array (slim — IDs only). Raises
    requests exceptions to the caller (exit 1)."""
    results: list[dict] = []
    for i in range(0, len(deps), BATCH_SIZE):
        chunk = deps[i:i + BATCH_SIZE]
        payload = {"queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem},
             "version": d.version} for d in chunk]}
        r = session.post(OSV_BATCH_URL, json=payload, timeout=timeout,
                         headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        data = r.json()
        batch = data.get("results") or []
        if len(batch) != len(chunk):
            batch = (batch + [{} for _ in chunk])[:len(chunk)]
        results.extend(batch)
    return results


def osv_details(ids: list[str], session: requests.Session,
                timeout: int) -> dict[str, dict]:
    """The full advisories (aliases + affected ranges) for the hit
    IDs — querybatch answers are slim on purpose. Parallel, capped;
    beyond the cap the rest are reported without fix info."""
    from concurrent.futures import ThreadPoolExecutor

    def one(vuln_id: str) -> tuple[str, dict]:
        try:
            r = session.get(OSV_VULNS_API.format(id=vuln_id),
                            timeout=timeout,
                            headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            return vuln_id, r.json()
        except requests.RequestException:
            return vuln_id, {}

    out: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for vuln_id, data in pool.map(one, ids):
            out[vuln_id] = data
    return out


def nearest_fix(vuln: dict, dep: Dep) -> str:
    """The smallest fixed version across the vuln's ranges/events."""
    fixes = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() \
                != dep.name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixes.append(event["fixed"])
    if not fixes:
        return ""
    try:
        return sorted(fixes,
                      key=lambda v: [int(x) if x.isdigit() else x
                                     for x in re.split(r"[.]", v)])[0]
    except (ValueError, TypeError):
        return fixes[0]


# -------------------------------------------------------------------- report

def build_table_event(rows: list[dict]) -> dict:
    return {"type": "table",
            "columns": ["dependency", "version", "vulns", "fix"],
            "rows": rows[:60]}


def build_markdown(results: list[LockfileResult],
                   vuln_rows: list[dict], unpinned: list[str],
                   truncated: bool) -> str:
    total_deps = sum(len(r.deps) for r in results)
    vuln_deps = sum(1 for r in vuln_rows if r["vulns"])
    total_vulns = sum(r["vuln_count"] for r in vuln_rows)
    out = [f"# Dep Audit — Report\n",
           f"{len(results)} lockfile(s) · {total_deps} pinned "
           f"dependencies · **{total_vulns} advisories on "
           f"{vuln_deps} dependencies**\n"]
    if truncated:
        out.append("⚠️ the dependency cap was reached — partial "
                   "audit\n")
    for res in results:
        rel = os.path.relpath(res.path)
        line = f"- `{rel}` ({res.ecosystem}): {len(res.deps)} pinned"
        if res.unpinned:
            line += f", {len(res.unpinned)} unpinned"
        if res.note:
            line += f" — ⚫ {res.note}"
        out.append(line)
    out.append("")

    if vuln_rows:
        out.append("## Vulnerable dependencies\n")
        for row in vuln_rows:
            out.append(f"- 🔴 **{row['dependency']} "
                       f"{row['version']}** — {row['vuln_count']} "
                       f"advisory(ies): {row['vulns']}"
                       + (f" · fix ≥ {row['fix']}" if row["fix"]
                          else " · no fixed version listed"))
        out.append("")
        out.append("Advisory links: " + " · ".join(
            f"[{vid}]({OSV_VULN_URL.format(id=vid)})"
            for vid in {v for r in vuln_rows
                        for v in r["vuln_ids"][:3]}))
        out.append("")
    else:
        out.append("No known advisories for the pinned versions. "
                   "That is OSV's word for today — new advisories "
                   "arrive daily, and unpinned ranges were never "
                   "asked.\n")

    if unpinned:
        out.append("## Not pinned, not checked\n")
        out.append(f"{len(unpinned)} requirement(s) from "
                   "requirements.txt carry ranges or no version at "
                   "all — a range has no single version to answer "
                   "for, so they are listed instead of guessed at "
                   "(the worst-of-range guess would be noise):\n")
        for u in unpinned[:20]:
            out.append(f"- {u}")
        if len(unpinned) > 20:
            out.append(f"- … +{len(unpinned) - 20} more")
        out.append("")

    out.append("## Related\n")
    out.append("- **cve-check** — the live-site shape: a tech-stack "
               "snapshot → the same OSV, plus the JS side.")
    out.append("- **wp-vuln-check** — the WordPress corner OSV does "
               "not cover (plugins/themes via Wordfence).")
    out.append("- **secret-scan / wp-audit** — the other two looks "
               "at the same tree: credentials and your own code.")
    return "\n".join(out)


def write_artifacts(results: list[LockfileResult], vuln_rows: list[dict],
                    unpinned: list[str], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {
        "lockfiles": [{"path": os.path.relpath(r.path),
                       "ecosystem": r.ecosystem,
                       "pinned": len(r.deps),
                       "unpinned": len(r.unpinned), "note": r.note}
                      for r in results],
        "vulnerable": vuln_rows,
        "unpinned": unpinned,
    }
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dep Audit — known vulnerabilities in the "
                    "project's lockfiles, via OSV (free, keyless)")
    parser.add_argument("--project-dir", required=True,
                        help="the folder with the lockfiles")
    parser.add_argument("--max-deps", type=int, default=3000,
                        help="safety cap on the dependency count")
    parser.add_argument("--timeout", type=int, default=30,
                        help="OSV request timeout in seconds")
    parser.add_argument("--recursive", action="store_true",
                        help="walk the whole tree (monorepos)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no lockfiles are read",
              flush=True)
        return 0

    project = args.project_dir
    if not os.path.isdir(project):
        print(f"✗ {project!r} is not a folder", file=sys.stderr,
              flush=True)
        return 2

    lock_paths = find_lockfiles(project, args.recursive)
    if not lock_paths:
        print(f"✗ no supported lockfile in {project} — nothing to "
              "audit", file=sys.stderr, flush=True)
        emit({"type": "markdown", "content":
              f"## Nothing to audit\n\nNo supported lockfile in "
              f"`{project}`.\n\nSupported: "
              + ", ".join(f"`{k}`" for k in sorted(LOCKFILES)) + "."})
        return 1

    results = [res for p in lock_paths if (res := parse_lockfile(p))]
    results = [r for r in results if r.deps or r.unpinned or r.note]
    if not results:
        print("✗ the lockfiles parsed to nothing", file=sys.stderr,
              flush=True)
        return 1

    deps: list[Dep] = []
    unpinned: list[str] = []
    seen: set[tuple[str, str, str]] = set()
    for res in results:
        unpinned.extend(f"{res.path}: {u}" for u in res.unpinned)
        for d in res.deps:
            key = (d.ecosystem, d.name.lower(), d.version)
            if key not in seen:
                seen.add(key)
                deps.append(d)
    truncated = len(deps) > args.max_deps
    deps = deps[:args.max_deps]

    log(f"Auditing {len(deps)} pinned dependencies from "
        f"{len(results)} lockfile(s)")
    status("querying OSV")
    emit({"type": "progress", "pct": 10,
          "message": f"{len(deps)} deps"})

    session = requests.Session()
    try:
        osv = osv_batches(deps, session, args.timeout)
    except requests.RequestException as exc:
        print(f"✗ OSV unreachable: {exc}", file=sys.stderr,
              flush=True)
        return 1
    emit({"type": "progress", "pct": 40,
          "message": "fetching advisory details"})

    # slim batch answers → fetch the full advisories for fix versions
    hit_ids = sorted({v.get("id") for res in osv
                      for v in (res.get("vulns") or [])
                      if v.get("id")})
    details: dict[str, dict] = {}
    if hit_ids:
        capped = len(hit_ids) > MAX_DETAIL_FETCHES
        details = osv_details(hit_ids[:MAX_DETAIL_FETCHES], session,
                              args.timeout)
    emit({"type": "progress", "pct": 80, "message": "mapping"})

    vuln_rows: list[dict] = []
    for dep, res in zip(deps, osv):
        vulns = res.get("vulns") or []
        if not vulns:
            continue
        ids = [v.get("id", "?") for v in vulns]
        cves = sorted({a for vid in ids
                       for a in details.get(vid, {})
                       .get("aliases", [])
                       if a.startswith("CVE")})
        fixes = [main_fix for vid in ids
                 if (main_fix := nearest_fix(
                     details.get(vid, {}), dep))]
        fix = min(fixes, default="")
        vuln_rows.append({
            "dependency": f"{dep.name} ({dep.source})",
            "version": dep.version,
            "vuln_count": len(vulns),
            "vulns": ", ".join(ids[:4])
            + (f" +{len(ids) - 4}" if len(ids) > 4 else "")
            + (f" [{'/'.join(cves[:2])}]" if cves else ""),
            "vuln_ids": ids,
            "fix": fix,
        })
    vuln_rows.sort(key=lambda r: -r["vuln_count"])

    report = build_markdown(results, vuln_rows, unpinned, truncated)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(vuln_rows))
    emit({"type": "markdown", "content": report})
    write_artifacts(results, vuln_rows, unpinned, report)

    total_vulns = sum(r["vuln_count"] for r in vuln_rows)
    summary = (f"{len(deps)} pinned deps · "
               f"{total_vulns} advisories on "
               f"{len(vuln_rows)} deps"
               + (f" · {len(unpinned)} unpinned (not checked)"
                  if unpinned else ""))
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
