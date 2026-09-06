# Dep Audit

Known vulnerabilities in the project's own dependencies — the
lockfiles' **pinned** versions checked against OSV (free, keyless,
batched): requirements.txt (`==` pins; ranges listed honestly as
*not pinned, not checked*), poetry.lock, package-lock.json,
yarn.lock, pnpm-lock.yaml, composer.lock, go.mod, Gemfile.lock,
Cargo.lock. Advisory IDs, CVE aliases and the nearest fixed version
per dependency.

The third look at the same tree: secret-scan (credentials), wp-audit
(your code), **this** (someone else's code with known holes).

---

## Before running

1. Pick the **Project folder** — every supported lockfile in it (and
   one subfolder level, for monorepo layouts; **Recursive** walks
   the whole tree, skipping node_modules/.git/vendor).
2. **Prepare Env** — installs `requests` and `pyyaml`.
3. Press **Run** (⌘↩).

## Fields

### Target

- **Project folder** — the folder with the lockfiles. Nothing is
  modified; the lockfiles are only read.
- **Max dependencies** — safety cap (10–20000, default 3000);
  reaching it marks the audit as partial.
- **OSV request timeout (s)** — each batch query and each advisory
  fetch gets this long.

---

## Result

- **Results tab** — the table (dependency · version · vulns · fix)
  and the report:
  - **Vulnerable dependencies** — advisory IDs with CVE aliases and
    the smallest fixed version among the advisories (`fix ≥ X`),
    links to the OSV pages; no fixed version listed is said as
    such.
  - **The per-lockfile census** — ecosystem, pinned count, unpinned
    count, read errors.
  - **Not pinned, not checked** — the requirements.txt ranges: a
    range has no single version to answer for; listed, never
    guessed at (the worst-of-range guess would be noise).
- **Artifacts** — `report.md`, `findings.json` (machine-readable
  vulnerable list + the unpinned list).

### The honesty lines

- Batch answers are slim by design — advisory details (aliases,
  fix ranges) are fetched per ID, parallel, capped at 200; beyond
  the cap fixes are reported as unknown rather than slowing the
  audit to a crawl.
- `npm` lockfiles deduplicate across the three flavors; a
  dependency pinned in two lockfiles is asked once.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | no supported lockfile, lockfiles parse to nothing, or OSV unreachable |
| 2 | bad arguments: not a folder |

## Related

- **cve-check** — the live-site shape: a tech-stack snapshot → the
  same OSV.
- **wp-vuln-check** — the WordPress corner OSV does not cover.
- **secret-scan / wp-audit** — the other two looks at the same
  tree.
