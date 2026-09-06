# WP Audit

A [PyShell](https://github.com/mono-ninja/PyShell) script that runs
**SAST over a WordPress site's own code** — the themes and plugins in
`wp-content` (the default scan root when it's present; WordPress core
in `wp-admin`/`wp-includes` is not your code, and `--whole-tree`
overrides deliberately). Reads files only: nothing is executed,
nothing leaves the machine.

The curated rulebook (19 rules, ported from the NinjaTools original)
covers the signatures that matter:

- **SQL injection** — `$wpdb` interpolation, sprintf-built queries
  without `prepare()`;
- **XSS** — superglobals and `get_query_var()` echoed without
  `esc_*()`;
- **Code execution** — `eval()` over `base64_decode`/`gzinflate`
  chains (the classic injected-malware signature), long obfuscated
  blobs near eval, the shell-exec family;
- **File operations** — variable-path `include`/`require` and writes,
  uploads moved without type checks;
- **Object injection** — `unserialize()` over request data;
- **SSRF / open redirect** — `wp_remote_*` and `wp_redirect` over
  user-controlled targets;
- **Access control** — AJAX handlers without nonces, REST routes
  without `permission_callback`, spoofable-IP trusts;
- **Header injection, hardcoded secrets** (wp-config.php exempt —
  it's supposed to hold them).

**Rules are YAML data** (`rules.yaml`, the tech.yaml precedent): the
documented schema (match / exclude windows / require_source /
file globs) is also what a `--custom-rules` file speaks — bring your
own signatures without touching code.

The code-side sibling of [WP Exposure Check](../wp-exposure-check)
(the HTTP surface) and [Log Attack Checker](../log-attack-checker)
(what the attacks looked like): this one reads the source they
exploit.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `pyyaml`.
3. **Site folder** — press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --site-dir /var/www/mysite
python3 main.py --site-dir /var/www/mysite --whole-tree
python3 main.py --site-dir /var/www/mysite --custom-rules my-rules.yaml
python3 main.py --site-dir /var/www/mysite --fail-on critical   # CI gate
```

## Result

- **Results tab** — the findings table (severity · file:line · rule ·
  finding) and the report: per-category counts, the top findings with
  their trigger-line snippets, and per-category advice.
- **Artifacts** — `findings.json` (every finding, machine-readable),
  `report.md`.

## Exit codes

- `0` — the scan ran. Findings are results, not failures.
- `1` — no PHP files under the scan root.
- `2` — bad arguments (not a folder, a malformed rules file — with the
  exact rule and reason).
- `3` — the opt-in CI gate (`--fail-on critical` / `any`).

## Layout

```
wp-audit/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # thin entry point: validation, scan loop
├── rules.yaml           # the rulebook — YAML data, the documented schema
├── requirements.txt     # pyyaml
├── src/
│   ├── rules.py         # rule model, loader, validator
│   ├── scanner.py       # file discovery + the matching engine
│   └── report.py        # table, markdown, artifacts
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
