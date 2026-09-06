# WP Exposure Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that checks which
**WordPress doors a site leaves open** — the endpoints every scanner's
first recon burst asks for, each answered with a verdict and the fix:

- **REST user enumeration** — `/wp-json/wp/v2/users` (and the
  `?rest_route=` spelling a filter can forget): the logins a brute-force
  attack would try, listed with the exact slugs found.
- **XML-RPC** — a live `xmlrpc.php` (pingback DoS, credential stuffing).
- **readme.html** — the file that ships with every install and names the
  exact version.
- **debug.log** in the webroot — downloadable debug output.
- **uploads directory listing** — a browsable `/wp-content/uploads/`.
- **wp-login.php** — reachable? (informational; the brute-force context
  is what [Log Attack Checker](../log-attack-checker) adds.)
- **generator meta tag** — the other version leak, read off the homepage
  without an extra request.

Passive by contract: **one plain GET per endpoint**, redirects followed,
no POSTs, no login attempts, nothing sent that a thousand other visitors
don't send. Point it at sites you own or are responsible for.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. **Site URL** — press **Run** (⌘↩). Seconds for one site.

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --url https://example.com
python3 main.py --url https://example.com --timeout 15
python3 main.py --url https://example.com --fail-on any   # CI gate: exit 3 on exposures
```

## Result

- **Results tab** — the endpoint table (status · check · what was seen)
  and the report: every check with its evidence and, for each exposure,
  **how to close it**, ordered fix-first.
- **Artifacts** — `findings.json` (every check, machine-readable),
  `report.md`.

An honest note: when the homepage shows no WordPress markers at all, the
report says so — the endpoint verdicts still stand on their own, but the
site may simply not be WordPress.

## Exit codes

- `0` — the check ran. Exposures are findings, not failures.
- `1` — the target never answered (or answered an HTTP error on the
  homepage): there was nothing to check.
- `2` — bad arguments (no scheme/host).
- `3` — the opt-in CI gate tripped (`--fail-on any` with exposures).

## Layout

```
wp-exposure-check/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # endpoint checks, verdicts, report
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
