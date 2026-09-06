# Password Check

A [PyShell](https://github.com/mono-ninja/PyShell) script that answers
two questions about passwords:

- **Check** — is this password already in a known breach? The lookup
  uses [Have I Been Pwned](https://haveibeenpwned.com/Passwords) with
  **k-anonymimity**: the password is SHA-1-hashed locally and only the
  first **5 characters of the hash** are sent; the server answers with
  the whole hash range and the match happens on this machine. The
  password never leaves the machine in any recoverable form, no API key
  is needed, and it arrives as a **secret field** — Keychain, env,
  never argv.
- **Generate** — cryptographically strong passwords (the `secrets`
  module), tunable length and alphabet.

The check also runs a local analysis — length, character classes,
entropy in bits, obvious patterns (sequences, triple repeats) — so the
verdict is never just "found / not found".

**Privacy contract: no artifacts.** Nothing is written to disk; the
checked password is masked everywhere it appears (first character and
length only); generated passwords show in the Results tab and the run
log — copying them is the point — but never in a file.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `requests`.
3. Pick a mode; in check mode type the password into the secret field
   and press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

PASSWORD='hunter2' python3 main.py                     # check mode
PASSWORD='hunter2' python3 main.py --timeout 15
python3 main.py --mode generate                        # 3 × 20 chars
python3 main.py --mode generate --generate-length 32 --generate-count 5
python3 main.py --mode generate --no-include-symbols
```

## Result

- **Check** — the metrics table (length, classes, entropy, strength,
  breach count) and the verdict: breach occurrences with a change-it
  advisory, or the not-found caveat spelled out honestly. Pattern
  warnings list what entropy math can't see.
- **Generate** — the password list with per-password entropy.

## Exit codes

- `0` — the run completed. A pwned password is a finding, not a
  failure; an unreachable HIBP server degrades the report with a
  warning (the local analysis stands), it doesn't fail the run.
- `1` — check mode without a password (the secret field is empty).
- `2` — bad arguments (generate length/count out of range).

## Layout

```
password-check/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: analysis, HIBP lookup, generation
├── requirements.txt     # requests
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
