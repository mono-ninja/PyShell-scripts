# Password Check

Two questions about passwords, one script.

- **Check** — is this password already in a known breach? The lookup
  uses [Have I Been Pwned](https://haveibeenpwned.com/Passwords) with
  **k-anonymimity**: the password is SHA-1-hashed locally and only the
  first 5 characters of the hash are sent. The server answers with
  every hash in that range, and the match happens **on this machine**.
  The password never leaves the machine in any recoverable form; no API
  key, no account.
- **Generate** — cryptographically strong passwords (`secrets` /
  os.urandom), tunable length and alphabet.

Plus a local analysis in check mode: length, character classes,
entropy in bits, and pattern warnings (keyboard sequences, triple
repeats) — the things entropy math can't see.

---

## Before running

1. Pick a **Mode**.
2. Click **Prepare Env** — installs `requests`.
3. Check mode: type the password into the **Password** field — a secret
   field (Keychain, env, never argv). Generate mode: set length and
   count. Press **Run** (⌘↩).

## Fields

### Mode

- **Mode** — *Check a password* or *Generate passwords*.
- **Password** (check) — the password under test. It travels from the
  Keychain via the environment variable `PASSWORD`; the script never
  prints it in full and never writes it to a file. Only its 5-character
  hash prefix is ever sent anywhere.

### Generate

- **Length** — characters per password, 8–128 (default 20).
- **How many** — 1–20 passwords per run (default 3).
- **Include symbols** — adds `!@#$%^&*…` to the alphabet (default on).
  Every generated password is guaranteed to contain all selected
  character classes.

### Query

- **HIBP timeout (s)** — how long to wait for the range server
  (default 10).

---

## Result

- **Check** — the metrics table (length, character classes, entropy,
  strength, breach count) and the verdict report:
  - **Pwned** — the exact number of times the password appears in the
    breach corpus, with a change-it-everywhere advisory (breach corpora
    feed every credential-stuffing wordlist; reuse multiplies the
    blast radius).
  - **Not found** — good, but honest: it says nothing about reuse,
    phishing, or breaches not yet indexed.
  - **Unknown** — HIBP unreachable; the local analysis stands, the
    breach lookup doesn't. The run still exits 0.
- **Generate** — the password list with per-password entropy.

**No artifacts are written** — checked or generated, no password lands
on disk. Generated passwords appear in the Results tab and the run log
(copy from there) and nowhere else.

## Exit codes

- `0` — the run completed. A pwned password is a finding; an
  unreachable HIBP server is a warning, not a failure.
- `1` — check mode with an empty password field.
- `2` — bad arguments (generate length/count out of range).
