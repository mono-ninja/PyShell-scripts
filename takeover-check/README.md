# Takeover Check

**Which of your subdomains can be hijacked.** Subdomain Search
finds the subdomains, CT Log Check the former ones — this asks the
question neither does: **which of them points at a resource
somebody else can claim?**

- a **CNAME to an unclaimed cloud resource** — the classic dangling
  delegation: `assets.example.com → example-assets.s3.amazonaws.com`
  where the bucket no longer exists. Whoever creates that bucket
  owns your subdomain's content.
- **NXDOMAIN on the CNAME target** — the target no longer resolves
  at all: the strongest dangling hint, visible before any HTTP.
- the **response marker** — the provider's own "nothing here" page
  (each fingerprint carries its marker text), compared against one
  GET.
- the **closed-vs-open nuance** — Fastly, Vercel, Netlify,
  WordPress.com require domain verification now; a match on a
  closed service is its own answer, never a silent skip.

**The passivity contract:** DNS queries and one GET per candidate —
nothing else. The script never registers a resource, never
"confirms" a takeover by claiming one; it shows the signs and links
the provider's documentation. Fingerprints are YAML data (the
tech.yaml precedent) — the takeover flags will age; flipping them
is a data edit.

## Using with PyShell

1. Enter the **Domain** (candidates come from the crt.sh feed), or
   point **Subdomains file** at an existing list (e.g. Subdomain
   Search output) to skip the collection.
2. Press **Prepare Env** (installs `requests`, `dnspython`,
   `pyyaml`), then **Run** (⌘↩).

## Running standalone

```bash
python3 -m pip install -r requirements.txt
python3 main.py --domain example.com
python3 main.py --domain example.com --subdomains-file subs.txt
```

## Result

- **Results tab** — a table (host · cname · service · verdict) and
  the report: every CNAME-bearing candidate with its verdict, the
  fix list for the red ones, the passivity statement.
- **Artifacts** — `report.md`, `findings.json` (per-finding docs
  links).

### Verdicts

🔴 dangling (NXDOMAIN target) · 🔴 marker matches — likely
claimable · 🟠 marker matches — service closed the hole · ⚪
fingerprint target, no marker (alive) · ⚫ outside the fingerprint
list · ⚫ no CNAME.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are results |
| 1 | feed unreachable, or no candidates |
| 2 | bad arguments |

## Layout

```
takeover-check/
├── pyshell.yaml               # manifest
├── main.py                    # fingerprints · DNS · marker · report
├── takeover_fingerprints.yaml # the curated signature list (data)
├── requirements.txt           # requests, dnspython, pyyaml
├── docs/                      # EN + UA docs
└── tests/                     # 12 tests: fake resolver + fake HTTP
```

## License

MIT — see the root [LICENSE](../LICENSE).
