# DNS Propagation

A [PyShell](https://github.com/mono-ninja/PyShell) script that checks
one DNS record across **~20 public resolvers from different operators**
— Google, Cloudflare, Quad9, OpenDNS, Level3, DNS.Watch, Yandex,
Comodo, SafeDNS, Freenom, Neustar, CIRA — plus the system resolver, and
lays the answers side by side. The "did my DNS change reach everyone"
check that a single lookup can never give.

Pure DNS queries to the resolvers' addresses; the authoritative
nameservers are never contacted, nothing is changed.

## What it does

- **Propagation mode** — give the expected (new) value and every
  resolver is classified: serving it, or serving something else. A bar
  chart shows the split; comma-separated expected values cover
  round-robin sets.
- **Agreement mode** — no expected value, and the report answers the
  consistency question: how many distinct answers exist, which
  resolvers serve which (geo-splits, wrong records and round-robins
  all show up here).
- **Type-aware comparison** — TXT strips quotes, MX compares the host
  part, CNAME/NS fold case and the trailing dot; A/AAAA exact.
- **TTLs per resolver** — a stale answer isn't broken, it's cached;
  the TTL column shows how long each resolver may keep it.
- **Honest statuses** — updated / differs / NXDOMAIN / no records /
  error; a resolver that said nothing never counts as an answer.

## Using with PyShell

1. Import this folder via **+ Folder** (⇧⌘O).
2. Press **Prepare Env** — installs `dnspython`.
3. **Record name** (+ type, + expected value when tracking a change).
   Press **Run** (⌘↩).

Field-by-field documentation lives in [`docs/pyshell.md`](docs/pyshell.md) —
the same text is shown in PyShell's **Docs** panel (⌘D).

## Running standalone

```bash
python3 -m pip install -r requirements.txt

python3 main.py --name example.com
python3 main.py --name www.example.com --type A --expected 93.184.216.34
python3 main.py --name example.com --type TXT
python3 main.py --name example.com --expected 104.21.44.149,172.64.80.1
```

## Result

- **Results tab** — the propagation or agreement summary, a bar chart
  (propagation mode), and the per-resolver table with TTLs.
- **Artifacts** — `dns_propagation.json`, `report.md`.

## Exit codes

- `0` — the check ran; disagreement is a result, not a failure.
- `1` — every resolver failed to answer.
- `2` — bad arguments.

## Layout

```
dns-propagation/
├── pyshell.yaml         # manifest: form fields, bindings, artifacts
├── main.py              # entry point: catalogue, queries, classification
├── requirements.txt     # dnspython
└── docs/
    ├── pyshell.md       # operator docs (Docs panel)
    └── pyshell_ua.md    # Ukrainian translation
```

## License

[MIT](../LICENSE), same as the repository.
