# FW Audit

**What the firewall rules actually allow.** Port Check asks the wire
— *what answers right now?* — this asks the rules: *what is allowed
even when you're not looking?*  Saved firewall dumps are reviewed
passively (nothing runs as root, nothing is changed), the format of
each file detected automatically:

- **ufw** — the output of `ufw status verbose`
- **iptables** — an `iptables-save` dump
- **pf** — a `pf.conf` (the macOS/BSD one — including the stock
  anchor-only ruleset, reported honestly as "the rules live in the
  anchor files")
- **firewalld** — the output of `firewall-cmd --list-all`

The common model: the default input policy, every inbound allow rule
with its source, and the flags — ports open to **Anywhere** in risk
groups (databases, admin panels, remote access…), allow-**all**
rules, rules scoped to a source (the good practice, named as such),
IPv6 parity, and iptables first-match shadowing (a deny that can
never fire because an allow sits above it).

## Using with PyShell

1. Export the dump on the host (see the cheat sheet below), bring
   the file over.
2. Pick a **Source** — one dump, several, or a folder (every file is
   sniffed; non-firewall files are skipped with a note).
3. Press **Run** (⌘↩).

### Export cheat sheet

| Firewall | Command on the host |
|---|---|
| ufw | `sudo ufw status verbose > ufw.txt` |
| iptables | `sudo iptables-save > iptables.save` |
| pf | `sudo pfctl -sr > pf.txt` (running ruleset) or copy `pf.conf` |
| firewalld | `sudo firewall-cmd --list-all > firewalld.txt` |

## Running standalone

```bash
python3 main.py --single-file ufw.txt
python3 main.py --mode multiple --input-file ufw.txt --input-file iptables.save
python3 main.py --mode folder --input-folder ./dumps --recursive
```

## Result

- **Results tab** — a table (file · format · default-in · rules ·
  risky ports open · verdict) and the per-dump report: the rule list
  with **→ Anywhere** markers, the flags, the notes, and "what good
  looks like".
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

- 🔴 **default-open** — default input policy is allow, an allow-all
  rule exists, or the firewall is inactive: everything not explicitly
  blocked is open.
- 🟠 **risky ports open** — default is sane, but databases / admin
  panels / remote access answer to Anywhere.
- 🟢 **sane** — deny by default, nothing risky to the world.
- 🟡 **see notes** — the truth is in the details (pf without
  `block all`, firewalld zone targets, anchor-only rulesets).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are in the report |
| 1 | no dump matched a firewall format |
| 2 | bad arguments (missing file, empty folder) |

## Layout

```
fw-audit/
├── pyshell.yaml      # manifest
├── main.py           # detect · parse ×4 · analyze · report
├── docs/             # EN + UA docs
└── tests/            # 20 tests: realistic dumps of all four formats
```

## License

MIT — see the root [LICENSE](../LICENSE).
