# FW Audit

**What the firewall rules actually allow** — the rules-vs-reality
companion to Port Check. Saved dumps of **ufw**, **iptables**, **pf**
and **firewalld** are reviewed passively (format detected
automatically, nothing runs as root, nothing is changed): default
input policies, every inbound allow rule with its source, risky
ports open to **Anywhere** grouped like Port Check's exposure groups,
allow-all rules, source-scoped rules (praised, not just flagged),
IPv6 parity and iptables first-match shadowing.

---

## Before running

1. Export the dump on the host:
   `sudo ufw status verbose > ufw.txt` ·
   `sudo iptables-save > iptables.save` ·
   `sudo pfctl -sr > pf.txt` (or copy `pf.conf`) ·
   `sudo firewall-cmd --list-all > firewalld.txt`
2. Pick a **Source** — one dump, several, or a folder (every file is
   sniffed; files that match no firewall format are skipped with a
   note).
3. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **Source** — single / multiple / folder; `--recursive` descends
  into subfolders in folder mode.
- The format of each file is detected from its content — ufw
  (`Status: active`), iptables-save (`*filter` / `:INPUT`),
  pf (`pass`/`block`/anchor syntax), firewalld (`zone (active)` +
  services/ports).
- The stock macOS `pf.conf` (anchors only, zero pass/block) is
  recognized and reported honestly: the real rules live in the
  anchor files it points to.

---

## Result

- **Results tab** — the table (file · format · default-in · rules ·
  risky open · verdict) and the per-dump report:
  - **Inbound allow rules** — each with `→ Anywhere` or the scoped
    source, and the raw line.
  - **Flags** — risky ports open to the world (MySQL/Redis/etc. by
    risk group), allow-all and pass-all rules, iptables shadowed
    denies, missing `block all` in pf, inactive ufw.
  - **Notes** — rule counts, IPv6 parity (v4 rules with no v6 twin),
    source-scoped rules (the good practice), loopback exclusions,
    LIMIT rules, firewalld zone names.
  - **What good looks like** — deny by default; management ports
    scoped; databases never to the world; the Docker-bypasses-ufw
    warning.
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

🔴 **default-open** (policy allow / allow-all rule / inactive) · 🟠
**risky ports open** · 🟢 **sane** · 🟡 **see notes** (pf without
`block all`, firewalld zone targets, anchor-only rulesets). No
guesses beyond the dump: an unrecognized file is reported as such.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are in the report |
| 1 | no dump matched a firewall format |
| 2 | bad arguments: missing file, empty folder |

## Related

- **Port Check** — the wire side: what answers right now. Run both
  against the same host; the reports are designed to be read
  together.
- **SSH Log Check** — what the open SSH port has been absorbing.
- **Secret Scan** — the other half of "what did I leave open": keys
  in the repo.
