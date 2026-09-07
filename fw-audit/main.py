#!/usr/bin/env python3
"""fw-audit/main.py — what the firewall rules actually allow.

Port Check asks the wire: *what answers right now?* — this script
asks the rules: *what is allowed even when you're not looking?*  It
reviews saved firewall dumps passively (nothing runs as root, nothing
is changed): **ufw** (`ufw status verbose`), **iptables**
(`iptables-save`), **pf** (a pf.conf — the macOS/BSD one) and
**firewalld** (`firewall-cmd --list-all`), the format of each file
detected automatically.

The common model every parser feeds: the default input policy, the
inbound allow rules with their sources, and the flags — a port open
to **Anywhere** in a risk group (databases, admin panels, remote
access…), an allow-**all** rule, rules scoped to a specific source
(the good practice, named as such), IPv6 parity, and the
iptables first-match shadowing (a deny that can never fire because an
allow sits above it).

The verdict vocabulary is deliberately boring: 🔴 default-allow or
allow-all, 🟠 risky ports open to the world, 🟢 sane. No guesses
beyond the dump: an unreadable or unrecognized file is reported as
such, never interpreted.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field

RISK_GROUPS = {
    "remote access": {22: "SSH", 23: "telnet", 992: "telnets",
                      3389: "RDP", 5900: "VNC", 5901: "VNC :1",
                      5985: "WinRM", 5986: "WinRM TLS"},
    "databases & caches": {1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
                           5432: "PostgreSQL", 6379: "Redis",
                           9200: "Elasticsearch", 11211: "memcached",
                           27017: "MongoDB", 6380: "Redis alt"},
    "admin & dev tooling": {2375: "Docker (plain!)", 2376: "Docker TLS",
                            2379: "etcd", 6443: "Kubernetes API",
                            8080: "HTTP alt / panels", 8888: "Jupyter",
                            9001: "Supervisor", 10000: "Webmin",
                            15672: "RabbitMQ mgmt", 5555: "DevStack"},
    "file sharing": {139: "SMB", 445: "SMB", 2049: "NFS"},
    "mail": {25: "SMTP", 110: "POP3", 143: "IMAP", 587: "submission",
             993: "IMAPS", 995: "POP3S"},
}

DANGEROUS_ANYWHERE = {p for ports in RISK_GROUPS.values() for p in ports}
ANYWHERE_WORDS = {"anywhere", "any", "all", "0.0.0.0/0", "::/0", "any"}


def emit(event: dict) -> None:
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def status(message: str) -> None:
    emit({"type": "status", "message": message})


def log(message: str) -> None:
    print(message, flush=True)


# -------------------------------------------------------------------- model

@dataclass
class Rule:
    raw: str = ""
    action: str = "allow"        # allow / pass / accept / deny…
    port: str = ""               # "22", "80,443", "any", "8000:8100"
    proto: str = ""              # tcp / udp / any
    source: str = "anywhere"     # the qualifier that matters
    direction: str = "in"

    @property
    def open_to_world(self) -> bool:
        src = self.source.strip().lower()
        return bool(src) and src.split()[0] in ANYWHERE_WORDS

    def ports_list(self) -> list[int]:
        out = []
        for chunk in re.split(r"[,\s]+", self.port):
            if chunk.isdigit():
                out.append(int(chunk))
            elif re.match(r"^\d+[:-]\d+$", chunk):
                a, b = re.split(r"[:-]", chunk)
                out.extend(range(int(a), int(b) + 1))
        return out


@dataclass
class FirewallConfig:
    path: str
    fmt: str = "unknown"         # ufw | iptables | pf | firewalld
    default_in: str = "unknown"  # deny | allow | reject | unknown
    rules: list[Rule] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    verdict: str = ""


# ---------------------------------------------------------------- detection

def detect_format(text: str) -> str:
    head = text[:4000]
    if re.search(r"^Status:\s+(in)?active", head, re.M):
        return "ufw"
    if re.match(r"^\*filter\b", head.strip()) or re.search(
            r"^(-A|:)\s?\S*(INPUT|input)", head, re.M):
        return "iptables"
    if len(re.findall(r"^\s*(pass|block|match|set skip|table|anchor"
                      r"|scrub-anchor|nat-anchor|rdr-anchor"
                      r"|dummynet-anchor|load anchor)\b",
                      head, re.M)) >= 2:
        return "pf"
    if re.search(r"^\w[\w-]*\s+\(active\)", head, re.M) \
            and ("services:" in head or "ports:" in head
                 or "rich rules:" in head):
        return "firewalld"
    return "unknown"


# ------------------------------------------------------------------ parsers

def parse_ufw(text: str, cfg: FirewallConfig) -> None:
    m = re.search(r"^Default:\s+(\w+)\s+\(incoming\)", text, re.M)
    if m:
        cfg.default_in = m.group(1).lower()
    if re.search(r"^Status:\s+inactive", text, re.M):
        cfg.flags.append("ufw is INACTIVE — every port is the app's "
                         "own business")
        cfg.default_in = "inactive"
        return
    for line in text.splitlines():
        # "22/tcp (v6)        ALLOW IN    Anywhere (v6)"
        m = re.match(
            r"^([\d:,/.]+(?:/\w+)?)\s*(?:\(v6\)\s*)?"
            r"(ALLOW(?: LIMIT)?|DENY|REJECT)\s+"
            r"(?:IN\s+|OUT\s+|FWD\s+)?(.*)$",
            line.strip())
        if not m:
            continue
        portspec, action, rest = m.groups()
        port, _, proto = portspec.partition("/")
        rule = Rule(raw=line.strip(), action=action.lower(),
                    port=port, proto=proto or "any",
                    source=rest or "anywhere",
                    direction="in")
        cfg.rules.append(rule)
    v6_rules = [r for r in cfg.rules if "(v6)" in r.raw]
    v4_rules = [r for r in cfg.rules if "(v6)" not in r.raw]
    v6_ports = {r.port for r in v6_rules}
    v4_only = [r for r in v4_rules if r.port not in v6_ports]
    if v4_only:
        cfg.notes.append(f"{len(v4_only)} IPv4-only rule(s) — ufw "
                         "applies them to IPv4 only; IPv6 traffic "
                         "skips them")
    limit = sum(1 for r in cfg.rules if r.action == "allow limit")
    if limit:
        cfg.notes.append(f"{limit} LIMIT rule(s) — rate-limited, "
                         "good for SSH")


def parse_iptables(text: str, cfg: FirewallConfig) -> None:
    for line in text.splitlines():
        m = re.match(r"^:INPUT\s+(\w+)", line.strip())
        if m:
            cfg.default_in = m.group(1).lower()
            break
    if cfg.default_in == "unknown":
        cfg.flags.append("no :INPUT policy line — the dump is not a "
                         "full iptables-save")
    for line in text.splitlines():
        s = line.strip()
        m = re.match(
            r"^-A\s+INPUT\s+(.*)$", s)
        if not m:
            continue
        rest = m.group(1)
        action_m = re.search(r"-j\s+(ACCEPT|DROP|REJECT)", rest)
        if not action_m:
            continue
        action = action_m.group(1).lower()
        port_m = re.search(r"(?:--dports?\s+|destination-port:?s?\s+)"
                           r"([\d,:!]+)", rest)
        proto_m = re.search(r"-p\s+(\w+)", rest)
        src_m = re.search(r"-s\s+(\S+)", rest)
        iface_m = re.search(r"-i\s+(\S+)", rest)
        if iface_m and iface_m.group(1).startswith("lo"):
            continue  # loopback
        rule = Rule(raw=s, action=action,
                    port=port_m.group(1) if port_m else "any",
                    proto=proto_m.group(1) if proto_m else "any",
                    source=src_m.group(1) if src_m else "anywhere")
        cfg.rules.append(rule)
    # first-match shadowing: an ACCEPT above a DROP for the same port
    seen_allow: dict[str, Rule] = {}
    for rule in cfg.rules:
        if rule.port in ("", "any") or not rule.open_to_world:
            continue
        key = f"{rule.port}/{rule.proto}"
        if rule.action == "accept" and key not in seen_allow:
            seen_allow[key] = rule
        elif rule.action in ("drop", "reject") and key in seen_allow:
            cfg.flags.append(
                f"shadowed deny: `{rule.raw}` can never fire — "
                f"`{seen_allow[key].raw}` above it accepts first "
                "(iptables is first-match)")
    for rule in cfg.rules:
        if rule.action == "accept" and rule.port == "any" \
                and rule.open_to_world:
            cfg.flags.append(f"allow-ALL rule: `{rule.raw}` — every "
                             "port is open")


def parse_pf(text: str, cfg: FirewallConfig) -> None:
    blocks_all = False
    anchor_lines = 0
    for line in text.splitlines():
        s = line.split("#")[0].strip()
        if not s:
            continue
        if re.match(r"^(scrub-anchor|nat-anchor|rdr-anchor"
                    r"|dummynet-anchor|anchor|load anchor)\b", s):
            anchor_lines += 1
            continue
        m = re.match(r"^(pass|block)\s+(.*?)\s*$", s)
        if not m:
            if re.match(r"^set\s+skip\s+on\s+lo", s):
                cfg.notes.append("loopback excluded (set skip on lo)")
            continue
        action, rest = m.group(1).lower(), m.group(2)
        if action == "block" and rest.strip() == "all":
            blocks_all = True
        direction = "in" if re.search(r"\bin\b", rest) else (
            "out" if re.search(r"\bout\b", rest) else "both")
        port_m = re.search(r"port\s+([\d:,\s]+?)(?:\s|$)", rest)
        proto_m = re.search(r"proto\s+(\w+)", rest)
        src_m = re.search(r"from\s+(\S+)", rest)
        to_any = "to any" in rest
        rule = Rule(raw=s, action="allow" if action == "pass" else "deny",
                    port=(port_m.group(1).strip() if port_m else "any"),
                    proto=proto_m.group(1) if proto_m else "any",
                    source=src_m.group(1) if src_m else "anywhere",
                    direction=direction)
        if action == "pass":
            cfg.rules.append(rule)
            if rule.port == "any" and rule.open_to_world and to_any:
                cfg.flags.append(f"pass-all rule: `{s}` — every port "
                                 "passes")
    if not blocks_all and not cfg.rules and anchor_lines:
        cfg.notes.append("the ruleset only loads anchors — the real "
                         "rules live in the anchor files it points to "
                         "(macOS: /etc/pf.anchors/*)")
    elif not blocks_all:
        cfg.flags.append("no `block all` default found — pf's default "
                         "is pass; without an explicit block the rules "
                         "above are additions, not exceptions")
    if cfg.default_in == "unknown":
        cfg.default_in = "deny" if blocks_all else "unknown"


def parse_firewalld(text: str, cfg: FirewallConfig) -> None:
    zone = re.search(r"^([\w-]+)\s+\((active|default)\)", text, re.M)
    if zone:
        cfg.notes.append(f"zone: {zone.group(1)}")
    services = re.search(r"services:\s*(.*)", text)
    ports = re.search(r"^\s*ports:\s*(.*)", text, re.M)
    if services:
        for svc in services.group(1).split():
            cfg.rules.append(Rule(raw=f"service {svc}", action="allow",
                                  port=svc, proto="service",
                                  source="anywhere"))
    if ports:
        for spec in ports.group(1).split():
            port, _, proto = spec.partition("/")
            cfg.rules.append(Rule(raw=spec, action="allow", port=port,
                                  proto=proto or "tcp",
                                  source="anywhere"))
    cfg.default_in = "unknown"
    cfg.notes.append("firewalld: the zone's default target applies to "
                     "everything not listed; check `firewall-cmd "
                     "--zone=<zone> --list-all` for the target line")


PARSERS = {"ufw": parse_ufw, "iptables": parse_iptables,
           "pf": parse_pf, "firewalld": parse_firewalld}


def read_config(path: str) -> FirewallConfig:
    cfg = FirewallConfig(path=path)
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as exc:
        cfg.flags.append(f"unreadable: {exc}")
        cfg.verdict = "⚫ unreadable"
        return cfg
    cfg.fmt = detect_format(text)
    if cfg.fmt == "unknown":
        cfg.verdict = "⚫ unrecognized format"
        cfg.flags.append("matches none of: ufw status verbose, "
                         "iptables-save, pf.conf, firewall-cmd "
                         "--list-all")
        return cfg
    PARSERS[cfg.fmt](text, cfg)
    finalize(cfg)
    return cfg


# ----------------------------------------------------------------- analysis

def risky_ports_of(rules: list[Rule]) -> list[tuple[int, str, str]]:
    """(port, service name, risk group) for world-open risky ports."""
    out = []
    for rule in rules:
        if rule.action not in ("allow", "pass", "accept", "allow limit"):
            continue
        if not rule.open_to_world:
            continue
        for port in rule.ports_list():
            if port in DANGEROUS_ANYWHERE:
                for group, ports in RISK_GROUPS.items():
                    if port in ports:
                        out.append((port, ports[port], group))
                        break
    return sorted(set(out))


def finalize(cfg: FirewallConfig) -> None:
    if cfg.verdict:
        return
    risky = risky_ports_of(cfg.rules)
    world_open = [r for r in cfg.rules
                  if r.open_to_world and r.action.startswith(("allow",
                                                              "pass",
                                                              "accept"))]
    scoped = [r for r in cfg.rules if not r.open_to_world]
    allow_all = any("allow-ALL" in f or "pass-all" in f
                    for f in cfg.flags)

    if cfg.default_in in ("allow", "accept") or allow_all \
            or cfg.default_in == "inactive":
        cfg.verdict = "🔴 default-open"
    elif risky:
        cfg.verdict = "🟠 risky ports open"
    elif cfg.default_in in ("deny", "reject", "drop"):
        cfg.verdict = "🟢 sane"
    else:
        cfg.verdict = "🟡 see notes"
    cfg.notes.insert(0, f"{len(world_open)} rule(s) open to the world, "
                        f"{len(scoped)} scoped to a source")
    for port, service, group in risky:
        cfg.flags.append(f"{port} ({service}) open to Anywhere — "
                         f"the {group} group; scope it to a source or "
                         "close it")
    if scoped:
        good = "; ".join(sorted({r.source for r in scoped})[:5])
        cfg.notes.append(f"source-scoped rules (good practice): "
                         f"{good}")


# -------------------------------------------------------------------- report

def build_table_event(configs: list[FirewallConfig]) -> dict:
    rows = []
    for cfg in configs:
        risky = risky_ports_of(cfg.rules)
        rows.append([
            os.path.basename(cfg.path),
            cfg.fmt,
            cfg.default_in,
            len(cfg.rules),
            ", ".join(f"{p}/{svc}" for p, svc, _ in
                      risky[:4]) or "—",
            cfg.verdict,
        ])
    return {"type": "table",
            "columns": ["file", "format", "default in", "rules",
                        "risky open", "verdict"],
            "rows": rows}


def build_markdown(configs: list[FirewallConfig]) -> str:
    red = sum(1 for c in configs if c.verdict.startswith("🔴"))
    green = sum(1 for c in configs if c.verdict.startswith("🟢"))
    out = [f"# FW Audit — Report\n",
           f"{len(configs)} dump(s): {green} sane, {red} default-open, "
           f"{len(configs) - red - green} in between or unreadable.\n",
           "The rules are read, not tested — what is *allowed*, not "
           "what answers. For the wire side run **Port Check** against "
           "the same host; the two reports are designed to be read "
           "together.\n"]

    for cfg in configs:
        rel = os.path.basename(cfg.path)
        out.append(f"\n## {rel}\n")
        out.append(f"- Format: **{cfg.fmt}** · default input policy: "
                   f"**{cfg.default_in}** · verdict: **{cfg.verdict}**")
        for note in cfg.notes:
            out.append(f"- ℹ️ {note}")
        out.append("")
        if cfg.flags:
            out.append("### Flags\n")
            for flag in cfg.flags:
                out.append(f"- 🚩 {flag}")
            out.append("")
        if cfg.rules:
            out.append("### Inbound allow rules\n")
            for rule in cfg.rules:
                world = "**→ Anywhere**" if rule.open_to_world \
                    else f"→ {rule.source}"
                out.append(f"- `{rule.port or 'any'}`/{rule.proto} "
                           f"{world} — `{rule.raw[:90]}`")
            out.append("")

    out.append("\n## What good looks like\n")
    out.append("- Default **deny** for inbound, then explicit allows — "
               "everything not listed is closed.")
    out.append("- Management ports (SSH, panels, databases) scoped to "
               "a source — the office IP, a VPN CIDR — not "
               "**Anywhere**.")
    out.append("- Databases and caches (3306, 5432, 6379, 27017, "
               "9200…) never listen to the world; the app talks to "
               "them locally or over a private network.")
    out.append("- Docker beware: `DOCKER` chain rules bypass ufw "
               "silently — a published port is open even when ufw "
               "denies it (check with Port Check).")
    out.append("\n## Related\n")
    out.append("- **Port Check** — the wire side: what answers right "
               "now (TCP connect, banners, ownership-gated).")
    out.append("- **SSH Log Check** — what the open SSH port has been "
               "absorbing.")
    return "\n".join(out)


def write_artifacts(configs: list[FirewallConfig], report: str) -> None:
    out_dir = os.environ.get("PYSHELL_OUTPUT_DIR", ".")
    os.makedirs(out_dir, exist_ok=True)
    payload = {"configs": [{
        "file": os.path.basename(c.path),
        "format": c.fmt,
        "default_in": c.default_in,
        "verdict": c.verdict,
        "rules": [{
            "raw": r.raw, "action": r.action, "port": r.port,
            "proto": r.proto, "source": r.source,
            "open_to_world": r.open_to_world,
        } for r in c.rules],
        "risky_open": [{"port": p, "service": s, "group": g}
                       for p, s, g in risky_ports_of(c.rules)],
        "flags": c.flags,
        "notes": c.notes,
    } for c in configs]}
    with open(os.path.join(out_dir, "findings.json"), "w",
              encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w",
              encoding="utf-8") as fh:
        fh.write(report)


# --------------------------------------------------------------------- input

def collect_inputs(args) -> list[str]:
    if args.mode == "single":
        if not args.single_file:
            raise ValueError("--single-file is required in single mode")
        if not os.path.isfile(args.single_file):
            raise ValueError(f"{args.single_file}: file not found")
        return [args.single_file]
    if args.mode == "multiple":
        if not args.input_file:
            raise ValueError("select at least one dump (--input-file, "
                             "repeatable)")
        for path in args.input_file:
            if not os.path.isfile(path):
                raise ValueError(f"{path}: file not found")
        return list(args.input_file)
    if not args.input_folder:
        raise ValueError("--input-folder is required in folder mode")
    if not os.path.isdir(args.input_folder):
        raise ValueError(f"{args.input_folder}: folder not found")
    found: list[str] = []
    skipped = 0
    walker = os.walk(args.input_folder) if args.recursive else [
        (args.input_folder, [], sorted(os.listdir(args.input_folder)))]
    for root, _dirs, files in walker:
        for name in sorted(files):
            found.append(os.path.join(root, name))
    # folder mode: sniff every file, keep the recognized ones
    recognized = []
    for full in found:
        try:
            text = open(full, encoding="utf-8",
                        errors="replace").read(4000)
        except OSError:
            skipped += 1
            continue
        if detect_format(text) != "unknown":
            recognized.append(full)
        else:
            skipped += 1
    if skipped:
        log(f"  ⚫ {skipped} file(s) not in a firewall format, skipped")
    if not recognized:
        raise ValueError(f"{args.input_folder}: no firewall dumps "
                         "recognized (ufw / iptables-save / pf.conf / "
                         "firewalld)")
    return recognized


# ---------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="FW Audit — what the firewall rules allow: ufw, "
                    "iptables, pf and firewalld dumps reviewed "
                    "passively")
    parser.add_argument("--mode", choices=["single", "multiple", "folder"],
                        default="single", help="input mode (default single)")
    parser.add_argument("--single-file", help="the firewall dump to review")
    parser.add_argument("--input-file", action="append", default=[],
                        help="a firewall dump; repeatable")
    parser.add_argument("--input-folder", help="folder of dumps")
    parser.add_argument("--recursive", action="store_true",
                        help="folder mode: include subfolders")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode — no dumps are read", flush=True)
        return 0

    try:
        sources = collect_inputs(args)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr, flush=True)
        return 2

    total = len(sources)
    log(f"Reviewing {total} firewall dump(s)")
    status(f"{total} dump(s)")

    configs: list[FirewallConfig] = []
    for i, src in enumerate(sources, 1):
        cfg = read_config(src)
        configs.append(cfg)
        rel = os.path.basename(src)
        if cfg.fmt == "unknown":
            log(f"  ⚫ {rel}: {cfg.flags[0] if cfg.flags else 'unrecognized'}")
        else:
            log(f"  {cfg.verdict} {rel} ({cfg.fmt}, default-in "
                f"{cfg.default_in}, {len(cfg.rules)} rule(s))")
        emit({"type": "progress", "pct": int(100 * i / total),
              "message": f"{i}/{total} · {rel}"})

    recognized = [c for c in configs if c.fmt != "unknown"]
    if not recognized:
        print("✗ no dump matched a firewall format — nothing to review",
              file=sys.stderr, flush=True)
        return 1

    report = build_markdown(configs)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit(build_table_event(configs))
    emit({"type": "markdown", "content": report})
    write_artifacts(configs, report)

    red = sum(1 for c in configs if c.verdict.startswith("🔴"))
    orange = sum(1 for c in configs if c.verdict.startswith("🟠"))
    summary = (f"{len(recognized)} reviewed · {red} default-open · "
               f"{orange} with risky ports open")
    status(summary)
    log(f"← {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
