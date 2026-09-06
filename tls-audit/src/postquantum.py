"""The post-quantum probe — the X25519MLKEM768 hybrid via the
system ``openssl`` binary.

Python's :mod:`ssl` cannot request a key-share group, so the hybrid
(group ``0x11EC``) is probed by shelling out to ``openssl s_client``
offering **only** that group.  A TLS 1.3 server that cannot use it
either asks for a group the client did not offer or aborts — so a
completed TLS 1.3 handshake means the hybrid was negotiated.

The four shapes, each verified against a live server:

* ``Protocol version: TLSv1.3`` — the hybrid was negotiated;
* ``CONNECTION ESTABLISHED`` with a lower version — TLS 1.2 ignores
  key-share groups entirely, so this is *no TLS 1.3*, never
  "refused the hybrid";
* alert ``handshake failure`` with no established connection — the
  server has TLS 1.3 and refused the hybrid group;
* ``SSL_CONF_cmd(-groups, …) failed`` — the local OpenSSL is too
  old to offer the group at all.

The honesty line (the dnssec-check ``indeterminate`` pattern): when
the local client cannot make the probe, the verdict is **not
checked** — never "not supported".  A verdict the client couldn't
test is a note, not a guess.  Absence of the hybrid is
informational anyway: it is forward-looking readiness, not a
vulnerability being graded today.
"""
from __future__ import annotations

import re
import subprocess

# OpenSSL 3.5 is the first release that can offer X25519MLKEM768.
MIN_OPENSSL = (3, 5)
GROUP_NAME = "X25519MLKEM768"          # OpenSSL's spelling of 0x11EC


def parse_openssl_version(text: str) -> tuple[int, int, int] | None:
    """``OpenSSL 3.5.1 …`` → (3, 5, 1); None when unparseable
    (LibreSSL answers with its own banner — treated as unknown)."""
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", text or "")
    if not m:
        return None
    return tuple(int(g) for g in m.groups())  # type: ignore[return-value]


def classify(stdout: str, stderr: str) -> str:
    """The pure verdict from one ``s_client`` run:
    ``supported`` / ``not offered`` / ``not checked``."""
    out = (stdout or "") + (stderr or "")
    if "SSL_CONF_cmd" in out:
        # The local OpenSSL rejected the group name — it cannot
        # offer the hybrid at all.
        return "not checked"
    if "Protocol version: TLSv1.3" in out:
        return "supported"
    if "CONNECTION ESTABLISHED" in out:
        # A handshake happened, but not TLS 1.3 — key-share groups
        # never applied (a TLS 1.2 server ignores -groups).
        return "not offered"
    if "alert handshake failure" in out or "alert" in out.lower():
        # TLS 1.3 was there; the hybrid group was not.
        return "not offered"
    return "not checked"


def probe_pq(host: str, port: int, timeout: int) -> dict:
    """One ``openssl s_client`` run offering only the hybrid group.

    Returns ``{state, note}`` where state is ``supported`` /
    ``not offered`` / ``not checked`` (never a guess).
    """
    note = ""
    try:
        proc = subprocess.run(
            ["openssl", "version"], capture_output=True, text=True,
            timeout=10)
        version = parse_openssl_version(
            (proc.stdout or "") + (proc.stderr or ""))
    except (OSError, subprocess.TimeoutExpired):
        version = None
    if version is None:
        return {"state": "not checked",
                "note": "no parsable system OpenSSL found — the "
                        "hybrid group cannot be offered from this "
                        "machine (never read as 'not supported')"}
    if version < MIN_OPENSSL:
        return {"state": "not checked",
                "note": f"local OpenSSL {'.'.join(map(str, version))} "
                        f"< 3.5 — it cannot offer X25519MLKEM768; "
                        "upgrade to check (never read as 'not "
                        "supported')"}
    try:
        proc = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}",
             "-groups", GROUP_NAME, "-brief"],
            input="", capture_output=True, text=True,
            timeout=timeout + 5)
        state = classify(proc.stdout, proc.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"state": "not checked",
                "note": f"the probe did not run: {exc}"}
    if state == "supported":
        note = ("the server negotiated the X25519MLKEM768 hybrid — "
                "classical key exchange wrapped with a lattice "
                "KEM; a passive recorder storing today's traffic "
                "cannot decrypt it with a future quantum machine")
    elif state == "not offered":
        if "CONNECTION ESTABLISHED" in (proc.stdout or "") + \
                (proc.stderr or ""):
            note = ("the endpoint has no TLS 1.3 — the hybrid is a "
                    "TLS 1.3 feature; the protocol findings cover "
                    "that gap")
        else:
            note = ("TLS 1.3 is there but the hybrid group was "
                    "refused — classical key exchange only; "
                    "informational in 2026, worth enabling when the "
                    "frontend supports it (about half of the "
                    "measured web already has it)")
    else:
        note = ("the probe could not produce a verdict from this "
                "client — not checked, never 'not supported'")
    return {"state": state, "note": note}
