"""src/phases.py — the phase presets. Pure.

A phase is *what to ask for*, never *what to attack with*: GETs of
expensive pages, one minimal XML-RPC POST. No credentials, no
amplification payloads — the docstrings and the report keep saying
so.
"""
from __future__ import annotations

import random
import string
from dataclasses import dataclass
from urllib.parse import quote_plus

XMLRPC_LIST_METHODS = (
    '<?xml version="1.0"?>'
    "<methodCall><methodName>system.listMethods</methodName>"
    "<params></params></methodCall>"
)


# A phase spec: *what to ask for*, never *what to attack with*.
@dataclass(frozen=True)
class PhaseSpec:
    key: str
    label: str
    description: str
    method: str = "GET"
    path: str = "/"
    body: str | None = None
    custom: bool = False         # fetch the operator's paths round-robin

    def request_for(self, base: str, i: int,
                    custom_paths: list[str] | None = None) -> dict:
        """One request description: {method, url, data}. The search
        phase randomizes its term per request — a cache-busting load,
        the point of the phase."""
        if self.key == "search":
            term = "".join(random.choices(string.ascii_lowercase, k=6))
            return {"method": "GET",
                    "url": f"{base}/?s={quote_plus(term)}",
                    "data": None}
        if self.custom:
            paths = custom_paths or ["/"]
            return {"method": "GET",
                    "url": base.rstrip("/") + paths[i % len(paths)],
                    "data": None}
        return {"method": self.method,
                "url": base.rstrip("/") + self.path,
                "data": self.body}


PHASES: dict[str, PhaseSpec] = {
    "baseline": PhaseSpec(
        key="baseline", label="Baseline — homepage",
        description="GET / at the set rate: the reference latency every "
                    "other phase is graded against."),
    "search": PhaseSpec(
        key="search", label="Search — /?s=<random>",
        description="GET /?s=<random term> — cache-busting search load "
                    "that reaches the database."),
    "rest": PhaseSpec(
        key="rest", label="REST API — /wp-json/wp/v2/posts",
        description="GET the posts endpoint — the JSON path's cost.",
        path="/wp-json/wp/v2/posts"),
    "login": PhaseSpec(
        key="login", label="Login page — wp-login.php",
        description="GET the login page (sessions and nonces make it "
                    "expensive). **Never submitted** — no credentials "
                    "are sent, ever.",
        path="/wp-login.php"),
    "xmlrpc": PhaseSpec(
        key="xmlrpc", label="XML-RPC — system.listMethods",
        description="One minimal POST to xmlrpc.php — the endpoint's "
                    "cost, no amplification payload, no credentials.",
        method="POST", path="/xmlrpc.php", body=XMLRPC_LIST_METHODS),
    "custom": PhaseSpec(
        key="custom", label="Custom paths",
        description="Your paths, fetched round-robin at the set rate.",
        custom=True),
}

PHASE_ORDER = ["baseline", "search", "rest", "login", "xmlrpc", "custom"]


def build_plan(selected: list[str],
               custom_paths: list[str] | None) -> list[PhaseSpec]:
    """The ordered plan from the selected phase keys. Baseline always
    first when present (it's the reference); unknown keys rejected."""
    unknown = [p for p in selected if p not in PHASES]
    if unknown:
        raise ValueError(f"unknown phase(s): {', '.join(unknown)}")
    if not selected:
        raise ValueError("no phases selected")
    if "custom" in selected:
        if not custom_paths:
            raise ValueError("the custom phase needs --custom-paths "
                             "(one path per line)")
        for p in custom_paths:
            if not p.startswith("/"):
                raise ValueError(f"custom path {p!r} must start with /")
    ordered = [k for k in PHASE_ORDER if k in selected]
    return [PHASES[k] for k in ordered]


def request_for(phase: PhaseSpec, base: str, i: int,
                custom_paths: list[str] | None = None) -> dict:
    """Public alias — one request description for the i-th beat."""
    return phase.request_for(base, i, custom_paths)
