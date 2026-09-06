"""src/engine.py — the paced load generator.

A worker pool (`ThreadPoolExecutor`, thread-local sessions) driven by
a pacer that submits request *i* at `start + i / rps` — the achieved
rate can only undershoot the target (workers or the target can't keep
up), never overshoot it. That's the honest shape: "target rate" is a
ceiling, "achieved rate" is a measurement.

Live reporting follows the uptime-monitor pattern: every wall second
the caller's `on_second` hook fires with the results so far, and the
chart event carries the whole window each time.
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests

_local = threading.local()
USER_AGENT = "PyShell-load-test/1.0"


def configure(user_agent: str) -> None:
    """Set the UA once from main (kept here so the module owns the
    thread-local session factory)."""
    global USER_AGENT
    USER_AGENT = user_agent


class worker_session:
    """Namespace alias — main calls configure(); the pool calls
    _session() per thread. Kept as a small class for a stable import
    surface."""

    @staticmethod
    def configure(user_agent: str) -> None:
        configure(user_agent)


def _session() -> requests.Session:
    """One Session per worker thread — Sessions are not documented
    thread-safe, and thread-locals give each worker its own pool."""
    if getattr(_local, "session", None) is None:
        s = requests.Session()
        s.headers["User-Agent"] = USER_AGENT
        _local.session = s
    return _local.session


@dataclass
class RequestResult:
    offset: float            # seconds since the run started
    phase_key: str
    status: int | None
    latency_ms: float | None # None when the request errored
    error: str = ""


@dataclass
class Pacer:
    """Target: n requests, evenly spaced at rps. `wait_for(i)` sleeps
    until beat i is due."""
    start: float
    rps: float

    def wait_for(self, i: int) -> None:
        due = self.start + i / self.rps
        now = time.monotonic()
        if due > now:
            time.sleep(due - now)


def do_request(desc: dict, phase_key: str, timeout: int,
               t0: float) -> RequestResult:
    """One request, timed wall-clock. Never raises."""
    start = time.monotonic()
    try:
        resp = _session().request(desc["method"], desc["url"],
                                  data=desc.get("data"),
                                  timeout=timeout,
                                  allow_redirects=True)
        latency = (time.monotonic() - start) * 1000
        return RequestResult(offset=start - t0, phase_key=phase_key,
                             status=resp.status_code,
                             latency_ms=round(latency, 1))
    except requests.RequestException as exc:
        latency = (time.monotonic() - start) * 1000
        return RequestResult(offset=start - t0, phase_key=phase_key,
                             status=None,
                             latency_ms=round(latency, 1)
                             if type(exc).__name__ == "Timeout" else None,
                             error=type(exc).__name__)


def run_phase(phase, base: str, rps: int, duration: int, timeout: int,
              progress, on_second=None,
              custom_paths: list[str] | None = None) -> list[RequestResult]:
    """One phase at the target rate. The pacer submits beats; results
    land as they complete; every wall second the live hook fires.
    Returns the phase's results (order roughly by offset)."""
    from .phases import request_for

    total = max(1, rps * duration)
    t0 = time.monotonic()
    pacer = Pacer(start=t0, rps=rps)
    results: list[RequestResult] = []
    lock = threading.Lock()

    workers = min(128, max(8, rps * 2))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []
        last_second = -1
        for i in range(total):
            pacer.wait_for(i)
            desc = request_for(phase, base, i, custom_paths)
            futures.append(pool.submit(do_request, desc, phase.key,
                                       timeout, t0))
            # Live reporting: once per wall second, with everything
            # completed so far.
            second = int(time.monotonic() - t0)
            if second != last_second and on_second is not None:
                last_second = second
                on_second(list(results))
                progress(min(99, int(100 * second / duration)),
                         f"second {second}/{duration} · "
                         f"{len(results)} done")
        for fut in futures:
            r = fut.result()
            with lock:
                results.append(r)

    if on_second is not None:
        on_second(list(results))
    progress(100, f"{len(results)} request(s) done")
    results.sort(key=lambda r: r.offset)
    return results
