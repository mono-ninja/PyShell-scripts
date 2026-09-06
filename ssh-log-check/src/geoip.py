"""src/geoip.py — optional country enrichment via ip-api.com batch.

Same pattern as Log Attack Checker: POST a JSON array (≤100 per call)
to the free ip-api.com batch endpoint, get countries and the
proxy/hosting flags back. Any failure degrades to "no geo" — the
analysis never depends on it. Off entirely with --skip-geoip.
"""
from __future__ import annotations

import requests

from .events import log

BATCH_URL = "http://ip-api.com/batch"
FIELDS = "status,country,countryCode,proxy,hosting"


def fetch_geo(ips: list[str]) -> dict[str, dict]:
    """ip → {country, country_code, proxy, hosting}. Empty dict when the
    endpoint can't be reached — the report says "no geo", never lies."""
    out: dict[str, dict] = {}
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        try:
            resp = requests.post(BATCH_URL, json=batch,
                                 params={"fields": FIELDS}, timeout=10)
            resp.raise_for_status()
            results = resp.json()
        except (requests.RequestException, ValueError) as exc:
            log(f"  ⚠️ GeoIP batch failed ({type(exc).__name__}) — "
                "continuing without geo")
            break
        for ip, entry in zip(batch, results):
            if isinstance(entry, dict) and entry.get("status") == "success":
                out[ip] = {
                    "country": entry.get("country", ""),
                    "country_code": entry.get("countryCode", ""),
                    "proxy": bool(entry.get("proxy")),
                    "hosting": bool(entry.get("hosting")),
                }
    return out
