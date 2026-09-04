"""GeoIP enrichment via the ip-api.com batch endpoint."""
from collections import Counter

import requests

from src.config import Config
from src.events import console, logger

def get_geoip(ip_list: list, cfg: Config) -> tuple:
    """Fetch country + proxy/hosting flags via the ip-api.com batch endpoint.

    The free endpoint does not offer TLS and does not identify Tor specifically;
    ``proxy`` (Proxy/VPN) and ``hosting`` (Hosting/Datacenter) are the only
    anonymiser signals it returns.  ``--skip-geoip`` avoids the network call.

    Returns ``(countries, proxy_types, ip_countries)`` where ``ip_countries``
    maps each looked-up IP to its country — used downstream to weight the
    geo-blocking recommendation by request volume, not bare IP count.
    """
    countries = Counter()
    proxy_types = Counter()
    ip_countries = {}
    if not ip_list or cfg.skip_geoip:
        return countries, proxy_types, ip_countries

    ips = ip_list[:cfg.geoip_limit]
    console.print(f"[info]Fetching GeoIP for {len(ips)} IPs (batch)...[/info]")
    logger.info("Fetching GeoIP for %d IPs", len(ips))

    # ip-api.com batch: POST a JSON array of IPs (<=100 per call), get back a
    # list of objects in the same order. One request replaces N sequential ones.
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        try:
            r = requests.post(
                "http://ip-api.com/batch",
                json=batch,
                params={"fields": "status,country,proxy,hosting"},
                timeout=10,
            )
            r.raise_for_status()
            results = r.json()
        except Exception:
            continue
        for ip, entry in zip(batch, results):
            if not isinstance(entry, dict) or entry.get('status') != 'success':
                continue
            country = entry.get('country', 'Unknown')
            if country:
                countries[country] += 1
                ip_countries[ip] = country
            if entry.get('proxy'):
                proxy_types['Proxy/VPN'] += 1
            if entry.get('hosting'):
                proxy_types['Hosting/Datacenter'] += 1

    return countries, proxy_types, ip_countries
