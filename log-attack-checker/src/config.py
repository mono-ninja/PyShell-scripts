"""Runtime configuration and CLI-value normalisation."""
import re
from dataclasses import dataclass, field

def parse_whitelist(raw) -> list:
    """Accept both ``-w 1.2.3.4 5.6.7.8`` and ``-w 1.2.3.4,5.6.7.8`` forms."""
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for item in raw:
        for part in re.split(r"[,\s]+", item):
            part = part.strip()
            if part:
                out.append(part)
    return out

@dataclass
class Config:
    logs_dir: str = "logs"
    output_dir: str = "."
    site: str = ""
    resolved_ip: str = ""
    whitelist: list = field(default_factory=list)
    bruteforce_threshold: int = 5
    wp_login_post_threshold: int = 10
    notfound_flood_threshold: int = 50
    wp_cron_flood_threshold: int = 20
    attack_chain_min_vectors: int = 3
    time_window_minutes: int = 5
    rate_limit_threshold: int = 100
    geoip_limit: int = 20
    skip_geoip: bool = False
    large_response_bytes: int = 100_000
    attack_burst_factor: float = 10.0
