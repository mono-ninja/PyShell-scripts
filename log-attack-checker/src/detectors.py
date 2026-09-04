"""Threshold detectors over merged per-IP statistics (O(N) sliding windows)."""
from collections import Counter
from datetime import timedelta

def detect_bruteforce(ip_timestamps: dict, threshold: int, window_minutes: int) -> set:
    """O(N) sliding-window detection. Returns set of flagged IPs."""
    flagged = set()
    window = timedelta(minutes=window_minutes)
    for ip, times in ip_timestamps.items():
        if len(times) < threshold:
            continue
        times_sorted = sorted(times)
        j = 0
        for i in range(len(times_sorted)):
            while times_sorted[i] - times_sorted[j] > window:
                j += 1
            if i - j + 1 >= threshold:
                flagged.add(ip)
                break
    return flagged


def detect_rate_limiting(ip_minute_counts: dict, threshold: int, window_minutes: int) -> set:
    """Sliding-window rate-limit detection over per-IP minute-bucket counts.

    Each IP maps to a ``{minute_epoch: count}`` dict.  We slide a window of
    ``window_minutes + 1`` consecutive buckets (the +1 covers boundary cases
    where a window straddles two minute boundaries) and flag the IP if the sum
    reaches ``threshold``.  This is an over-approximation vs. exact timestamps
    — acceptable for a rate-limit heuristic and saves storing every datetime.
    """
    flagged = set()
    span = window_minutes + 1
    for ip, buckets in ip_minute_counts.items():
        if sum(buckets.values()) < threshold:
            continue
        minutes = sorted(buckets)
        counts = [buckets[m] for m in minutes]
        window_sum = 0
        j = 0
        for i in range(len(minutes)):
            window_sum += counts[i]
            while minutes[i] - minutes[j] >= span:
                window_sum -= counts[j]
                j += 1
            if window_sum >= threshold:
                flagged.add(ip)
                break
    return flagged


def detect_attack_chains(ip_wp_attack_types: dict, min_vectors: int,
                         hostile_vectors: set, ip_2xx: Counter,
                         ip_4xx: Counter, ip_5xx: Counter) -> dict:
    """Flag coordinated attack chains using a two-tier model (C1).

    An IP qualifies when it trips ≥ ``min_vectors`` distinct WP vectors AND at
    least one *hostile* vector AND a majority of its responses are non-2xx
    (i.e. 4xx+5xx > 2xx). Recon-only combinations — a normal admin session
    hitting admin-ajax, wp-admin and wp-json — are excluded because they lack
    a hostile vector and are almost entirely 2xx.
    """
    chains = {}
    for ip, types in ip_wp_attack_types.items():
        if len(types) < min_vectors:
            continue
        if not (types & hostile_vectors):
            continue
        n_2xx = ip_2xx.get(ip, 0)
        n_err = ip_4xx.get(ip, 0) + ip_5xx.get(ip, 0)
        if n_err <= n_2xx:
            continue
        chains[ip] = sorted(types)
    return chains


def detect_attack_bursts(hourly_attacks: Counter, factor: float) -> dict:
    if not hourly_attacks:
        return {}
    values = list(hourly_attacks.values())
    avg = sum(values) / len(values) if values else 0
    if avg == 0:
        return {}
    return {k: v for k, v in hourly_attacks.items() if v > avg * factor}
