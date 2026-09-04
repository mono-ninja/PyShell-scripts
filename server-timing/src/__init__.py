"""srvtime — server response time measurement with phase breakdown.

Measures HTTP(S) response time split into phases (DNS, TCP, TLS, TTFB, transfer),
runs a series of requests, and reports percentiles instead of the mean.
Works both as a plain CLI (``python main.py``) and as a PyShell script.
"""
__version__ = "1.0.0"
