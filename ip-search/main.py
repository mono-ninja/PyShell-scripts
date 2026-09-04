#!/usr/bin/env python3
"""IP Search — resolve a website's IP address using every available method."""
import argparse
import base64
import csv
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.resolver
except ImportError:
    dns = None


USER_AGENT = "ip-search/1.0"

ALL_METHODS = ["system", "dnspython", "doh", "dot", "connect", "tools",
               "hosting", "dnsrecs", "whois", "cdn", "traceroute"]

RESOLUTION_METHODS = ["system", "dnspython", "doh", "dot", "connect", "tools"]
ANALYSIS_METHODS = ["hosting", "dnsrecs", "whois", "cdn", "traceroute"]

DOH_PROVIDERS = [
    ("Google (8.8.8.8)", "https://dns.google/resolve", "https://dns.google/dns-query"),
    ("Cloudflare (1.1.1.1)", "https://cloudflare-dns.com/dns-query", "https://cloudflare-dns.com/dns-query"),
    ("DNS.SB", "https://doh.dns.sb/dns-query", "https://doh.dns.sb/dns-query"),
]

DOT_SERVERS = [
    ("Google (8.8.8.8)", "8.8.8.8"),
    ("Cloudflare (1.1.1.1)", "1.1.1.1"),
]

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 28: "AAAA", 15: "MX", 6: "SOA"}

# Common multi-part registrable-domain suffixes. Anything ending in one of
# these has its registrable domain three labels deep; otherwise two.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.ua", "org.ua", "net.ua", "gov.ua", "in.ua", "at.ua", "kiev.ua",
    "co.jp", "co.kr", "co.nz", "co.in", "co.id", "co.th", "co.za",
    "co.il", "co.at", "com.au", "com.br", "com.cn", "com.tw", "com.sg",
    "com.mx", "com.ar", "com.hk", "com.my", "com.tr", "com.pl", "com.es",
    "com.tw", "net.au", "org.au", "edu.au", "eu.org",
}

# Org-name fragments that mark a CDN edge; SSH banner grab is skipped for these.
CDN_ORG_NAMES = ("cloudflare", "cloudfront", "fastly", "akamai", "vercel",
                 "sucuri", "amazon", "aws", "azure", "imperva", "incapsula",
                 "bunny", "keycdn")

# Stable display ordering for the results table.
METHOD_ORDER = {
    "socket.getaddrinfo": 0, "socket.gethostbyname": 1,
    "socket.gethostbyname_ex": 2, "dnspython": 3,
    "dnspython (raw UDP)": 4, "DNS-over-HTTPS": 5, "DNS-over-TLS": 6,
    "TCP socket connect": 7, "http.client": 8, "dig": 9, "host": 10,
    "nslookup": 11,
}


def emit(event):
    event["pyshell"] = True
    print(json.dumps(event), file=sys.stderr, flush=True)


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def looks_like_host(s):
    """True if *s* plausibly a DNS hostname (used to accept CNAME targets)."""
    if not s or len(s) > 253:
        return False
    s = s.rstrip(".")
    if "." not in s:
        return False
    return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$", s))


def md_escape(s):
    """Escape a value for safe interpolation into markdown tables / inline."""
    if s is None:
        return ""
    s = str(s)
    s = s.replace("|", "\\|")
    s = s.replace("\n", " ")
    return s


def source_group(source):
    """Collapse a method's descriptive *source* into an independent origin."""
    s = (source or "").lower()
    if "google" in s or "8.8.8.8" in s:
        return "Google (8.8.8.8)"
    if "cloudflare" in s or "1.1.1.1" in s:
        return "Cloudflare (1.1.1.1)"
    if "dns.sb" in s:
        return "DNS.SB"
    if s.startswith("port ") or s.startswith("https://") or s.startswith("http://"):
        return "observed peer"
    return "local resolver"


def registrable_domain(host):
    """Derive the registrable domain, stripping subdomains like ``www``.

    Punycodes IDN hosts first (RDAP expects the A-label). Falls back to the
    last two labels, or three when the last two are a known multi-part suffix.
    """
    host = (host or "").lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return last_two


def extract_host(url):
    if "://" not in url:
        url = "http://" + url
    return urlparse(url).hostname


def result(method, source, value, rtype, ttl="", details="", status="OK",
           ms=0.0, hosting=""):
    if ttl is None or ttl == "":
        ttl = ""
    else:
        try:
            ttl = int(ttl)
        except (ValueError, TypeError):
            ttl = str(ttl)
    ip = value if is_ip(value) else ""
    return {
        "method": method,
        "source": source,
        "source_group": source_group(source),
        "ip": ip,
        "value": value,
        "type": rtype,
        "ttl": ttl,
        "details": details,
        "status": status,
        "ms": round(ms, 1),
        "hosting": hosting,
    }


def parse_dns_response(resp):
    out = []
    for rrset in resp.answer:
        for rdata in rrset:
            if rdata.rdtype == dns.rdatatype.A:
                out.append((str(rdata), "A", rrset.ttl))
            elif rdata.rdtype == dns.rdatatype.AAAA:
                out.append((str(rdata), "AAAA", rrset.ttl))
            elif rdata.rdtype == dns.rdatatype.CNAME:
                out.append((str(rdata.target), "CNAME", rrset.ttl))
    return out


# --- HTTP helper (User-Agent + one retry on 429/5xx/timeout) ---

def http_get_json(url, timeout, headers=None, retries=1):
    """GET *url* and return parsed JSON. Retries once on transient errors."""
    hdrs = {"accept": "application/json", "user-agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = e
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
    raise last_err


# --- Resolution methods ---

def m_getaddrinfo(host, timeout, ipv6):
    out = []
    t0 = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        seen = set()
        for info in infos:
            ip = info[4][0]
            if ip in seen:
                continue
            seen.add(ip)
            rtype = "AAAA" if ":" in ip else "A"
            if rtype == "AAAA" and not ipv6:
                continue
            out.append(result("socket.getaddrinfo", "system resolver", ip, rtype,
                              ms=(time.monotonic() - t0) * 1000))
    except Exception as e:
        out.append(result("socket.getaddrinfo", "system resolver", "", "",
                          status="ERROR", details=type(e).__name__ + ": " + str(e),
                          ms=(time.monotonic() - t0) * 1000))
    return out


def m_gethostbyname(host, timeout, ipv6):
    out = []
    for label, fn in (("socket.gethostbyname", socket.gethostbyname),
                      ("socket.gethostbyname_ex", socket.gethostbyname_ex)):
        t0 = time.monotonic()
        try:
            res = fn(host)
            if label.endswith("_ex"):
                canonical, aliases, ips = res
                detail = "canonical=" + canonical
                if aliases:
                    detail += "; aliases=" + ",".join(aliases)
                for ip in ips:
                    out.append(result(label, "system resolver", ip, "A",
                                      details=detail, ms=(time.monotonic() - t0) * 1000))
            else:
                out.append(result(label, "system resolver", res, "A",
                                  ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result(label, "system resolver", "", "",
                              status="ERROR", details=type(e).__name__ + ": " + str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


def m_dnspython_resolver(host, timeout, ipv6):
    if dns is None:
        return [result("dnspython", "system resolver", "", "",
                       status="SKIPPED", details="dnspython not installed")]
    out = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    for rdtype in (["A", "AAAA"] if ipv6 else ["A"]):
        t0 = time.monotonic()
        try:
            answer = resolver.resolve(host, rdtype)
            for rrset in answer.response.answer:
                for rdata in rrset:
                    if rdata.rdtype == dns.rdatatype.A:
                        out.append(result("dnspython", "system resolver", str(rdata), "A",
                                          ttl=rrset.ttl, ms=(time.monotonic() - t0) * 1000))
                    elif rdata.rdtype == dns.rdatatype.AAAA:
                        out.append(result("dnspython", "system resolver", str(rdata), "AAAA",
                                          ttl=rrset.ttl, ms=(time.monotonic() - t0) * 1000))
                    elif rdata.rdtype == dns.rdatatype.CNAME:
                        out.append(result("dnspython", "system resolver", str(rdata.target), "CNAME",
                                          ttl=rrset.ttl, ms=(time.monotonic() - t0) * 1000))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN as e:
            out.append(result("dnspython", "system resolver", "", rdtype,
                              status="ERROR", details="NXDOMAIN", ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("dnspython", "system resolver", "", rdtype,
                              status="ERROR", details=type(e).__name__ + ": " + str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


def m_dnspython_udp(host, timeout, ipv6, server, label):
    if dns is None:
        return [result("dnspython (raw UDP)", label, "", "",
                       status="SKIPPED", details="dnspython not installed")]
    out = []
    for rdtype in (["A", "AAAA"] if ipv6 else ["A"]):
        t0 = time.monotonic()
        try:
            q = dns.message.make_query(host, rdtype)
            resp = dns.query.udp(q, server, timeout=timeout)
            for ip, rtype, ttl in parse_dns_response(resp):
                out.append(result("dnspython (raw UDP)", label, ip, rtype,
                                  ttl=ttl, ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("dnspython (raw UDP)", label, "", rdtype,
                              status="ERROR", details=type(e).__name__ + ": " + str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


def doh_wireformat(host, rdtype, wire_url, timeout):
    q = dns.message.make_query(host, rdtype)
    wire = q.to_wire()
    b64 = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")
    full = wire_url + "?dns=" + b64
    req = urllib.request.Request(
        full, headers={"accept": "application/dns-message",
                       "user-agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return parse_dns_response(dns.message.from_wire(data))


def doh_json(host, rdtype, json_url, timeout):
    full = json_url + "?" + urllib.parse.urlencode({"name": host, "type": rdtype})
    data = http_get_json(full, timeout, headers={"accept": "application/dns-json"})
    out = []
    for ans in data.get("Answer", []):
        rtype = DNS_TYPES.get(ans.get("type"), str(ans.get("type")))
        if rtype in ("A", "AAAA", "CNAME"):
            out.append((ans.get("data", ""), rtype, ans.get("TTL", "")))
    return out


def m_doh(host, timeout, ipv6, label, json_url, wire_url):
    out = []
    for rdtype in (["A", "AAAA"] if ipv6 else ["A"]):
        t0 = time.monotonic()
        records = None
        note = ""
        if dns is not None and wire_url:
            try:
                records = doh_wireformat(host, rdtype, wire_url, timeout)
            except Exception as e:
                note = "wireformat: " + type(e).__name__ + ": " + str(e)
        if records is None and json_url:
            try:
                records = doh_json(host, rdtype, json_url, timeout)
            except Exception as e:
                note = note or (type(e).__name__ + ": " + str(e))
        if records is None:
            out.append(result("DNS-over-HTTPS", label, "", rdtype,
                              status="ERROR", details=note,
                              ms=(time.monotonic() - t0) * 1000))
            continue
        if not records:
            out.append(result("DNS-over-HTTPS", label, "", rdtype,
                              status="ERROR", details="no records",
                              ms=(time.monotonic() - t0) * 1000))
            continue
        for ip, rtype, ttl in records:
            if rtype == "AAAA" and not ipv6:
                continue
            out.append(result("DNS-over-HTTPS", label, ip, rtype, ttl=ttl,
                              ms=(time.monotonic() - t0) * 1000))
    return out


def _dot_query(host, rdtype, server, timeout):
    q = dns.message.make_query(host, rdtype)
    try:
        return dns.query.tls(q, server, timeout=timeout, port=853), "TLS verified"
    except Exception:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return dns.query.tls(q, server, timeout=timeout, port=853, ssl_context=ctx), "TLS unverified"


def m_dot(host, timeout, ipv6, label, server):
    if dns is None:
        return [result("DNS-over-TLS", label, "", "",
                       status="SKIPPED", details="dnspython not installed")]
    out = []
    for rdtype in (["A", "AAAA"] if ipv6 else ["A"]):
        t0 = time.monotonic()
        try:
            resp, note = _dot_query(host, rdtype, server, timeout)
            for ip, rtype, ttl in parse_dns_response(resp):
                out.append(result("DNS-over-TLS", label, ip, rtype, ttl=ttl,
                                  details=note, ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("DNS-over-TLS", label, "", rdtype,
                              status="ERROR", details=type(e).__name__ + ": " + str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


def m_socket_connect(host, timeout, ipv6):
    out = []
    for port in (443, 80):
        t0 = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                ip = sock.getpeername()[0]
                rtype = "AAAA" if ":" in ip else "A"
                if rtype == "AAAA" and not ipv6:
                    continue
                out.append(result("TCP socket connect", "port %d" % port, ip, rtype,
                                  details="connected to port %d" % port,
                                  ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("TCP socket connect", "port %d" % port, "", "",
                              status="ERROR", details=type(e).__name__ + ": " + str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


def m_httpclient(host, timeout, ipv6):
    out = []
    for scheme, port in (("https", 443), ("http", 80)):
        t0 = time.monotonic()
        conn = None
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("HEAD", "/", headers={"User-Agent": USER_AGENT})
            conn.getresponse()
            ip = conn.sock.getpeername()[0]
            rtype = "AAAA" if ":" in ip else "A"
            if rtype == "AAAA" and not ipv6:
                continue
            out.append(result("http.client", "%s://%s" % (scheme, host), ip, rtype,
                              details="%s connection" % scheme,
                              ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("http.client", "%s://%s" % (scheme, host), "", "",
                              status="ERROR", details=type(e).__name__ + ": " + str(e),
                              ms=(time.monotonic() - t0) * 1000))
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    return out


def _parse_dig_answer_line(line):
    """Parse a ``dig +noall +answer`` line → (value, rtype, ttl) or None."""
    parts = line.split()
    if len(parts) < 5 or parts[2] != "IN":
        return None
    rtype = parts[3]
    if rtype not in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"):
        return None
    ttl = parts[1]
    value = " ".join(parts[4:])
    return value, rtype, ttl


def m_dig(host, timeout, ipv6):
    out = []
    for rdtype in (["A", "AAAA"] if ipv6 else ["A"]):
        t0 = time.monotonic()
        try:
            cmd = ["dig", "+noall", "+answer", "+time=" + str(timeout), host, rdtype]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            found = False
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                parsed = _parse_dig_answer_line(line)
                if not parsed:
                    continue
                val, rtype, ttl = parsed
                if rtype == "CNAME":
                    val = val.rstrip(".")
                    if not looks_like_host(val):
                        continue
                if rtype == "AAAA" and not ipv6:
                    continue
                found = True
                out.append(result("dig", "system tool", val, rtype, ttl=ttl,
                                  ms=(time.monotonic() - t0) * 1000))
            if not found:
                out.append(result("dig", "system tool", "", rdtype,
                                  status="ERROR", details="no records",
                                  ms=(time.monotonic() - t0) * 1000))
        except FileNotFoundError:
            out.append(result("dig", "system tool", "", rdtype,
                              status="SKIPPED", details="dig not installed",
                              ms=(time.monotonic() - t0) * 1000))
        except subprocess.TimeoutExpired:
            out.append(result("dig", "system tool", "", rdtype,
                              status="ERROR", details="timeout",
                              ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("dig", "system tool", "", rdtype,
                              status="ERROR", details=str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


def m_host(host, timeout, ipv6):
    out = []
    seen_cnames = set()
    for rdtype in (["A", "AAAA"] if ipv6 else ["A"]):
        t0 = time.monotonic()
        try:
            cmd = ["host", "-W", str(timeout), "-t", rdtype, host]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            found = False
            for line in proc.stdout.splitlines():
                line = line.strip()
                if "has IPv6 address" in line:
                    found = True
                    out.append(result("host", "system tool", line.split()[-1], "AAAA",
                                      ms=(time.monotonic() - t0) * 1000))
                elif "has address" in line:
                    found = True
                    out.append(result("host", "system tool", line.split()[-1], "A",
                                      ms=(time.monotonic() - t0) * 1000))
                elif "is an alias for" in line:
                    cname = line.split()[-1].rstrip(".")
                    if cname not in seen_cnames:
                        seen_cnames.add(cname)
                        found = True
                        out.append(result("host", "system tool", cname, "CNAME",
                                          ms=(time.monotonic() - t0) * 1000))
            if not found:
                out.append(result("host", "system tool", "", rdtype,
                                  status="ERROR", details="no records",
                                  ms=(time.monotonic() - t0) * 1000))
        except FileNotFoundError:
            out.append(result("host", "system tool", "", rdtype,
                              status="SKIPPED", details="host not installed",
                              ms=(time.monotonic() - t0) * 1000))
        except subprocess.TimeoutExpired:
            out.append(result("host", "system tool", "", rdtype,
                              status="ERROR", details="timeout",
                              ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("host", "system tool", "", rdtype,
                              status="ERROR", details=str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


def parse_nslookup_ips(stdout):
    """Extract answer IPs from nslookup output, robust across BIND/Windows.

    Skips the resolver header block (everything up to the first blank line),
    ignores ``#port``-bearing tokens, and stops at the trailing
    ``Authoritative answers can be found from:`` section whose NS IPs are
    decoys. Works for the ``has address`` / ``has AAAA address`` (BIND) and
    ``Name:`` / ``Address:`` (Windows) answer formats alike.
    """
    lines = stdout.splitlines()
    start = 0
    for idx, line in enumerate(lines):
        if line.strip() == "":
            start = idx + 1
            break
    ips = []
    seen = set()
    for line in lines[start:]:
        low = line.strip().lower()
        if low.startswith("authoritative answers can be found"):
            break
        if low.startswith("server:"):
            continue
        for token in line.split():
            if "#" in token:
                continue
            if is_ip(token) and token not in seen:
                seen.add(token)
                ips.append(token)
    return ips


def m_nslookup(host, timeout, ipv6):
    out = []
    for rdtype in (["A", "AAAA"] if ipv6 else ["A"]):
        t0 = time.monotonic()
        try:
            cmd = ["nslookup", "-timeout=" + str(timeout), "-type=" + rdtype, host]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            ips = parse_nslookup_ips(proc.stdout)
            if not ips:
                out.append(result("nslookup", "system tool", "", rdtype,
                                  status="ERROR", details="no addresses parsed",
                                  ms=(time.monotonic() - t0) * 1000))
            for ip in ips:
                rtype = "AAAA" if ":" in ip else "A"
                if rtype == "AAAA" and not ipv6:
                    continue
                out.append(result("nslookup", "system tool", ip, rtype,
                                  ms=(time.monotonic() - t0) * 1000))
        except FileNotFoundError:
            out.append(result("nslookup", "system tool", "", rdtype,
                              status="SKIPPED", details="nslookup not installed",
                              ms=(time.monotonic() - t0) * 1000))
        except subprocess.TimeoutExpired:
            out.append(result("nslookup", "system tool", "", rdtype,
                              status="ERROR", details="timeout",
                              ms=(time.monotonic() - t0) * 1000))
        except Exception as e:
            out.append(result("nslookup", "system tool", "", rdtype,
                              status="ERROR", details=str(e),
                              ms=(time.monotonic() - t0) * 1000))
    return out


# --- Hosting (RDAP + ASN + PTR + optional SSH banner) ---

def rdap_lookup(ip, timeout):
    """Query RDAP for IP registration data. Falls back to ARIN on transient errors."""
    url = "https://rdap.org/ip/" + urllib.parse.quote(ip, safe=":")
    try:
        return http_get_json(url, timeout, headers={"accept": "application/rdap+json"})
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise
        url2 = "https://rdap.arin.net/registry/ip/" + urllib.parse.quote(ip, safe=":")
        return http_get_json(url2, timeout, headers={"accept": "application/rdap+json"})
    except Exception:
        url2 = "https://rdap.arin.net/registry/ip/" + urllib.parse.quote(ip, safe=":")
        return http_get_json(url2, timeout, headers={"accept": "application/rdap+json"})


def parse_rdap(data):
    """Extract org, network, ASN, country, CIDR from an RDAP response."""
    net_name = data.get("name") or ""
    country = data.get("country") or ""
    org_name = ""
    asn = ""
    adr_label = ""
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard_arr = entity.get("vcardArray", [])
        vcard = vcard_arr[1] if len(vcard_arr) > 1 else []
        for entry in vcard:
            if entry[0] == "fn" and ("registrant" in roles or "administrative" in roles):
                org_name = entry[3] if len(entry) > 3 else ""
            if entry[0] == "adr":
                params = entry[1] if len(entry) > 1 else {}
                if isinstance(params, dict) and "label" in params:
                    adr_label = params["label"]
        handle = entity.get("handle", "")
        if handle.startswith("AS") and handle[2:].isdigit():
            asn = handle
        for sub in entity.get("entities", []):
            sub_handle = sub.get("handle", "")
            if sub_handle.startswith("AS") and sub_handle[2:].isdigit():
                asn = sub_handle
    if not country and adr_label:
        lines = [l.strip() for l in adr_label.split("\n") if l.strip()]
        if lines:
            country = lines[-1]
    cidrs = []
    for c in data.get("cidr0_cidrs", []):
        v4 = c.get("v4prefix")
        v6p = c.get("v6prefix")
        if v4:
            cidrs.append("%s/%d" % (v4, c.get("length", 0)))
        if v6p:
            cidrs.append("%s/%d" % (v6p, c.get("length", 0)))
    if not cidrs:
        start = data.get("startAddress", "")
        end = data.get("endAddress", "")
        if start and end:
            cidrs.append("%s - %s" % (start, end))
    return {
        "org": org_name or net_name,
        "network": net_name,
        "asn": asn,
        "country": country,
        "cidr": ", ".join(cidrs) if cidrs else "",
    }


def ptr_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""


def ssh_banner(ip, port, timeout):
    try:
        sock_timeout = min(timeout, 5)
        with socket.create_connection((ip, port), timeout=sock_timeout) as sock:
            sock.settimeout(sock_timeout)
            data = sock.recv(256)
            banner = data.decode("utf-8", errors="replace").strip()
            return banner if banner.startswith("SSH-") else ""
    except Exception:
        return ""


def asn_lookup(ip, timeout):
    """Look up announcing ASN and AS name via RIPEstat."""
    res = {"asn": "", "as_name": "", "prefix": "", "error": ""}
    try:
        url = "https://stat.ripe.net/data/network-info/data.json?resource=" + ip
        data = http_get_json(url, timeout)
        asns = data.get("data", {}).get("asns", [])
        if asns:
            res["asn"] = "AS" + asns[0]
            res["prefix"] = data.get("data", {}).get("prefix", "")
        if res["asn"]:
            url2 = ("https://stat.ripe.net/data/as-overview/data.json?resource="
                    + res["asn"])
            data2 = http_get_json(url2, timeout)
            res["as_name"] = data2.get("data", {}).get("holder", "")
    except Exception as e:
        res["error"] = type(e).__name__
    return res


class RdapCache:
    """Cache RDAP results by network so CDN-shared allocations are queried once."""

    def __init__(self):
        self._entries = []  # list of (ip_network, info)
        self._lock = threading.Lock()

    def lookup(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return None
        with self._lock:
            for net, info in self._entries:
                if addr in net:
                    return dict(info)
        return None

    def store(self, ip, info):
        cidr = info.get("cidr", "")
        if not cidr:
            return
        for token in cidr.split(","):
            token = token.strip()
            if " - " in token or not token:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            with self._lock:
                self._entries.append((net, dict(info)))
            break


def hosting_lookup(ip, timeout, do_ssh, ssh_port, rdap_cache=None):
    """Look up hosting info for an IP: RDAP + ASN + PTR + optional SSH banner."""
    info = {"org": "", "network": "", "asn": "", "as_name": "", "country": "",
            "cidr": "", "ptr": "", "ssh": "", "error": "", "cached": False}
    cached = rdap_cache.lookup(ip) if rdap_cache else None
    if cached:
        for k in ("org", "network", "asn", "as_name", "country", "cidr"):
            info[k] = cached.get(k, "")
        info["cached"] = True
    else:
        try:
            data = rdap_lookup(ip, timeout)
            info.update(parse_rdap(data))
            if rdap_cache:
                rdap_cache.store(ip, info)
        except urllib.error.HTTPError as e:
            info["error"] = "RDAP HTTP %d" % e.code
        except Exception as e:
            info["error"] = "RDAP: " + type(e).__name__
        if not info["asn"]:
            asn_info = asn_lookup(ip, timeout)
            if asn_info["asn"]:
                info["asn"] = asn_info["asn"]
            if asn_info["as_name"]:
                info["as_name"] = asn_info["as_name"]
            if asn_info.get("error") and not info["error"]:
                info["error"] = "ASN: " + asn_info["error"]
    info["ptr"] = ptr_lookup(ip)
    if do_ssh:
        org_low = (info.get("org") or "").lower()
        if any(c in org_low for c in CDN_ORG_NAMES):
            info["ssh"] = "skipped (CDN edge)"
        else:
            info["ssh"] = ssh_banner(ip, ssh_port, timeout)
    if not info["org"] and info["network"]:
        info["org"] = info["network"]
    if not info["org"] and info.get("as_name"):
        info["org"] = info["as_name"]
    return info


# --- DNS records (NS, MX, TXT, SOA, CAA) ---

DNSREC_TYPES = ["NS", "MX", "TXT", "SOA", "CAA"]


def m_dns_records(host, timeout):
    """Query additional DNS record types on the registrable domain.

    Returns ``{"records": [...], "no_answer": [...], "queried": name}`` so the
    summary can tell “no such record” apart from “method never ran”.
    """
    queried = registrable_domain(host)
    records = []
    no_answer = []
    if dns is not None:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        for rdtype in DNSREC_TYPES:
            t0 = time.monotonic()
            try:
                answer = resolver.resolve(queried, rdtype)
                for rrset in answer.response.answer:
                    for rdata in rrset:
                        records.append({
                            "type": rdtype, "value": str(rdata).strip(),
                            "ttl": rrset.ttl, "status": "OK",
                            "ms": round((time.monotonic() - t0) * 1000, 1),
                        })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                no_answer.append(rdtype)
            except Exception as e:
                records.append({"type": rdtype, "value": "", "ttl": "",
                                "status": "ERROR",
                                "details": type(e).__name__ + ": " + str(e),
                                "ms": round((time.monotonic() - t0) * 1000, 1)})
    else:
        for rdtype in DNSREC_TYPES:
            t0 = time.monotonic()
            try:
                cmd = ["dig", "+noall", "+answer", "+time=" + str(timeout),
                       queried, rdtype]
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=timeout + 5)
                found = False
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    parsed = _parse_dig_answer_line(line)
                    if not parsed:
                        continue
                    val, rtype, ttl = parsed
                    if rtype != rdtype:
                        continue
                    found = True
                    records.append({"type": rdtype, "value": val, "ttl": ttl,
                                    "status": "OK",
                                    "ms": round((time.monotonic() - t0) * 1000, 1)})
                if not found:
                    no_answer.append(rdtype)
            except FileNotFoundError:
                records.append({"type": rdtype, "value": "", "ttl": "",
                                "status": "SKIPPED", "details": "dig not installed",
                                "ms": round((time.monotonic() - t0) * 1000, 1)})
            except Exception as e:
                records.append({"type": rdtype, "value": "", "ttl": "",
                                "status": "ERROR", "details": str(e),
                                "ms": round((time.monotonic() - t0) * 1000, 1)})
    return {"records": records, "no_answer": no_answer, "queried": queried}


# --- Domain WHOIS via RDAP ---

def m_domain_whois(host, timeout):
    """Query domain registration data via RDAP on the registrable domain."""
    info = {"registrar": "", "created": "", "updated": "", "expires": "",
            "nameservers": [], "status": [], "dnssec": False, "error": "",
            "queried": ""}
    reg_domain = registrable_domain(host)
    info["queried"] = reg_domain
    url = "https://rdap.org/domain/" + urllib.parse.quote(reg_domain, safe=".")
    try:
        data = http_get_json(url, timeout, headers={"accept": "application/rdap+json"})
    except urllib.error.HTTPError as e:
        if e.code == 404 and host != reg_domain:
            info["queried"] = host
            url2 = "https://rdap.org/domain/" + urllib.parse.quote(host, safe=".")
            try:
                data = http_get_json(url2, timeout,
                                     headers={"accept": "application/rdap+json"})
            except urllib.error.HTTPError as e2:
                info["error"] = "RDAP HTTP %d" % e2.code
                return info
            except Exception as e2:
                info["error"] = type(e2).__name__ + ": " + str(e2)
                return info
        else:
            info["error"] = "RDAP HTTP %d" % e.code
            return info
    except Exception as e:
        info["error"] = type(e).__name__ + ": " + str(e)
        return info
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration":
            info["created"] = date
        elif action == "last changed":
            info["updated"] = date
        elif action == "expiration":
            info["expires"] = date
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])[1] or []
            for entry in vcard:
                if entry[0] == "fn" and len(entry) > 3:
                    info["registrar"] = entry[3]
    for ns in data.get("nameservers", []):
        name = ns.get("ldhName", "") or ns.get("unicodeName", "")
        if name:
            info["nameservers"].append(name)
    info["status"] = data.get("status", [])
    info["dnssec"] = bool(data.get("secureDNS", {}).get("delegationSigned", False))
    return info


# --- CDN / WAF detection ---

CDN_SIGNATURES = [
    ("cf-ray", "", "Cloudflare"),
    ("cloudflare", "", "Cloudflare"),
    ("x-fastly-request-id", "", "Fastly"),
    ("x-served-by", "cache-", "Fastly"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-amz-cf-pop", "", "AWS CloudFront"),
    ("x-akamai-transformed", "", "Akamai"),
    ("x-vercel-id", "", "Vercel"),
    ("x-vercel-proxy", "", "Vercel"),
    ("x-sucuri-id", "", "Sucuri WAF"),
    ("x-drupal-cache", "", "Drupal"),
    ("x-github-request", "", "GitHub"),
    ("fly-request-id", "", "Fly.io"),
    ("x-bunnycdn-", "", "BunnyCDN"),
    ("x-keycdn-", "", "KeyCDN"),
    ("x-cdn-", "", "CDN"),
    ("server", "cloudflare", "Cloudflare"),
    ("server", "cloudfront", "AWS CloudFront"),
    ("x-powered-by", "express", "Express"),
]

WAF_SIGNATURES = [
    ("x-sucuri-id", "Sucuri"),
    ("cf-ray", "Cloudflare WAF"),
    ("x-waf-", "WAF"),
]


def m_cdn_detect(host, timeout):
    """Detect CDN/WAF via HTTP headers and TLS certificate."""
    info = {"cdn": "", "waf": "", "server": "", "powered_by": "",
            "via": "", "headers": {}, "cert_issuer": "", "cert_sans": [],
            "cert_error": "", "error": "", "scheme_errors": []}
    for scheme, port in (("https", 443), ("http", 80)):
        conn = None
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request("HEAD", "/", headers={"User-Agent": USER_AGENT})
            resp = conn.getresponse()
            info["headers"] = {k: v for k, v in resp.getheaders()}
            info["server"] = resp.getheader("Server", "") or ""
            info["powered_by"] = resp.getheader("X-Powered-By", "") or ""
            info["via"] = resp.getheader("Via", "") or ""
            resp.read()
            conn.close()
            info["error"] = ""
            break
        except Exception as e:
            info["scheme_errors"].append("%s: %s" % (scheme, type(e).__name__))
            info["error"] = type(e).__name__ + ": " + str(e)
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    for h_name, h_val in info["headers"].items():
        hl = h_name.lower()
        vl = h_val.lower()
        for sig_h, sig_v, cdn_name in CDN_SIGNATURES:
            if hl == sig_h or hl.startswith(sig_h):
                if not sig_v or sig_v in vl:
                    if not info["cdn"]:
                        info["cdn"] = cdn_name
        for sig_h, waf_name in WAF_SIGNATURES:
            if hl == sig_h or hl.startswith(sig_h):
                if not info["waf"]:
                    info["waf"] = waf_name

    if not info["cdn"] and info["server"]:
        sl = info["server"].lower()
        if "cloudflare" in sl:
            info["cdn"] = "Cloudflare"
        elif "cloudfront" in sl:
            info["cdn"] = "AWS CloudFront"

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    info["cert_issuer"] = issuer.get("organizationName", "") or \
                        issuer.get("commonName", "")
                    san = cert.get("subjectAltName", ())
                    info["cert_sans"] = [x[1] for x in san if x[0] == "DNS"]
                    il = info["cert_issuer"].lower()
                    if "cloudflare" in il and not info["cdn"]:
                        info["cdn"] = "Cloudflare"
    except Exception as e:
        info["cert_error"] = type(e).__name__

    return info


# --- Traceroute ---

def _parse_traceroute_lines(lines, is_win):
    """Parse traceroute/tracert output lines into hop dicts."""
    hops = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if is_win:
            if line.startswith("Tracing route") or "over a maximum" in line:
                continue
            if "Trace complete" in line:
                continue
            parts = line.split()
            if parts and parts[0].isdigit():
                hop_num = int(parts[0])
                ip = ""
                hostname = ""
                ms_vals = []
                rest = parts[1:]
                i = 0
                while i < len(rest):
                    p = rest[i]
                    if p == "*" or (re.match(r"^\d+ms$", p) or re.match(r"^\d+\s+ms$", p)):
                        ms_vals.append(p)
                        if p == "*" and i + 1 < len(rest) and rest[i + 1] == "ms":
                            i += 1
                    elif is_ip(p):
                        ip = p
                    elif p != "ms":
                        if not hostname:
                            hostname = p
                    i += 1
                hops.append({"hop": hop_num, "ip": ip, "hostname": hostname,
                             "ms": " ".join(ms_vals) if ms_vals else "*"})
        else:
            if line.startswith("traceroute"):
                continue
            parts = line.split()
            if parts and parts[0].isdigit():
                hop_num = int(parts[0])
                ip = ""
                hostname = ""
                rest = parts[1:]
                i = 0
                while i < len(rest):
                    p = rest[i]
                    if p.startswith("(") and p.endswith(")"):
                        ip = p[1:-1]
                    elif is_ip(p) and not ip:
                        ip = p
                        if not hostname:
                            hostname = p
                    elif p.endswith("ms"):
                        pass
                    elif not p.replace(".", "").replace("-", "").isalnum():
                        pass
                    else:
                        if not hostname and not is_ip(p):
                            hostname = p
                    i += 1
                ms_vals = []
                for j, p in enumerate(rest):
                    if p == "ms" and j > 0:
                        ms_vals.append(rest[j - 1] + " ms")
                    elif p.endswith("ms") and p != "ms":
                        ms_vals.append(p)
                    elif p == "*" and not ms_vals:
                        ms_vals.append("*")
                hops.append({"hop": hop_num, "ip": ip, "hostname": hostname,
                             "ms": " ".join(ms_vals) if ms_vals else "*"})
    return hops


def m_traceroute(host, timeout):
    """Run traceroute to the host, preserving partial output on timeout."""
    cmd_name = "tracert" if sys.platform == "win32" else "traceroute"
    is_win = sys.platform == "win32"
    wait = min(timeout, 3)
    max_hops = 15
    proc_timeout = max(max_hops * wait, 30)
    try:
        if is_win:
            cmd = [cmd_name, "-w", str(wait * 1000), "-h", str(max_hops), host]
        else:
            cmd = [cmd_name, "-w", str(wait), "-m", str(max_hops), "-q", "1", host]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=proc_timeout)
        hops = _parse_traceroute_lines(proc.stdout.splitlines(), is_win)
        if not hops:
            hops.append({"hop": 0, "ip": "", "hostname": "", "ms": "",
                         "error": "no hops parsed"})
        return hops
    except FileNotFoundError:
        return [{"hop": 0, "ip": "", "hostname": "", "ms": "",
                 "error": cmd_name + " not installed"}]
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        hops = _parse_traceroute_lines(partial.splitlines(), is_win)
        if hops:
            hops.append({"hop": 0, "ip": "", "hostname": "", "ms": "",
                         "error": "timeout (partial trace)"})
        else:
            hops.append({"hop": 0, "ip": "", "hostname": "", "ms": "",
                         "error": "timeout"})
        return hops
    except Exception as e:
        return [{"hop": 0, "ip": "", "hostname": "", "ms": "",
                 "error": str(e)}]


# --- Task assembly & progress ---

class Phase:
    """Map a phase's 0..1 progress onto a slice of the single 0–100 bar.

    Emits at most one event per whole percent (each event is a separate IPC
    message — see _reference/authoring-guide.md, “Rate-limit yourself”).
    """

    def __init__(self, name, lo, hi):
        self.name = name
        self.lo = lo
        self.hi = hi
        self._last = -1

    def report(self, done, total, detail=""):
        fraction = done / total if total else 1.0
        pct = int(self.lo + (self.hi - self.lo) * fraction)
        if pct == self._last:
            return
        self._last = pct
        message = "%s — %s" % (self.name, detail) if detail else self.name
        emit({"type": "progress", "pct": pct, "message": message})

    def done(self):
        if self._last != int(self.hi):
            self._last = int(self.hi)
            emit({"type": "progress", "pct": int(self.hi), "message": self.name})


def build_tasks(methods, host, timeout, ipv6):
    tasks = []
    if "system" in methods:
        tasks.append(("socket.getaddrinfo", lambda: m_getaddrinfo(host, timeout, ipv6)))
        tasks.append(("socket.gethostbyname(_ex)", lambda: m_gethostbyname(host, timeout, ipv6)))
    if "dnspython" in methods:
        tasks.append(("dnspython resolver", lambda: m_dnspython_resolver(host, timeout, ipv6)))
        tasks.append(("dnspython UDP 8.8.8.8", lambda: m_dnspython_udp(host, timeout, ipv6, "8.8.8.8", "Google")))
        tasks.append(("dnspython UDP 1.1.1.1", lambda: m_dnspython_udp(host, timeout, ipv6, "1.1.1.1", "Cloudflare")))
    if "doh" in methods:
        for label, json_url, wire_url in DOH_PROVIDERS:
            tasks.append(("DoH " + label,
                          lambda l=label, j=json_url, w=wire_url: m_doh(host, timeout, ipv6, l, j, w)))
    if "dot" in methods:
        for label, server in DOT_SERVERS:
            tasks.append(("DoT " + label, lambda l=label, s=server: m_dot(host, timeout, ipv6, l, s)))
    if "connect" in methods:
        tasks.append(("TCP socket connect", lambda: m_socket_connect(host, timeout, ipv6)))
        tasks.append(("http.client", lambda: m_httpclient(host, timeout, ipv6)))
    if "tools" in methods:
        tasks.append(("dig", lambda: m_dig(host, timeout, ipv6)))
        tasks.append(("host", lambda: m_host(host, timeout, ipv6)))
        tasks.append(("nslookup", lambda: m_nslookup(host, timeout, ipv6)))
    return tasks


def sort_key(r):
    return (METHOD_ORDER.get(r.get("method", ""), 99),
            str(r.get("source", "")), str(r.get("type", "")),
            str(r.get("value", "")))


def emit_table(results):
    columns = ["Method", "Source", "Address", "Type", "TTL", "Status",
               "Details", "Time (ms)", "Hosting"]
    rows = []
    for r in results:
        row = [r["method"], r["source"], r["value"], r["type"], str(r["ttl"]),
               r["status"], r["details"], str(r["ms"]), r.get("hosting", "")]
        rows.append(row)
    emit({"type": "table", "columns": columns, "rows": rows})


def build_summary(host, results, hosting_map=None, analysis=None):
    ip_methods = defaultdict(set)
    ip_sources = defaultdict(set)
    ip_types = {}
    errors = 0
    skipped = 0
    for r in results:
        if r["status"] == "ERROR":
            errors += 1
        elif r["status"] == "SKIPPED":
            skipped += 1
        if r["status"] == "OK" and r["ip"] and is_ip(r["ip"]):
            ip_methods[r["ip"]].add(r["method"])
            ip_sources[r["ip"]].add(r.get("source_group", source_group(r["source"])))
            ip_types[r["ip"]] = r["type"]
    lines = ["## IP Search — `%s`\n" % md_escape(host)]
    if ip_methods:
        lines.append("**Unique IPs found: %d**\n" % len(ip_methods))
        for ip in sorted(ip_methods.keys()):
            methods = ip_methods[ip]
            sources = ip_sources[ip]
            lines.append("- `%s` (%s) — confirmed by %d method(s) from %d "
                         "independent source(s): %s" %
                         (ip, ip_types.get(ip, "?"), len(methods), len(sources),
                          ", ".join(sorted(sources))))
    else:
        lines.append("_No IPs resolved._")
    lines.append("\n**Totals:** %d records, %d errors, %d skipped." %
                 (len(results), errors, skipped))

    # Divergence (O2): flag IPs the local resolver sees but no public resolver
    # does (split-horizon / interception), disagreement among public DNS
    # resolvers, and IPs the observed peer reached that no resolver returned
    # (CDN / load-balancer redirect).
    if ip_methods:
        all_sources = set()
        for ip in ip_methods:
            all_sources |= ip_sources[ip]
        dns_sources = all_sources - {"observed peer"}
        public_dns = dns_sources - {"local resolver"}
        lines.append("\n## Divergence\n")
        notes = []
        local_only = sorted(ip for ip in ip_methods
                            if ip_sources[ip] <= {"local resolver"} and public_dns)
        if local_only:
            notes.append("- **Local-resolver-only IPs** (possible split-horizon "
                         "DNS or local interception): %s" %
                         ", ".join("`%s`" % ip for ip in local_only))
        if len(public_dns) > 1:
            for ip in sorted(ip_methods):
                seen = ip_sources[ip] & public_dns
                missing = public_dns - ip_sources[ip]
                if seen and missing:
                    notes.append("- `%s` returned by %s but not by %s." %
                                 (ip, ", ".join(sorted(seen)),
                                  ", ".join(sorted(missing))))
        if "observed peer" in all_sources:
            peer_only = sorted(ip for ip in ip_methods
                               if "observed peer" in ip_sources[ip]
                               and not (ip_sources[ip] & dns_sources))
            if peer_only:
                notes.append("- **Observed peer reached IP(s) no resolver "
                             "returned** (CDN / load balancer): %s" %
                             ", ".join("`%s`" % ip for ip in peer_only))
        if not notes:
            lines.append("_No divergence detected._")
        else:
            lines.extend(notes)
        lines.append("")

    if hosting_map:
        lines.append("\n## Hosting\n")
        for ip in sorted(hosting_map.keys()):
            info = hosting_map[ip]
            lines.append("### `%s`\n" % ip)
            provider = info.get("org") or "unknown"
            lines.append("- **Provider:** %s" % md_escape(provider))
            if info.get("network"):
                lines.append("- **Network:** %s" % md_escape(info["network"]))
            if info.get("asn"):
                asn_line = "- **ASN:** %s" % info["asn"]
                if info.get("as_name"):
                    asn_line += " (%s)" % md_escape(info["as_name"])
                lines.append(asn_line)
            if info.get("country"):
                lines.append("- **Country:** %s" % md_escape(info["country"]))
            if info.get("cidr"):
                lines.append("- **CIDR:** %s" % md_escape(info["cidr"]))
            if info.get("ptr"):
                lines.append("- **PTR:** `%s`" % md_escape(info["ptr"]))
            if info.get("ssh"):
                lines.append("- **SSH banner:** `%s`" % md_escape(info["ssh"]))
            if info.get("cached"):
                lines.append("- _RDAP reused from a cached network allocation._")
            if info.get("error"):
                lines.append("- **RDAP error:** %s" % md_escape(info["error"]))
            lines.append("")

    if analysis:
        dns_recs = analysis.get("dns_records")
        if dns_recs is not None:
            lines.append("\n## DNS Records\n")
            queried = analysis.get("dnsrecs_queried")
            if queried and queried != host:
                lines.append("_Queried: `%s`_\n" % md_escape(queried))
            ok_rows = [r for r in dns_recs if r.get("status") == "OK" and r.get("value")]
            if ok_rows:
                lines.append("| Type | Value | TTL |")
                lines.append("|------|-------|-----|")
                for r in ok_rows:
                    val = md_escape(r["value"])
                    if len(val) > 120:
                        val = val[:117] + "..."
                    lines.append("| %s | `%s` | %s |" % (r["type"], val, r.get("ttl", "")))
            else:
                lines.append("_No records returned._")
            for r in dns_recs:
                if r.get("status") == "ERROR":
                    lines.append("| %s | _error: %s_ | |" %
                                 (r["type"], md_escape(r.get("details", ""))))
            no_ans = analysis.get("dnsrecs_no_answer")
            if no_ans:
                lines.append("\n_No answer for: %s._" % ", ".join(no_ans))
            lines.append("")

        whois_info = analysis.get("whois_info")
        if whois_info:
            lines.append("\n## Domain WHOIS\n")
            if whois_info.get("queried") and whois_info["queried"] != host:
                lines.append("_Queried: `%s`_\n" % md_escape(whois_info["queried"]))
            if whois_info.get("error"):
                lines.append("_Error: %s_" % md_escape(whois_info["error"]))
            else:
                if whois_info.get("registrar"):
                    lines.append("- **Registrar:** %s" % md_escape(whois_info["registrar"]))
                if whois_info.get("created"):
                    lines.append("- **Created:** %s" % md_escape(whois_info["created"]))
                if whois_info.get("updated"):
                    lines.append("- **Updated:** %s" % md_escape(whois_info["updated"]))
                if whois_info.get("expires"):
                    lines.append("- **Expires:** %s" % md_escape(whois_info["expires"]))
                if whois_info.get("dnssec"):
                    lines.append("- **DNSSEC:** Yes")
                else:
                    lines.append("- **DNSSEC:** No")
                if whois_info.get("nameservers"):
                    lines.append("- **Nameservers:**")
                    for ns in whois_info["nameservers"]:
                        lines.append("  - `%s`" % md_escape(ns.lower()))
                if whois_info.get("status"):
                    lines.append("- **Status:** %s" %
                                 ", ".join(md_escape(s) for s in whois_info["status"]))
            lines.append("")

        cdn_info = analysis.get("cdn_info")
        if cdn_info:
            lines.append("\n## CDN / WAF\n")
            if cdn_info.get("error") and not cdn_info.get("cdn"):
                lines.append("_HTTP error: %s_" % md_escape(cdn_info["error"]))
            else:
                lines.append("- **CDN:** %s" % (cdn_info.get("cdn") or "not detected"))
                lines.append("- **WAF:** %s" % (cdn_info.get("waf") or "not detected"))
                if cdn_info.get("server"):
                    lines.append("- **Server:** `%s`" % md_escape(cdn_info["server"]))
                if cdn_info.get("powered_by"):
                    lines.append("- **X-Powered-By:** `%s`" % md_escape(cdn_info["powered_by"]))
                if cdn_info.get("via"):
                    lines.append("- **Via:** `%s`" % md_escape(cdn_info["via"]))
                if cdn_info.get("cert_issuer"):
                    lines.append("- **TLS issuer:** %s" % md_escape(cdn_info["cert_issuer"]))
                if cdn_info.get("cert_sans"):
                    sans = cdn_info["cert_sans"][:5]
                    more = " (+%d more)" % (len(cdn_info["cert_sans"]) - 5) \
                        if len(cdn_info["cert_sans"]) > 5 else ""
                    lines.append("- **TLS SANs:** %s%s" %
                                 (", ".join("`%s`" % md_escape(s) for s in sans), more))
                if cdn_info.get("cert_error"):
                    lines.append("- _TLS cert read failed: %s_" %
                                 md_escape(cdn_info["cert_error"]))
            lines.append("")

        trace_hops = analysis.get("traceroute_hops")
        if trace_hops:
            lines.append("\n## Traceroute\n")
            has_error = any(h.get("error") for h in trace_hops)
            if has_error and len(trace_hops) == 1:
                lines.append("_Error: %s_" % md_escape(trace_hops[0].get("error", "")))
            else:
                lines.append("| Hop | IP | Hostname | RTT |")
                lines.append("|-----|----|----------|-----|")
                for h in trace_hops:
                    if h.get("error"):
                        lines.append("| — | _%s_ | | |" % md_escape(h["error"]))
                    else:
                        lines.append("| %s | `%s` | %s | %s |" %
                                     (h.get("hop", ""), md_escape(h.get("ip", "")),
                                      md_escape(h.get("hostname", "")) or "—",
                                      md_escape(h.get("ms", "*"))))
            lines.append("")

    return "\n".join(lines)


def save_artifacts(host, results, methods, output_dir, hosting_map=None, analysis=None):
    os.makedirs(output_dir, exist_ok=True)

    # R1: remove stale conditional artifacts this run did not produce.
    produced = {"results.csv", "results.json"}
    if "dnsrecs" in methods:
        produced.add("dns_records.csv")
    if "traceroute" in methods:
        produced.add("traceroute.csv")
    for name in ("dns_records.csv", "traceroute.csv"):
        if name not in produced:
            stale = os.path.join(output_dir, name)
            if os.path.exists(stale):
                try:
                    os.remove(stale)
                except OSError:
                    pass

    csv_path = os.path.join(output_dir, "results.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        headers = ["method", "source", "ip", "value", "type", "ttl",
                   "status", "details", "ms", "hosting"]
        writer.writerow(headers)
        for r in results:
            writer.writerow([r["method"], r["source"], r["ip"], r["value"],
                             r["type"], r["ttl"], r["status"], r["details"],
                             r["ms"], r.get("hosting", "")])

    if analysis:
        if "dns_records" in analysis:
            dns_path = os.path.join(output_dir, "dns_records.csv")
            with open(dns_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["type", "value", "ttl", "status", "ms"])
                for r in analysis["dns_records"]:
                    w.writerow([r.get("type", ""), r.get("value", ""),
                                r.get("ttl", ""), r.get("status", ""),
                                r.get("ms", "")])
        if "traceroute_hops" in analysis:
            tr_path = os.path.join(output_dir, "traceroute.csv")
            with open(tr_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["hop", "ip", "hostname", "ms", "error"])
                for h in analysis["traceroute_hops"]:
                    w.writerow([h.get("hop", ""), h.get("ip", ""),
                                h.get("hostname", ""), h.get("ms", ""),
                                h.get("error", "")])

    json_path = os.path.join(output_dir, "results.json")
    payload = {
        "host": host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "methods": methods,
        "count": len(results),
        "results": results,
    }
    if hosting_map is not None:
        payload["hosting_info"] = hosting_map
    if analysis:
        payload["analysis"] = analysis
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Resolve a website's IP address using every available method.")
    parser.add_argument("--url", required=True, help="URL or domain of the target site")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Per-operation timeout in seconds")
    parser.add_argument("--ipv6", choices=["yes", "no"], default="yes",
                        help="Include IPv6 (AAAA) records")
    parser.add_argument("--method", action="append", default=None,
                        choices=ALL_METHODS,
                        help="Method group to use (repeatable)")
    parser.add_argument("--ssh-banner", action="store_true", default=False,
                        help="Grab SSH banner from port 22 (only with 'hosting' method)")
    parser.add_argument("--ssh-port", type=int, default=22,
                        help="Port for SSH banner grab")
    parser.add_argument("--output-dir", default=None,
                        help="Directory for artifacts (default: $PYSHELL_OUTPUT_DIR or '.')")
    return parser


def run_resolution(tasks, phase1_end):
    all_results = []
    if not tasks:
        return all_results
    phase = Phase("Resolving", 0, phase1_end)
    total = len(tasks)
    with ThreadPoolExecutor(max_workers=min(12, total)) as ex:
        future_map = {ex.submit(fn): label for label, fn in tasks}
        done = 0
        for fut in as_completed(future_map):
            label = future_map[fut]
            done += 1
            try:
                results = fut.result()
            except Exception as e:
                results = [result(label, "unknown", "", "",
                                  status="ERROR", details="unexpected: " + str(e))]
            all_results.extend(results)
            phase.report(done, total, "%d/%d · %s" % (done, total, label))
    phase.done()
    all_results.sort(key=sort_key)
    return all_results


def run_hosting(unique_ips, timeout, do_ssh, ssh_port, phase1_end, phase2_end):
    hosting_map = {}
    if not unique_ips:
        return hosting_map
    rdap_cache = RdapCache()
    phase = Phase("Hosting", phase1_end, phase2_end)
    total = len(unique_ips)
    with ThreadPoolExecutor(max_workers=min(8, total)) as ex:
        future_map = {
            ex.submit(hosting_lookup, ip, timeout, do_ssh, ssh_port, rdap_cache): ip
            for ip in unique_ips
        }
        done = 0
        for fut in as_completed(future_map):
            ip = future_map[fut]
            done += 1
            try:
                hosting_map[ip] = fut.result()
            except Exception as e:
                hosting_map[ip] = {"org": "", "error": "unexpected: " + str(e)}
            phase.report(done, total, "%d/%d · %s" % (done, total, ip))
    phase.done()
    return hosting_map


def run_analysis(analysis_methods, host, timeout, phase2_end):
    analysis = {}
    if not analysis_methods:
        return analysis
    label_map = {"dnsrecs": "DNS records", "whois": "Domain WHOIS",
                 "cdn": "CDN/WAF detection", "traceroute": "Traceroute"}
    key_map = {"whois": "whois_info", "cdn": "cdn_info",
               "traceroute": "traceroute_hops"}

    def dispatch(am):
        if am == "dnsrecs":
            return am, m_dns_records(host, timeout)
        if am == "whois":
            return am, m_domain_whois(host, timeout)
        if am == "cdn":
            return am, m_cdn_detect(host, timeout)
        if am == "traceroute":
            return am, m_traceroute(host, timeout)
        return am, {"error": "unknown method"}

    phase = Phase("Analysis", phase2_end, 100)
    total = len(analysis_methods)
    with ThreadPoolExecutor(max_workers=min(4, total)) as ex:
        future_map = {ex.submit(dispatch, am): am for am in analysis_methods}
        done = 0
        for fut in as_completed(future_map):
            am = future_map[fut]
            done += 1
            label = label_map.get(am, am)
            try:
                key, val = fut.result()
                if key == "dnsrecs":
                    analysis["dns_records"] = val["records"]
                    analysis["dnsrecs_no_answer"] = val["no_answer"]
                    analysis["dnsrecs_queried"] = val["queried"]
                else:
                    analysis[key_map.get(key, key)] = val
            except Exception as e:
                analysis[key_map.get(am, am)] = {"error": type(e).__name__ + ": " + str(e)}
            phase.report(done, total, "%d/%d · %s" % (done, total, label))
    phase.done()
    return analysis


def main():
    parser = build_parser()
    args = parser.parse_args()

    if os.environ.get("PYSHELL_INTROSPECT") == "1":
        print("Introspection mode, skipping real work")
        sys.exit(0)

    host = extract_host(args.url)
    if not host:
        print("Could not parse hostname from URL", file=sys.stderr)
        sys.exit(1)

    methods = args.method if args.method else ALL_METHODS
    timeout = max(1, args.timeout)
    ipv6 = (args.ipv6 == "yes")
    do_hosting = "hosting" in methods
    do_ssh = do_hosting and args.ssh_banner
    output_dir = args.output_dir or os.environ.get("PYSHELL_OUTPUT_DIR", ".")

    resolution_methods = [m for m in methods if m in RESOLUTION_METHODS]
    analysis_methods = [m for m in methods if m in ANALYSIS_METHODS and m != "hosting"]
    if not resolution_methods and not analysis_methods:
        resolution_methods = ["system"]
    if not resolution_methods and "hosting" in methods:
        resolution_methods = ["system"]

    print("Resolving IP for: %s" % host, flush=True)
    emit({"type": "status", "message": "Host: %s" % host})

    all_results = []
    hosting_map = {}
    analysis = {}
    try:
        tasks = build_tasks(resolution_methods, host, timeout, ipv6)
        n_ana = len(analysis_methods)
        phase1_end = 60 if (do_hosting or n_ana) else 100
        phase2_end = 80 if n_ana else 100

        # Phase 1 — resolution (concurrent).
        all_results = run_resolution(tasks, phase1_end)

        # Phase 2 — hosting (concurrent, per unique IP, with RDAP CIDR cache).
        if do_hosting:
            unique_ips = sorted({r["ip"] for r in all_results
                                 if r["status"] == "OK" and r["ip"] and is_ip(r["ip"])})
            if unique_ips:
                emit({"type": "status",
                      "message": "Hosting lookup for %d IP(s)…" % len(unique_ips)})
                hosting_map = run_hosting(unique_ips, timeout, do_ssh, args.ssh_port,
                                          phase1_end, phase2_end)
                for r in all_results:
                    if r["ip"] in hosting_map:
                        r["hosting"] = hosting_map[r["ip"]].get("org", "")

        # Phase 3 — analysis (concurrent; traceroute is the long pole).
        analysis = run_analysis(analysis_methods, host, timeout, phase2_end)
    except Exception as e:
        # Every method already turns its own failure into an ERROR record;
        # this is the backstop for anything that still escapes (e.g. a bug in
        # the pipeline glue itself), so one broken phase can't take down the
        # whole run or flip the exit code.
        all_results.append(result("pipeline", "internal", "", "", status="ERROR",
                                  details=type(e).__name__ + ": " + str(e)))

    emit_table(all_results)
    emit({"type": "progress", "pct": 100, "message": "Done"})
    emit({"type": "markdown",
          "content": build_summary(host, all_results, hosting_map or None,
                                   analysis or None)})
    try:
        save_artifacts(host, all_results, methods, output_dir,
                       hosting_map or None, analysis or None)
    except OSError as e:
        print("Could not write artifacts to %s: %s" % (output_dir, e), file=sys.stderr)

    emit({"type": "status", "message": "Done: %d records" % len(all_results)})
    print("Finished. %d records." % len(all_results), flush=True)


if __name__ == "__main__":
    main()
