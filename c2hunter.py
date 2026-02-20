#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║          C2 BEACON HUNTER  —  Threat Hunt TUI             ║
║   Zero external dependencies  |  Python 3.6+  |  stdlib   ║
╚═══════════════════════════════════════════════════════════╝

Usage:
    sudo python3 c2hunter.py                  # live capture (requires root + /proc/net)
    python3 c2hunter.py --demo                # simulated traffic (no root needed)
    python3 c2hunter.py --pcap <file.pcap>    # offline pcap analysis
    python3 c2hunter.py --log <netflow.csv>   # analyse netflow/csv export

Controls:
    ↑/↓ or j/k   scroll flow list
    ENTER         inspect selected flow
    f             cycle threat filter  (ALL → CRITICAL → HIGH → MEDIUM → LOW → CLEAN)
    s             sort  (time / score / src / dst)
    e             export findings to c2hunter_findings.json
    m             manual flow entry
    q / ESC       quit
"""

import curses
import curses.textpad
import sys
import os
import re
import time
import math
import json
import random
import socket
import struct
import hashlib
import argparse
import threading
import ipaddress
from datetime import datetime
from collections import defaultdict, deque

# ─── ANSI colour pairs (curses) ──────────────────────────────────────────────
CP_RED     = 1   # CRITICAL
CP_ORANGE  = 2   # HIGH
CP_YELLOW  = 3   # MEDIUM
CP_GREEN   = 4   # LOW / OK
CP_CYAN    = 5   # info / headers
CP_WHITE   = 6   # normal text
CP_DIM     = 7   # dim / border
CP_BLACK   = 8   # inverted highlight
CP_REDHL   = 9   # red highlight (selected critical)
CP_GREENHL = 10  # green highlight bar

# ─── C2 SIGNATURES ───────────────────────────────────────────────────────────
C2_FRAMEWORKS = {
    "Cobalt Strike": {
        "color": CP_RED,
        "ua_patterns": [
            r"Mozilla/4\.0 \(compatible; MSIE [67]\.0",
            r"Mozilla/5\.0 \(Windows NT 6\.1\).*Chrome/5[0-9]",
            r"curl/7\.\d+\.\d+$",
        ],
        "uri_patterns": [
            r"^/submit\.php$",
            r"^/news\.php$",
            r"^/jquery-\d+\.\d+\.\d+\.min\.js\?[a-z0-9]{6,}",
            r"^/[a-z]{4,8}\.(gif|png|jpg)\?[A-Za-z0-9+/]{8,}",
            r"^/(updates|login|image/|pixel\.gif|__utm\.gif)",
            r"^/[A-Z][a-z]{2,6}/[A-Z][a-z]{2,8}$",
        ],
        "default_paths": ["/updates", "/login", "/submit.php", "/pixel.gif", "/news.php"],
        "known_ja3": [
            "72a589da586844d7f0818ce684948eea",
            "a0e9f5d64349fb13191bc781f81f42e1",
            "6734f37431670b3ab4292b8f60f29984",
        ],
        "beacon_intervals": [60, 120, 300, 600],
        "notes": "Malleable C2 profiles can mimic legit traffic. Check JA3 + beacon timing.",
    },
    "Metasploit": {
        "color": CP_ORANGE,
        "ua_patterns": [
            r"Mozilla/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)",
        ],
        "uri_patterns": [
            r"^/[A-Za-z0-9+/]{76,}$",
            r"^/[A-Za-z0-9]{4,6}$",
        ],
        "default_paths": ["/189212.exe", "/cXh", "/TqxJ"],
        "known_ja3": ["b386946a5a44d1ddcc843bc75336dfce"],
        "beacon_intervals": [5, 10, 30],
        "notes": "Meterpreter reverse HTTPS uses self-signed certs with random CN.",
    },
    "PowerShell Empire": {
        "color": CP_ORANGE,
        "ua_patterns": [
            r"Mozilla/5\.0.*Windows NT 6\.1.*WOW64.*Trident/7\.0",
        ],
        "uri_patterns": [
            r"^/[a-z]{8,12}/[a-z]{4,8}(/index\.jsp)?$",
            r"^/[a-z]+/[a-z]+/[a-z]+\.php$",
        ],
        "default_paths": [],
        "known_ja3": [],
        "beacon_intervals": [5, 10, 60],
        "notes": "Often hides behind IIS/Apache response headers.",
    },
    "Havoc C2": {
        "color": CP_RED,
        "ua_patterns": [],
        "uri_patterns": [
            r"^/[a-zA-Z0-9]{8}$",
            r"^/[a-zA-Z0-9]{6,10}/[a-zA-Z0-9]{4,8}$",
        ],
        "default_paths": [],
        "known_ja3": [],
        "beacon_intervals": [5, 10, 15],
        "notes": "Newer framework. Short random URIs, low beacon intervals.",
    },
    "Brute Ratel": {
        "color": CP_RED,
        "ua_patterns": [],
        "uri_patterns": [
            r"^/api/v\d+/[a-z]+$",
            r"^/cdn/static/[a-zA-Z0-9]+\.js$",
        ],
        "default_paths": [],
        "known_ja3": [],
        "beacon_intervals": [5, 30, 60],
        "notes": "Evades EDR. Uses x-request-id header for session tracking.",
    },
    "Sliver": {
        "color": CP_YELLOW,
        "ua_patterns": [],
        "uri_patterns": [
            r"^/[a-z]{4,6}\.[a-z]{2,4}$",
            r"^/fonts/[a-z]+\.woff2?$",
            r"^/static/[a-zA-Z0-9_-]+\.(js|css|png)$",
        ],
        "default_paths": [],
        "known_ja3": [],
        "beacon_intervals": [60, 300],
        "notes": "Open-source Go C2. Supports mTLS, WireGuard, HTTP, DNS implants.",
    },
    "Covenant": {
        "color": CP_YELLOW,
        "ua_patterns": [],
        "uri_patterns": [
            r"^/[a-zA-Z0-9]{10,20}$",
        ],
        "default_paths": [],
        "known_ja3": [],
        "beacon_intervals": [5, 10, 60],
        "notes": ".NET C2. Grunts communicate over HTTP/S or SMB.",
    },
}

KNOWN_BAD_JA3 = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike default",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike variant",
    "6734f37431670b3ab4292b8f60f29984": "Cobalt Strike variant",
    "b386946a5a44d1ddcc843bc75336dfce": "Metasploit Meterpreter",
    "c35b954d2a4d339f0776e89bb3f2f13a": "Cobalt Strike (TLS 1.3)",
    "e7d705a3286e19ea42f587b344ee6865": "Havoc C2",
    "fc54e0d16d9764783542f0146a98b300": "Brute Ratel",
}

HTTP_MASKING_CHECKS = [
    ("No Referer on POST",         30, lambda f: f.get("method") == "POST" and not f.get("referer")),
    ("GET with body (padded)",     35, lambda f: f.get("method") == "GET" and f.get("body_len", 0) > 0),
    ("Wildcard Accept header",     20, lambda f: f.get("accept") == "*/*" and not f.get("accept_lang")),
    ("URI double-encoding",        45, lambda f: bool(re.search(r"%[0-9a-f]{2}%[0-9a-f]{2}", f.get("uri", ""), re.I))),
    ("Low byte ratio (C2 checkin)",40, lambda f: 0 < f.get("bytes_sent", 0) < 512 and f.get("bytes_recv", 0) < 256),
    ("Missing Host header",        50, lambda f: not f.get("host")),
    ("Non-standard port HTTPS",    25, lambda f: f.get("dport") not in (0, 443, 8443) and f.get("proto") == "HTTPS"),
    ("CDN host / SNI mismatch",    95, lambda f: f.get("host") and f.get("sni") and f["host"] != f["sni"]),
    ("IP-based dest (no DNS)",     35, lambda f: _is_public_ip(f.get("dst_ip", "")) and not f.get("host")),
    ("Suspicious URI entropy",     40, lambda f: _uri_entropy(f.get("uri", "")) > 4.2),
]

def _is_public_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local)
    except Exception:
        return False

def _uri_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())

# ─── DNS BEACON DETECTION ────────────────────────────────────────────────────
DNS_BEACON_RE = [
    re.compile(r"^[a-f0-9]{16,}\.", re.I),        # hex-encoded data
    re.compile(r"^[a-z2-7]{20,}\.", re.I),         # base32-encoded data
    re.compile(r"^[A-Za-z0-9+/]{24,}\."),          # base64-encoded data
    re.compile(r"^[a-zA-Z0-9_-]{30,}\."),          # long random label
]

def score_dns_beacon(query):
    if not query:
        return 0, []
    hits = []
    score = 0
    for pat in DNS_BEACON_RE:
        if pat.match(query):
            hits.append(f"Encoded subdomain: {query[:40]}")
            score = max(score, 88)
    parts = query.rstrip(".").split(".")
    if len(parts) >= 2 and len(parts[0]) > 25:
        hits.append(f"Anomalously long label ({len(parts[0])} chars)")
        score = max(score, 82)
    return score, hits

# ─── BEACON INTERVAL ANALYSIS ────────────────────────────────────────────────
def analyse_intervals(timestamps):
    """Return (score, description) based on regularity of timestamps."""
    if len(timestamps) < 3:
        return 0, ""
    ts = sorted(timestamps)
    diffs = [ts[i+1] - ts[i] for i in range(len(ts)-1)]
    avg = sum(diffs) / len(diffs)
    if avg <= 0:
        return 0, ""
    variance = sum((d - avg)**2 for d in diffs) / len(diffs)
    cv = math.sqrt(variance) / avg  # coefficient of variation

    if cv < 0.05:
        return 95, f"Machine-perfect interval ~{avg:.0f}s (CV={cv:.3f})"
    elif cv < 0.15:
        return 90, f"Very regular beacon ~{avg:.0f}s (CV={cv:.3f})"
    elif cv < 0.30:
        return 80, f"Regular beacon ~{avg:.0f}s (CV={cv:.3f})"
    elif 0.05 < cv < 0.35:
        return 75, f"Jitter-evasion pattern ~{avg:.0f}s ±{cv*100:.0f}%"
    elif cv < 0.60:
        return 40, f"Somewhat regular traffic ~{avg:.0f}s"
    else:
        return 10, f"Irregular intervals (CV={cv:.2f})"

# ─── MAIN ANALYSIS ENGINE ─────────────────────────────────────────────────────
def analyse_flow(flow):
    """
    flow dict keys:
      src_ip, dst_ip, dport, proto, host, sni, uri, method,
      user_agent, ja3, dns_query, referer, accept, accept_lang,
      bytes_sent, bytes_recv, body_len, timestamps[]
    Returns enriched dict with .analysis sub-dict.
    """
    score = 0
    indicators = []   # (name, score, severity)
    fw_hits = []      # (framework_name, fw_score, [hit_strings])

    ua  = flow.get("user_agent", "")
    uri = flow.get("uri", "")
    ja3 = flow.get("ja3", "")

    # ── Framework signature matching ──
    for fw_name, fw in C2_FRAMEWORKS.items():
        fw_score = 0
        hits = []
        for pat in fw.get("ua_patterns", []):
            if re.search(pat, ua, re.I):
                fw_score += 30
                hits.append(f"UA matches {fw_name}")
        for pat in fw.get("uri_patterns", []):
            if re.search(pat, uri, re.I):
                fw_score += 25
                hits.append(f"URI pattern: {fw_name}")
        if uri in fw.get("default_paths", []):
            fw_score += 40
            hits.append(f"Default C2 path: {uri}")
        if ja3 and ja3 in fw.get("known_ja3", []):
            fw_score += 50
            hits.append(f"Known JA3 for {fw_name}")
        if fw_score > 0:
            fw_hits.append((fw_name, fw_score, hits))
            score = max(score, fw_score)

    # ── JA3 database check ──
    if ja3 in KNOWN_BAD_JA3:
        label = KNOWN_BAD_JA3[ja3]
        indicators.append((f"JA3 match: {label}", 95, "critical"))
        score = max(score, 95)

    # ── Domain fronting ──
    host = flow.get("host", "")
    sni  = flow.get("sni", "")
    if host and sni and host != sni:
        indicators.append((f"DOMAIN FRONTING  Host:{host} ≠ SNI:{sni}", 95, "critical"))
        score = max(score, 95)

    # ── DNS beacon ──
    dns_score, dns_hits = score_dns_beacon(flow.get("dns_query", ""))
    if dns_score > 0:
        for h in dns_hits:
            indicators.append((h, dns_score, "critical"))
        score = max(score, dns_score)

    # ── Beacon interval analysis ──
    ts = flow.get("timestamps", [])
    iv_score, iv_desc = analyse_intervals(ts)
    if iv_score > 40:
        sev = "critical" if iv_score > 80 else "high" if iv_score > 60 else "medium"
        indicators.append((iv_desc, iv_score, sev))
        score = max(score, iv_score)

    # ── HTTP masking checks ──
    for name, weight, check in HTTP_MASKING_CHECKS:
        try:
            if check(flow):
                sev = "critical" if weight >= 80 else "high" if weight >= 40 else "medium"
                indicators.append((name, weight, sev))
                score = min(100, score + weight)
        except Exception:
            pass

    # ── Determine top framework ──
    top_fw = None
    if fw_hits:
        fw_hits.sort(key=lambda x: x[1], reverse=True)
        top_fw = fw_hits[0][0]

    confidence = min(100, score)
    if confidence >= 85:
        threat = "CRITICAL"
    elif confidence >= 65:
        threat = "HIGH"
    elif confidence >= 40:
        threat = "MEDIUM"
    elif confidence >= 20:
        threat = "LOW"
    else:
        threat = "CLEAN"

    flow["analysis"] = {
        "score":      confidence,
        "threat":     threat,
        "framework":  top_fw,
        "fw_hits":    fw_hits,
        "indicators": indicators,
        "timestamp":  datetime.now().strftime("%H:%M:%S"),
    }
    return flow

# ─── DEMO TRAFFIC GENERATOR ──────────────────────────────────────────────────
_DEMO_SCENARIOS = [
    # Cobalt Strike domain-fronted via Cloudflare
    lambda i: {
        "src_ip": f"192.168.1.{10 + i % 20}",
        "dst_ip": f"104.21.{random.randint(1,254)}.{random.randint(1,254)}",
        "dport": 443, "proto": "HTTPS",
        "host": "cdn.cloudflare.com",
        "sni":  "c2.redteam-operator.io",
        "uri":  "/submit.php",
        "method": "POST",
        "user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "ja3": "72a589da586844d7f0818ce684948eea",
        "timestamps": [time.time() - 300 + x*60 for x in range(6)],
        "bytes_sent": 256, "bytes_recv": 48, "body_len": 0,
    },
    # Cobalt Strike jQuery malleable profile
    lambda i: {
        "src_ip": f"10.0.0.{5 + i % 10}",
        "dst_ip": f"52.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "dport": 443, "proto": "HTTPS",
        "host": "code.jquery.com",
        "sni":  "code.jquery.com",
        "uri":  f"/jquery-3.3.1.min.js?{''.join(random.choices('abcdefABCDEF0123456789',k=8))}",
        "method": "GET",
        "user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
        "ja3": "6734f37431670b3ab4292b8f60f29984",
        "timestamps": [time.time() - 600 + x*120 + random.uniform(-6,6) for x in range(6)],
        "bytes_sent": 304, "bytes_recv": 96, "body_len": 0,
    },
    # DNS beacon
    lambda i: {
        "src_ip": f"172.16.{random.randint(0,5)}.{random.randint(1,100)}",
        "dst_ip": f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "dport": 53, "proto": "DNS",
        "host": "",  "sni": "",
        "uri":  "/",
        "method": "UDP",
        "dns_query": f"{''.join(random.choices('abcdef0123456789',k=24))}.beacon.attacker.io",
        "user_agent": "",
        "timestamps": [time.time() - 120 + x*30 + random.uniform(-1,1) for x in range(5)],
        "bytes_sent": 64, "bytes_recv": 32, "body_len": 0,
    },
    # Metasploit reverse HTTPS
    lambda i: {
        "src_ip": f"10.10.{random.randint(0,5)}.{random.randint(1,254)}",
        "dst_ip": f"45.33.32.{random.randint(1,254)}",
        "dport": 4444, "proto": "HTTPS",
        "host": "", "sni": "",
        "uri":  f"/{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',k=80))}",
        "method": "GET",
        "user_agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "timestamps": [time.time() - 30 + x*10 for x in range(4)],
        "bytes_sent": 128, "bytes_recv": 2048, "body_len": 0,
    },
    # Empire PowerShell
    lambda i: {
        "src_ip": f"192.168.{random.randint(1,5)}.{random.randint(1,254)}",
        "dst_ip": f"34.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "dport": 80, "proto": "HTTP",
        "host": "update.windowscorp.com",
        "sni":  "",
        "uri":  f"/{''.join(random.choices('abcdefghij',k=10))}/{''.join(random.choices('abcde',k=6))}/index.jsp",
        "method": "GET",
        "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "accept": "*/*",
        "timestamps": [time.time() - 50 + x*5 + random.uniform(-0.3,0.3) for x in range(11)],
        "bytes_sent": 184, "bytes_recv": 64, "body_len": 0,
    },
    # Legitimate HTTPS (clean)
    lambda i: {
        "src_ip": f"192.168.{random.randint(1,3)}.{random.randint(1,254)}",
        "dst_ip": f"142.250.{random.randint(1,254)}.{random.randint(1,254)}",
        "dport": 443, "proto": "HTTPS",
        "host": "fonts.googleapis.com",
        "sni":  "fonts.googleapis.com",
        "uri":  "/css2?family=Roboto:wght@400;700",
        "method": "GET",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "referer": "https://example.com",
        "accept": "text/css,*/*;q=0.1",
        "accept_lang": "en-US,en;q=0.9",
        "timestamps": [time.time()],
        "bytes_sent": 512, "bytes_recv": 8192, "body_len": 0,
    },
    # Sliver with redirector
    lambda i: {
        "src_ip": f"10.20.{random.randint(0,5)}.{random.randint(1,254)}",
        "dst_ip": f"13.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "dport": 443, "proto": "HTTPS",
        "host": "d1a2b3c4e5f6.cloudfront.net",
        "sni":  "sliver.operator.net",
        "uri":  "/fonts/roboto.woff2",
        "method": "GET",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "timestamps": [time.time() - 600 + x*300 + random.uniform(-15,15) for x in range(3)],
        "bytes_sent": 200, "bytes_recv": 80, "body_len": 0,
    },
]

_demo_counter = 0
def next_demo_flow():
    global _demo_counter
    idx = _demo_counter % len(_DEMO_SCENARIOS)
    _demo_counter += 1
    flow = _DEMO_SCENARIOS[idx](_demo_counter)
    flow.setdefault("id", f"flow_{_demo_counter:05d}")
    flow.setdefault("referer", "")
    flow.setdefault("accept", "")
    flow.setdefault("accept_lang", "")
    flow.setdefault("dns_query", "")
    flow.setdefault("ja3", "")
    flow.setdefault("host", "")
    flow.setdefault("sni", "")
    return analyse_flow(flow)

# ─── LIVE CAPTURE (Linux /proc/net/tcp + /proc/net/tcp6) ─────────────────────
def read_proc_tcp():
    """
    Parse /proc/net/tcp and /proc/net/tcp6 for established connections.
    Returns list of (src_ip, dst_ip, dport) tuples.
    """
    conns = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    state = parts[3]
                    if state != "01":  # 01 = ESTABLISHED
                        continue
                    loc = parts[1]
                    rem = parts[2]
                    try:
                        if ":" not in rem:
                            continue
                        rip_hex, rport_hex = rem.rsplit(":", 1)
                        lip_hex, lport_hex = loc.rsplit(":", 1)
                        dport = int(rport_hex, 16)
                        # IPv4
                        if len(rip_hex) == 8:
                            dst = socket.inet_ntop(socket.AF_INET, bytes.fromhex(rip_hex)[::-1])
                            src = socket.inet_ntop(socket.AF_INET, bytes.fromhex(lip_hex)[::-1])
                        else:
                            dst = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(rip_hex))
                            src = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(lip_hex))
                        conns.append((src, dst, dport))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
    return conns

def build_flow_from_conn(src, dst, dport):
    proto = "HTTPS" if dport == 443 else "HTTP" if dport == 80 else "DNS" if dport == 53 else f"TCP/{dport}"
    flow = {
        "id": f"live_{src}_{dst}_{dport}",
        "src_ip": src,
        "dst_ip": dst,
        "dport":  dport,
        "proto":  proto,
        "host": "", "sni": "", "uri": "/",
        "method": "TCP",
        "user_agent": "", "ja3": "",
        "dns_query": "", "referer": "",
        "accept": "", "accept_lang": "",
        "bytes_sent": 0, "bytes_recv": 0, "body_len": 0,
        "timestamps": [time.time()],
    }
    # Flag connections to non-standard ports as suspicious
    if dport not in (80, 443, 53, 22, 25, 587, 465, 21, 3306, 5432):
        flow["_nonstandard_port"] = True
    return analyse_flow(flow)

# ─── STATE ────────────────────────────────────────────────────────────────────
class AppState:
    def __init__(self):
        self.flows        = deque(maxlen=2000)
        self.lock         = threading.Lock()
        self.selected     = 0
        self.scroll       = 0
        self.filter       = "ALL"
        self.sort_key     = "time"   # time / score / src / dst
        self.mode         = "live"   # live | detail | manual
        self.running      = True
        self.demo_mode    = False
        self.log          = deque(maxlen=200)
        self.stats        = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
        self.manual_fields = {
            "src_ip": "", "dst_ip": "", "dport": "443",
            "proto": "HTTPS", "host": "", "sni": "",
            "uri": "/", "method": "GET",
            "user_agent": "", "ja3": "",
            "dns_query": "",
        }
        self._manual_field_idx = 0

    def add_flow(self, flow):
        with self.lock:
            # Merge repeated flows from same src→dst
            key = (flow["src_ip"], flow["dst_ip"], flow["dport"])
            existing = next((f for f in self.flows if
                             (f["src_ip"], f["dst_ip"], f["dport"]) == key), None)
            if existing:
                existing["timestamps"].append(time.time())
                existing["analysis"]["score"] = min(100, existing["analysis"]["score"] + 5)
                # Re-analyse interval
                iv_s, iv_d = analyse_intervals(existing["timestamps"])
                if iv_s > 50:
                    existing["analysis"]["score"] = max(existing["analysis"]["score"], iv_s)
                self._update_threat(existing)
            else:
                self.flows.appendleft(flow)
            self._recalc_stats()

    def _update_threat(self, flow):
        s = flow["analysis"]["score"]
        if s >= 85:   flow["analysis"]["threat"] = "CRITICAL"
        elif s >= 65: flow["analysis"]["threat"] = "HIGH"
        elif s >= 40: flow["analysis"]["threat"] = "MEDIUM"
        elif s >= 20: flow["analysis"]["threat"] = "LOW"
        else:         flow["analysis"]["threat"] = "CLEAN"

    def _recalc_stats(self):
        c = defaultdict(int)
        for f in self.flows:
            c[f["analysis"]["threat"]] += 1
        self.stats = {
            "total":    len(self.flows),
            "critical": c["CRITICAL"],
            "high":     c["HIGH"],
            "medium":   c["MEDIUM"],
            "low":      c["LOW"],
            "clean":    c["CLEAN"],
        }

    def filtered_flows(self):
        with self.lock:
            fl = list(self.flows)
        if self.filter != "ALL":
            fl = [f for f in fl if f["analysis"]["threat"] == self.filter]
        if self.sort_key == "score":
            fl.sort(key=lambda f: f["analysis"]["score"], reverse=True)
        elif self.sort_key == "src":
            fl.sort(key=lambda f: f["src_ip"])
        elif self.sort_key == "dst":
            fl.sort(key=lambda f: f["dst_ip"])
        # default: time (deque order = newest first)
        return fl

    def add_log(self, msg, level="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.appendleft(f"[{ts}] {level.upper():8s} {msg}")

    def export_findings(self):
        findings = []
        for f in self.flows:
            if f["analysis"]["threat"] in ("CRITICAL", "HIGH"):
                findings.append({
                    "timestamp": f["analysis"]["timestamp"],
                    "threat":    f["analysis"]["threat"],
                    "score":     f["analysis"]["score"],
                    "framework": f["analysis"]["framework"],
                    "src_ip":    f["src_ip"],
                    "dst_ip":    f["dst_ip"],
                    "dport":     f["dport"],
                    "proto":     f["proto"],
                    "host":      f.get("host", ""),
                    "sni":       f.get("sni", ""),
                    "uri":       f.get("uri", ""),
                    "user_agent": f.get("user_agent", ""),
                    "ja3":       f.get("ja3", ""),
                    "indicators": [(n, s) for n, s, _ in f["analysis"]["indicators"]],
                })
        fname = f"c2hunter_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w") as fp:
            json.dump(findings, fp, indent=2)
        return fname, len(findings)

# ─── TUI RENDER ──────────────────────────────────────────────────────────────
THREAT_CP = {"CRITICAL": CP_RED, "HIGH": CP_ORANGE, "MEDIUM": CP_YELLOW,
             "LOW": CP_GREEN, "CLEAN": CP_DIM}

FILTER_CYCLE = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(CP_RED,     curses.COLOR_RED,     -1)
    curses.init_pair(CP_ORANGE,  curses.COLOR_YELLOW,  -1)   # terminal orange approx
    curses.init_pair(CP_YELLOW,  curses.COLOR_YELLOW,  -1)
    curses.init_pair(CP_GREEN,   curses.COLOR_GREEN,   -1)
    curses.init_pair(CP_CYAN,    curses.COLOR_CYAN,    -1)
    curses.init_pair(CP_WHITE,   curses.COLOR_WHITE,   -1)
    curses.init_pair(CP_DIM,     8,                    -1)   # dark grey if supported
    curses.init_pair(CP_BLACK,   curses.COLOR_BLACK,   curses.COLOR_GREEN)
    curses.init_pair(CP_REDHL,   curses.COLOR_WHITE,   curses.COLOR_RED)
    curses.init_pair(CP_GREENHL, curses.COLOR_BLACK,   curses.COLOR_CYAN)

def cp(pair): return curses.color_pair(pair)

def draw_header(win, state, W):
    title = " C2 BEACON HUNTER "
    subtitle = " Threat Hunt TUI | C2/Beacon/Redirect Detection "
    win.attron(cp(CP_GREEN) | curses.A_BOLD)
    win.addstr(0, 0, "═" * W)
    cx = (W - len(title)) // 2
    win.addstr(0, cx, title)
    win.attroff(cp(CP_GREEN) | curses.A_BOLD)

    # Stats bar
    s = state.stats
    bar = (f" FLOWS:{s['total']}  "
           f"CRIT:{s['critical']}  "
           f"HIGH:{s['high']}  "
           f"MED:{s['medium']}  "
           f"CLEAN:{s['clean']} ")
    win.attron(cp(CP_DIM))
    win.addstr(1, 0, bar[:W])
    win.attroff(cp(CP_DIM))

    # Mode / filter / sort on right
    info = f" FILTER:{state.filter}  SORT:{state.sort_key.upper()}  {'DEMO' if state.demo_mode else 'LIVE'} "
    x = max(0, W - len(info))
    win.attron(cp(CP_CYAN))
    win.addstr(1, x, info[:W-x])
    win.attroff(cp(CP_CYAN))

def draw_flow_list(win, state, y0, H, W):
    flows = state.filtered_flows()
    visible = H - 2
    if not flows:
        win.attron(cp(CP_DIM))
        win.addstr(y0 + visible // 2, W // 2 - 10, "  NO FLOWS  (start scanning)  ")
        win.attroff(cp(CP_DIM))
        return flows

    # Clamp selection
    state.selected = max(0, min(state.selected, len(flows) - 1))
    if state.selected < state.scroll:
        state.scroll = state.selected
    if state.selected >= state.scroll + visible:
        state.scroll = state.selected - visible + 1

    # Column widths
    col_threat = 9
    col_score  = 4
    col_src    = 17
    col_dst    = 17
    col_port   = 6
    col_proto  = 7
    col_fw     = 18
    col_host   = W - col_threat - col_score - col_src - col_dst - col_port - col_proto - col_fw - 9
    col_host   = max(10, col_host)

    # Header row
    hdr = (f"{'THREAT':<{col_threat}} {'SCR':>{col_score}} {'SRC IP':<{col_src}} "
           f"{'DST IP (RED TEAM)':<{col_dst}} {'PORT':<{col_port}} {'PROTO':<{col_proto}} "
           f"{'FRAMEWORK':<{col_fw}} HOST/PATH")
    win.attron(cp(CP_CYAN) | curses.A_BOLD)
    win.addstr(y0, 0, hdr[:W])
    win.attroff(cp(CP_CYAN) | curses.A_BOLD)

    for i in range(visible):
        idx = state.scroll + i
        if idx >= len(flows):
            break
        f   = flows[idx]
        an  = f["analysis"]
        thr = an["threat"]
        sel = (idx == state.selected)
        colour = THREAT_CP.get(thr, CP_WHITE)

        threat_str = f"{thr:<{col_threat}}"
        score_str  = f"{an['score']:>3}%"
        src_str    = f"{f['src_ip']:<{col_src}}"
        dst_str    = f"{f['dst_ip']:<{col_dst}}"
        port_str   = f"{f['dport']:<{col_port}}"
        proto_str  = f"{f['proto']:<{col_proto}}"
        fw_str     = f"{(an['framework'] or '—'):<{col_fw}}"
        host_str   = (f.get('sni') or f.get('host') or f.get('dns_query') or f.get('uri', ''))[:col_host]

        line = (f"{threat_str} {score_str} {src_str} {dst_str} "
                f"{port_str} {proto_str} {fw_str} {host_str}")

        attr = cp(colour) | curses.A_BOLD if sel else cp(colour)
        if sel and thr == "CRITICAL":
            attr = cp(CP_REDHL) | curses.A_BOLD
        elif sel:
            attr = cp(CP_GREENHL) | curses.A_BOLD

        win.attron(attr)
        win.addstr(y0 + 1 + i, 0, line[:W])
        win.attroff(attr)

    return flows

def draw_detail(win, flow, y0, H, W):
    an  = flow["analysis"]
    thr = an["threat"]
    colour = THREAT_CP.get(thr, CP_WHITE)

    y = y0
    def row(label, val, clr=CP_WHITE):
        nonlocal y
        if y >= y0 + H:
            return
        win.attron(cp(CP_DIM))
        win.addstr(y, 0, f"  {label:<18}")
        win.attroff(cp(CP_DIM))
        win.attron(cp(clr))
        win.addstr(y, 20, str(val)[:W-21])
        win.attroff(cp(clr))
        y += 1

    def sep(title=""):
        nonlocal y
        if y >= y0 + H:
            return
        win.attron(cp(CP_GREEN) | curses.A_BOLD)
        if title:
            win.addstr(y, 0, f"── {title} " + "─" * max(0, W - len(title) - 4))
        else:
            win.addstr(y, 0, "─" * W)
        win.attroff(cp(CP_GREEN) | curses.A_BOLD)
        y += 1

    sep(f"FLOW ANALYSIS  [{thr}  {an['score']}% confidence]")
    row("THREAT LEVEL",  thr,               colour)
    row("CONFIDENCE",    f"{an['score']}%", colour)
    row("FRAMEWORK",     an["framework"] or "Unknown", CP_ORANGE if an["framework"] else CP_DIM)
    row("TIMESTAMP",     an["timestamp"],   CP_DIM)

    sep("NETWORK")
    row("Source IP",     flow["src_ip"],    CP_CYAN)
    row("Dest IP",       flow["dst_ip"],    CP_RED if thr in ("CRITICAL","HIGH") else CP_WHITE)
    row("Dest Port",     flow["dport"],     CP_WHITE)
    row("Protocol",      flow["proto"],     CP_WHITE)
    if flow.get("host"): row("HTTP Host",   flow["host"], CP_WHITE)
    if flow.get("sni"):  row("TLS SNI",     flow["sni"],  CP_RED if flow.get("host") and flow["host"] != flow["sni"] else CP_WHITE)
    if flow.get("uri"):  row("URI",         flow["uri"],  CP_WHITE)
    if flow.get("user_agent"): row("User-Agent", flow["user_agent"][:60], CP_DIM)
    if flow.get("ja3"):  row("JA3",         flow["ja3"],  CP_RED if flow["ja3"] in KNOWN_BAD_JA3 else CP_DIM)
    if flow.get("dns_query"): row("DNS Query", flow["dns_query"][:60], CP_YELLOW)

    if flow.get("host") and flow.get("sni") and flow["host"] != flow["sni"]:
        sep("⚠  DOMAIN FRONTING DETECTED")
        row("Redirector",   flow["host"],   CP_YELLOW)
        row("Real C2",      flow["sni"],    CP_RED)
        row("Red Team IP",  flow["dst_ip"], CP_RED)

    if an["indicators"]:
        sep(f"INDICATORS  ({len(an['indicators'])})")
        for name, score, sev in an["indicators"]:
            sev_cp = CP_RED if sev == "critical" else CP_ORANGE if sev == "high" else CP_YELLOW
            row(f"+{score:3d} pts", name, sev_cp)

    if an["fw_hits"]:
        sep("SIGNATURE MATCHES")
        for fw_name, fw_score, hits in an["fw_hits"]:
            fw = C2_FRAMEWORKS.get(fw_name, {})
            clr = fw.get("color", CP_ORANGE)
            row(fw_name, f"score={fw_score}", clr)
            for h in hits:
                row("  └", h, CP_DIM)
            if fw.get("notes") and y < y0 + H:
                row("  NOTE", fw["notes"][:W-25], CP_DIM)

    sep("PRESS q/ESC TO RETURN")

def draw_manual(win, state, y0, H, W):
    fields = list(state.manual_fields.items())
    y = y0
    win.attron(cp(CP_GREEN) | curses.A_BOLD)
    win.addstr(y, 0, "── MANUAL FLOW ANALYSIS " + "─"*(W-25))
    win.attroff(cp(CP_GREEN) | curses.A_BOLD)
    y += 1
    win.attron(cp(CP_DIM))
    win.addstr(y, 0, "  TAB/↑↓ navigate fields  |  Type to edit  |  ENTER to analyse  |  ESC to cancel")
    win.attroff(cp(CP_DIM))
    y += 2

    for i, (k, v) in enumerate(fields):
        sel = i == state._manual_field_idx
        clr = CP_CYAN if sel else CP_DIM
        attr = cp(clr) | curses.A_BOLD if sel else cp(clr)
        label = k.replace("_", " ").upper()
        win.attron(attr)
        win.addstr(y + i, 0, f"  {label:<16} : {v:<{W-22}}")
        win.attroff(attr)

def draw_log(win, state, y0, H, W):
    win.attron(cp(CP_GREEN))
    win.addstr(y0, 0, "─"*W)
    win.attroff(cp(CP_GREEN))
    logs = list(state.log)
    for i in range(min(H - 1, len(logs))):
        line = logs[i][:W-1]
        if "CRITICAL" in line:
            win.attron(cp(CP_RED))
        elif "HIGH" in line or "WARN" in line:
            win.attron(cp(CP_ORANGE))
        elif "SUCCESS" in line:
            win.attron(cp(CP_GREEN))
        else:
            win.attron(cp(CP_DIM))
        win.addstr(y0 + 1 + i, 0, line)
        win.attroff(cp(CP_RED) | cp(CP_ORANGE) | cp(CP_GREEN) | cp(CP_DIM))

def draw_footer(win, state, H, W):
    keys = "[↑↓/jk] scroll  [ENTER] inspect  [f] filter  [s] sort  [e] export  [m] manual  [q] quit"
    if state.mode == "detail":
        keys = "[↑↓/jk] scroll  [q/ESC] back to list"
    elif state.mode == "manual":
        keys = "[TAB/↑↓] field  [Type] edit  [ENTER] analyse  [DEL] clear  [ESC] cancel"
    win.attron(cp(CP_DIM))
    win.addstr(H-1, 0, keys[:W-1])
    win.attroff(cp(CP_DIM))

def redraw(stdscr, state):
    stdscr.erase()
    H, W = stdscr.getmaxyx()

    header_h = 2
    footer_h = 1
    log_h    = 5
    detail_h = H - header_h - footer_h

    draw_header(stdscr, state, W)

    if state.mode == "manual":
        draw_manual(stdscr, state, header_h, detail_h, W)
    elif state.mode == "detail":
        flows = state.filtered_flows()
        if flows and 0 <= state.selected < len(flows):
            draw_detail(stdscr, flows[state.selected], header_h, detail_h, W)
        else:
            state.mode = "live"
    else:
        list_h = H - header_h - footer_h - log_h - 1
        flows = draw_flow_list(stdscr, state, header_h, list_h, W)
        log_y = header_h + list_h
        draw_log(stdscr, state, log_y, log_h, W)

    draw_footer(stdscr, state, H, W)

    try:
        stdscr.refresh()
    except curses.error:
        pass

# ─── BACKGROUND SCANNER THREADS ──────────────────────────────────────────────
def demo_scanner(state):
    state.add_log("DEMO mode active — simulating C2 traffic", "info")
    state.add_log("Signatures loaded: " + ", ".join(C2_FRAMEWORKS.keys()), "success")
    while state.running:
        flow = next_demo_flow()
        state.add_flow(flow)
        an = flow["analysis"]
        if an["threat"] == "CRITICAL":
            state.add_log(
                f"CRITICAL C2: {flow['src_ip']} → {flow['dst_ip']}:{flow['dport']}  "
                f"fw={an['framework'] or '?'}  score={an['score']}%", "critical")
        elif an["threat"] == "HIGH":
            state.add_log(
                f"HIGH RISK:  {flow['src_ip']} → {flow['dst_ip']}:{flow['dport']}  "
                f"score={an['score']}%", "warn")
        time.sleep(random.uniform(0.6, 1.8))

INJECT_PORT = 19117   # c2hunter_inject.py sends flows here

def inject_listener(state):
    """Accept JSON flows from c2hunter_inject.py over localhost TCP."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", INJECT_PORT))
        srv.listen(8)
        srv.settimeout(1.0)
        state.add_log(f"Inject listener on :{INJECT_PORT} — run c2hunter_inject.py in another terminal", "success")
    except OSError as e:
        state.add_log(f"Inject listener unavailable: {e}", "warn")
        return

    buf = b""
    while state.running:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except Exception:
            break
        try:
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            conn.close()
            for line in buf.split(b"\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    flows = data if isinstance(data, list) else [data]
                    for flow in flows:
                        for k in ("referer","accept","accept_lang","dns_query","ja3","host","sni"):
                            flow.setdefault(k, "")
                        flow.setdefault("timestamps", [time.time()])
                        flow.setdefault("bytes_sent", 0)
                        flow.setdefault("bytes_recv", 0)
                        flow.setdefault("body_len", 0)
                        flow.setdefault("id", f"inj_{int(time.time()*1000)}")
                        result = analyse_flow(flow)
                        state.add_flow(result)
                        an = result["analysis"]
                        lvl = "critical" if an["threat"] == "CRITICAL" else "warn" if an["threat"] == "HIGH" else "info"
                        state.add_log(
                            f"[INJECT] {an['threat']}  {flow['src_ip']} -> "
                            f"{flow['dst_ip']}:{flow.get('dport',0)}  "
                            f"{an.get('framework') or ''}  {an['score']}%", lvl)
                except Exception as ex:
                    state.add_log(f"Inject parse error: {ex}", "warn")
            buf = b""
        except Exception as ex:
            state.add_log(f"Inject conn error: {ex}", "warn")
            buf = b""
    srv.close()

def live_scanner(state):
    state.add_log("LIVE mode — /proc/net/tcp  |  run c2hunter_inject.py to inject scenarios", "info")
    state.add_log("Or: curl http://example.com  to generate real traffic", "info")
    seen = set()
    while state.running:
        try:
            conns = read_proc_tcp()
            for src, dst, dport in conns:
                key = (src, dst, dport)
                if key not in seen and not dst.startswith("127.") and dst != "::1":
                    seen.add(key)
                    flow = build_flow_from_conn(src, dst, dport)
                    state.add_flow(flow)
                    an = flow["analysis"]
                    if an["threat"] in ("CRITICAL", "HIGH"):
                        state.add_log(
                            f"{an['threat']}: {src} -> {dst}:{dport}  score={an['score']}%",
                            "critical" if an["threat"] == "CRITICAL" else "warn")
        except Exception as e:
            state.add_log(f"Capture error: {e}", "warn")
        time.sleep(2)

# ─── INPUT HANDLING ───────────────────────────────────────────────────────────
def handle_input(stdscr, state, key):
    H, W = stdscr.getmaxyx()

    if state.mode == "manual":
        fields = list(state.manual_fields.keys())
        fi = state._manual_field_idx
        fk = fields[fi]

        if key in (curses.KEY_UP, ord('k')):
            state._manual_field_idx = max(0, fi - 1)
        elif key in (curses.KEY_DOWN, ord('j'), ord('\t'), 9):
            state._manual_field_idx = min(len(fields) - 1, fi + 1)
        elif key in (curses.KEY_BACKSPACE, 127, curses.KEY_DC):
            state.manual_fields[fk] = state.manual_fields[fk][:-1]
        elif key == ord('\n'):
            # Analyse
            f = dict(state.manual_fields)
            try:
                f["dport"] = int(f.get("dport", 443))
            except ValueError:
                f["dport"] = 443
            f.setdefault("host", ""); f.setdefault("sni", "")
            f.setdefault("uri", "/"); f.setdefault("ja3", "")
            f.setdefault("dns_query", ""); f.setdefault("referer", "")
            f.setdefault("accept", ""); f.setdefault("accept_lang", "")
            f.setdefault("bytes_sent", 0); f.setdefault("bytes_recv", 0); f.setdefault("body_len", 0)
            f["timestamps"] = [time.time()]
            f["id"] = f"manual_{int(time.time())}"
            result = analyse_flow(f)
            state.add_flow(result)
            an = result["analysis"]
            state.add_log(
                f"MANUAL: {f['src_ip']} → {f['dst_ip']}:{f['dport']}  "
                f"threat={an['threat']}  score={an['score']}%",
                "critical" if an["threat"] == "CRITICAL" else "info")
            state.mode = "live"
        elif key in (27, curses.KEY_EXIT):   # ESC
            state.mode = "live"
        elif 32 <= key <= 126:
            state.manual_fields[fk] += chr(key)
        return

    if state.mode == "detail":
        if key in (ord('q'), 27, curses.KEY_EXIT, ord('h')):
            state.mode = "live"
        elif key in (curses.KEY_UP, ord('k')):
            state.selected = max(0, state.selected - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            flows = state.filtered_flows()
            state.selected = min(len(flows) - 1, state.selected + 1)
        return

    # Live mode
    if key in (ord('q'), 27):
        state.running = False
    elif key in (curses.KEY_UP, ord('k')):
        state.selected = max(0, state.selected - 1)
    elif key in (curses.KEY_DOWN, ord('j')):
        flows = state.filtered_flows()
        state.selected = min(len(flows) - 1, state.selected + 1)
    elif key in (curses.KEY_PPAGE,):  # PgUp
        state.selected = max(0, state.selected - 10)
    elif key in (curses.KEY_NPAGE,):  # PgDn
        flows = state.filtered_flows()
        state.selected = min(len(flows) - 1, state.selected + 10)
    elif key in (ord('\n'), curses.KEY_ENTER, 10):
        flows = state.filtered_flows()
        if flows:
            state.mode = "detail"
    elif key == ord('f'):
        idx = FILTER_CYCLE.index(state.filter)
        state.filter = FILTER_CYCLE[(idx + 1) % len(FILTER_CYCLE)]
        state.selected = 0
    elif key == ord('s'):
        sorts = ["time", "score", "src", "dst"]
        idx = sorts.index(state.sort_key)
        state.sort_key = sorts[(idx + 1) % len(sorts)]
    elif key == ord('e'):
        try:
            fname, n = state.export_findings()
            state.add_log(f"Exported {n} findings → {fname}", "success")
        except Exception as ex:
            state.add_log(f"Export failed: {ex}", "warn")
    elif key == ord('m'):
        state.mode = "manual"
        state._manual_field_idx = 0
    elif key == ord('c'):
        with state.lock:
            state.flows.clear()
        state._recalc_stats()
        state.add_log("Flow list cleared", "info")

# ─── MAIN CURSES LOOP ─────────────────────────────────────────────────────────
def main_loop(stdscr, state):
    init_colors()
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    last_draw = 0
    while state.running:
        try:
            key = stdscr.getch()
        except curses.error:
            key = -1

        if key != -1:
            handle_input(stdscr, state, key)

        now = time.time()
        if now - last_draw > 0.25:
            redraw(stdscr, state)
            last_draw = now

        time.sleep(0.05)

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="C2 Beacon Hunter — Threat Hunt TUI")
    parser.add_argument("--demo",   action="store_true", help="Simulated demo traffic (no root needed)")
    parser.add_argument("--pcap",   help="Offline pcap file (requires scapy)")
    parser.add_argument("--log",    help="Netflow/CSV log file")
    parser.add_argument("--no-inject", dest="no_inject", action="store_true",
                        help="Disable injection listener (port 19117)")
    args = parser.parse_args()

    state = AppState()

    # ── always start the inject listener unless disabled ──────────────────────
    if not args.no_inject:
        inj = threading.Thread(target=inject_listener, args=(state,), daemon=True)
        inj.start()

    # ── pick traffic source ───────────────────────────────────────────────────
    if args.demo or (not args.pcap and not args.log and not os.path.exists("/proc/net/tcp")):
        state.demo_mode = True
        t = threading.Thread(target=demo_scanner, args=(state,), daemon=True)
    elif args.pcap:
        print("PCAP mode requires scapy: pip install scapy")
        print("Falling back to demo mode.")
        state.demo_mode = True
        t = threading.Thread(target=demo_scanner, args=(state,), daemon=True)
    else:
        state.demo_mode = False
        t = threading.Thread(target=live_scanner, args=(state,), daemon=True)

    t.start()

    try:
        curses.wrapper(main_loop, state)
    except KeyboardInterrupt:
        pass
    finally:
        state.running = False

    print("\nC2 Hunter exited.")
    s = state.stats
    print(f"Flows analysed: {s['total']}  |  CRITICAL: {s['critical']}  |  HIGH: {s['high']}")

if __name__ == "__main__":
    main()
