#!/usr/bin/env python3
"""
beacon_interceptor.py  —  C2 Beacon Intercept & Poison Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Zero external dependencies | Python 3.6+ | stdlib only

WHAT IT DOES:
  Spins up HTTP and/or HTTPS servers on any port.
  Every request — regardless of URI, headers, method — is:
    1. Fully logged (headers, body, src IP, timestamp)
    2. Identified (matched against CS/MSF/Empire/Sliver signatures)
    3. Poisoned  (returns a crafted "not today" response)

  The poison response is designed to:
    - Return a valid-looking HTTP 200 so the beacon doesn't
      immediately retry or alert the operator
    - Deliver a "not today" message as the response body
    - Optionally serve a fake CS task that tells the beacon to sleep
      forever (beacon kill via crafted task)
    - Record every captured request to a JSON log

HOW TO USE:
  Step 1 — Find attacker IP via c2hunter.py
  Step 2 — Set up intercept:
            a) ARP spoof / DNS poison to redirect beacon traffic to YOU
               OR
            b) If you control the compromised host, redirect via /etc/hosts
               OR
            c) If attacker uses a redirector you've identified, use iptables
               REDIRECT rule to send their traffic to this server
  Step 3 — Run this tool and watch beacons check in to YOU instead

USAGE:
    # Interactive menu
    python3 beacon_interceptor.py

    # Listen on HTTP 80 + HTTPS 443
    python3 beacon_interceptor.py --http 80 --https 443

    # Listen on specific ports, target a known beacon IP
    python3 beacon_interceptor.py --http 8080 --beacon-ip 192.168.1.50

    # Use your own cert (if you have one matching the C2 domain)
    python3 beacon_interceptor.py --https 443 --cert server.crt --key server.key

    # Aggressive mode: serve a crafted CS sleep-forever task
    python3 beacon_interceptor.py --https 443 --mode kill

REDIRECT SETUP (pick one):
    # If you can run iptables on the same host as the beacon:
    sudo iptables -t nat -A OUTPUT -d <c2_ip> -p tcp --dport 443 -j REDIRECT --to-port 443
    sudo iptables -t nat -A OUTPUT -d <c2_ip> -p tcp --dport 80  -j REDIRECT --to-port 80

    # To intercept ALL outbound HTTP/S on this machine:
    sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 4443
    sudo iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-port 8080

    # /etc/hosts redirect (if you can edit the compromised host):
    echo "127.0.0.1  c2.attacker-domain.com" >> /etc/hosts
"""

import sys, os, re, ssl, time, json, socket, struct, threading, argparse
import http.server, http.client, base64, hashlib, ipaddress
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

# ── colours ───────────────────────────────────────────────────────────────────
G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"
D="\033[90m"; B="\033[1m";  RS="\033[0m"; O="\033[33m"; M="\033[95m"

def hdr(t):  print(f"\n{B}{C}{'━'*64}{RS}\n{B}{C}  {t}{RS}\n{B}{C}{'━'*64}{RS}")
def ok(t):   print(f"  {G}{B}[+]{RS} {t}")
def bad(t):  print(f"  {R}{B}[!]{RS} {t}")
def warn(t): print(f"  {Y}[~]{RS} {t}")
def inf(t):  print(f"  {C}[i]{RS} {t}")
def cap(t):  print(f"  {M}{B}[CAPTURE]{RS} {t}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BEACON IDENTIFICATION SIGNATURES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BEACON_SIGS = [
    {
        "name": "Cobalt Strike (MSIE UA)",
        "color": R+B,
        "ua":  re.compile(r"Mozilla/4\.0 \(compatible; MSIE [678]\.", re.I),
        "uri": re.compile(r"/(submit\.php|updates|pixel\.gif|news\.php|__utm\.gif|jquery.*\.js|ca)"),
        "method": {"GET","POST"},
    },
    {
        "name": "Cobalt Strike (jQuery malleable)",
        "color": R+B,
        "ua":  re.compile(r"Mozilla/4\.0.*MSIE 8.*Trident", re.I),
        "uri": re.compile(r"/jquery-\d+\.\d+\.\d+\.min\.js"),
        "method": {"GET"},
    },
    {
        "name": "Cobalt Strike (default staging)",
        "color": R+B,
        "ua":  re.compile(r"Mozilla/4\.0.*MSIE.*Windows NT", re.I),
        "uri": re.compile(r"^/[A-Za-z0-9+/]{4,}$"),
        "method": {"GET"},
    },
    {
        "name": "Metasploit Meterpreter",
        "color": O+B,
        "ua":  re.compile(r"Mozilla/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)", re.I),
        "uri": re.compile(r"^/[A-Za-z0-9+/]{76,}$"),
        "method": {"GET"},
    },
    {
        "name": "PowerShell Empire",
        "color": O+B,
        "ua":  re.compile(r"Mozilla/5\.0.*Trident/7\.0", re.I),
        "uri": re.compile(r"^/[a-z]{8,12}/[a-z]{4,8}(/index\.jsp)?$"),
        "method": {"GET","POST"},
    },
    {
        "name": "Sliver C2",
        "color": Y+B,
        "ua":  re.compile(r"Mozilla/5\.0", re.I),
        "uri": re.compile(r"^/fonts/.*\.woff2?$|^/static/.*\.(js|css)$"),
        "method": {"GET"},
    },
    {
        "name": "Havoc C2",
        "color": R+B,
        "ua":  re.compile(r"", re.I),  # UA varies
        "uri": re.compile(r"^/[a-zA-Z0-9]{8}$"),
        "method": {"GET","POST"},
    },
    {
        "name": "Generic C2 (low byte ratio)",
        "color": Y,
        "ua":  re.compile(r".*"),
        "uri": re.compile(r".*"),
        "method": {"GET","POST","PUT"},
        "generic": True,  # only triggers if other signals present
    },
]

def identify_beacon(method, path, headers, body):
    """Return (framework_name, confidence) or (None, 0)."""
    ua = headers.get("user-agent","")
    results = []
    for sig in BEACON_SIGS:
        if sig.get("generic"):
            continue
        ua_match  = sig["ua"].search(ua) is not None
        uri_match = sig["uri"].search(path) is not None
        meth_match = method.upper() in sig["method"]
        score = (ua_match * 40) + (uri_match * 35) + (meth_match * 10)
        if score >= 40:
            results.append((sig["name"], score, sig["color"]))

    if results:
        results.sort(key=lambda x: x[1], reverse=True)
        return results[0]
    return None, 0, D

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# POISON RESPONSE BUILDER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NOT_TODAY_MESSAGE = """\
NOT TODAY.

Your beacon has been intercepted.
This C2 channel is now compromised.

  Captured by: NCAE Blue Team
  Timestamp:   {timestamp}
  Your IP:     {client_ip}
  Request:     {method} {path}
  Framework:   {framework}

The game is up. We know where you are.

  ███╗   ██╗ ██████╗ ████████╗    ████████╗ ██████╗ ██████╗  █████╗ ██╗   ██╗
  ████╗  ██║██╔═══██╗╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
  ██╔██╗ ██║██║   ██║   ██║          ██║   ██║   ██║██║  ██║███████║ ╚████╔╝ 
  ██║╚██╗██║██║   ██║   ██║          ██║   ██║   ██║██║  ██║██╔══██║  ╚██╔╝  
  ██║ ╚████║╚██████╔╝   ██║          ██║   ╚██████╔╝██████╔╝██║  ██║   ██║   
  ╚═╝  ╚═══╝ ╚═════╝    ╚═╝          ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝  
"""

# Cobalt Strike crafted task: sleep for 2147483647ms (~24 days) = beacon kill
# CS task format: 4-byte task ID + 4-byte command + payload
# Command 4 = SLEEP, payload = sleep time as 4-byte LE int + jitter
def craft_cs_sleep_forever():
    """
    Return bytes that, if the beacon decrypts them as a CS task,
    will tell the beacon to sleep for ~24 days.
    This only works if we know / can guess the AES key — without it
    the beacon will ignore/error on malformed tasks.
    We send it anyway to disrupt partial implementations.
    """
    task_id = struct.pack(">I", 0xDEADBEEF)
    cmd_sleep = struct.pack(">I", 4)          # CS task 4 = sleep
    sleep_ms  = struct.pack("<I", 0x7FFFFFFF) # 24.8 days
    jitter    = struct.pack("<I", 0)
    payload   = task_id + cmd_sleep + sleep_ms + jitter
    length    = struct.pack(">I", len(payload))
    return length + payload

def build_poison_response(mode, client_ip, method, path, framework):
    """Return (http_status, headers, body_bytes)."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    if mode == "nottoday":
        # Primary mode: return a text file that says NOT TODAY
        body = NOT_TODAY_MESSAGE.format(
            timestamp=ts, client_ip=client_ip,
            method=method, path=path,
            framework=framework or "Unknown C2"
        ).encode("utf-8")
        headers = {
            "Content-Type":   "text/plain; charset=utf-8",
            "Content-Length": str(len(body)),
            "Cache-Control":  "no-store, no-cache",
            "X-Intercepted":  "true",
            # Mimic whatever the real server would say to keep beacon alive
            # but confused — CS default is no special headers
            "Server":         "Microsoft-IIS/8.5",
        }
        return 200, headers, body

    elif mode == "kill":
        # Kill mode: serve crafted CS sleep-forever task
        # (only effective against CS beacons where we have the AES key,
        #  otherwise it'll fail to decrypt but still disrupts)
        body = craft_cs_sleep_forever()
        headers = {
            "Content-Type":   "application/octet-stream",
            "Content-Length": str(len(body)),
            "Cache-Control":  "no-store, no-cache",
            "Server":         "Microsoft-IIS/8.5",
        }
        return 200, headers, body

    elif mode == "redirect":
        # Redirect mode: 301 to a honeypot or loopback
        headers = {
            "Location":       "http://127.0.0.1/",
            "Content-Length": "0",
        }
        return 301, headers, b""

    elif mode == "stall":
        # Stall mode: 200 with empty body — beacon waits for task, times out
        headers = {
            "Content-Type":   "text/plain",
            "Content-Length": "0",
            "Server":         "Microsoft-IIS/8.5",
        }
        return 200, headers, b""

    elif mode == "404":
        # 404 mode: make C2 think the endpoint moved
        body = b"404 Not Found"
        headers = {
            "Content-Type":   "text/plain",
            "Content-Length": str(len(body)),
        }
        return 404, headers, body

    # Default fallback
    return 200, {"Content-Type":"text/plain","Content-Length":"9"}, b"not today"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CAPTURE LOGGER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CaptureLog:
    def __init__(self, logfile=None):
        self.entries    = []
        self.lock       = threading.Lock()
        self.logfile    = logfile or f"intercept_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.counts     = defaultdict(int)
        self.first_seen = {}  # ip → timestamp

    def record(self, entry):
        with self.lock:
            self.entries.append(entry)
            ip = entry.get("client_ip","?")
            self.counts[ip] += 1
            if ip not in self.first_seen:
                self.first_seen[ip] = entry["timestamp"]
            # Append to file immediately
            try:
                with open(self.logfile, "w") as f:
                    json.dump(self.entries, f, indent=2)
            except Exception:
                pass

    def stats(self):
        with self.lock:
            return dict(self.counts), len(self.entries)

CAPTURE = None  # global, set at startup

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTTP REQUEST HANDLER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class InterceptHandler(http.server.BaseHTTPRequestHandler):
    # Set by the server before starting
    poison_mode   = "nottoday"
    beacon_ip     = None         # if set, only poison this IP; pass others
    target_ips    = set()        # whitelist — always intercept
    passthrough   = False        # if True, proxy legit requests
    verbose       = True

    def log_message(self, fmt, *args):
        # Suppress default access log — we do our own
        pass

    def _get_client_ip(self):
        # Check X-Forwarded-For first (in case behind proxy)
        xff = self.headers.get("X-Forwarded-For","")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 0:
            return self.rfile.read(min(length, 65536))
        return b""

    def _should_intercept(self, client_ip):
        if not self.beacon_ip and not self.target_ips:
            return True  # intercept everything
        if self.beacon_ip and client_ip == self.beacon_ip:
            return True
        if client_ip in self.target_ips:
            return True
        return False

    def _handle_request(self):
        client_ip = self._get_client_ip()
        method    = self.command
        path      = self.path
        headers   = {k.lower(): v for k,v in self.headers.items()}
        body      = self._read_body()
        ts        = datetime.now().isoformat()
        proto     = "HTTPS" if hasattr(self.connection, "_sslobj") else "HTTP"

        # Identify framework
        framework, confidence, fw_color = identify_beacon(method, path, headers, body)

        # Build log entry
        entry = {
            "timestamp":  ts,
            "client_ip":  client_ip,
            "proto":      proto,
            "method":     method,
            "path":       path,
            "headers":    dict(headers),
            "body_len":   len(body),
            "body_hex":   body[:64].hex() if body else "",
            "framework":  framework,
            "confidence": confidence,
            "poisoned":   self._should_intercept(client_ip),
        }

        # Print capture
        ts_short = datetime.now().strftime("%H:%M:%S")
        fw_str   = f"  {fw_color}[{framework}]{RS}" if framework else ""
        icp_str  = f"{M}{B}INTERCEPTED{RS}" if self._should_intercept(client_ip) else f"{D}PASSTHROUGH{RS}"

        print(f"\n  {B}{'─'*62}{RS}")
        print(f"  {ts_short}  {icp_str}{fw_str}")
        print(f"  {C}{client_ip:<18}{RS} {Y}{method:<6}{RS} {proto:<5}  {B}{path}{RS}")

        # Print interesting headers
        interesting = ["user-agent","host","referer","x-forwarded-for",
                       "cookie","authorization","content-type","content-length"]
        for h in interesting:
            if h in headers:
                print(f"  {D}  {h}: {headers[h][:80]}{RS}")

        # Print body preview
        if body:
            printable = body.decode("utf-8","replace")
            if all(0x20 <= ord(c) < 0x7f or c in "\r\n\t" for c in printable[:32]):
                print(f"  {D}  body: {printable[:60]}{RS}")
            else:
                print(f"  {D}  body: [binary {len(body)}b]  hex={body[:16].hex()}{RS}")

        if framework:
            cap(f"{fw_color}{framework}{RS}  confidence={confidence}%")

        # Record
        if CAPTURE:
            CAPTURE.record(entry)
            counts, total = CAPTURE.stats()
            print(f"  {D}  log: {CAPTURE.logfile}  total_captured={total}  this_ip={counts.get(client_ip,0)}{RS}")

        # ── Send response ────────────────────────────────────────────────────
        if self._should_intercept(client_ip):
            status, resp_headers, resp_body = build_poison_response(
                self.poison_mode, client_ip, method, path, framework
            )

            self.send_response(status)
            for k, v in resp_headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp_body)

            mode_color = R+B if self.poison_mode=="kill" else M+B
            print(f"  {mode_color}[POISONED]{RS}  {status}  {len(resp_body)}b  mode={self.poison_mode}")
            if self.poison_mode == "nottoday":
                print(f"  {M}  Sent: NOT TODAY.txt ({len(resp_body)}b){RS}")

        else:
            # Passthrough — return generic 200 to not break legit traffic
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

    # Handle all HTTP methods
    def do_GET(self):     self._handle_request()
    def do_POST(self):    self._handle_request()
    def do_PUT(self):     self._handle_request()
    def do_HEAD(self):    self._handle_request()
    def do_OPTIONS(self): self._handle_request()
    def do_DELETE(self):  self._handle_request()
    def do_PATCH(self):   self._handle_request()

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SERVER FACTORY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ThreadedHTTPServer(http.server.HTTPServer):
    """One thread per connection."""
    def process_request(self, request, client_address):
        t = threading.Thread(
            target=self.__process_request_thread,
            args=(request, client_address), daemon=True
        )
        t.start()

    def __process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            pass
        finally:
            self.shutdown_request(request)

def make_handler(mode, beacon_ip, target_ips):
    """Return a customised handler class."""
    class H(InterceptHandler):
        poison_mode = mode
        pass
    H.beacon_ip   = beacon_ip
    H.target_ips  = set(target_ips) if target_ips else set()
    return H

def start_http_server(port, handler_class):
    srv = ThreadedHTTPServer(("0.0.0.0", port), handler_class)
    ok(f"HTTP  listener  →  0.0.0.0:{port}")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv

def start_https_server(port, handler_class, certfile, keyfile):
    srv = ThreadedHTTPServer(("0.0.0.0", port), handler_class)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    # Accept all cipher suites — we want to talk to C2 beacons that may use old TLS
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)

    ok(f"HTTPS listener  →  0.0.0.0:{port}  (cert={certfile})")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv

def ensure_cert(certfile, keyfile):
    """Generate a self-signed cert if none exists."""
    if os.path.exists(certfile) and os.path.exists(keyfile):
        return True
    inf("Generating self-signed certificate...")
    import subprocess
    try:
        result = subprocess.run([
            "openssl","req","-x509","-newkey","rsa:2048",
            "-keyout", keyfile,
            "-out",    certfile,
            "-days",   "365",
            "-nodes",
            "-subj",   "/C=US/ST=State/L=City/O=Corp/CN=localhost",
        ], capture_output=True, timeout=15)
        if result.returncode == 0:
            ok(f"Certificate generated: {certfile}")
            return True
        else:
            bad(f"openssl failed: {result.stderr.decode()[:100]}")
            return False
    except Exception as e:
        bad(f"Could not generate cert: {e}")
        return False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LIVE DISPLAY THREAD
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def stats_display(capture, interval=30):
    """Print a stats summary every N seconds."""
    while True:
        time.sleep(interval)
        counts, total = capture.stats()
        if total == 0:
            continue
        print(f"\n{B}{D}{'─'*64}{RS}")
        print(f"{B}{D}  INTERCEPT STATS  |  total={total}  unique_ips={len(counts)}{RS}")
        for ip, n in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            bar = "█" * min(n, 40)
            print(f"{D}  {ip:<18} {n:4d}  {C}{bar}{RS}")
        print(f"{B}{D}{'─'*64}{RS}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# IPTABLES HELPER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def setup_redirect(c2_ip, http_port, https_port):
    """Add iptables REDIRECT rules to intercept beacon traffic."""
    import subprocess
    rules = []
    if c2_ip:
        if http_port:
            rules.append(["iptables","-t","nat","-A","OUTPUT",
                           "-d",c2_ip,"-p","tcp","--dport","80",
                           "-j","REDIRECT","--to-port",str(http_port)])
        if https_port:
            rules.append(["iptables","-t","nat","-A","OUTPUT",
                           "-d",c2_ip,"-p","tcp","--dport","443",
                           "-j","REDIRECT","--to-port",str(https_port)])
    else:
        # Intercept all outbound HTTP/S
        if http_port and http_port != 80:
            rules.append(["iptables","-t","nat","-A","OUTPUT",
                           "-p","tcp","--dport","80",
                           "-j","REDIRECT","--to-port",str(http_port)])
        if https_port and https_port != 443:
            rules.append(["iptables","-t","nat","-A","OUTPUT",
                           "-p","tcp","--dport","443",
                           "-j","REDIRECT","--to-port",str(https_port)])

    sub("Applying iptables REDIRECT rules")
    applied = []
    for rule in rules:
        try:
            r = subprocess.run(rule, capture_output=True)
            if r.returncode == 0:
                ok("Applied: " + " ".join(rule))
                applied.append(rule)
            else:
                bad("Failed: " + " ".join(rule) + f"\n  {r.stderr.decode()[:80]}")
        except FileNotFoundError:
            bad("iptables not found — apply manually:")
            inf("  " + " ".join(rule))
        except Exception as e:
            bad(f"Error: {e}")
    return applied

def cleanup_redirect(rules):
    """Remove the iptables rules we added."""
    import subprocess
    for rule in rules:
        cleanup = [r if r != "-A" else "-D" for r in rule]
        try:
            subprocess.run(cleanup, capture_output=True)
        except Exception:
            pass

def sub(t): print(f"\n{B}{Y}  ── {t}{RS}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INTERACTIVE MENU
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def interactive_setup():
    hdr("BEACON INTERCEPTOR — Setup Wizard")

    print(f"""
  {B}How it works:{RS}
  {D}  1. This server listens on HTTP/HTTPS ports you choose
     2. Any C2 beacon that connects gets a "NOT TODAY" text response
     3. Every request is logged to JSON with headers, body, framework ID
     4. You pick the poison mode (nottoday / kill / stall / 404)

  {B}Before starting, make sure beacon traffic reaches this server:{RS}
  {D}  Option A (same host as beacon):
       sudo iptables -t nat -A OUTPUT -d <c2_ip> -p tcp --dport 443 -j REDIRECT --to-port <your_port>

  Option B (DNS/ARP position):
       Point c2 domain to this machine's IP in /etc/hosts or via ARP spoof

  Option C (control compromised host):
       Add to /etc/hosts on the compromised machine:
       127.0.0.1  <c2-domain>
       Then run this tool on that machine{RS}
""")

    # Beacon IP
    beacon_ip = input(f"  Target beacon IP to intercept (or ENTER for ALL IPs): ").strip() or None
    if beacon_ip:
        ok(f"Will intercept traffic from: {beacon_ip}")
    else:
        warn("Intercepting ALL incoming connections")

    # Ports
    http_port_str  = input(f"  HTTP  port  [80 / ENTER to skip]:  ").strip()
    https_port_str = input(f"  HTTPS port  [443 / ENTER to skip]: ").strip()
    http_port  = int(http_port_str)  if http_port_str.isdigit() else None
    https_port = int(https_port_str) if https_port_str.isdigit() else None

    if not http_port and not https_port:
        http_port = 8080
        warn("No ports specified — defaulting to HTTP 8080")

    # Mode
    print(f"""
  {B}Poison modes:{RS}
  {M}  nottoday{RS}  — Return a text file saying NOT TODAY (default, recommended)
  {R}  kill    {RS}  — Serve crafted CS sleep-forever task (CS beacons only)
  {Y}  stall   {RS}  — Return empty 200 — beacon waits forever for a task
  {D}  404     {RS}  — Return 404 — beacon thinks C2 moved
  {D}  redirect{RS}  — 301 redirect to loopback
""")
    mode = input(f"  Mode [nottoday]: ").strip().lower() or "nottoday"
    if mode not in ("nottoday","kill","stall","404","redirect"):
        mode = "nottoday"

    # Cert
    certfile = "intercept_cert.pem"
    keyfile  = "intercept_key.pem"
    if https_port:
        custom = input(f"  Custom cert file (ENTER to auto-generate): ").strip()
        if custom and os.path.exists(custom):
            certfile = custom
            keyfile  = input(f"  Key file: ").strip()

    # iptables redirect
    redirect_rules = []
    if beacon_ip:
        apply_ipt = input(f"\n  Auto-apply iptables REDIRECT for {beacon_ip}? [y/N]: ").strip().lower()
        if apply_ipt == "y":
            redirect_rules = setup_redirect(beacon_ip, http_port, https_port)

    return beacon_ip, http_port, https_port, mode, certfile, keyfile, redirect_rules

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_servers(http_port, https_port, mode, beacon_ip, target_ips,
                certfile, keyfile, logfile):
    global CAPTURE
    CAPTURE = CaptureLog(logfile)

    handler = make_handler(mode, beacon_ip, target_ips)
    servers = []

    hdr("BEACON INTERCEPTOR — RUNNING")

    if http_port:
        try:
            servers.append(start_http_server(http_port, handler))
        except OSError as e:
            bad(f"HTTP port {http_port}: {e}")

    if https_port:
        if ensure_cert(certfile, keyfile):
            try:
                servers.append(start_https_server(https_port, handler, certfile, keyfile))
            except OSError as e:
                bad(f"HTTPS port {https_port}: {e}")
        else:
            bad("Could not start HTTPS — no certificate")

    if not servers:
        bad("No servers started"); return

    print()
    inf(f"Poison mode:   {M}{B}{mode}{RS}")
    inf(f"Beacon filter: {C}{beacon_ip or 'ALL IPs'}{RS}")
    inf(f"Capture log:   {G}{CAPTURE.logfile}{RS}")
    print()
    warn("Waiting for beacon connections... (Ctrl+C to stop)")
    print(f"  {D}{'─'*62}{RS}")

    # Start stats thread
    stats_t = threading.Thread(target=stats_display, args=(CAPTURE,), daemon=True)
    stats_t.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n\n{B}{Y}  Shutting down...{RS}")
        for s in servers:
            try: s.shutdown()
            except: pass

    # Final summary
    counts, total = CAPTURE.stats()
    hdr("SESSION SUMMARY")
    ok(f"Total requests intercepted: {total}")
    ok(f"Unique source IPs: {len(counts)}")
    if counts:
        print()
        bad("Captured beacon IPs:")
        for ip, n in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    {R}{B}{ip:<20}{RS}  {n} requests")
    ok(f"Full capture log: {CAPTURE.logfile}")

def main():
    parser = argparse.ArgumentParser(description="C2 Beacon Interceptor & Poison Server")
    parser.add_argument("--http",       type=int,   help="HTTP  listen port (e.g. 80)")
    parser.add_argument("--https",      type=int,   help="HTTPS listen port (e.g. 443)")
    parser.add_argument("--mode",       default="nottoday",
                        choices=["nottoday","kill","stall","404","redirect"],
                        help="Poison mode (default: nottoday)")
    parser.add_argument("--beacon-ip",  help="Only intercept from this source IP")
    parser.add_argument("--target",     action="append", default=[],
                        help="Additional IPs to always intercept (repeat flag)")
    parser.add_argument("--cert",       default="intercept_cert.pem", help="TLS cert file")
    parser.add_argument("--key",        default="intercept_key.pem",  help="TLS key file")
    parser.add_argument("--log",        help="Output JSON log file")
    parser.add_argument("--redirect-ip",help="Auto-apply iptables REDIRECT rules for this C2 IP")
    args = parser.parse_args()

    redirect_rules = []

    if not args.http and not args.https:
        # Interactive wizard
        beacon_ip, http_port, https_port, mode, certfile, keyfile, redirect_rules = \
            interactive_setup()
    else:
        beacon_ip  = args.beacon_ip
        http_port  = args.http
        https_port = args.https
        mode       = args.mode
        certfile   = args.cert
        keyfile    = args.key

        if args.redirect_ip:
            redirect_rules = setup_redirect(args.redirect_ip, http_port, https_port)

    try:
        run_servers(
            http_port  = http_port,
            https_port = https_port,
            mode       = mode,
            beacon_ip  = beacon_ip,
            target_ips = args.target if hasattr(args,"target") else [],
            certfile   = certfile,
            keyfile    = keyfile,
            logfile    = args.log if hasattr(args,"log") else None,
        )
    finally:
        if redirect_rules:
            cleanup_redirect(redirect_rules)
            ok("iptables REDIRECT rules removed")

if __name__ == "__main__":
    main()
