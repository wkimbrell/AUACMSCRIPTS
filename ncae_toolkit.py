#!/usr/bin/env python3
"""
ncae_toolkit.py  —  NCAE Cyber Games Threat Hunting Toolkit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Zero external dependencies | Python 3.6+ | stdlib only

Tools included:
  1  Port Scanner          TCP connect scan, banner grab, service ID
  2  ARP/Host Discovery    Sweep subnet for live hosts (ICMP + TCP)
  3  Brute-Force Detector  Parse auth logs for brute force attempts
  4  DNS Anomaly Hunter    Find DNS beacons, exfil, tunnels
  5  Log Analyzer          grep /var/log/* for IOCs, persistence, shells
  6  Lateral Movement      Track east-west connections across /proc/net
  7  Process Hunter        Find suspicious processes, parent chains, injection
  8  File Integrity        Hash key system files, detect modifications
  9  Network Baseline      Snapshot connections, alert on new ones
 10  Quick IOC Scan        Fire all tools, summarize findings

Usage:
    python3 ncae_toolkit.py                 # interactive TUI menu
    python3 ncae_toolkit.py --tool portscan --target 10.0.0.0/24
    python3 ncae_toolkit.py --tool brutedet --log /var/log/auth.log
    python3 ncae_toolkit.py --tool quickscan
    python3 ncae_toolkit.py --tool all

NCAE-specific:
    - Assumes blue team defending typical Linux + Windows AD environment
    - All tools write findings to ncae_findings_<timestamp>.json
    - Designed to work during competition with no internet access
"""

import sys, os, re, time, math, json, socket, struct, argparse, threading
import subprocess, hashlib, ipaddress, random, glob, signal
from datetime import datetime
from collections import defaultdict, deque

# ── platform ──────────────────────────────────────────────────────────────────
IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    import ctypes, msvcrt
    try:
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# ── colours ───────────────────────────────────────────────────────────────────
G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"
D="\033[90m"; B="\033[1m";  RS="\033[0m"; O="\033[33m"; M="\033[95m"
BG_RED="\033[41m"; BG_GRN="\033[42m"

def hdr(t):  print(f"\n{B}{C}{'━'*64}{RS}\n{B}{C}  {t}{RS}\n{B}{C}{'━'*64}{RS}")
def sub(t):  print(f"\n{B}{Y}  ── {t}{RS}")
def ok(t):   print(f"  {G}{B}[+]{RS} {t}")
def bad(t):  print(f"  {R}{B}[!]{RS} {t}")
def warn(t): print(f"  {Y}{B}[~]{RS} {t}")
def inf(t):  print(f"  {C}[i]{RS} {t}")
def dim(t):  print(f"  {D}    {t}{RS}")
def sep():   print(f"  {D}{'─'*60}{RS}")

FINDINGS = []

def finding(category, severity, title, detail, data=None):
    f = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "data": data or {},
    }
    FINDINGS.append(f)
    c = {
        "CRITICAL": R+B, "HIGH": O+B, "MEDIUM": Y,
        "LOW": G, "INFO": C
    }.get(severity, D)
    print(f"  {c}[{severity:8s}]{RS}  {B}{title}{RS}  {D}{detail[:70]}{RS}")
    return f

def save_findings(prefix="ncae_findings"):
    if not FINDINGS:
        return None
    fname = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as fp:
        json.dump(FINDINGS, fp, indent=2)
    return fname

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 1: PORT SCANNER
# ──────────────────────────────────────────────────────────────────────────────

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 137:"NetBIOS",
    139:"NetBIOS", 143:"IMAP", 389:"LDAP", 443:"HTTPS", 445:"SMB",
    465:"SMTPS", 587:"SMTP", 631:"IPP", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 1521:"Oracle", 2049:"NFS", 2375:"Docker",
    3306:"MySQL", 3389:"RDP", 4444:"Meterpreter?", 4445:"Meterpreter?",
    5432:"PostgreSQL", 5900:"VNC", 5985:"WinRM-HTTP", 5986:"WinRM-HTTPS",
    6379:"Redis", 8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"Jupyter?",
    9200:"Elasticsearch", 27017:"MongoDB", 50050:"TeamServer?",
}

SUSPICIOUS_PORTS = {4444, 4445, 50050, 8888, 31337, 1337, 9001, 9002}

def tcp_connect(host, port, timeout=0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        # Try banner grab
        banner = ""
        try:
            s.settimeout(0.3)
            data = s.recv(256)
            banner = data.decode("utf-8", errors="replace").strip()[:80]
        except Exception:
            pass
        s.close()
        return True, banner
    except Exception:
        return False, ""

def port_scan(target, ports=None, timeout=0.8, threads=100):
    hdr(f"PORT SCANNER  →  {target}")

    # Resolve / expand target
    targets = []
    try:
        net = ipaddress.ip_network(target, strict=False)
        targets = [str(h) for h in net.hosts()]
        if len(targets) > 256:
            warn(f"Large subnet ({len(targets)} hosts) — limiting to /24 or specify a single IP")
            targets = targets[:254]
    except ValueError:
        targets = [target]

    if ports is None:
        ports = sorted(COMMON_PORTS.keys())

    inf(f"Scanning {len(targets)} host(s), {len(ports)} port(s), {threads} threads")
    print()

    open_ports = defaultdict(list)
    lock = threading.Lock()
    sem  = threading.Semaphore(threads)
    tasks = [(h, p) for h in targets for p in ports]
    done  = [0]
    total = len(tasks)

    def scan_one(host, port):
        with sem:
            ok_flag, banner = tcp_connect(host, port, timeout)
            if ok_flag:
                svc = COMMON_PORTS.get(port, "?")
                with lock:
                    open_ports[host].append((port, svc, banner))
                    done[0] += 1
                    suspicious = port in SUSPICIOUS_PORTS
                    sev = "CRITICAL" if suspicious else "HIGH" if port in (22,23,3389,5900) else "INFO"
                    finding("PortScan", sev,
                            f"Open port {host}:{port}/{svc}",
                            banner[:60] if banner else f"Service: {svc}",
                            {"host":host,"port":port,"service":svc,"banner":banner})

    tlist = [threading.Thread(target=scan_one, args=(h,p), daemon=True)
             for h,p in tasks]
    for t in tlist: t.start()

    # Progress bar
    start = time.time()
    while any(t.is_alive() for t in tlist):
        pct  = sum(1 for t in tlist if not t.is_alive()) / max(1,len(tlist)) * 100
        ela  = time.time() - start
        bar  = int(pct / 2)
        sys.stdout.write(f"\r  {D}[{'█'*bar:{'─'}<50}] {pct:5.1f}%  {ela:.1f}s{RS}")
        sys.stdout.flush()
        time.sleep(0.2)
    for t in tlist: t.join()
    print("\r" + " "*70 + "\r", end="")

    # Results
    if not open_ports:
        warn("No open ports found")
        return

    sub("Results")
    for host in sorted(open_ports.keys()):
        ports_list = sorted(open_ports[host], key=lambda x: x[0])
        print(f"\n  {B}{C}{host}{RS}")
        for port, svc, banner in ports_list:
            susp = port in SUSPICIOUS_PORTS
            pc = R+B if susp else O if port in (23,4444) else G
            flag = f"  {R}{B}◈ SUSPICIOUS{RS}" if susp else ""
            print(f"    {pc}{port:5d}/{svc:<16}{RS}  {D}{banner[:50]}{RS}{flag}")

    sep()
    inf(f"Found {sum(len(v) for v in open_ports.values())} open ports across {len(open_ports)} hosts")
    susp_found = [(h,p,s) for h,pl in open_ports.items() for p,s,_ in pl if p in SUSPICIOUS_PORTS]
    if susp_found:
        print()
        bad(f"SUSPICIOUS PORTS FOUND:")
        for h,p,s in susp_found:
            bad(f"  {h}:{p} ({s}) — possible C2/RAT listener")

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 2: HOST DISCOVERY
# ──────────────────────────────────────────────────────────────────────────────

def ping_host(ip, timeout=0.5):
    """ICMP ping via OS (no raw sockets needed)."""
    flag = "-n" if IS_WINDOWS else "-c"
    w    = "-w" if IS_WINDOWS else "-W"
    try:
        result = subprocess.run(
            ["ping", flag, "1", w, str(int(timeout*1000) if IS_WINDOWS else int(timeout)),
             ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout+0.5
        )
        return result.returncode == 0
    except Exception:
        return False

def arp_scan(subnet, timeout=0.5, threads=64):
    hdr(f"HOST DISCOVERY  →  {subnet}")
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = [str(h) for h in net.hosts()]
    except ValueError:
        bad(f"Invalid subnet: {subnet}"); return []

    if len(hosts) > 1022:
        warn(f"Limiting to first 254 hosts of {len(hosts)}"); hosts = hosts[:254]

    inf(f"Pinging {len(hosts)} hosts with {threads} threads...")
    live = []
    lock = threading.Lock()
    sem  = threading.Semaphore(threads)

    def check(ip):
        with sem:
            if ping_host(ip, timeout):
                with lock:
                    live.append(ip)
                    # Also try quick port check
                    open_p = []
                    for p in [22, 80, 443, 445, 3389]:
                        ok_f, _ = tcp_connect(ip, p, timeout=0.3)
                        if ok_f: open_p.append(p)
                    svc_str = ",".join(str(p) for p in open_p)
                    finding("Discovery","INFO",f"Live host: {ip}",
                            f"Responds to ping  open_ports=[{svc_str}]",
                            {"ip":ip,"open_ports":open_p})

    ts = [threading.Thread(target=check, args=(h,), daemon=True) for h in hosts]
    for t in ts: t.start()
    for t in ts: t.join()

    sub(f"Live hosts ({len(live)})")
    for ip in sorted(live, key=lambda x: ipaddress.ip_address(x)):
        print(f"  {G}◆{RS}  {B}{ip}{RS}")

    return live

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 3: BRUTE-FORCE DETECTOR
# ──────────────────────────────────────────────────────────────────────────────

BRUTE_PATTERNS = [
    # SSH
    (re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+ ssh2"),  "SSH",  "failed_password"),
    (re.compile(r"Invalid user (\S+) from ([\d.]+)"),                                          "SSH",  "invalid_user"),
    (re.compile(r"authentication failure.*user=(\S+).*rhost=([\d.]+)"),                        "SSH",  "pam_failure"),
    # sudo
    (re.compile(r"sudo.*FAILED.*user=(\S+).*"),                                                "sudo", "sudo_fail"),
    # FTP
    (re.compile(r"FAILED LOGIN.*\[(\S+)\].*from ([\d.]+)"),                                    "FTP",  "ftp_fail"),
    # Windows (if parsing Windows event logs exported)
    (re.compile(r"Logon Type:\s+3.*Account Name:\s+(\S+).*Source Network Address:\s+([\d.]+)", re.S),"WinLogon","net_logon"),
    # RDP
    (re.compile(r"session opened for user (\S+).*\(([\d.]+)\)"),                              "RDP",  "rdp_session"),
]

def parse_brute_log(logfile, threshold=5, window=60):
    hdr(f"BRUTE-FORCE DETECTOR  →  {logfile}")

    if not os.path.exists(logfile):
        # Try common locations
        candidates = [
            "/var/log/auth.log", "/var/log/secure",
            "/var/log/syslog", "/var/log/messages",
            "/var/log/faillog", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        ]
        for c in candidates:
            if os.path.exists(c):
                logfile = c
                inf(f"Found log at: {logfile}")
                break
        else:
            warn("No auth log found. Trying journalctl...")
            try:
                lines = subprocess.check_output(
                    ["journalctl", "-u", "sshd", "--no-pager", "-n", "2000"],
                    stderr=subprocess.DEVNULL
                ).decode(errors="replace").splitlines()
            except Exception:
                bad("Could not read any auth logs"); return
            _analyse_brute_lines(lines, threshold, window)
            return

    try:
        with open(logfile, "r", errors="replace") as f:
            lines = f.readlines()
    except PermissionError:
        bad(f"Permission denied: {logfile} — try sudo")
        return

    inf(f"Analysing {len(lines):,} log lines...")
    _analyse_brute_lines(lines, threshold, window)

def _analyse_brute_lines(lines, threshold, window):
    # Count failures per source IP per service
    failures  = defaultdict(lambda: defaultdict(list))  # ip → service → [timestamps]
    usernames = defaultdict(set)                         # ip → set of usernames tried
    success_after_fail = []

    for line in lines:
        for pat, svc, kind in BRUTE_PATTERNS:
            m = pat.search(line)
            if m:
                try:
                    user = m.group(1)
                    src  = m.group(2) if len(m.groups()) >= 2 else "unknown"
                except Exception:
                    user, src = "?", "?"
                failures[src][svc].append(time.time())  # we don't parse real timestamps for simplicity
                usernames[src].add(user)

    sub("Brute-force summary")
    found = False
    for src_ip, svcs in sorted(failures.items(), key=lambda x: sum(len(v) for v in x[1].values()), reverse=True):
        total = sum(len(v) for v in svcs.values())
        if total < threshold:
            continue
        found = True
        users_str = ", ".join(sorted(usernames[src_ip])[:5])
        svc_str   = ", ".join(f"{s}:{len(v)}" for s,v in svcs.items())
        sev = "CRITICAL" if total > 50 else "HIGH" if total > 20 else "MEDIUM"
        finding("BruteForce", sev,
                f"Brute-force from {src_ip}",
                f"{total} attempts  services=[{svc_str}]  users=[{users_str}]",
                {"src_ip":src_ip,"total_attempts":total,"services":dict(svcs),
                 "usernames":list(usernames[src_ip])})
        dim(f"  Users tried: {users_str}")

    if not found:
        ok(f"No brute-force detected above threshold={threshold}")
    else:
        sep()
        # Spread attack detection
        unique_targets = len(set(ip for ip in failures))
        if unique_targets > 10:
            finding("BruteForce","CRITICAL","Credential spraying detected",
                    f"{unique_targets} source IPs with auth failures — coordinated attack",
                    {"unique_sources":unique_targets})

    # Check for successful logins from IPs that had failures
    sub("Successful logins after failures")
    failed_ips = set(failures.keys())
    success_count = 0
    for line in lines:
        if "Accepted password" in line or "session opened" in line.lower():
            for ip in failed_ips:
                if ip in line:
                    finding("BruteForce","CRITICAL",
                            f"Successful login after brute-force from {ip}",
                            line.strip()[:100],
                            {"ip":ip,"log_line":line.strip()})
                    success_count += 1
    if success_count == 0:
        ok("No successful logins detected from brute-force sources")

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 4: DNS ANOMALY HUNTER
# ──────────────────────────────────────────────────────────────────────────────

DNS_EXFIL_RE = [
    re.compile(r"^[a-f0-9]{16,}\.",    re.I),  # hex
    re.compile(r"^[a-z2-7]{20,}\.",    re.I),  # base32
    re.compile(r"^[A-Za-z0-9+/]{20,}\."),      # base64
    re.compile(r"^[a-zA-Z0-9_-]{30,}\."),      # long random
]

DNS_TUNNEL_DOMAINS = [
    "iodine", "dnscat", "dns2tcp", "heyoka", "tuns",
    "dnstunnel", "tcpoverdns", "ozymandns",
]

def dns_anomaly_hunt(logfile=None, interface=None):
    hdr("DNS ANOMALY HUNTER")
    lines = []

    # Try to get DNS queries from multiple sources
    sources_tried = []
    if logfile and os.path.exists(logfile):
        with open(logfile, errors="replace") as f:
            lines = f.readlines()
        sources_tried.append(logfile)

    if not lines:
        for p in ["/var/log/syslog", "/var/log/messages", "/var/log/named/default",
                  "/var/log/bind.log", "/var/log/dnsmasq.log"]:
            if os.path.exists(p):
                try:
                    with open(p, errors="replace") as f:
                        content = f.readlines()
                    dns_lines = [l for l in content if "query" in l.lower() or "dns" in l.lower()]
                    if dns_lines:
                        lines.extend(dns_lines)
                        sources_tried.append(p)
                except Exception:
                    pass

    # Try tcpdump/ss for live DNS
    if not lines:
        inf("No DNS logs found. Trying to capture live DNS for 5s...")
        try:
            out = subprocess.check_output(
                ["tcpdump", "-l", "-i", "any", "port", "53", "-c", "50"],
                stderr=subprocess.DEVNULL, timeout=5
            ).decode(errors="replace")
            lines = out.splitlines()
            sources_tried.append("tcpdump live")
        except Exception:
            pass

    if not lines:
        warn("No DNS data available. Showing demo analysis...")
        _demo_dns_analysis()
        return

    inf(f"Analysing {len(lines):,} lines from: {', '.join(sources_tried)}")
    _analyse_dns_lines(lines)

def _demo_dns_analysis():
    """Show what DNS anomaly detection finds with example data."""
    demo_queries = [
        "a1b2c3d4e5f6a1b2c3d4e5f6.beacon.attacker.io",
        "0001.MFRA2YTBMJQXIZLTOQQGM4TTMU3TINRR.exfil.evil.com",
        "fonts.googleapis.com",
        "www.google.com",
        "update.microsoft.com",
        "a"*35 + ".tunnel.hax.io",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAA.dnstunnel.c2.net",
    ]
    print()
    inf("Demo DNS analysis (no live data available):")
    print()
    for q in demo_queries:
        score, flags = _score_dns_query(q)
        if score > 40:
            sev = "CRITICAL" if score>75 else "HIGH" if score>50 else "MEDIUM"
            finding("DNS", sev, f"Suspicious DNS: {q[:50]}", f"Score={score} flags={flags}",
                    {"query":q,"score":score,"flags":flags})
        else:
            ok(f"CLEAN  {q[:50]}")

def _score_dns_query(query):
    score = 0
    flags = []
    q = query.lower().strip(".")

    # Encoded subdomains
    first_label = q.split(".")[0] if "." in q else q
    for pat in DNS_EXFIL_RE:
        if pat.match(q):
            score += 70; flags.append("encoded_subdomain"); break

    # Long first label
    if len(first_label) > 30:
        score += 50; flags.append(f"long_label({len(first_label)})")
    elif len(first_label) > 20:
        score += 25; flags.append(f"medium_label({len(first_label)})")

    # High entropy
    if len(first_label) > 5:
        freq = defaultdict(int)
        for c in first_label: freq[c] += 1
        n = len(first_label)
        ent = -sum((v/n)*math.log2(v/n) for v in freq.values())
        if ent > 4.0: score += 40; flags.append(f"high_entropy({ent:.1f})")
        elif ent > 3.5: score += 15; flags.append(f"medium_entropy({ent:.1f})")

    # Tunnel tool names
    for tool in DNS_TUNNEL_DOMAINS:
        if tool in q:
            score += 90; flags.append(f"tunnel_tool:{tool}")

    # Numeric/sequential patterns (data chunking)
    if re.match(r"^\d{4}\.", q):
        score += 30; flags.append("sequential_prefix")

    return min(100, score), flags

def _analyse_dns_lines(lines):
    queries = defaultdict(list)   # domain → [src IPs]
    scores  = {}

    # Extract DNS queries from various log formats
    dns_re = [
        re.compile(r"query: (\S+) IN"),
        re.compile(r"DNS.*query.*for (\S+)"),
        re.compile(r"(\S+\.\S+) A\?"),
        re.compile(r"> (\S+\.\S{2,6}):? (type|A|AAAA|TXT)"),
    ]

    for line in lines:
        for pat in dns_re:
            m = pat.search(line)
            if m:
                q = m.group(1).strip(".")
                src = re.search(r"([\d.]+)#?\d*\s*(>|query)", line)
                src_ip = src.group(1) if src else "?"
                queries[q].append(src_ip)
                break

    sub(f"Analysed {len(queries)} unique DNS queries")
    suspicious = []
    for q, srcs in queries.items():
        score, flags = _score_dns_query(q)
        if score > 40:
            suspicious.append((q, score, flags, list(set(srcs))))

    suspicious.sort(key=lambda x: x[1], reverse=True)

    if not suspicious:
        ok("No suspicious DNS queries found")
        return

    bad(f"Found {len(suspicious)} suspicious DNS queries:")
    print()
    for q, score, flags, srcs in suspicious[:20]:
        sev = "CRITICAL" if score>75 else "HIGH" if score>50 else "MEDIUM"
        finding("DNS", sev, f"Suspicious DNS: {q[:50]}",
                f"score={score}  flags={','.join(flags)}  srcs={','.join(srcs[:3])}",
                {"query":q,"score":score,"flags":flags,"sources":srcs})

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 5: LOG ANALYZER
# ──────────────────────────────────────────────────────────────────────────────

IOC_PATTERNS = [
    # Shells / reverse shells
    ("RevShell",  "CRITICAL", re.compile(r"bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e\s+/bin/(bash|sh)|python[23]?\s+-c.*socket|perl\s+-e.*socket", re.I)),
    ("RevShell",  "CRITICAL", re.compile(r"mkfifo.*nc|/bin/sh.*-i|socat.*exec", re.I)),
    # Webshell indicators
    ("Webshell",  "CRITICAL", re.compile(r"eval\(base64_decode|assert\(\$_POST|system\(\$_GET|exec\(\$_REQUEST|passthru\(", re.I)),
    ("Webshell",  "CRITICAL", re.compile(r"FilesMan|c99shell|r57shell|WSO\s+shell", re.I)),
    # Persistence
    ("Persist",   "HIGH",     re.compile(r"crontab\s+-[el]|/etc/cron\.(daily|hourly|weekly|d/)|@reboot", re.I)),
    ("Persist",   "HIGH",     re.compile(r"HKLM.*Run|HKCU.*Run|schtasks.*\/create|New-ScheduledTask", re.I)),
    ("Persist",   "HIGH",     re.compile(r"\.bashrc|\.profile|\.bash_profile|/etc/rc\.local|/etc/init\.d/", re.I)),
    # Privilege escalation
    ("PrivEsc",   "HIGH",     re.compile(r"sudo\s+-l|/etc/sudoers|NOPASSWD|pkexec|polkit", re.I)),
    ("PrivEsc",   "HIGH",     re.compile(r"chmod\s+[0-9]*s|chmod\s+u\+s|SUID|setuid|capsh|getcap", re.I)),
    # Credential access
    ("Creds",     "CRITICAL", re.compile(r"/etc/shadow|/etc/passwd|SAM\s+hive|NTDS\.dit|lsass\.exe.*dump|mimikatz|sekurlsa", re.I)),
    ("Creds",     "HIGH",     re.compile(r"hashdump|credential.*dump|pass.*the.*hash|pth-|wce\.exe|fgdump", re.I)),
    # C2 tools
    ("C2Tool",    "CRITICAL", re.compile(r"cobalt.?strike|meterpreter|beacon\.exe|cs\.jar|teamserver|empire.*http|sliver.*serve", re.I)),
    ("C2Tool",    "CRITICAL", re.compile(r"metasploit|msfconsole|msfvenom|handler.*reverse|multi/handler", re.I)),
    # Recon
    ("Recon",     "MEDIUM",   re.compile(r"nmap|masscan|rustscan|zmap|gobuster|nikto|dirb|dirbuster|ffuf|feroxbuster", re.I)),
    ("Recon",     "MEDIUM",   re.compile(r"net\s+view|net\s+user|whoami\s+/all|systeminfo|nltest|dsquery|bloodhound", re.I)),
    # Exfil
    ("Exfil",     "HIGH",     re.compile(r"curl.*-T|wget.*--post-file|scp\s+-r|rsync.*--remove|tar.*\|\s*nc", re.I)),
    # Network manipulation
    ("NetManip",  "HIGH",     re.compile(r"iptables.*ACCEPT|ufw\s+disable|setenforce\s+0|systemctl\s+stop\s+(firewall|ufw|iptables)", re.I)),
    # Suspicious downloads
    ("Download",  "HIGH",     re.compile(r"curl.*http.*\|\s*(bash|sh|python)|wget.*-O.*\|\s*(bash|sh)|powershell.*IEX.*Net.WebClient|Invoke-Expression.*DownloadString", re.I)),
]

def log_analyzer(paths=None):
    hdr("LOG ANALYZER — IOC Scanner")

    if paths is None:
        paths = [
            "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
            "/var/log/messages", "/var/log/apache2/access.log",
            "/var/log/apache2/error.log", "/var/log/nginx/access.log",
            "/var/log/nginx/error.log", "/var/log/audit/audit.log",
            "/var/log/bash_history", os.path.expanduser("~/.bash_history"),
            "/root/.bash_history",
        ]
        # Add all bash_history files
        for entry in glob.glob("/home/*/.bash_history"):
            paths.append(entry)

    total_hits = 0
    for logpath in paths:
        if not os.path.exists(logpath):
            continue
        try:
            with open(logpath, "r", errors="replace") as f:
                content = f.read()
            lines = content.splitlines()
        except PermissionError:
            dim(f"Permission denied: {logpath}")
            continue

        hits = []
        for i, line in enumerate(lines, 1):
            for cat, sev, pat in IOC_PATTERNS:
                if pat.search(line):
                    hits.append((i, cat, sev, line.strip()[:120]))
                    break

        if hits:
            sub(f"{logpath}  ({len(hits)} hits)")
            for lineno, cat, sev, line in hits[:10]:
                finding("LogAnalyzer", sev, f"{cat} in {os.path.basename(logpath)}:{lineno}",
                        line[:100], {"file":logpath,"line":lineno,"content":line})
            if len(hits) > 10:
                warn(f"  ...and {len(hits)-10} more hits in {logpath}")
            total_hits += len(hits)
        else:
            dim(f"CLEAN  {logpath}")

    sep()
    if total_hits:
        bad(f"Total IOC hits: {total_hits} across {len(paths)} files")
    else:
        ok("No IOCs found in checked log files")

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 6: LATERAL MOVEMENT TRACKER
# ──────────────────────────────────────────────────────────────────────────────

LATERAL_PORTS = {22:"SSH", 135:"MSRPC", 139:"NetBIOS", 445:"SMB",
                 3389:"RDP", 5985:"WinRM", 5986:"WinRM-S", 4444:"C2?"}

def lateral_movement_track(subnet_prefix="10."):
    hdr("LATERAL MOVEMENT TRACKER")
    inf("Reading current connections from /proc/net/tcp...")

    conns = _read_tcp_conns()
    if not conns:
        warn("No TCP connections found (try sudo or browse/SSH first)")
        return

    # Filter for internal east-west on lateral movement ports
    lateral = []
    external = []
    for src, dst, dport in conns:
        if dport in LATERAL_PORTS:
            if dst.startswith(subnet_prefix) or dst.startswith("192.168.") or dst.startswith("172."):
                lateral.append((src, dst, dport))
            elif not (dst.startswith("127.") or dst.startswith("::1")):
                external.append((src, dst, dport))

    sub(f"Internal lateral movement connections ({len(lateral)})")
    seen_paths = set()
    for src, dst, dport in lateral:
        svc  = LATERAL_PORTS.get(dport, str(dport))
        path = f"{src}→{dst}:{dport}"
        if path in seen_paths: continue
        seen_paths.add(path)
        sev  = "CRITICAL" if dport in (4444,) else "HIGH" if dport in (445,135,5985) else "MEDIUM"
        finding("LateralMove", sev, f"Lateral: {src} → {dst}:{svc}",
                f"Protocol: {svc}  Port: {dport}",
                {"src":src,"dst":dst,"dport":dport,"service":svc})

    sub(f"External connections on sensitive ports ({len(external)})")
    for src, dst, dport in external[:20]:
        svc  = LATERAL_PORTS.get(dport, str(dport))
        sev  = "CRITICAL" if dport == 4444 else "HIGH"
        finding("LateralMove", sev, f"External {svc}: {src}→{dst}:{dport}",
                "Sensitive service exposed externally",
                {"src":src,"dst":dst,"dport":dport,"service":svc})

    if not lateral and not external:
        ok("No lateral movement connections detected")

def _read_tcp_conns():
    conns = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) < 4 or p[3] != "01": continue
                    try:
                        rip, rport = p[2].rsplit(":", 1)
                        lip, _     = p[1].rsplit(":", 1)
                        dport = int(rport, 16)
                        if len(rip) == 8:
                            dst = socket.inet_ntop(socket.AF_INET, bytes.fromhex(rip)[::-1])
                            src = socket.inet_ntop(socket.AF_INET, bytes.fromhex(lip)[::-1])
                        else:
                            dst = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(rip))
                            src = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(lip))
                        conns.append((src, dst, dport))
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
    if not conns and IS_WINDOWS:
        try:
            out = subprocess.check_output(["netstat","-n","-p","TCP"],
                                          stderr=subprocess.DEVNULL,timeout=5).decode(errors="replace")
            for line in out.splitlines():
                p = line.split()
                if len(p)>=4 and p[3]=="ESTABLISHED":
                    try:
                        dst_s = p[2]
                        if ":" in dst_s:
                            parts = dst_s.rsplit(":",1)
                            conns.append(("local", parts[0], int(parts[1])))
                    except Exception: pass
        except Exception: pass
    return conns

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 7: PROCESS HUNTER
# ──────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_PROCS = [
    (re.compile(r"nc\b|ncat\b|netcat\b"),            "CRITICAL", "Netcat (reverse shell?)"),
    (re.compile(r"msfconsole|meterpreter|msf[45]"),  "CRITICAL", "Metasploit"),
    (re.compile(r"cobalt|beacon\.exe|cs\.jar"),      "CRITICAL", "Cobalt Strike"),
    (re.compile(r"mimikatz|sekurlsa|wce\.exe"),      "CRITICAL", "Credential dumper"),
    (re.compile(r"empire.*http|stager|grunt"),       "CRITICAL", "PowerShell Empire"),
    (re.compile(r"socat.*exec|socat.*tcp"),          "HIGH",     "Socat (possible shell)"),
    (re.compile(r"python.*-c.*socket|perl.*-e.*socket"), "HIGH", "Scripted reverse shell"),
    (re.compile(r"nmap|masscan|rustscan"),           "MEDIUM",   "Network scanner"),
    (re.compile(r"tcpdump|wireshark|tshark"),        "LOW",      "Packet capture"),
    (re.compile(r"curl.*\|\s*sh|wget.*\|\s*bash"),   "HIGH",     "Pipe-to-shell download"),
]

def process_hunter():
    hdr("PROCESS HUNTER")

    # Get process list
    procs = []
    if os.path.exists("/proc"):
        for pid_dir in glob.glob("/proc/[0-9]*"):
            try:
                pid = int(os.path.basename(pid_dir))
                with open(f"{pid_dir}/cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace").strip()
                with open(f"{pid_dir}/status") as f:
                    status = dict(line.split(":\t",1) for line in f.readlines() if ":\t" in line)
                ppid = int(status.get("PPid","0").strip())
                name = status.get("Name","?").strip()
                uid  = status.get("Uid","?\t?\t?\t?").strip().split()[0]
                procs.append({"pid":pid,"ppid":ppid,"name":name,"cmd":cmdline,"uid":uid})
            except Exception:
                pass
    else:
        try:
            out = subprocess.check_output(["ps","aux"], stderr=subprocess.DEVNULL).decode(errors="replace")
            for line in out.splitlines()[1:]:
                p = line.split(None, 10)
                if len(p) >= 11:
                    procs.append({"pid":p[1],"ppid":"?","name":p[10].split()[0],"cmd":p[10],"uid":p[0]})
        except Exception:
            bad("Cannot enumerate processes"); return

    inf(f"Checking {len(procs)} processes...")
    hits = 0
    for proc in procs:
        cmd = proc["cmd"].lower()
        for pat, sev, desc in SUSPICIOUS_PROCS:
            if pat.search(cmd):
                finding("Process", sev, f"Suspicious process: {desc}",
                        f"PID={proc['pid']} UID={proc['uid']} CMD={proc['cmd'][:80]}",
                        {"pid":proc["pid"],"uid":proc["uid"],"cmd":proc["cmd"],"name":proc["name"]})
                hits += 1
                break

    # Check for processes listening on suspicious ports
    sub("Processes on suspicious ports")
    try:
        out = subprocess.check_output(
            ["ss", "-tlnp"] if not IS_WINDOWS else ["netstat","-tlnp"],
            stderr=subprocess.DEVNULL
        ).decode(errors="replace")
        for line in out.splitlines():
            for sport in SUSPICIOUS_PORTS:
                if f":{sport}" in line or f" {sport} " in line:
                    finding("Process","CRITICAL",
                            f"Process listening on suspicious port {sport}",
                            line.strip()[:100],{"line":line.strip()})
    except Exception:
        pass

    # Check for SUID binaries recently modified
    sub("Recently modified SUID binaries")
    try:
        out = subprocess.check_output(
            ["find", "/", "-perm", "-4000", "-newer", "/etc/passwd",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode(errors="replace")
        for line in out.strip().splitlines():
            if line:
                finding("Process","CRITICAL",
                        f"New SUID binary: {line.strip()}",
                        "SUID binary modified more recently than /etc/passwd",
                        {"path":line.strip()})
    except Exception:
        pass

    if hits == 0:
        ok("No suspicious processes detected")

SUSPICIOUS_PORTS = {4444, 4445, 50050, 8888, 31337, 1337, 9001, 9002, 9003}

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 8: FILE INTEGRITY
# ──────────────────────────────────────────────────────────────────────────────

CRITICAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
    "/etc/ssh/sshd_config", "/etc/crontab", "/etc/rc.local",
    "/etc/ld.so.preload", "/etc/ld.so.conf",
    "/bin/bash", "/bin/sh", "/usr/bin/sudo", "/usr/bin/passwd",
    "/sbin/sshd", "/usr/sbin/sshd",
]

BASELINE_FILE = "ncae_file_baseline.json"

def file_integrity(check_mode=False):
    hdr("FILE INTEGRITY CHECKER")

    current_hashes = {}
    for path in CRITICAL_FILES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            stat = os.stat(path)
            current_hashes[path] = {
                "sha256": h,
                "size":   stat.st_size,
                "mtime":  stat.st_mtime,
                "mtime_str": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            }
        except PermissionError:
            dim(f"Permission denied: {path}")
        except Exception as e:
            dim(f"Error hashing {path}: {e}")

    inf(f"Hashed {len(current_hashes)} critical files")

    if check_mode and os.path.exists(BASELINE_FILE):
        # Compare against baseline
        with open(BASELINE_FILE) as f:
            baseline = json.load(f)

        sub("Comparing against baseline")
        changed = 0
        for path, curr in current_hashes.items():
            if path not in baseline:
                finding("FileIntegrity","HIGH",f"New file (not in baseline): {path}",
                        f"sha256={curr['sha256'][:16]}...",curr)
                changed += 1
            elif curr["sha256"] != baseline[path]["sha256"]:
                finding("FileIntegrity","CRITICAL",f"FILE MODIFIED: {path}",
                        f"was={baseline[path]['sha256'][:16]}  now={curr['sha256'][:16]}",
                        {"path":path,"old_hash":baseline[path]["sha256"],"new_hash":curr["sha256"]})
                changed += 1
            else:
                ok(f"OK  {path}")

        for path in baseline:
            if path not in current_hashes:
                finding("FileIntegrity","HIGH",f"File deleted/missing: {path}","Was in baseline",{"path":path})
                changed += 1

        sep()
        if changed:
            bad(f"{changed} file integrity violation(s) detected")
        else:
            ok("All critical files match baseline")
    else:
        # Save baseline
        with open(BASELINE_FILE, "w") as f:
            json.dump(current_hashes, f, indent=2)
        ok(f"Baseline saved → {BASELINE_FILE}")
        inf("Run again with --check to detect modifications")
        sub("Current hashes")
        for path, info in current_hashes.items():
            print(f"  {D}{info['sha256'][:16]}...  {info['mtime_str']}  {path}{RS}")

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 9: NETWORK BASELINE
# ──────────────────────────────────────────────────────────────────────────────

NET_BASELINE_FILE = "ncae_net_baseline.json"

def network_baseline(check=False, watch=False):
    hdr("NETWORK BASELINE")

    def snapshot():
        conns = _read_tcp_conns()
        return {f"{s}→{d}:{p}" for s,d,p in conns}

    current = snapshot()
    inf(f"Current connections: {len(current)}")

    if watch:
        inf("Watching for new connections (Ctrl+C to stop)...")
        try:
            baseline = current.copy()
            while True:
                time.sleep(2)
                now = snapshot()
                new = now - baseline
                gone = baseline - now
                for c in new:
                    parts = c.replace("→","|").replace(":"," ").split("|")
                    finding("NetBaseline","HIGH",f"NEW connection: {c}",
                            "Not seen at baseline time",{"conn":c})
                    baseline.add(c)
                for c in gone:
                    inf(f"Connection dropped: {D}{c}{RS}")
                    baseline.discard(c)
        except KeyboardInterrupt:
            print(); inf("Watch mode stopped")
        return

    if check and os.path.exists(NET_BASELINE_FILE):
        with open(NET_BASELINE_FILE) as f:
            baseline_set = set(json.load(f)["connections"])
        new = current - baseline_set
        sub(f"New connections since baseline ({len(new)})")
        for c in sorted(new):
            finding("NetBaseline","MEDIUM",f"New connection: {c}","Not in baseline",{"conn":c})
        if not new:
            ok("No new connections since baseline")
    else:
        with open(NET_BASELINE_FILE,"w") as f:
            json.dump({"time":datetime.now().isoformat(),"connections":list(current)},f,indent=2)
        ok(f"Baseline saved → {NET_BASELINE_FILE}  ({len(current)} connections)")
        sub("Current connections")
        for c in sorted(current)[:30]:
            print(f"  {D}{c}{RS}")

# ──────────────────────────────────────────────────────────────────────────────
# TOOL 10: QUICK SCAN (all tools)
# ──────────────────────────────────────────────────────────────────────────────

def quick_scan(target_subnet=None):
    hdr("QUICK IOC SCAN  —  Running all threat hunting tools")
    start = time.time()

    inf("Step 1/6 — Brute-force log analysis")
    parse_brute_log("/var/log/auth.log", threshold=5)

    inf("Step 2/6 — Log IOC scan")
    log_analyzer()

    inf("Step 3/6 — Process hunting")
    process_hunter()

    inf("Step 4/6 — Lateral movement detection")
    lateral_movement_track()

    inf("Step 5/6 — DNS anomaly check")
    dns_anomaly_hunt()

    inf("Step 6/6 — File integrity check")
    file_integrity(check_mode=os.path.exists(BASELINE_FILE))

    if target_subnet:
        inf(f"Bonus — Port scan {target_subnet}")
        port_scan(target_subnet)

    # Summary
    ela = time.time() - start
    hdr(f"QUICK SCAN COMPLETE  ({ela:.1f}s)")

    by_sev = defaultdict(list)
    for f in FINDINGS:
        by_sev[f["severity"]].append(f)

    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        items = by_sev.get(sev, [])
        if not items: continue
        c = {
            "CRITICAL":R+B,"HIGH":O+B,"MEDIUM":Y,"LOW":G,"INFO":C
        }.get(sev,D)
        print(f"\n  {c}[{sev}]  {len(items)} finding(s):{RS}")
        for f in items[:5]:
            print(f"    {D}{f['category']:15s}  {f['title'][:60]}{RS}")
        if len(items) > 5:
            dim(f"    ...and {len(items)-5} more")

    fname = save_findings()
    if fname:
        print(f"\n  {G}{B}Findings saved → {fname}{RS}")

# ──────────────────────────────────────────────────────────────────────────────
# INTERACTIVE MENU
# ──────────────────────────────────────────────────────────────────────────────

MENU = [
    ("1", "port_scan",   "Port Scanner",          "TCP connect scan + banner grab"),
    ("2", "hosts",       "Host Discovery",         "ICMP ping sweep subnet"),
    ("3", "brutedet",    "Brute-Force Detector",   "Parse auth logs for attacks"),
    ("4", "dns",         "DNS Anomaly Hunter",      "Beacons, exfil, tunnels"),
    ("5", "logs",        "Log Analyzer",            "IOC grep across all logs"),
    ("6", "lateral",     "Lateral Movement",        "East-west suspicious conns"),
    ("7", "prochunt",    "Process Hunter",          "Suspicious PIDs, SUID"),
    ("8", "filecheck",   "File Integrity",          "Hash critical system files"),
    ("9", "netbase",     "Network Baseline",        "Snapshot / alert new conns"),
    ("A", "quickscan",   "QUICK SCAN (all)",        "Run all tools, summarize"),
    ("E", "export",      "Export Findings",         "Save to JSON"),
    ("Q", "quit",        "Quit",                    ""),
]

def interactive():
    print(f"\n{B}{C}{'━'*64}{RS}")
    print(f"{B}{C}  NCAE THREAT HUNTING TOOLKIT{RS}")
    print(f"{B}{C}{'━'*64}{RS}")
    print(f"  {D}Zero dependencies  |  Python 3.6+  |  stdlib only{RS}")

    while True:
        print(f"\n{B}  Tools:{RS}")
        for key, _, name, desc in MENU:
            print(f"  {C}{key}{RS}  {B}{name:<24}{RS}  {D}{desc}{RS}")

        try:
            choice = input(f"\n{B}  > {RS}").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print(); break

        if choice in ("Q","QUIT","EXIT"):
            break
        elif choice in ("1","PORT_SCAN","PORTSCAN"):
            t = input(f"  Target IP or CIDR [{D}192.168.1.0/24{RS}]: ").strip() or "127.0.0.1"
            port_scan(t)
        elif choice in ("2","HOSTS","DISCOVER"):
            s = input(f"  Subnet [{D}192.168.1.0/24{RS}]: ").strip() or "192.168.1.0/24"
            arp_scan(s)
        elif choice in ("3","BRUTEDET","BRUTE"):
            l = input(f"  Log file [{D}/var/log/auth.log{RS}]: ").strip() or "/var/log/auth.log"
            parse_brute_log(l)
        elif choice in ("4","DNS"):
            dns_anomaly_hunt()
        elif choice in ("5","LOGS","LOG"):
            log_analyzer()
        elif choice in ("6","LATERAL"):
            lateral_movement_track()
        elif choice in ("7","PROCHUNT","PROC"):
            process_hunter()
        elif choice in ("8","FILECHECK","FILE"):
            mode = input(f"  Mode — [B]aseline or [C]heck [{D}B{RS}]: ").strip().upper()
            file_integrity(check_mode=(mode=="C"))
        elif choice in ("9","NETBASE","NET"):
            mode = input(f"  Mode — [S]napshot, [C]heck, or [W]atch [{D}S{RS}]: ").strip().upper()
            network_baseline(check=(mode=="C"), watch=(mode=="W"))
        elif choice in ("A","QUICKSCAN","ALL","10"):
            t = input(f"  Target subnet for port scan (leave blank to skip): ").strip()
            quick_scan(t or None)
        elif choice in ("E","EXPORT"):
            fname = save_findings()
            if fname:
                ok(f"Saved {len(FINDINGS)} findings → {fname}")
            else:
                warn("No findings to export yet")
        else:
            bad(f"Unknown choice: {choice}")

# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="NCAE Threat Hunting Toolkit")
    parser.add_argument("--tool",   "-t", help="Tool to run directly")
    parser.add_argument("--target", "-T", help="Target IP/CIDR for port scan/discovery")
    parser.add_argument("--log",    "-l", help="Log file to analyse")
    parser.add_argument("--check",  "-c", action="store_true", help="Check mode (vs baseline)")
    parser.add_argument("--watch",  "-w", action="store_true", help="Watch mode (network baseline)")
    parser.add_argument("--export", "-e", action="store_true", help="Auto-export findings on exit")
    args = parser.parse_args()

    if args.tool:
        t = args.tool.lower()
        if t in ("portscan","port_scan","scan"):
            port_scan(args.target or "127.0.0.1")
        elif t in ("hosts","discover","arp"):
            arp_scan(args.target or "192.168.1.0/24")
        elif t in ("brutedet","brute"):
            parse_brute_log(args.log or "/var/log/auth.log")
        elif t in ("dns",):
            dns_anomaly_hunt(args.log)
        elif t in ("logs","log"):
            log_analyzer([args.log] if args.log else None)
        elif t in ("lateral","pivot"):
            lateral_movement_track()
        elif t in ("proc","process","prochunt"):
            process_hunter()
        elif t in ("file","filecheck","integrity"):
            file_integrity(args.check)
        elif t in ("net","netbase","network"):
            network_baseline(args.check, args.watch)
        elif t in ("quick","quickscan","all"):
            quick_scan(args.target)
        else:
            bad(f"Unknown tool: {args.tool}")
            interactive()
    else:
        interactive()

    if args.export or FINDINGS:
        fname = save_findings()
        if fname:
            ok(f"Findings exported → {fname}")

if __name__ == "__main__":
    main()
