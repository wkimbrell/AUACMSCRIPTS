# SECCDC 2026 - Linux Service Hardening Guide
## Wild West Parks Inc. - Complete Reference

---

## ⚠️ CRITICAL CCDC REQUIREMENTS

### Black Team Agent (BTA) - DO NOT BLOCK!
**Blocking = up to 50% point penalty**

**File Locations:**
- Binary: `/usr/sbin/bta`
- Config: `/etc/bta.enc`
- Status: `/usr/sbin/bta.status`

**Service:**
- Service name: `bta` (systemd)
- Must run with full root privileges

**Network Requirements:**
- Must reach `10.250.250.11:443` (outbound)
- Must reach `169.254.169.254:80` (outbound)
- No proxy allowed

**Check Status:**
```bash
systemctl status bta
cat /usr/sbin/bta.status
```

### SECCDC User Accounts - DO NOT MODIFY!
- Any account with "seccdc" prefix must remain active
- DO NOT rotate passwords
- DO NOT remove admin privileges
- These are for Black Team monitoring only

### Scored Administrative User
- **Username:** `alexisj`
- **Default Password:** `Trying-Our-Best1`
- **MUST UPDATE** in scoring engine after password change

### Password Requirements
**Allowed special characters ONLY:**
```
) ( ' . , @ | = : ; / - !
```
All other special characters are FORBIDDEN.

---

## 🎯 SCORED SERVICES OVERVIEW

Your network: `10.250.5X.0/24` (where X = team number)

| Hostname | IP | Likely Services |
|----------|-----|----------------|
| frontier | 10.250.5X.10 | Various |
| drifter | 10.250.5X.11 | Various |
| mustang | 10.250.5X.12 | Various |
| praire | 10.250.5X.13 | Various |
| cactus | 10.250.5X.14 | Various |
| governor | 10.250.5X.15 | Various |
| sunset | 10.250.5X.250 | Various |
| sunrise | 10.250.5X.252 | Various |

---

## 🔐 SSH HARDENING

### Quick Hardening
```bash
# Backup config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Apply hardening
sudo sed -i 's/^.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/^.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config

# Restart
sudo systemctl restart sshd
```

### Key Settings
```
PermitRootLogin no                    # Disable root SSH
PasswordAuthentication yes            # Required for scoring
PermitEmptyPasswords no               # No blank passwords
MaxAuthTries 4                        # Limit failed attempts
LoginGraceTime 60                     # 60 second timeout
Protocol 2                            # SSH v2 only
X11Forwarding no                      # Disable X11
```

### Monitoring
```bash
# Watch for brute force
tail -f /var/log/auth.log | grep sshd

# Check current sessions
who
w

# Last logins
lastlog
last
```

---

## 🌐 WEB SERVER HARDENING

### Apache

**Configuration:** `/etc/apache2/apache2.conf` or `/etc/httpd/conf/httpd.conf`

```bash
# Disable directory listing
sed -i 's/Options Indexes FollowSymLinks/Options -Indexes +FollowSymLinks/' /etc/apache2/apache2.conf

# Hide version info
echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf

# Disable unnecessary modules
a2dismod autoindex
a2dismod status

# Enable security headers
a2enmod headers
```

**Security Headers (.htaccess or VirtualHost):**
```apache
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "SAMEORIGIN"
Header set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000"
```

**Restart:**
```bash
sudo systemctl restart apache2
```

### Nginx

**Configuration:** `/etc/nginx/nginx.conf`

```bash
# Hide version
sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf

# Add to http block
cat >> /etc/nginx/nginx.conf << 'EOF'
http {
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Disable autoindex
    autoindex off;
}
EOF

# Restart
sudo systemctl restart nginx
```

### Web Shell Detection
```bash
# Find recently modified PHP files
find /var/www/html -name "*.php" -mtime -1 -ls

# Search for suspicious PHP functions
grep -r "eval(" /var/www/html/
grep -r "base64_decode(" /var/www/html/
grep -r "system(" /var/www/html/
grep -r "exec(" /var/www/html/
grep -r "shell_exec(" /var/www/html/

# Check for odd file permissions
find /var/www/html -type f -perm 0777
```

---

## 📁 FTP HARDENING (vsftpd)

**Configuration:** `/etc/vsftpd.conf`

```bash
# Backup config
sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.backup

# Key settings (check scenario requirements first!)
anonymous_enable=NO              # Disable anonymous (if allowed by scenario)
local_enable=YES                 # Allow local users
write_enable=YES                 # Allow uploads (if required)
chroot_local_user=YES            # Jail users to home dir
chroot_list_enable=NO            # Don't exempt anyone from chroot
allow_writeable_chroot=YES       # Allow chroot with write access

# Logging
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log

# Security
ssl_enable=NO                    # Depends on scenario
pasv_min_port=40000
pasv_max_port=40100

# Restart
sudo systemctl restart vsftpd
```

**Monitor FTP access:**
```bash
tail -f /var/log/vsftpd.log
```

---

## 🌍 DNS HARDENING (BIND)

**Configuration:** `/etc/bind/named.conf` or `/etc/named.conf`

```bash
# Validate configuration
sudo named-checkconf

# Validate zone files
sudo named-checkzone example.com /etc/bind/db.example.com

# Key security options (add to options block)
cat >> /etc/bind/named.conf.options << 'EOF'
options {
    version "DNS Server";              # Hide version
    recursion no;                      # Disable if authoritative only
    allow-transfer { none; };          # Prevent zone transfers
    allow-query { any; };              # Allow queries
    dnssec-validation auto;            # Enable DNSSEC
};
EOF

# Restart
sudo systemctl restart bind9  # or named
```

**Monitor DNS queries:**
```bash
# Enable query logging
rndc querylog on

# Watch logs
tail -f /var/log/syslog | grep named
```

---

## 🗂️ SAMBA/SMB HARDENING

**Configuration:** `/etc/samba/smb.conf`

```bash
# Backup config
sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.backup

# Add to [global] section
sudo nano /etc/samba/smb.conf
```

**Key Settings:**
```ini
[global]
    # Security
    client min protocol = SMB2
    server min protocol = SMB2
    ntlm auth = yes
    
    # Logging
    log file = /var/log/samba/log.%m
    max log size = 1000
    log level = 2
    
    # Restrict access
    hosts allow = 10.250.0.0/16
    hosts deny = 0.0.0.0/0
    
    # Hide unreadable shares
    access based share enum = yes
```

**Manage Shares:**
```bash
# List shares
smbstatus
net usershare info --long

# Remove a share
sudo net usershare delete sharename

# Add Samba user
sudo smbpasswd -a username

# List current sessions
sudo smbstatus
```

**Restart:**
```bash
sudo systemctl restart smbd nmbd
```

---

## 🔑 KERBEROS CONFIGURATION

**Configuration:** `/etc/krb5.conf`

```ini
[libdefaults]
    default_realm = CCDC.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    CCDC.LOCAL = {
        kdc = dc.ccdc.local
        admin_server = dc.ccdc.local
    }

[domain_realm]
    .ccdc.local = CCDC.LOCAL
    ccdc.local = CCDC.LOCAL
```

**Initialize Realm (if AD server):**
```bash
sudo krb5_newrealm
```

**Kerberos Admin:**
```bash
sudo kadmin.local

# Commands in kadmin:
# addprinc username
# delprinc username
# listprincs
```

---

## 📧 POP3/MAIL HARDENING (Dovecot)

**Configuration:** `/etc/dovecot/dovecot.conf`

```bash
# Key settings
protocols = pop3                     # Enable POP3
disable_plaintext_auth = no          # Allow plaintext if required by scenario
mail_location = mbox:~/mail:INBOX=/var/mail/%u

# SSL (if required)
ssl = required
ssl_cert = </etc/ssl/certs/dovecot.pem
ssl_key = </etc/ssl/private/dovecot.pem

# Restart
sudo systemctl restart dovecot
```

**Test POP3:**
```bash
telnet localhost 110
# Commands: USER username, PASS password, LIST, RETR 1, QUIT
```

---

## 🔥 FIREWALL CONFIGURATION (UFW)

```bash
# Reset firewall
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# CRITICAL: Allow BTA
sudo ufw allow out to 10.250.250.11 port 443
sudo ufw allow out to 169.254.169.254 port 80

# Allow supporting infrastructure
sudo ufw allow out to 10.250.250.0/24

# Common services (adjust based on what's scored)
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 21/tcp comment 'FTP'
sudo ufw allow 53 comment 'DNS'
sudo ufw allow 389/tcp comment 'LDAP'
sudo ufw allow 636/tcp comment 'LDAPS'
sudo ufw allow 88/tcp comment 'Kerberos'
sudo ufw allow 445/tcp comment 'SMB'
sudo ufw allow 139/tcp comment 'NetBIOS'
sudo ufw allow 110/tcp comment 'POP3'

# Enable
sudo ufw --force enable

# Check status
sudo ufw status verbose
```

---

## 🔍 MALWARE HUNTING

### Check for Backdoors
```bash
# Suspicious processes
ps aux | grep -v "^\[" | awk '{if($3>50) print $0}'

# Network connections
netstat -tulpn | grep ESTABLISHED
lsof -i -n -P

# Unusual cron jobs
cat /etc/crontab
ls -la /etc/cron.*
for user in $(cut -f1 -d: /etc/passwd); do 
    echo "=== $user ==="
    crontab -u $user -l 2>/dev/null
done

# SUID/SGID files
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null

# Recently modified system files
find /usr/bin /usr/sbin -mtime -1 -type f

# Check for hidden files
find / -name ".*" -type f 2>/dev/null | grep -v "/proc" | grep -v "/sys"

# Suspicious bash history
cat ~/.bash_history | grep -E "wget|curl|nc |ncat|/dev/tcp"
```

### Persistence Mechanisms
```bash
# Systemd services
systemctl list-units --type=service --state=running

# Check for unusual services
systemctl list-unit-files | grep enabled

# Init scripts
ls -la /etc/init.d/
ls -la /etc/rc*.d/

# User accounts
cat /etc/passwd | awk -F: '$3 >= 1000 {print $0}'

# Check sudoers
cat /etc/sudoers
ls -la /etc/sudoers.d/

# SSH authorized keys
find /home -name authorized_keys 2>/dev/null -exec ls -la {} \;
```

---

## 📊 INCIDENT RESPONSE REPORTING

**Required Information:**
1. **Affected Hosts** - List by hostname with evidence
2. **Time Frame** - Explicit start/stop times
3. **Observed Activity** - What the attacker did
4. **Persistence/Access Method** - How they maintained access
5. **Technical Analysis** - Logs, IPs, domains, etc.
6. **Remediation Steps** - What you did to fix it
7. **Evidence Appendix** - Screenshots

**⚠️ DO NOT upload malware to VirusTotal or similar services!**

**Can recover up to 50% of Red Team point deductions**

---

## 📝 PASSWORD ROTATION

### Update Scoring Engine
After changing any scored user password:
1. Go to scoring engine: `https://10.250.250.10/`
2. Find the affected service check
3. Update credential information
4. Test the service

### Allowed Special Characters
```
) ( ' . , @ | = : ; / - !
```

### Change Password
```bash
# For scored users
sudo passwd alexisj

# Remember to update in scoring engine!
```

---

## 🚨 EMERGENCY PROCEDURES

### Request Reboot
**Mattermost:** `https://10.250.250.5/`
**Channel:** `#black-team-requests`

Format (check channel for current format):
```
REBOOT REQUEST
Hostname: frontier
Team: 7
Reason: System unresponsive
```

### Request Reversion
**WARNING:** Destroys all your work on that machine!

**Excessive reversions = point penalties**
- 2+ reversions of same machine
- 6+ total reversions
- >15% of your machines reverted

Only use as last resort!

---

## 🎯 QUICK START CHECKLIST

1. ☐ Verify BTA is running
2. ☐ Change alexisj password
3. ☐ Update scoring engine with new password
4. ☐ Check for unauthorized users
5. ☐ Harden SSH
6. ☐ Configure firewall (whitelist BTA IPs!)
7. ☐ Check for web shells
8. ☐ Hunt for persistence mechanisms
9. ☐ Monitor service status on scoreboard
10. ☐ Submit incident reports for any compromises

---

## 📞 SUPPORT

- **Mattermost:** `https://10.250.250.5/`
- **Scoreboard:** `https://10.250.250.10/`
- **Discord AMA:** `https://discord.gg/4Hvcyh5q9j`

---

**Good luck, Team! Defend the frontier! 🤠**
