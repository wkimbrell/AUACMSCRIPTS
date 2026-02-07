#!/bin/bash
#
# SECCDC 2026 - Linux Quick Hardening Script
# Wild West Parks Inc. - Team Hardening Automation
#
# WARNING: Review and customize before running!
# This script performs rapid hardening of Linux systems for CCDC competition
#

set -e

echo "=========================================="
echo "SECCDC 2026 Linux Quick Hardening Script"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# CRITICAL: Verify BTA is running and NOT blocked
echo -e "${YELLOW}[CRITICAL] Checking Black Team Agent (BTA)...${NC}"
if systemctl is-active --quiet bta; then
    echo -e "${GREEN}✓ BTA service is running${NC}"
else
    echo -e "${RED}✗ WARNING: BTA service is NOT running!${NC}"
    echo "This will result in massive point penalties!"
fi

if [ -f "/usr/sbin/bta.status" ]; then
    echo "BTA Status:"
    cat /usr/sbin/bta.status
fi

# Prompt for team-specific info
echo ""
echo "Enter team number (e.g., 7 for team 7, 22 for team 22):"
read TEAM_NUM

if [ "$TEAM_NUM" -lt 10 ]; then
    TEAM_OCTET="5${TEAM_NUM}"
else
    TEAM_OCTET="$((50 + TEAM_NUM))"
fi

echo "Your network will be: 10.250.${TEAM_OCTET}.0/24"
echo ""
echo -e "${YELLOW}WARNING: This script will make system changes. Continue? (yes/no)${NC}"
read CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "=========================================="
echo "PHASE 1: USER MANAGEMENT"
echo "=========================================="

echo -e "${YELLOW}[1.1] Rotating passwords for scored/admin accounts...${NC}"

# === ACCOUNTS TO ROTATE ===
# Add/remove usernames here
USERS_TO_ROTATE=(
    "alexisj"
    "aubryimogene"
    "bookerrudolph"
    "ellisonjessie"
    "fairchildestella"
    "guehomaurice"
    "laramiesylvester"
    "northropbirdie"
    "overtonbonnie"
    "preussgwendolyn"
    "reddinggail"
    "sutterglenn"
    "yorktheodore"
    "beckerandrew"
    "caldwelllaverne"
    "elmsworthcecil"
    "farnhamsam"
    "hesslerpat"
    "nolanfrances"
    "nugentnell"
    "overtonmollie"
    "quintalfelix"
    "reynoldslouise"
    "vaughankarl"
    "ashworthconstance"
    "berrysophia"
    "douglasskaren"
    "estevesrudolph"
    "foretcharley"
    "jansenvirgil"
    "norrissamuel"
    "osterhausloretta"
    "patoutann"
    "radcliffealice"
    "schroederoliver"
    "yardleyherman"
)


for USER in "${USERS_TO_ROTATE[@]}"; do
    # Verify user exists
    if ! id "$USER" &>/dev/null; then
        echo -e "${RED}✗ User '$USER' does not exist — skipping${NC}"
        continue
    fi

    echo ""
    echo -e "${CYAN}Changing password for user: $USER${NC}"

    while true; do
        read -s -p "Enter NEW password for $USER: " PASS1
        echo
        read -s -p "Confirm NEW password for $USER: " PASS2
        echo

        if [ -z "$PASS1" ]; then
            echo -e "${RED}Password cannot be empty.${NC}"
        elif [ "$PASS1" != "$PASS2" ]; then
            echo -e "${RED}Passwords do not match. Try again.${NC}"
        else
            echo "$USER:$PASS1" | chpasswd
            unset PASS1 PASS2
            echo -e "${GREEN}✓ Password changed for $USER${NC}"
            break
        fi
    done
done

# Lock root account from SSH (but keep it for local access)
echo -e "${YELLOW}[1.2] Checking for unauthorized users...${NC}"
# List users with UID >= 1000 (non-system users)
USERS=$(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd)
echo "Current non-system users:"
echo "$USERS"
echo ""
echo "Review this list. Lock any suspicious accounts manually with: passwd -l <username>"

echo ""
echo "=========================================="
echo "PHASE 2: SSH HARDENING"
echo "=========================================="

echo -e "${YELLOW}[2.1] Backing up SSH config...${NC}"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d-%H%M%S)

echo -e "${YELLOW}[2.2] Hardening SSH configuration...${NC}"

# Disable root login via SSH
sed -i 's/^.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
# Ensure password auth is enabled (needed for scoring)
sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# Disable empty passwords
sed -i 's/^.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
# Limit login grace time
sed -i 's/^.*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
# Set max auth tries
sed -i 's/^.*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config

grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
grep -q "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# Add these if they don't exist
grep -q "^Protocol 2" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
grep -q "^X11Forwarding no" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config

echo -e "${YELLOW}[2.3] Restarting SSH service...${NC}"
systemctl restart sshd || systemctl restart ssh
echo -e "${GREEN}✓ SSH hardened and restarted${NC}"

echo ""
echo "=========================================="
echo "PHASE 3: FIREWALL CONFIGURATION"
echo "=========================================="

echo -e "${YELLOW}[3.1] Configuring UFW firewall...${NC}"

# Install UFW if not present
if ! command -v ufw &> /dev/null; then
    apt-get update && apt-get install -y ufw
fi

# Reset UFW to defaults
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing

# CRITICAL: Allow BTA communication
echo -e "${YELLOW}[3.2] Whitelisting Black Team Agent IPs (CRITICAL)...${NC}"
ufw allow out to 10.250.250.11 port 443
ufw allow out to 169.254.169.254 port 80

# Allow supporting infrastructure
ufw allow out to 10.250.250.0/24

# Common scored services (adjust based on actual scenario)
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow 21/tcp comment 'FTP'
ufw allow 53 comment 'DNS'

# LDAP/Kerberos (if this is a domain controller)
ufw allow 389/tcp comment 'LDAP'
ufw allow 636/tcp comment 'LDAPS'
ufw allow 88/tcp comment 'Kerberos'

# SMB/Samba
ufw allow 445/tcp comment 'SMB'
ufw allow 139/tcp comment 'NetBIOS'

# Enable firewall
ufw --force enable
echo -e "${GREEN}✓ Firewall configured and enabled${NC}"

echo ""
echo "=========================================="
echo "PHASE 4: SERVICE HARDENING"
echo "=========================================="

# Apache/Nginx Hardening
if systemctl is-active --quiet apache2; then
    echo -e "${YELLOW}[4.1] Hardening Apache...${NC}"
    
    # Disable directory listing
    sed -i 's/Options Indexes FollowSymLinks/Options -Indexes +FollowSymLinks/' /etc/apache2/apache2.conf
    
    # Hide version info
    echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
    echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf
    
    systemctl restart apache2
    echo -e "${GREEN}✓ Apache hardened${NC}"
fi

if systemctl is-active --quiet nginx; then
    echo -e "${YELLOW}[4.1] Hardening Nginx...${NC}"
    
    # Hide version
    sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf
    
    systemctl restart nginx
    echo -e "${GREEN}✓ Nginx hardened${NC}"
fi

# FTP Hardening (vsftpd)
if systemctl is-active --quiet vsftpd; then
    echo -e "${YELLOW}[4.2] Hardening FTP (vsftpd)...${NC}"
    
    cp /etc/vsftpd.conf /etc/vsftpd.conf.backup.$(date +%Y%m%d-%H%M%S)
    
    # Disable anonymous FTP (check scenario requirements first!)
    # sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf
    
    # Chroot users
    sed -i 's/^#chroot_local_user=YES/chroot_local_user=YES/' /etc/vsftpd.conf
    
    systemctl restart vsftpd
    echo -e "${GREEN}✓ FTP hardened${NC}"
fi

# DNS (BIND) Hardening
if systemctl is-active --quiet named || systemctl is-active --quiet bind9; then
    echo -e "${YELLOW}[4.3] Hardening DNS (BIND)...${NC}"
    
    # Check configuration
    named-checkconf
    
    echo -e "${GREEN}✓ DNS configuration validated${NC}"
fi

# Samba Hardening
if systemctl is-active --quiet smbd; then
    echo -e "${YELLOW}[4.4] Hardening Samba...${NC}"
    
    cp /etc/samba/smb.conf /etc/samba/smb.conf.backup.$(date +%Y%m%d-%H%M%S)
    
    # Add security settings to global section
    sed -i '/\[global\]/a \
    # Security hardening\n\
    client min protocol = SMB2\n\
    server min protocol = SMB2\n\
    ntlm auth = yes' /etc/samba/smb.conf
    
    systemctl restart smbd
    echo -e "${GREEN}✓ Samba hardened${NC}"
fi

echo ""
echo "=========================================="
echo "PHASE 5: PASSWORD POLICIES"
echo "=========================================="

echo -e "${YELLOW}[5.1] Configuring password policy...${NC}"

# Backup login.defs
cp /etc/login.defs /etc/login.defs.backup.$(date +%Y%m%d-%H%M%S)

# Set password aging
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   5/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Account lockout (PAM)
if [ -f /etc/pam.d/common-auth ]; then
    grep -q pam_faillock.so /etc/pam.d/common-auth || \
    echo "auth required pam_faillock.so deny=5 unlock_time=1800" >> /etc/pam.d/common-auth
fi

echo -e "${GREEN}✓ Password policy configured${NC}"

echo ""
echo "=========================================="
echo "PHASE 6: AUDITING & MONITORING"
echo "=========================================="

echo -e "${YELLOW}[6.1] Enabling system auditing...${NC}"

if command -v auditctl &> /dev/null; then
    auditctl -e 1
    echo -e "${GREEN}✓ Auditing enabled${NC}"
else
    echo -e "${YELLOW}⚠ auditd not installed${NC}"
fi

echo ""
echo "=========================================="
echo "PHASE 7: MALWARE HUNTING"
echo "=========================================="

echo -e "${YELLOW}[7.1] Checking for suspicious processes...${NC}"

# Look for unusual network connections
echo "Checking for suspicious network connections..."
netstat -tulpn | grep -v "127.0.0.1" | grep -v "::1" | grep ESTABLISHED

echo ""
echo "Checking for processes with unusual parent PIDs..."
ps -ef | awk '$3 == 1 && $2 != 1 {print $0}'

echo ""
echo -e "${YELLOW}[7.2] Checking for suspicious cron jobs...${NC}"
echo "System crontabs:"
cat /etc/crontab
ls -la /etc/cron.*

echo ""
echo "User crontabs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v "^#" && echo "User: $user"
done

echo ""
echo -e "${YELLOW}[7.3] Checking for unusual SUID/SGID files...${NC}"
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | head -20

echo ""
echo "=========================================="
echo "PHASE 8: SYSTEM UPDATES"
echo "=========================================="

echo -e "${YELLOW}[8.1] Updating package lists...${NC}"
apt-get update

echo -e "${YELLOW}Note: Full system upgrade disabled by default${NC}"
echo "Run manually if needed: apt-get upgrade -y"

echo ""
echo "=========================================="
echo "HARDENING COMPLETE!"
echo "=========================================="
echo ""
echo -e "${GREEN}✓ Basic hardening applied${NC}"
echo ""
echo "CRITICAL NEXT STEPS:"
echo "1. Update scoring engine with new password for alexisj"
echo "2. Verify BTA is still running: systemctl status bta"
echo "3. Check service status on scoreboard"
echo "4. Hunt for Red Team persistence mechanisms"
echo "5. Review /var/log/auth.log for suspicious activity"
echo "6. Check for backdoor user accounts"
echo "7. Review web application files for web shells"
echo ""
echo "REMEMBER:"
echo "- DO NOT block BTA IPs: 10.250.250.11 and 169.254.169.254"
echo "- DO NOT modify seccdc* user accounts"
echo "- Update scoring engine when rotating passwords"
echo "- Only use allowed special chars: )('. ,@|=:;/-!"
echo ""
echo "Logs saved. Review any warnings above!"
echo "=========================================="
