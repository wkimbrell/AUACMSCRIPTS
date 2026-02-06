# SECCDC 2026 - Windows Service Hardening Guide
## Wild West Parks Inc. - Complete Reference

---

## ⚠️ CRITICAL CCDC REQUIREMENTS

### Black Team Agent (BTA) - DO NOT BLOCK!
**Blocking = up to 50% point penalty**

**File Locations:**
- Binary: `C:\Program Files\BTA\bta.exe`
- Config: `C:\Program Files\BTA\bta.enc`
- Status: `C:\Program Files\BTA\bta.status`

**Service:**
- Service name: `BTA` (Windows Service)
- Must run with full SYSTEM privileges

**Network Requirements:**
- Must reach `10.250.250.11:443` (outbound)
- Must reach `169.254.169.254:80` (outbound)
- No proxy allowed

**Check Status:**
```powershell
Get-Service BTA
Get-Content "C:\Program Files\BTA\bta.status"
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

## 🔐 RDP (Remote Desktop) HARDENING

### Enable & Harden RDP
```powershell
# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Enable in firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Require Network Level Authentication (NLA)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1

# Enforce encryption
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "SecurityLayer" -Value 2
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "MinEncryptionLevel" -Value 3

# Limit RDP users (replace with actual scored users)
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "alexisj"
```

### Monitor RDP Sessions
```powershell
# Current sessions
qwinsta

# Event logs
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 20

# Failed RDP attempts
Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4625} | Select-Object -First 10
```

---

## 🌐 WEB SERVER HARDENING (IIS)

### Basic Hardening
```powershell
# Import IIS module
Import-Module WebAdministration

# Disable directory browsing
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false

# Remove default headers
Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name='X-Powered-By'}

# Add security headers (to web.config or applicationHost.config)
Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name='X-Content-Type-Options';value='nosniff'}
Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name='X-Frame-Options';value='SAMEORIGIN'}

# Disable detailed error messages
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpErrors" -Name "errorMode" -Value "Custom"

# Restart IIS
iisreset
```

### Application Pool Hardening
```powershell
# Set application pool identity
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.identityType -Value "ApplicationPoolIdentity"

# Enable 32-bit applications if needed
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name enable32BitAppOnWin64 -Value $false

# Set idle timeout
Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name processModel.idleTimeout -Value "00:20:00"
```

### Web Shell Detection
```powershell
# Find recently modified files
Get-ChildItem -Path C:\inetpub\wwwroot -Recurse -File | Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-24)} | Select-Object FullName, LastWriteTime

# Search for suspicious content
Get-ChildItem -Path C:\inetpub\wwwroot -Recurse -Include *.asp,*.aspx,*.php,*.jsp | Select-String -Pattern "eval\(|base64_decode|cmd.exe|powershell.exe"

# Check for odd permissions
Get-ChildItem -Path C:\inetpub\wwwroot -Recurse | Get-Acl | Where-Object {$_.Access.IdentityReference -like "*Everyone*"}
```

---

## 🗂️ SMB/FILE SHARING HARDENING

### Disable SMBv1
```powershell
# Disable SMBv1 (critical security issue)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Verify
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
```

### Harden SMB
```powershell
# Require signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Enable encryption
Set-SmbServerConfiguration -EncryptData $true -Force

# Reject unencrypted access
Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Force
```

### Manage Shares
```powershell
# List shares
Get-SmbShare

# Remove a share
Remove-SmbShare -Name "ShareName" -Force

# Create a restricted share
New-SmbShare -Name "SecureShare" -Path "C:\SharedData" -FullAccess "alexisj" -ReadAccess "Domain Users"

# Check share permissions
Get-SmbShareAccess -Name "ShareName"
```

### Monitor SMB Sessions
```powershell
# Current sessions
Get-SmbSession

# Open files
Get-SmbOpenFile

# Connection statistics
Get-SmbConnection
```

---

## 🔧 WinRM HARDENING

### Enable & Configure WinRM
```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Disable basic auth (use Kerberos/NTLM)
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false

# Require encryption
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false

# Restrict to specific users
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI

# Limit memory
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 1024

# Restart WinRM
Restart-Service WinRM
```

### Firewall Rules
```powershell
# Allow WinRM
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

# Or manually
New-NetFirewallRule -DisplayName "WinRM-HTTP" -Direction Inbound -LocalPort 5985 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "WinRM-HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow
```

---

## 📧 EMAIL (Exchange/POP3) CONFIGURATION

### If using Windows POP3 Service
```powershell
# Install POP3 feature
Install-WindowsFeature -Name SMTP-Server,POP3-Server

# Configure POP3
# Access via: C:\Windows\System32\inetsrv\appcmd.exe
```

### Monitor Mail Logs
```powershell
# Check SMTP logs
Get-Content "C:\inetpub\logs\LogFiles\SMTPSVC1\*.log" | Select-Object -Last 50

# Event viewer
Get-EventLog -LogName Application -Source "MSExchange*" -Newest 20
```

---

## 🌍 DNS SERVER HARDENING (Windows DNS)

### DNS Server Configuration
```powershell
# List DNS zones
Get-DnsServerZone

# Enable DNSSEC if required
Enable-DnsServerSigningKeyRollover -ZoneName "example.com"

# Restrict zone transfers
Set-DnsServerPrimaryZone -Name "example.com" -SecureSecondaries "TransferToSecureServers"

# Disable recursion on authoritative servers
Set-DnsServerRecursion -Enable $false

# Clear DNS cache
Clear-DnsServerCache -Force

# Restart DNS
Restart-Service DNS
```

### Monitor DNS
```powershell
# Enable debug logging
Set-DnsServerDiagnostics -All $true

# View DNS queries
Get-DnsServerQueryResolutionStatistics

# Check for suspicious queries
Get-WinEvent -LogName "DNS Server" -MaxEvents 50
```

---

## 🔑 ACTIVE DIRECTORY / LDAP / KERBEROS

### Domain Controller Hardening
```powershell
# Check domain functional level
Get-ADDomain | Select-Object DomainMode

# Disable LM hash storage
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1

# Require strong keys
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 0x7FFFFFFE

# Audit account logons
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

### User Account Management
```powershell
# List domain admins
Get-ADGroupMember -Identity "Domain Admins"

# Check for disabled accounts
Get-ADUser -Filter {Enabled -eq $false} | Select-Object Name, SamAccountName

# Find accounts with non-expiring passwords
Get-ADUser -Filter {PasswordNeverExpires -eq $true} | Select-Object Name, SamAccountName

# Set password expiration
Set-ADUser -Identity "username" -PasswordNeverExpires $false

# Force password change
Set-ADUser -Identity "username" -ChangePasswordAtLogon $true
```

### Monitor AD Events
```powershell
# Account lockouts
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4740} -MaxEvents 10

# Account modifications
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4738} -MaxEvents 10

# Failed logons
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 20
```

---

## 🔥 WINDOWS FIREWALL

### Basic Configuration
```powershell
# Enable firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Set default policies
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# CRITICAL: Allow BTA
New-NetFirewallRule -DisplayName "BTA - 10.250.250.11:443" -Direction Outbound -RemoteAddress 10.250.250.11 -RemotePort 443 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "BTA - 169.254.169.254:80" -Direction Outbound -RemoteAddress 169.254.169.254 -RemotePort 80 -Protocol TCP -Action Allow

# Allow supporting infrastructure
New-NetFirewallRule -DisplayName "CCDC Infrastructure" -Direction Outbound -RemoteAddress 10.250.250.0/24 -Protocol Any -Action Allow
```

### Service-Specific Rules
```powershell
# RDP
New-NetFirewallRule -DisplayName "RDP-In" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

# HTTP/HTTPS
New-NetFirewallRule -DisplayName "HTTP-In" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "HTTPS-In" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

# SMB
New-NetFirewallRule -DisplayName "SMB-In" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

# WinRM
New-NetFirewallRule -DisplayName "WinRM-HTTP-In" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -DisplayName "WinRM-HTTPS-In" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

# DNS
New-NetFirewallRule -DisplayName "DNS-In" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow

# LDAP/Kerberos
New-NetFirewallRule -DisplayName "LDAP-In" -Direction Inbound -Protocol TCP -LocalPort 389 -Action Allow
New-NetFirewallRule -DisplayName "LDAPS-In" -Direction Inbound -Protocol TCP -LocalPort 636 -Action Allow
New-NetFirewallRule -DisplayName "Kerberos-In" -Direction Inbound -Protocol TCP -LocalPort 88 -Action Allow
```

### Check Firewall Status
```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} | Select-Object DisplayName, Direction, Action
```

---

## 🛡️ WINDOWS DEFENDER

### Enable & Configure
```powershell
# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable cloud protection
Set-MpPreference -MAPSReporting Advanced

# Enable automatic sample submission
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable PUA protection
Set-MpPreference -PUAProtection Enabled

# Update definitions
Update-MpSignature

# Start service
Set-Service -Name WinDefend -StartupType Automatic
Start-Service WinDefend
```

### Scan for Threats
```powershell
# Quick scan
Start-MpScan -ScanType QuickScan

# Full scan (background)
Start-MpScan -ScanType FullScan -AsJob

# Custom scan
Start-MpScan -ScanType CustomScan -ScanPath "C:\inetpub\wwwroot"

# Check threats
Get-MpThreatDetection
Get-MpThreat
```

### Exclusions (Use Sparingly!)
```powershell
# Add exclusion (ONLY for BTA if needed)
Add-MpPreference -ExclusionPath "C:\Program Files\BTA"
Add-MpPreference -ExclusionProcess "bta.exe"
```

---

## 🔍 MALWARE HUNTING

### Suspicious Processes
```powershell
# Processes not in standard locations
Get-Process | Where-Object {$_.Path -notlike "C:\Windows\*" -and $_.Path -notlike "C:\Program Files\*" -and $_.Path -ne $null} | Select-Object ProcessName, Path, Id

# High CPU processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 ProcessName, CPU, Path

# Network connections by process
Get-NetTCPConnection -State Established | ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        RemoteAddress = $_.RemoteAddress
        RemotePort = $_.RemotePort
        Process = $proc.ProcessName
        Path = $proc.Path
    }
} | Format-Table
```

### Scheduled Tasks
```powershell
# List non-Microsoft tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | Select-Object TaskName, TaskPath, State, Author

# Find recently created tasks
Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-7)} | Select-Object TaskName, Date, Actions

# Suspicious task actions
Get-ScheduledTask | ForEach-Object {
    $_ | Get-ScheduledTaskInfo
    $_.Actions
} | Where-Object {$_.Execute -like "*powershell*" -or $_.Execute -like "*cmd*"}
```

### Startup Programs
```powershell
# Registry run keys
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

# Startup folder
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# WMI persistence
Get-WmiObject -Class __EventFilter -Namespace root\subscription
Get-WmiObject -Class __EventConsumer -Namespace root\subscription
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription
```

### Services
```powershell
# List non-Microsoft services
Get-Service | Where-Object {$_.DisplayName -notlike "*Microsoft*" -and $_.DisplayName -notlike "*Windows*"} | Select-Object Name, DisplayName, Status, StartType

# Suspicious service binaries
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "C:\Windows\*"} | Select-Object Name, PathName, State
```

### Recent File Modifications
```powershell
# System directories
Get-ChildItem C:\Windows\System32 -File | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} | Select-Object Name, LastWriteTime

# Temp directories
Get-ChildItem $env:TEMP -Recurse -File | Where-Object {$_.CreationTime -gt (Get-Date).AddHours(-4)}
```

---

## 📊 INCIDENT RESPONSE REPORTING

**Required Information:**
1. **Affected Hosts** - List by hostname with evidence
2. **Time Frame** - Explicit start/stop times
3. **Observed Activity** - What the attacker did
4. **Persistence/Access Method** - How they maintained access
5. **Technical Analysis** - Event IDs, IPs, domains, etc.
6. **Remediation Steps** - What you did to fix it
7. **Evidence Appendix** - Screenshots

**⚠️ DO NOT upload malware to VirusTotal or similar services!**

**Can recover up to 50% of Red Team point deductions**

### Useful Event IDs
```
4624 - Successful logon
4625 - Failed logon
4672 - Special privileges assigned
4720 - User account created
4726 - User account deleted
4738 - User account changed
4740 - Account locked out
4768 - Kerberos TGT requested
4769 - Kerberos service ticket requested
7045 - Service installed
```

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
```powershell
# For scored users
Set-LocalUser -Name "alexisj" -Password (ConvertTo-SecureString "NewP@ssw0rd" -AsPlainText -Force)

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
5. ☐ Enable & configure Windows Firewall (whitelist BTA IPs!)
6. ☐ Enable Windows Defender
7. ☐ Harden RDP
8. ☐ Disable SMBv1
9. ☐ Check for web shells (if IIS)
10. ☐ Hunt for persistence mechanisms
11. ☐ Monitor service status on scoreboard
12. ☐ Submit incident reports for any compromises

---

## 📞 SUPPORT

- **Mattermost:** `https://10.250.250.5/`
- **Scoreboard:** `https://10.250.250.10/`
- **Discord AMA:** `https://discord.gg/4Hvcyh5q9j`

---

**Good luck, Team! Defend the frontier! 🤠**
