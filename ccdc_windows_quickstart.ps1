# SECCDC 2026 - Windows Quick Hardening Script
# Wild West Parks Inc. - Team Hardening Automation
#
# WARNING: Review and customize before running!
# This script performs rapid hardening of Windows systems for CCDC competition
#
# Run as Administrator in PowerShell

#Requires -RunAsAdministrator

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "SECCDC 2026 Windows Quick Hardening Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# CRITICAL: Verify BTA is running and NOT blocked
Write-Host "[CRITICAL] Checking Black Team Agent (BTA)..." -ForegroundColor Yellow
$btaService = Get-Service -Name "BTA" -ErrorAction SilentlyContinue

if ($btaService -and $btaService.Status -eq "Running") {
    Write-Host "✓ BTA service is running" -ForegroundColor Green
} else {
    Write-Host "✗ WARNING: BTA service is NOT running!" -ForegroundColor Red
    Write-Host "This will result in massive point penalties!" -ForegroundColor Red
}

if (Test-Path "C:\Program Files\BTA\bta.status") {
    Write-Host "BTA Status:" -ForegroundColor Cyan
    Get-Content "C:\Program Files\BTA\bta.status"
}

Write-Host ""
Write-Host "WARNING: This script will make system changes. Continue? (yes/no)" -ForegroundColor Yellow
$confirm = Read-Host

if ($confirm -ne "yes") {
    Write-Host "Aborted."
    exit
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 1: USER MANAGEMENT" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Change password for alexisj (default credential)
$usersToRotate = @(
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


foreach ($user in $usersToRotate) {
    Write-Host "Enter NEW password for $user" -ForegroundColor Cyan
    $cred = Get-Credential -UserName $user -Message "Enter NEW password"
    Set-LocalUser -Name $user -Password $cred.Password
    Write-Host "✓ Password changed for $user" -ForegroundColor Green
}

# List local administrators
Write-Host "[1.2] Current local administrators:" -ForegroundColor Yellow
Get-LocalGroupMember -Group "Administrators" | Format-Table Name, ObjectClass, PrincipalSource

Write-Host ""
Write-Host "Review this list. Remove any unauthorized admins manually." -ForegroundColor Yellow

# Check for suspicious users
Write-Host "[1.3] All local users:" -ForegroundColor Yellow
Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 2: PASSWORD & LOCKOUT POLICIES" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "[2.1] Configuring password policy..." -ForegroundColor Yellow
net accounts /minpwlen:10 /maxpwage:90 /minpwage:5 /uniquepw:10
Write-Host "✓ Password policy configured" -ForegroundColor Green

Write-Host "[2.2] Configuring account lockout policy..." -ForegroundColor Yellow
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
Write-Host "✓ Lockout policy configured" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 3: WINDOWS FIREWALL" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "[3.1] Enabling Windows Firewall..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
Write-Host "✓ Firewall enabled on all profiles" -ForegroundColor Green

Write-Host "[3.2] Whitelisting Black Team Agent IPs (CRITICAL)..." -ForegroundColor Yellow
# Allow BTA communication
New-NetFirewallRule -DisplayName "BTA - Allow 10.250.250.11:443" -Direction Outbound -RemoteAddress 10.250.250.11 -RemotePort 443 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "BTA - Allow 169.254.169.254:80" -Direction Outbound -RemoteAddress 169.254.169.254 -RemotePort 80 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
Write-Host "✓ BTA IPs whitelisted" -ForegroundColor Green

Write-Host "[3.3] Configuring firewall rules for scored services..." -ForegroundColor Yellow
# Allow common scored services inbound
$services = @(
    @{Name="RDP"; Port=3389; Protocol="TCP"},
    @{Name="HTTP"; Port=80; Protocol="TCP"},
    @{Name="HTTPS"; Port=443; Protocol="TCP"},
    @{Name="SMB"; Port=445; Protocol="TCP"},
    @{Name="WinRM-HTTP"; Port=5985; Protocol="TCP"},
    @{Name="WinRM-HTTPS"; Port=5986; Protocol="TCP"},
    @{Name="DNS"; Port=53; Protocol="UDP"},
    @{Name="Kerberos"; Port=88; Protocol="TCP"},
    @{Name="LDAP"; Port=389; Protocol="TCP"},
    @{Name="LDAPS"; Port=636; Protocol="TCP"}
)

foreach ($svc in $services) {
    New-NetFirewallRule -DisplayName "CCDC - Allow $($svc.Name)" -Direction Inbound -LocalPort $svc.Port -Protocol $svc.Protocol -Action Allow -ErrorAction SilentlyContinue
}
Write-Host "✓ Service firewall rules configured" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 4: WINDOWS DEFENDER" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "[4.1] Enabling Windows Defender..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $false
Set-Service -Name WinDefend -StartupType Automatic
Start-Service -Name WinDefend -ErrorAction SilentlyContinue
Write-Host "✓ Windows Defender enabled" -ForegroundColor Green

Write-Host "[4.2] Updating Windows Defender definitions..." -ForegroundColor Yellow
Update-MpSignature -ErrorAction SilentlyContinue
Write-Host "✓ Defender definitions updated" -ForegroundColor Green

Write-Host "[4.3] Running quick scan..." -ForegroundColor Yellow
Start-MpScan -ScanType QuickScan -AsJob
Write-Host "✓ Quick scan started in background" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 5: WINDOWS UPDATE" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "[5.1] Enabling Windows Update service..." -ForegroundColor Yellow
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv -ErrorAction SilentlyContinue
Write-Host "✓ Windows Update service enabled" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 6: SERVICE HARDENING" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# RDP Hardening
Write-Host "[6.1] Hardening RDP..." -ForegroundColor Yellow
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -Value 2
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Write-Host "✓ RDP hardened (NLA enabled, encryption enforced)" -ForegroundColor Green

# SMB Hardening
Write-Host "[6.2] Hardening SMB..." -ForegroundColor Yellow
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction SilentlyContinue
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction SilentlyContinue
Write-Host "✓ SMB hardened (SMBv1 disabled, encryption enabled)" -ForegroundColor Green

# WinRM Hardening
Write-Host "[6.3] Hardening WinRM..." -ForegroundColor Yellow
Enable-PSRemoting -Force -ErrorAction SilentlyContinue
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false -ErrorAction SilentlyContinue
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false -ErrorAction SilentlyContinue
Write-Host "✓ WinRM hardened (Basic auth disabled, encryption required)" -ForegroundColor Green

# IIS Hardening (if installed)
$iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if ($iis) {
    Write-Host "[6.4] Hardening IIS..." -ForegroundColor Yellow
    
    # Remove default IIS headers
    if (Get-Command Remove-WebConfigurationProperty -ErrorAction SilentlyContinue) {
        Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -AtElement @{name='X-Powered-By'} -ErrorAction SilentlyContinue
    }
    
    # Disable directory browsing
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/directoryBrowse" -Name "enabled" -Value $false -ErrorAction SilentlyContinue
    
    Write-Host "✓ IIS hardened" -ForegroundColor Green
}

# Disable unnecessary services
Write-Host "[6.5] Disabling unnecessary services..." -ForegroundColor Yellow
$servicesToDisable = @(
    "RemoteRegistry",
    "SSDPSRV",    # SSDP Discovery
    "upnphost",   # UPnP Device Host
    "WMPNetworkSvc" # Windows Media Player Network Sharing
)

foreach ($svc in $servicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "  Disabled: $svc" -ForegroundColor Gray
    }
}
Write-Host "✓ Unnecessary services disabled" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 7: AUDITING & MONITORING" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "[7.1] Enabling audit policies..." -ForegroundColor Yellow
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"System" /success:enable /failure:enable
Write-Host "✓ Audit policies enabled" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 8: MALWARE HUNTING" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "[8.1] Checking for suspicious processes..." -ForegroundColor Yellow
Get-Process | Where-Object {$_.Path -notlike "C:\Windows\*" -and $_.Path -notlike "C:\Program Files\*"} | 
    Select-Object ProcessName, Path, Id | Format-Table

Write-Host "[8.2] Checking for suspicious scheduled tasks..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | 
    Select-Object TaskName, TaskPath, State | Format-Table

Write-Host "[8.3] Checking for suspicious services..." -ForegroundColor Yellow
Get-Service | Where-Object {$_.StartType -eq "Automatic" -and $_.Status -eq "Running"} | 
    Select-Object Name, DisplayName, StartType | Sort-Object Name | Format-Table

Write-Host "[8.4] Checking network connections..." -ForegroundColor Yellow
Get-NetTCPConnection -State Established | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | 
    Format-Table

Write-Host "[8.5] Checking startup programs..." -ForegroundColor Yellow
Get-CimInstance Win32_StartupCommand | 
    Select-Object Name, Command, Location, User | Format-Table

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PHASE 9: REGISTRY HARDENING" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

Write-Host "[9.1] Applying registry hardening..." -ForegroundColor Yellow

# Disable AutoRun
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction SilentlyContinue

# Disable Windows Script Host
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -ErrorAction SilentlyContinue

# Enable LSA Protection
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -ErrorAction SilentlyContinue

# Disable LLMNR
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -ErrorAction SilentlyContinue

Write-Host "✓ Registry hardening applied" -ForegroundColor Green

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "HARDENING COMPLETE!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "✓ Basic hardening applied" -ForegroundColor Green
Write-Host ""
Write-Host "CRITICAL NEXT STEPS:" -ForegroundColor Yellow
Write-Host "1. Update scoring engine with new password for alexisj"
Write-Host "2. Verify BTA is still running: Get-Service BTA"
Write-Host "3. Check service status on scoreboard"
Write-Host "4. Hunt for Red Team persistence mechanisms"
Write-Host "5. Review Event Viewer for suspicious activity (Security log)"
Write-Host "6. Check for backdoor user accounts"
Write-Host "7. Review IIS/web server for web shells"
Write-Host "8. Check scheduled tasks for malicious jobs"
Write-Host ""
Write-Host "REMEMBER:" -ForegroundColor Yellow
Write-Host "- DO NOT block BTA IPs: 10.250.250.11 and 169.254.169.254"
Write-Host "- DO NOT modify seccdc* user accounts"
Write-Host "- Update scoring engine when rotating passwords"
Write-Host "- Only use allowed special chars: )('. ,@|=:;/-!"
Write-Host ""
Write-Host "Review any warnings above and check Defender scan results!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Export findings for review
Write-Host ""
Write-Host "Exporting system info for review..." -ForegroundColor Yellow
$exportPath = "C:\CCDC_HardeningReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

@"
SECCDC 2026 - System Hardening Report
Generated: $(Get-Date)
Hostname: $env:COMPUTERNAME

=== LOCAL ADMINISTRATORS ===
$(Get-LocalGroupMember -Group "Administrators" | Format-Table | Out-String)

=== LOCAL USERS ===
$(Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table | Out-String)

=== RUNNING SERVICES ===
$(Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType | Sort-Object Name | Format-Table | Out-String)

=== NETWORK CONNECTIONS ===
$(Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | Format-Table | Out-String)

=== SCHEDULED TASKS (Non-Microsoft) ===
$(Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | Select-Object TaskName, TaskPath, State | Format-Table | Out-String)

=== FIREWALL STATUS ===
$(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table | Out-String)

"@ | Out-File -FilePath $exportPath

Write-Host "✓ Report exported to: $exportPath" -ForegroundColor Green
Write-Host ""
