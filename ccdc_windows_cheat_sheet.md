
// CCDC Windows Administration & Hardening Cheat Sheet

// === USERS & GROUPS ===
net user <username> <password> /add                 // create local user
net user <username> /del                            // delete local user
New-LocalUser "<username>" -Password (ConvertTo-SecureString "<password>" -AsPlainText -Force) // create user (PS)
Remove-LocalUser -Name "<username>"                // delete user (PS)

net localgroup administrators <username> /add       // grant admin rights
net localgroup administrators <username> /del       // revoke admin rights
Add-LocalGroupMember -Group "Administrators" -Member "<username>" // add admin (PS)
Remove-LocalGroupMember -Group "Administrators" -Member "<username>" // remove admin (PS)

net user <username> N3wP@$$w0rd                      // reset password
Set-LocalUser -Name "<username>" -Password (ConvertTo-SecureString "N3wP@$$w0rd" -AsPlainText -Force) // reset pw (PS)

// === PASSWORD & LOCKOUT POLICY ===
net accounts /minpwlen:10                            // minimum length
net accounts /maxpwage:90                            // max password age
net accounts /minpwage:5                             // min password age
net accounts /uniquepw:10                            // history length

net accounts /lockoutthreshold:5                    // lock after failures
net accounts /lockoutduration:30                    // lock duration (min)
net accounts /lockoutwindow:30                      // failure window

// === FIREWALL & DEFENDER ===
netsh advfirewall set allprofiles state on           // enable firewall
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound // deny inbound

sc start WinDefend                                   // start Defender service
Set-MpPreference -DisableRealtimeMonitoring $false   // enable Defender realtime (PS)

// === WINDOWS UPDATE ===
sc config wuauserv start= auto                       // set updates auto
sc start wuauserv                                   // start update service

// === PROCESS HUNTING ===
tasklist                                            // list running processes
Get-Process | Select ID,ProcessName,Path             // detailed process list (PS)

tasklist | findstr badguy                           // locate malicious process
taskkill /F /IM badguy.exe                          // force kill by name
Stop-Process -Name badguy -Force                    // kill process (PS)

// === NETWORK & SHARES ===
net share                                           // list SMB shares
net share <sharename> /del                          // delete SMB share
Remove-SmbShare -Name "<sharename>" -Force          // delete share (PS)

netstat -ano                                        // active connections
Get-NetTCPConnection                                // connections (PS)

// === SOFTWARE REMOVAL ===
wmic product where "name like '%badsoft%'" call uninstall // uninstall software
Get-WmiObject Win32_Product | Where Name -like '*badsoft*' | ForEach { $_.Uninstall() } // uninstall (PS)

// === FILE SEARCH & CLEANUP ===
del /q /f /s C:\*.mp3                               // delete files (CMD)
Get-ChildItem C:\ -Recurse -Filter *.mp3 | Remove-Item -Force // delete files (PS)

// === SERVICES ===
sc query                                            // list services
sc config <service> start= disabled                 // disable service
net stop <service>                                  // stop service

Set-Service -Name "<service>" -StartupType Disabled // disable service (PS)
Stop-Service -Name "<service>" -Force               // stop service (PS)
```

