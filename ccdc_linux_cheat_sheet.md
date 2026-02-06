

// === USERS & PRIVILEGES ===
cat /etc/passwd | awk -F: '$3 >= 1000 && $3 < 2000'   // list non-system users
adduser <user>                                      // create user
 deluser <user>                                     // remove user
getent group sudo                                   // list sudo users
usermod -aG sudo <user>                             // add sudo rights
deluser <user> sudo                                 // remove sudo rights
passwd <user>                                      // set/reset password
passwd -l <user>                                   // lock account
passwd -u <user>                                   // unlock account
sudo -l -U <user>                                  // show sudo perms

// === PASSWORD / PAM ===
nano /etc/login.defs                                // edit password policy
PASS_MAX_DAYS 90                                   // force periodic change
PASS_MIN_DAYS 5                                    // prevent fast reuse
PASS_MIN_LEN 10                                    // minimum length
PASS_WARN_AGE 7                                    // expiry warning
pam_tally2.so deny=5 unlock_time=1800               // lock after 5 failures
pam_faillock.so deny=5 unlock_time=1800             // modern lockout

// === SSH ===
nano /etc/ssh/sshd_config                           // edit ssh config
PermitRootLogin no                                 // disable root ssh
PasswordAuthentication yes                         // allow passwords
AllowUsers ccdcuser                                // restrict access
systemctl reload ssh                               // reload ssh safely

// === LOGGING / AUDIT ===
journalctl -u ssh                                  // ssh logs
journalctl -xe                                     // system errors
auditctl -s                                       // audit status
auditctl -e 1                                     // enable auditing

// === FIREWALL ===
ufw enable                                         // enable firewall
ufw default deny incoming                          // block inbound
ufw default allow outgoing                         // allow outbound
ufw allow <port>                                   // allow service port
ufw status verbose                                 // show rules

// === NETWORK ===
ss -tulpn                                         // listening ports
netstat -tulpn                                    // legacy port view
lsof -i -n -P                                     // active connections

// === PROCESSES ===
ps aux                                            // list processes
top                                               // live process view
pkill -f badguy                                   // kill by name
kill -9 <PID>                                     // force kill
pgrep nc                                          // find netcat
apt purge netcat-openbsd                           // remove netcat

// === FILE CLEANUP ===
locate '*.mp3'                                    // find media files
find /home -name '*.mp3' -delete                  // delete junk
apt purge <pkg>                                   // remove software
apt autoremove                                    // cleanup deps
find / -perm -0002 -type f                        // world-writable files

// === DNS (BIND) ===
named-checkconf                                   // validate config
named-checkzone ccdc.local /etc/bind/db.ccdc.local // check zone

// === SAMBA ===
smbstatus                                         // active smb sessions
net usershare info --long                          // list shares
net usershare delete <share>                      // remove share

// === KERBEROS ===
krb5_newrealm                                     // init realm
kadmin.local                                      // local admin

default_realm = CCDC.LOCAL                         // set realm
dns_lookup_kdc = true                             // auto-discover KDC

// === DOVECOT ===
protocols = pop3                                  // enable pop3
disable_plaintext_auth = no                       // allow plaintext
```

