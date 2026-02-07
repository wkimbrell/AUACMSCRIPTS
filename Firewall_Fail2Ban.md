# **STEP 1 — Identify Yourself + Users & sudo (ROOT ACCESS FIRST)**

## **Users & sudo**

### Confirm who we are

- `whoami`

### Change password

- `passwd`

### Who has sudo and who can log in

- `getent group sudo`
- `grep -E "/bin/(bash|sh|zsh)$" /etc/passwd`

### Last login activity

- `lastlog`

### Finding suspicious activity

- `sudo tail -n 50 /var/log/auth.log`

### Lock their password

*(action decided based on evidence)*

### Hardening — avoid kicking yourself out

Only the right people can log in, and only the right people can become root.

---

# **STEP 2 — Firewall (UFW FIRST)**

## **Firewall**

### Recon philosophy

Allow first → deny second

### Install firewall

- `sudo apt install ufw`
- `sudo ufw enable`

### First required outbound rules

- `sudo ufw allow out to 10.250.250.11 port 443`
- `sudo ufw allow out to 169.254.169.254 port 80`

### Enable logging

- `ufw logging medium`
- Firewall logs:
    - `sudo tail -f /var/log/syslog | grep UFW`

### Check firewall status

- `sudo ufw status verbose`

### Identify listening ports

- `ss -tulpn`
- `0.0.0.0:PORT` or `:::PORT` = exposed to network (danger)

### Limit SSH access

- `ufw limit ssh`
    
    (SSH stays alive but rate-limited)
    

### Deny known bad ports

- `sudo ufw deny log 6667`
- `sudo ufw deny log 31337`

### Or deny everything except allowed rules

- `sudo ufw default deny incoming`
- `sudo ufw default allow outgoing`

### Rollback plan

- `sudo ufw disable`

---

# **STEP 3 — SSH Recon + Hardening (Before Fail2Ban)**

## **SSH**

### Recon — check SSH activity

- `grep -Ei "failed|accepted|sudo|useradd|usermod|passwd|root" /var/log/auth.log`

### Immediate response

Remove sudo if needed:

- `sudo deluser USER sudo`

### Hardening

### Confirm SSH is running

- `systemctl status ssh`

### Read SSH config (NO EDITING YET)

- `sudo nano /etc/ssh/sshd_config`

### Decide minimum safe hardening

- `PermitRootLogin no`
- `PasswordAuthentication yes`
- `AllowUsers <name root>` *(optional)*

---

# **STEP 4 — Fail2Ban Implementation (AFTER UFW + SSH)**

### Install + enable

- `sudo apt install fail2ban -y`
- `systemctl status fail2ban --no-pager`
- `sudo systemctl enable fail2ban`
- `sudo nano /etc/fail2ban/jail.local`

### Jail configuration

```
[DEFAULT]
bantime = 1h
findtime = 20m
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache2/error.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log

[vsftpd]
enabled = true
port = ftp,ftp-data,ftps,ftps-data
backend = systemd

```

### Restart + verify

- `sudo systemctl restart fail2ban`
- `sudo systemctl status fail2ban --no-pager`

### Check jails

- `sudo fail2ban-client status`

Check each jail:

- `sudo fail2ban-client status sshd`
- `sudo fail2ban-client status apache-auth`
- `sudo fail2ban-client status nginx-http-auth`
- `sudo fail2ban-client status vsftpd`

### Confirm logs exist

- `ls -l /var/log/auth.log /var/log/apache2/error.log /var/log/nginx/error.log /var/log/vsftpd.log`

---

# **STEP 5 — Logs + Validation (Evidence During Competition)**

## **Fail2Ban logs**

- `sudo tail -f /var/log/fail2ban.log` *(best single pane)*
- `sudo tail /var/log/fail2ban.log` *(last ~20 min)*
- `sudo fail2ban-client status sshd`

## **Service logs**

### SSH

- `sudo tail -f /var/log/auth.log`

### Web

- `sudo tail -f /var/log/apache2/error.log`
- `sudo tail -f /var/log/nginx/error.log`

### FTP

- `sudo tail -f /var/log/vsftpd.log`

## **Manual actions**

- `sudo fail2ban-client set sshd banip <IP>`
- `sudo fail2ban-client set sshd unbanip <IP>`

---

# **STEP 6 — Services / Ports / Processes Recon (Firewall Support)**

### Running services

- `systemctl list-units --state=running`

### Disable unnecessary services

- `sudo systemctl stop service_name`
- `sudo systemctl disable service_name`

### Exposed ports

- `ss -tulpn`

Bad example:

- `tcp LISTEN 0 4096 0.0.0.0:4444 users:(("nc",pid=1337))`

### Processes

- `ps aux`

### Service watchdog script

```bash
#!/bin/bash
while true; do
  SSH_STATUS=$(systemctl is-active ssh)
  APACHE_STATUS=$(systemctl is-active apache2)
  NGINX_STATUS=$(systemctl is-active nginx)

  if [ "$SSH_STATUS" != "active" ]; then
    systemctl restart ssh
    [ $? -ne 0 ] && echo "$(date): Failed to restart SSH" >> /var/log/service_monitor.log
  fi

  if [ "$APACHE_STATUS" != "active" ]; then
    systemctl restart apache2
    [ $? -ne 0 ] && echo "$(date): Failed to restart Apache2" >> /var/log/service_monitor.log
  fi

  if [ "$NGINX_STATUS" != "active" ]; then
    systemctl restart nginx
    [ $? -ne 0 ] && echo "$(date): Failed to restart Nginx" >> /var/log/service_monitor.log
  fi

  sleep 300
done

```
