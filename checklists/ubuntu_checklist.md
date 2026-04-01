# Ubuntu CyberPatriot Competition Checklist

> **Usage**: Work through each section in order. Check items off as you complete them. Items marked with `[SCRIPT]` are handled by `secure_ubuntu.sh` — verify they applied correctly. Items marked `[MANUAL]` require human judgment.

---

## Phase 0 — Read the README / Scenario

- [ ] **Read the competition README completely** before touching anything `[MANUAL]`
- [ ] Note which users are authorized and which should be removed
- [ ] Note which services must remain running (SSH, Apache, etc.)
- [ ] Note any required software or configurations
- [ ] Identify the forensic question(s) and begin researching answers
- [ ] **Take a VM snapshot / checkpoint** before making changes

---

## Phase 1 — Forensic Questions

- [ ] Read each forensic question carefully `[MANUAL]`
- [ ] Check common locations for answers:
  - `/home/*/Desktop/`, `/home/*/Documents/`, `/tmp/`
  - Browser history: `~/.mozilla/firefox/*.default/places.sqlite`
  - Bash history: `~/.bash_history`, `~/.zsh_history`
  - Log files: `/var/log/auth.log`, `/var/log/syslog`
  - Recently modified files: `find / -mtime -7 -type f 2>/dev/null`
- [ ] Submit forensic answers as you find them (they can be worth significant points)

---

## Phase 2 — User & Group Management

### 2.1 Unauthorized Users
- [ ] List all human users: `awk -F: '$3 >= 1000 && $3 < 65534' /etc/passwd` `[MANUAL]`
- [ ] Compare against the README's authorized user list
- [ ] Remove unauthorized users: `sudo userdel -r <username>`
- [ ] Check for users with UID 0 (should only be root): `awk -F: '$3 == 0' /etc/passwd` `[SCRIPT]`
- [ ] Check for users with empty passwords: `sudo awk -F: '($2 == "")' /etc/shadow`

### 2.2 Missing / Required Users
- [ ] Create any users listed in the README that don't exist: `sudo useradd -m <username>`
- [ ] Set strong passwords for all users: `sudo passwd <username>`

### 2.3 Group Membership
- [ ] Check sudo/admin group: `getent group sudo` `[MANUAL]`
- [ ] Remove unauthorized users from sudo: `sudo deluser <username> sudo`
- [ ] Add authorized admins to sudo: `sudo usermod -aG sudo <username>`
- [ ] Check other sensitive groups: `getent group adm`, `shadow`, `disk`, `plugdev`

### 2.4 Root Account
- [ ] Ensure root has a strong password
- [ ] Ensure root login is disabled in SSH `[SCRIPT]`
- [ ] Lock root account if not needed: `sudo passwd -l root`

---

## Phase 3 — Password & Authentication Policies

### 3.1 Password Aging (/etc/login.defs)
- [ ] `PASS_MAX_DAYS 90` (or as specified in README) `[SCRIPT]`
- [ ] `PASS_MIN_DAYS 7` `[SCRIPT]`
- [ ] `PASS_WARN_AGE 14` `[SCRIPT]`
- [ ] `PASS_MIN_LEN 12` (if the field exists)
- [ ] Apply aging to existing users: `sudo chage -M 90 -m 7 -W 14 <username>` for each user `[MANUAL]`

### 3.2 Password Complexity (PAM)
- [ ] Install libpam-pwquality: `sudo apt install libpam-pwquality` `[SCRIPT]`
- [ ] Verify `/etc/pam.d/common-password` contains: `[SCRIPT]`
  ```
  password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
  ```
- [ ] Ensure `pam_unix.so` line includes `remember=5` (password history)
- [ ] Verify settings: `grep pwquality /etc/pam.d/common-password`

### 3.3 Account Lockout (PAM)
- [ ] Configure lockout in `/etc/pam.d/common-auth` `[MANUAL]`
  ```
  auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
  auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
  ```
- [ ] Alternative (older systems): use `pam_tally2.so`

### 3.4 Login Banners
- [ ] Verify `/etc/issue` and `/etc/issue.net` contain warning text `[SCRIPT]`
- [ ] Verify SSH banner: check `Banner /etc/issue.net` in sshd_config

---

## Phase 4 — SSH Hardening

- [ ] Verify OpenSSH is installed: `dpkg -l openssh-server` `[MANUAL]`
- [ ] **PermitRootLogin no** `[SCRIPT]`
- [ ] **PasswordAuthentication no** (or yes if README requires it) `[SCRIPT]`
- [ ] **PermitEmptyPasswords no** `[SCRIPT]`
- [ ] **X11Forwarding no** `[SCRIPT]`
- [ ] **MaxAuthTries 3** `[SCRIPT]`
- [ ] **ClientAliveInterval 300** `[SCRIPT]`
- [ ] **ClientAliveCountMax 2** `[SCRIPT]`
- [ ] **AllowTcpForwarding no** `[SCRIPT]`
- [ ] **Protocol 2** `[SCRIPT]`
- [ ] Modern ciphers and MACs configured `[SCRIPT]`
- [ ] Restart SSH after changes: `sudo systemctl restart ssh`
- [ ] **Test SSH login in a separate terminal before closing current session**

---

## Phase 5 — Firewall Configuration

- [ ] Install UFW: `sudo apt install ufw` `[SCRIPT]`
- [ ] Default deny incoming: `sudo ufw default deny incoming` `[SCRIPT]`
- [ ] Default allow outgoing: `sudo ufw default allow outgoing` `[SCRIPT]`
- [ ] Allow required services per README (e.g., SSH, HTTP, HTTPS):
  ```bash
  sudo ufw allow ssh
  sudo ufw allow 80/tcp    # if web server required
  sudo ufw allow 443/tcp   # if HTTPS required
  ```
- [ ] Enable UFW: `sudo ufw enable` `[SCRIPT]`
- [ ] Verify: `sudo ufw status verbose` `[SCRIPT]`
- [ ] **Do NOT block services the README says must remain running**

---

## Phase 6 — System Updates & Package Management

### 6.1 Updates
- [ ] `sudo apt update && sudo apt upgrade -y` `[SCRIPT]`
- [ ] `sudo apt dist-upgrade -y` `[SCRIPT]`
- [ ] `sudo apt autoremove -y` `[SCRIPT]`
- [ ] Enable automatic security updates `[SCRIPT]`

### 6.2 Prohibited Software Removal
- [ ] Search for hacking tools: `[SCRIPT]`
  ```bash
  dpkg -l | grep -Ei "nmap|wireshark|john|hydra|aircrack|ophcrack|metasploit|nikto|netcat|hashcat|sqlmap|ettercap|kismet|tcpdump"
  ```
- [ ] Search for games: `[MANUAL]`
  ```bash
  dpkg -l | grep -Ei "game|minetest|supertux|freeciv|0ad|aisleriot|gnome-mines|steam"
  ```
- [ ] Search for peer-to-peer / torrent software:
  ```bash
  dpkg -l | grep -Ei "torrent|transmission|deluge|vuze|qbittorrent|frostwire"
  ```
- [ ] Search for remote access tools:
  ```bash
  dpkg -l | grep -Ei "teamviewer|anydesk|vnc|tightvnc|realvnc|x11vnc"
  ```
- [ ] Remove found prohibited software: `sudo apt purge -y <package>`

### 6.3 Required Software
- [ ] Install any software the README requires
- [ ] Verify required services are running after all changes

---

## Phase 7 — Service Management

### 7.1 Identify Running Services
- [ ] List all running services: `systemctl list-units --type=service --state=running` `[MANUAL]`
- [ ] List all enabled services: `systemctl list-unit-files --type=service --state=enabled`
- [ ] List listening ports: `sudo ss -tulnp` `[MANUAL]`
- [ ] Cross-reference with README — disable anything not required

### 7.2 Common Services to Disable
- [ ] **FTP**: `sudo systemctl disable --now vsftpd proftpd pure-ftpd` `[SCRIPT]`
- [ ] **Telnet**: `sudo apt purge telnetd` `[SCRIPT]`
- [ ] **CUPS** (printing): `sudo systemctl disable --now cups` `[SCRIPT]`
- [ ] **Avahi** (mDNS): `sudo systemctl disable --now avahi-daemon` `[SCRIPT]`
- [ ] **Samba**: `sudo systemctl disable --now smbd nmbd` `[SCRIPT]`
- [ ] **SNMP**: `sudo systemctl disable --now snmpd`
- [ ] **NFS**: `sudo systemctl disable --now nfs-server rpcbind`
- [ ] **Bluetooth**: `sudo systemctl disable --now bluetooth`
- [ ] **xinetd**: `sudo apt purge xinetd` `[SCRIPT]`
- [ ] **rsh/rlogin**: `sudo apt purge rsh-server rlogin-server` `[SCRIPT]`

### 7.3 Services to Harden (if required by README)
- [ ] **Apache**: see Application Hardening section below
- [ ] **MySQL/MariaDB**: see Application Hardening section below
- [ ] **PHP**: see Application Hardening section below
- [ ] **Nginx**: see Application Hardening section below

---

## Phase 8 — Kernel & Filesystem Hardening

### 8.1 Sysctl Settings
- [ ] Verify `/etc/sysctl.d/99-cyberpatriot-hardening.conf` exists with: `[SCRIPT]`
  - `net.ipv4.conf.all.accept_redirects = 0`
  - `net.ipv4.conf.all.send_redirects = 0`
  - `net.ipv4.conf.all.accept_source_route = 0`
  - `net.ipv4.tcp_syncookies = 1`
  - `kernel.randomize_va_space = 2` (ASLR)
  - `kernel.kptr_restrict = 2`
  - `kernel.dmesg_restrict = 1`
  - `fs.suid_dumpable = 0`
  - `net.ipv4.conf.all.log_martians = 1`
- [ ] Apply: `sudo sysctl --system` `[SCRIPT]`

### 8.2 Filesystem Module Blacklisting
- [ ] Verify cramfs, freevxfs, jffs2, hfs, hfsplus, udf are blacklisted `[SCRIPT]`

### 8.3 Shared Memory
- [ ] `/run/shm` mounted with `noexec,nosuid` `[SCRIPT]`

### 8.4 File Permissions
- [ ] `/etc/passwd` — 644, root:root `[SCRIPT]`
- [ ] `/etc/shadow` — 640, root:shadow `[SCRIPT]`
- [ ] `/etc/group` — 644, root:root
- [ ] `/etc/gshadow` — 640, root:shadow
- [ ] SSH host keys — 600 `[SCRIPT]`
- [ ] Remove world-writable files in /etc `[SCRIPT]`

### 8.5 SUID/SGID Audit
- [ ] Find SUID binaries: `find / -perm /4000 -type f 2>/dev/null` `[MANUAL]`
- [ ] Find SGID binaries: `find / -perm /2000 -type f 2>/dev/null`
- [ ] Review list for suspicious entries — compare against a clean system
- [ ] Remove SUID from unnecessary binaries: `sudo chmod u-s <file>`

---

## Phase 9 — Cron Job & Scheduled Task Audit

- [ ] Check root crontab: `sudo crontab -l` `[MANUAL]`
- [ ] Check each user's crontab: `sudo crontab -l -u <username>`
- [ ] Review system cron directories: `[MANUAL]`
  - `/etc/crontab`
  - `/etc/cron.d/`
  - `/etc/cron.daily/`
  - `/etc/cron.hourly/`
  - `/etc/cron.weekly/`
  - `/etc/cron.monthly/`
- [ ] Look for suspicious entries (reverse shells, wget/curl downloads, base64 encoded commands)
- [ ] Restrict cron access `[SCRIPT]`

---

## Phase 10 — Backdoor & Malware Hunting

### 10.1 Suspicious Processes
- [ ] Check running processes: `ps aux` `[MANUAL]`
- [ ] Look for netcat listeners: `ps aux | grep -E "nc |ncat|netcat"`
- [ ] Look for reverse shells: `ps aux | grep -E "bash -i|/dev/tcp"`
- [ ] Check for processes running as root that shouldn't be

### 10.2 Suspicious Network Connections
- [ ] Check established connections: `ss -tupn` `[MANUAL]`
- [ ] Check listening ports: `ss -tulnp`
- [ ] Look for unexpected outbound connections
- [ ] Check `/etc/hosts` for redirects `[SCRIPT]`

### 10.3 Suspicious Files
- [ ] Check `/tmp`, `/var/tmp`, `/dev/shm` for scripts/binaries `[MANUAL]`
- [ ] Find recently modified files: `find / -mtime -3 -type f 2>/dev/null | head -50`
- [ ] Find hidden files in home dirs: `find /home -name ".*" -type f`
- [ ] Check for unauthorized SSH keys: `find /home -name "authorized_keys" -exec cat {} \;`
- [ ] Check `.bashrc`, `.profile`, `.bash_logout` for malicious commands in each home dir

### 10.4 Rootkit Scans
- [ ] Run rkhunter: `sudo rkhunter --check --skip-keypress` `[MANUAL]`
- [ ] Run chkrootkit: `sudo chkrootkit`
- [ ] Run ClamAV: `sudo clamscan -r --bell -i /` (or target specific dirs)

### 10.5 Startup Persistence
- [ ] Check systemd services for suspicious entries: `systemctl list-unit-files --state=enabled`
- [ ] Check `/etc/rc.local` for suspicious commands
- [ ] Check `/etc/init.d/` for unauthorized scripts
- [ ] Check `/etc/xdg/autostart/` for suspicious autostart entries

---

## Phase 11 — Audit & Logging

- [ ] Install and enable auditd `[SCRIPT]`
- [ ] Verify audit rules monitor: `[SCRIPT]`
  - `/etc/passwd`, `/etc/shadow`, `/etc/group`
  - `/etc/sudoers`
  - `/var/log/auth.log`
  - Program execution (execve)
- [ ] Install and enable Fail2ban `[SCRIPT]`
- [ ] Verify log files exist and are being written to: `[MANUAL]`
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `/var/log/kern.log`
  - `/var/log/dpkg.log`
- [ ] Check auth.log for brute-force attempts: `grep "Failed password" /var/log/auth.log`

---

## Phase 12 — AppArmor / Mandatory Access Control

- [ ] Ensure AppArmor is installed: `sudo apt install apparmor apparmor-utils` `[SCRIPT]`
- [ ] Enable AppArmor: `sudo systemctl enable --now apparmor`
- [ ] Check status: `sudo aa-status` `[MANUAL]`
- [ ] Set profiles to enforce mode: `sudo aa-enforce /etc/apparmor.d/*`

---

## Phase 13 — Application-Specific Hardening

### 13.1 Apache (if required by README)
- [ ] Verify it's running: `sudo systemctl status apache2`
- [ ] Disable directory listing: add `Options -Indexes` to config
- [ ] Disable server signature: `ServerSignature Off` and `ServerTokens Prod` in `/etc/apache2/conf-available/security.conf`
- [ ] Disable unnecessary modules: `sudo a2dismod status autoindex`
- [ ] Enable security headers in config:
  ```
  Header set X-Content-Type-Options "nosniff"
  Header set X-Frame-Options "SAMEORIGIN"
  Header set X-XSS-Protection "1; mode=block"
  ```
- [ ] Ensure Apache runs as `www-data` (not root)
- [ ] Check `.htaccess` files for suspicious rewrites
- [ ] Remove default pages: `sudo rm /var/www/html/index.html`

### 13.2 MySQL / MariaDB (if required by README)
- [ ] Run secure installation: `sudo mysql_secure_installation`
  - Set root password
  - Remove anonymous users
  - Disallow remote root login
  - Remove test database
  - Reload privilege tables
- [ ] Check for users with no password: `SELECT user, host FROM mysql.user WHERE authentication_string='';`
- [ ] Verify bind-address: `bind-address = 127.0.0.1` in `/etc/mysql/mysql.conf.d/mysqld.cnf`
- [ ] Disable `LOCAL INFILE`: `local-infile = 0`

### 13.3 PHP (if installed)
- [ ] Edit `/etc/php/*/apache2/php.ini` (or cli/fpm):
  - `expose_php = Off`
  - `display_errors = Off`
  - `allow_url_fopen = Off`
  - `allow_url_include = Off`
  - `disable_functions = exec,passthru,shell_exec,system,proc_open,popen`
  - `session.cookie_httponly = 1`
  - `session.cookie_secure = 1`
  - `session.use_strict_mode = 1`

### 13.4 Nginx (if required by README)
- [ ] Disable server tokens: `server_tokens off;`
- [ ] Add security headers (same as Apache list above)
- [ ] Disable autoindex: `autoindex off;`
- [ ] Verify SSL configuration if HTTPS is used

### 13.5 BIND / DNS (if required)
- [ ] Restrict zone transfers: `allow-transfer { none; };`
- [ ] Hide version: `version "not disclosed";`
- [ ] Restrict recursion: `allow-recursion { 127.0.0.1; };`

### 13.6 Postfix / Mail (if required)
- [ ] Restrict relay: `mynetworks = 127.0.0.0/8`
- [ ] Disable VRFY: `disable_vrfy_command = yes`
- [ ] Set banner: `smtpd_banner = $myhostname ESMTP`

---

## Phase 14 — USB & Physical Security

- [ ] Block USB storage module `[SCRIPT]`
- [ ] Disable Ctrl+Alt+Del reboot `[SCRIPT]`
- [ ] Disable core dumps `[SCRIPT]`

---

## Phase 15 — Final Verification

- [ ] Recheck listening ports: `sudo ss -tulnp` `[MANUAL]`
- [ ] Recheck running services: `systemctl list-units --type=service --state=running`
- [ ] Verify required services are still running per README
- [ ] Run Lynis audit: `sudo lynis audit system`
- [ ] Review Lynis suggestions and address high-priority items
- [ ] Check scoring engine — verify points are being awarded
- [ ] **Do NOT reboot unless necessary** (may break running services)
- [ ] Take another VM snapshot

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| List users | `cat /etc/passwd \| awk -F: '$3>=1000'` |
| List groups | `cat /etc/group` |
| Check sudo users | `getent group sudo` |
| List services | `systemctl list-units --type=service` |
| List listening ports | `sudo ss -tulnp` |
| Check firewall | `sudo ufw status verbose` |
| Check processes | `ps aux --sort=-%mem` |
| Find SUID files | `find / -perm /4000 -type f 2>/dev/null` |
| Check cron | `sudo crontab -l && ls /etc/cron.*` |
| Recent file changes | `find / -mtime -1 -type f 2>/dev/null` |
| Check auth log | `tail -100 /var/log/auth.log` |
| Package search | `dpkg -l \| grep <name>` |
| Remove package | `sudo apt purge <name>` |
| Check password policy | `grep -E "^PASS" /etc/login.defs` |
| Check PAM | `cat /etc/pam.d/common-password` |
