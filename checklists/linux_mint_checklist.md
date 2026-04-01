# Linux Mint CyberPatriot Competition Checklist

> **Usage**: Work through each section in order. Items marked `[SCRIPT]` are handled by `secure_linux_mint.sh`. Items marked `[MANUAL]` require human judgment. Linux Mint is based on Ubuntu LTS, so most Ubuntu techniques apply — this checklist adds Mint-specific items.

---

## Phase 0 — Read the README / Scenario

- [ ] **Read the competition README completely** before touching anything `[MANUAL]`
- [ ] Note which users are authorized and which should be removed
- [ ] Note which services must remain running
- [ ] Note any required software or configurations
- [ ] Identify forensic questions
- [ ] **Take a VM snapshot / checkpoint**

---

## Phase 1 — Forensic Questions

- [ ] Read each forensic question carefully `[MANUAL]`
- [ ] Check common locations:
  - `/home/*/Desktop/`, `/home/*/Documents/`, `/tmp/`
  - Nemo recent files: `~/.local/share/recently-used.xbel`
  - Firefox history: `~/.mozilla/firefox/*.default/places.sqlite`
  - Bash history: `~/.bash_history`
  - System logs: `/var/log/auth.log`, `/var/log/syslog`
  - Mint-specific logs: `/var/log/mintUpdate.log`
  - Recently modified files: `find / -mtime -7 -type f 2>/dev/null`
- [ ] Submit forensic answers as you find them

---

## Phase 2 — User & Group Management

### 2.1 Unauthorized Users
- [ ] List all human users: `awk -F: '$3 >= 1000 && $3 < 65534' /etc/passwd` `[MANUAL]`
- [ ] Compare against the README's authorized user list
- [ ] Remove unauthorized users: `sudo userdel -r <username>`
- [ ] Check for UID 0 accounts (only root): `awk -F: '$3 == 0' /etc/passwd` `[SCRIPT]`
- [ ] Check for empty passwords: `sudo awk -F: '($2 == "")' /etc/shadow` `[SCRIPT]`

### 2.2 Missing / Required Users
- [ ] Create required users: `sudo useradd -m -s /bin/bash <username>`
- [ ] Set strong passwords: `sudo passwd <username>`

### 2.3 Group Membership
- [ ] Check sudo group: `getent group sudo` `[SCRIPT]`
- [ ] Check adm group: `getent group adm`
- [ ] Remove unauthorized sudoers: `sudo deluser <username> sudo`
- [ ] Add authorized admins: `sudo usermod -aG sudo <username>`
- [ ] Check other sensitive groups: `shadow`, `disk`, `plugdev`, `lpadmin`

### 2.4 Root Account
- [ ] Ensure root has a strong password
- [ ] Disable root SSH login `[SCRIPT]`
- [ ] Lock root if not needed: `sudo passwd -l root`

---

## Phase 3 — Password & Authentication Policies

### 3.1 Password Aging (/etc/login.defs)
- [ ] `PASS_MAX_DAYS 90` `[SCRIPT]`
- [ ] `PASS_MIN_DAYS 7` `[SCRIPT]`
- [ ] `PASS_WARN_AGE 14` `[SCRIPT]`
- [ ] Apply to existing users: `sudo chage -M 90 -m 7 -W 14 <username>` for each `[MANUAL]`
- [ ] Verify: `sudo chage -l <username>`

### 3.2 Password Complexity (PAM)
- [ ] libpam-pwquality installed `[SCRIPT]`
- [ ] `/etc/pam.d/common-password` has complexity rules `[SCRIPT]`
  ```
  password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root
  ```
- [ ] Password history: add `remember=5` to `pam_unix.so` line `[MANUAL]`

### 3.3 Account Lockout
- [ ] Configure pam_faillock in `/etc/pam.d/common-auth` `[SCRIPT]`
  ```
  auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
  ```

### 3.4 Login Banners
- [ ] `/etc/issue` and `/etc/issue.net` have warning banners `[SCRIPT]`

---

## Phase 4 — Linux Mint-Specific Items

### 4.1 Display Manager (LightDM)
- [ ] **Disable guest sessions**: `allow-guest=false` `[SCRIPT]`
- [ ] **Hide user list**: `greeter-hide-users=true` `[SCRIPT]`
- [ ] **Require manual login**: `greeter-show-manual-login=true` `[SCRIPT]`
- [ ] **Disable autologin** `[SCRIPT]`
- [ ] Verify: `cat /etc/lightdm/lightdm.conf.d/99-security.conf`

### 4.2 Screensaver / Screen Lock
- [ ] **Enable screen lock** `[SCRIPT]`
- [ ] **Set lock delay to 0** (lock immediately) `[SCRIPT]`
- [ ] Set idle timeout (5-10 minutes) via Cinnamon/MATE/Xfce settings `[MANUAL]`
- [ ] For Cinnamon: System Settings > Screensaver > Lock the computer when put to sleep
- [ ] For MATE: System > Preferences > Screensaver > Lock screen
- [ ] For Xfce: Settings > Screensaver + Power Manager

### 4.3 Mint Update Manager
- [ ] Open Update Manager and install all updates `[MANUAL]`
- [ ] Configure automatic security updates `[SCRIPT]`
- [ ] Switch to "Always display and install all available updates" policy

### 4.4 Firewall GUI (Gufw)
- [ ] Install GUI: `sudo apt install gufw` `[MANUAL]`
- [ ] Verify UFW is enabled (should be after running script)
- [ ] Add any required service rules via Gufw or CLI

### 4.5 Software Sources
- [ ] Open Software Sources and verify repositories `[MANUAL]`
- [ ] Ensure official Mint and Ubuntu repos are enabled
- [ ] Remove any unauthorized PPAs
- [ ] Check `/etc/apt/sources.list` and `/etc/apt/sources.list.d/` for suspicious entries

### 4.6 Timeshift (System Snapshots)
- [ ] If Timeshift is installed, review existing snapshots `[MANUAL]`
- [ ] Check that Timeshift isn't configured to expose sensitive data

---

## Phase 5 — SSH Hardening

- [ ] If SSH is needed, verify it's installed: `dpkg -l openssh-server` `[MANUAL]`
- [ ] **PermitRootLogin no** `[SCRIPT]`
- [ ] **PasswordAuthentication no** (or yes if README requires) `[SCRIPT]`
- [ ] **PermitEmptyPasswords no** `[SCRIPT]`
- [ ] **X11Forwarding no** `[SCRIPT]`
- [ ] **MaxAuthTries 3** `[SCRIPT]`
- [ ] **ClientAliveInterval 300** `[SCRIPT]`
- [ ] Modern ciphers configured `[SCRIPT]`
- [ ] Restart SSH: `sudo systemctl restart ssh`
- [ ] **Test SSH in a separate terminal before closing current session**
- [ ] If SSH is NOT needed: `sudo systemctl disable --now ssh`

---

## Phase 6 — Firewall

- [ ] UFW installed and enabled `[SCRIPT]`
- [ ] Default deny incoming `[SCRIPT]`
- [ ] Default allow outgoing `[SCRIPT]`
- [ ] Allow required services per README `[MANUAL]`
  ```bash
  sudo ufw allow ssh        # if needed
  sudo ufw allow 80/tcp     # if web server
  sudo ufw allow 443/tcp    # if HTTPS
  ```
- [ ] Verify: `sudo ufw status verbose`
- [ ] **Do NOT block services required by README**

---

## Phase 7 — System Updates & Package Management

### 7.1 Updates
- [ ] `sudo apt update && sudo apt upgrade -y` `[SCRIPT]`
- [ ] `sudo apt dist-upgrade -y` `[SCRIPT]`
- [ ] `sudo apt autoremove -y` `[SCRIPT]`
- [ ] Automatic security updates configured `[SCRIPT]`

### 7.2 Prohibited Software
- [ ] Hacking tools: `[SCRIPT scans, MANUAL removal]`
  ```bash
  dpkg -l | grep -Ei "nmap|wireshark|john|hydra|aircrack|ophcrack|metasploit|nikto|netcat|hashcat|sqlmap|ettercap|kismet"
  ```
- [ ] Games:
  ```bash
  dpkg -l | grep -Ei "game|minetest|supertux|freeciv|0ad|aisleriot|gnome-mines|steam|lutris"
  ```
- [ ] P2P / Torrents:
  ```bash
  dpkg -l | grep -Ei "torrent|transmission|deluge|vuze|qbittorrent"
  ```
- [ ] Remote access tools:
  ```bash
  dpkg -l | grep -Ei "teamviewer|anydesk|vnc|tightvnc|x11vnc"
  ```
- [ ] Mint may include some games by default — check and remove if not in README
- [ ] Remove prohibited software: `sudo apt purge -y <package>`

### 7.3 Required Software
- [ ] Install any software required by README
- [ ] Verify required services still work after changes

---

## Phase 8 — Service Management

### 8.1 Identify Running Services
- [ ] `systemctl list-units --type=service --state=running` `[MANUAL]`
- [ ] `systemctl list-unit-files --type=service --state=enabled`
- [ ] `sudo ss -tulnp`
- [ ] Cross-reference with README

### 8.2 Common Services to Disable
- [ ] **CUPS** (printing): disable unless needed `[SCRIPT]`
- [ ] **Avahi** (mDNS): `[SCRIPT]`
- [ ] **Samba**: `[SCRIPT]`
- [ ] **Bluetooth**: `[SCRIPT]`
- [ ] **SNMP**: `[SCRIPT]`
- [ ] **NFS / rpcbind**: `[SCRIPT]`
- [ ] **FTP**: `[SCRIPT]`
- [ ] **Telnet**: `[SCRIPT]`
- [ ] **xinetd**: `[SCRIPT]`

### 8.3 Mint-Specific Services
- [ ] **mintUpdate service**: Keep running (handles updates) `[MANUAL]`
- [ ] **cinnamon-screensaver**: Keep running (screen lock)
- [ ] **nemo-desktop**: OK to keep (desktop icons)

### 8.4 Application Hardening (if required)
- [ ] **Apache**: See Ubuntu checklist Phase 13 for details
- [ ] **MySQL/MariaDB**: Run `mysql_secure_installation`
- [ ] **PHP**: Harden php.ini settings
- [ ] **Nginx**: Disable server tokens, add security headers

---

## Phase 9 — Kernel & Filesystem Hardening

### 9.1 Sysctl
- [ ] Verify sysctl hardening applied `[SCRIPT]`
  - ICMP redirect blocking
  - Source routing disabled
  - TCP syncookies enabled
  - ASLR enabled (randomize_va_space=2)
  - Kernel pointer restriction
  - Core dump disabled
- [ ] Apply: `sudo sysctl --system`

### 9.2 Filesystem
- [ ] Uncommon filesystems blacklisted (cramfs, hfs, etc.) `[SCRIPT]`
- [ ] Shared memory hardened (noexec, nosuid) `[SCRIPT]`

### 9.3 File Permissions
- [ ] `/etc/passwd` — 644 `[SCRIPT]`
- [ ] `/etc/shadow` — 640 `[SCRIPT]`
- [ ] `/etc/group` — 644 `[SCRIPT]`
- [ ] `/etc/gshadow` — 640 `[SCRIPT]`
- [ ] SSH keys — 600 `[SCRIPT]`
- [ ] World-writable files removed from /etc `[SCRIPT]`

### 9.4 SUID/SGID Audit
- [ ] Find SUID: `find / -perm /4000 -type f 2>/dev/null` `[SCRIPT saves list]`
- [ ] Find SGID: `find / -perm /2000 -type f 2>/dev/null`
- [ ] Review for suspicious entries
- [ ] Remove SUID from unnecessary binaries: `sudo chmod u-s <file>`

---

## Phase 10 — Cron Job Audit

- [ ] Check root crontab: `sudo crontab -l` `[SCRIPT]`
- [ ] Check each user's crontab: `sudo crontab -l -u <username>`
- [ ] Review system cron directories `[SCRIPT]`
  - `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.daily/`, etc.
- [ ] Look for: reverse shells, wget/curl downloads, base64 commands
- [ ] Cron/at restricted to authorized users only `[SCRIPT]`

---

## Phase 11 — Backdoor & Malware Hunting

### 11.1 Suspicious Processes
- [ ] `ps aux` — look for unusual processes `[MANUAL]`
- [ ] `ps aux | grep -E "nc |ncat|netcat|bash -i|/dev/tcp"`
- [ ] Check for crypto miners or unusual high-CPU processes

### 11.2 Network Connections
- [ ] `ss -tupn` — check for unexpected connections `[SCRIPT audits ports]`
- [ ] `ss -tulnp` — check listeners
- [ ] Check `/etc/hosts` for redirects `[SCRIPT resets it]`

### 11.3 Suspicious Files
- [ ] Check `/tmp`, `/var/tmp`, `/dev/shm` `[MANUAL]`
- [ ] Find recent files: `find / -mtime -3 -type f 2>/dev/null | head -50`
- [ ] Find hidden files: `find /home -name ".*" -type f`
- [ ] Check authorized_keys: `find /home -name "authorized_keys" -exec cat {} \;`
- [ ] Check `.bashrc`, `.profile` in each home dir for malicious commands

### 11.4 Rootkit / Malware Scans
- [ ] `sudo rkhunter --check --skip-keypress` `[MANUAL]`
- [ ] `sudo chkrootkit`
- [ ] `sudo clamscan -r --bell -i /home /tmp /var`

### 11.5 Startup Persistence
- [ ] `systemctl list-unit-files --state=enabled` `[MANUAL]`
- [ ] Check `/etc/rc.local`
- [ ] Check `/etc/init.d/` for unauthorized scripts
- [ ] Check `/etc/xdg/autostart/` — Mint uses this heavily
- [ ] Check `~/.config/autostart/` for each user
- [ ] Look for Cinnamon/MATE startup applications:
  - Cinnamon: `~/.config/autostart/`
  - MATE: `~/.config/autostart/`

---

## Phase 12 — Audit & Logging

- [ ] auditd installed and running `[SCRIPT]`
- [ ] Audit rules monitoring critical files `[SCRIPT]`
- [ ] Fail2ban installed and running `[SCRIPT]`
- [ ] Log files exist and are being written: `[MANUAL]`
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `/var/log/kern.log`
  - `/var/log/dpkg.log`
- [ ] Check for brute-force: `grep "Failed password" /var/log/auth.log`

---

## Phase 13 — AppArmor

- [ ] AppArmor installed and enabled `[SCRIPT]`
- [ ] `sudo aa-status` — check profiles `[MANUAL]`
- [ ] Set profiles to enforce: `sudo aa-enforce /etc/apparmor.d/*`

---

## Phase 14 — USB & Physical Security

- [ ] USB storage blocked `[SCRIPT]`
- [ ] Ctrl+Alt+Del disabled `[SCRIPT]`
- [ ] Core dumps disabled `[SCRIPT]`

---

## Phase 15 — Final Verification

- [ ] Re-check listening ports: `sudo ss -tulnp` `[MANUAL]`
- [ ] Re-check running services match README requirements
- [ ] Verify required services are still running
- [ ] Run Lynis: `sudo lynis audit system`
- [ ] Check scoring engine for points
- [ ] **Do NOT reboot unless necessary**
- [ ] Take another VM snapshot

---

## Linux Mint vs Ubuntu — Key Differences

| Area | Ubuntu | Linux Mint |
|------|--------|------------|
| Display Manager | GDM3 | LightDM |
| Desktop | GNOME | Cinnamon/MATE/Xfce |
| File Manager | Nautilus | Nemo |
| Update Manager | GNOME Software | mintUpdate |
| Autostart | `/etc/xdg/autostart/` + GNOME | `/etc/xdg/autostart/` + Cinnamon |
| Firewall GUI | N/A (CLI) | Gufw available |
| Default Games | Minimal | May include more |
| System Snapshots | N/A | Timeshift |

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| List users | `awk -F: '$3>=1000 && $3<65534' /etc/passwd` |
| Check sudo users | `getent group sudo` |
| List services | `systemctl list-units --type=service` |
| Listening ports | `sudo ss -tulnp` |
| Firewall status | `sudo ufw status verbose` |
| Running processes | `ps aux --sort=-%mem` |
| Find SUID files | `find / -perm /4000 -type f 2>/dev/null` |
| Check cron | `sudo crontab -l && ls /etc/cron.*` |
| Recent changes | `find / -mtime -1 -type f 2>/dev/null` |
| Auth log | `tail -100 /var/log/auth.log` |
| Package search | `dpkg -l \| grep <name>` |
| Remove package | `sudo apt purge <name>` |
| Password policy | `grep -E "^PASS" /etc/login.defs` |
| PAM config | `cat /etc/pam.d/common-password` |
| Mint version | `cat /etc/linuxmint/info` |
| LightDM config | `cat /etc/lightdm/lightdm.conf` |
| Desktop env | `echo $XDG_CURRENT_DESKTOP` |
| Autostart apps | `ls /etc/xdg/autostart/ ~/.config/autostart/` |
