#!/usr/bin/env bash
# Linux Mint Security Hardening Script for CyberPatriot
# Tailored for Linux Mint (Cinnamon/MATE/Xfce) which is based on Ubuntu LTS.
# Covers Mint-specific components (MDM, Cinnamon settings, mintUpdate) alongside
# standard Debian/Ubuntu hardening.

set -euo pipefail

trap 'echo "[ERROR] Command \"${BASH_COMMAND}\" failed at line ${LINENO}." >&2' ERR

if [[ ${EUID} -ne 0 ]]; then
  echo "[ERROR] This script must be run as root (use sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# ---------- Logging helpers ----------
log() {
  local level=$1; shift
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

backup_file() {
  local file=$1
  if [[ -f $file ]]; then
    cp "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)"
    log INFO "Backup created for $file"
  fi
}

# ---------- Helper to set sshd_config options ----------
update_sshd_option() {
  local key=$1 value=$2 file=$3
  if grep -Eq "^[#[:space:]]*${key}\\b" "$file"; then
    sed -ri "s|^[#[:space:]]*${key}\\b.*|${key} ${value}|" "$file"
  else
    echo "${key} ${value}" >>"$file"
  fi
}

###############################################################################
# 1. SYSTEM UPDATES
###############################################################################
do_updates() {
  log INFO "Updating package lists and applying all upgrades"
  apt-get update -y
  apt-get upgrade -y
  apt-get dist-upgrade -y
  apt-get autoremove -y
  apt-get autoclean -y
}

###############################################################################
# 2. CONFIGURE AUTOMATIC SECURITY UPDATES
###############################################################################
configure_auto_updates() {
  log INFO "Configuring unattended security upgrades"
  apt-get install -y unattended-upgrades apt-listchanges

  # Determine codename
  local codename
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    codename=${UBUNTU_CODENAME:-${VERSION_CODENAME:-stable}}
  else
    codename="stable"
  fi

  cat <<EOC >/etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Origins-Pattern {
        "o=Ubuntu,a=stable";
        "o=Ubuntu,a=${codename}-updates";
        "o=Ubuntu,a=${codename}-security";
        "o=UbuntuESMApps";
        "o=UbuntuESM";
        "o=LinuxMint,a=stable";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
EOC

  cat <<'EOC' >/etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOC
  systemctl enable unattended-upgrades.service
}

###############################################################################
# 3. FIREWALL (UFW)
###############################################################################
configure_ufw() {
  log INFO "Configuring UFW firewall"
  apt-get install -y ufw
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw enable
  ufw status verbose
}

###############################################################################
# 4. FAIL2BAN
###############################################################################
configure_fail2ban() {
  log INFO "Installing and configuring Fail2ban"
  apt-get install -y fail2ban
  systemctl enable --now fail2ban
  cat <<'EOC' >/etc/fail2ban/jail.local
[DEFAULT]
banaction = ufw
findtime = 10m
maxretry = 5
bantime = 1h

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = systemd
EOC
  systemctl restart fail2ban
}

###############################################################################
# 5. SSH HARDENING
###############################################################################
harden_sshd() {
  local conf=/etc/ssh/sshd_config
  if [[ ! -f $conf ]]; then
    log WARN "OpenSSH server not installed — skipping SSH hardening"
    return
  fi
  log INFO "Hardening SSH daemon"
  backup_file "$conf"
  update_sshd_option "Protocol"                       "2"                                                                       "$conf"
  update_sshd_option "PermitRootLogin"                "no"                                                                      "$conf"
  update_sshd_option "PasswordAuthentication"         "no"                                                                      "$conf"
  update_sshd_option "ChallengeResponseAuthentication" "no"                                                                     "$conf"
  update_sshd_option "UsePAM"                         "yes"                                                                     "$conf"
  update_sshd_option "X11Forwarding"                  "no"                                                                      "$conf"
  update_sshd_option "ClientAliveInterval"            "300"                                                                     "$conf"
  update_sshd_option "ClientAliveCountMax"            "2"                                                                       "$conf"
  update_sshd_option "LoginGraceTime"                 "30"                                                                      "$conf"
  update_sshd_option "MaxAuthTries"                   "3"                                                                       "$conf"
  update_sshd_option "AllowTcpForwarding"             "no"                                                                      "$conf"
  update_sshd_option "PermitEmptyPasswords"           "no"                                                                      "$conf"
  update_sshd_option "KexAlgorithms"                  "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"        "$conf"
  update_sshd_option "Ciphers"                        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" "$conf"
  update_sshd_option "MACs"                           "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"             "$conf"
  sshd -t && systemctl restart ssh
}

###############################################################################
# 6. KERNEL HARDENING (sysctl)
###############################################################################
configure_sysctl() {
  log INFO "Applying kernel hardening via sysctl"
  cat <<'EOC' >/etc/sysctl.d/99-cyberpatriot-hardening.conf
# Network
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 1
net.ipv4.conf.default.secure_redirects = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0

# Kernel
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
EOC
  sysctl --system
}

###############################################################################
# 7. PASSWORD POLICIES
###############################################################################
configure_password_policies() {
  log INFO "Configuring password aging in /etc/login.defs"
  local file=/etc/login.defs
  backup_file "$file"
  sed -ri 's/^PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS   90/' "$file"
  sed -ri 's/^PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS   7/'  "$file"
  sed -ri 's/^PASS_WARN_AGE\s+.*/PASS_WARN_AGE   14/' "$file"

  log INFO "Enforcing password complexity via PAM"
  apt-get install -y libpam-pwquality
  local pam=/etc/pam.d/common-password
  backup_file "$pam"
  if grep -Eq '^password\s+requisite\s+pam_pwquality.so' "$pam"; then
    sed -ri 's/^password\s+requisite\s+pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' "$pam"
  else
    sed -ri 's/^password\s+\[success=1 default=ignore\]\s+pam_unix.so/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root\n&/' "$pam"
  fi

  log INFO "Configuring account lockout via PAM"
  local auth=/etc/pam.d/common-auth
  backup_file "$auth"
  if ! grep -q "pam_tally2.so\|pam_faillock.so" "$auth"; then
    sed -ri '0,/^auth\s/s//auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n&/' "$auth"
    echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" >>"$auth"
  fi
}

###############################################################################
# 8. LOGIN BANNERS
###############################################################################
configure_banners() {
  log INFO "Setting login warning banners"
  cat <<'EOC' >/etc/issue.net
*******************************************************************
* WARNING: Authorized Access Only. Unauthorized use is prohibited *
* and may be subject to criminal and/or civil penalties.          *
*******************************************************************
EOC
  cp /etc/issue.net /etc/issue
}

###############################################################################
# 9. SECURITY TOOLS
###############################################################################
install_security_tools() {
  log INFO "Installing security tools"
  apt-get install -y \
    clamav clamav-daemon \
    rkhunter chkrootkit \
    debsums lynis \
    apparmor apparmor-utils \
    libpam-tmpdir \
    apt-show-versions
  systemctl enable --now clamav-freshclam
  freshclam || true
  rkhunter --update || true
}

###############################################################################
# 10. AUDITD
###############################################################################
configure_auditd() {
  log INFO "Configuring auditd"
  apt-get install -y auditd audispd-plugins
  systemctl enable --now auditd
  cat <<'EOC' >/etc/audit/rules.d/hardening.rules
-D
-b 8192

# Identity files
-w /etc/passwd  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Privilege escalation
-w /etc/sudoers   -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /usr/bin/sudo   -p x  -k sudo_exec

# Authentication logs
-w /var/log/auth.log -p wa -k authlog
-w /var/log/sudo.log -p wa -k sudolog

# SSH config
-w /etc/ssh/sshd_config -p wa -k sshd

# Cron
-w /etc/crontab    -p wa -k cron
-w /etc/cron.d     -p wa -k cron
-w /var/spool/cron -p wa -k cron

# Program execution
-a always,exit -F arch=b64 -S execve -k program-execution
-a always,exit -F arch=b32 -S execve -k program-execution

# Module loading
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
EOC
  augenrules --load
}

###############################################################################
# 11. SHARED MEMORY HARDENING
###############################################################################
harden_shared_memory() {
  log INFO "Hardening shared memory"
  if ! grep -q '/run/shm' /etc/fstab; then
    echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' >>/etc/fstab
  else
    sed -ri 's#^(tmpfs\s+/run/shm\s+tmpfs\s+).*#\1defaults,noexec,nosuid 0 0#' /etc/fstab
  fi
  mount -o remount,noexec,nosuid /run/shm || true
}

###############################################################################
# 12. DISABLE UNCOMMON FILESYSTEMS
###############################################################################
disable_uncommon_filesystems() {
  log INFO "Disabling uncommon filesystem modules"
  cat <<'EOC' >/etc/modprobe.d/blacklist-uncommon-filesystems.conf
install cramfs   /bin/true
install freevxfs /bin/true
install jffs2    /bin/true
install hfs      /bin/true
install hfsplus  /bin/true
install udf      /bin/true
install squashfs /bin/true
EOC
}

###############################################################################
# 13. RESTRICT CRON / AT
###############################################################################
secure_cron_at() {
  log INFO "Restricting cron and at access"
  touch /etc/cron.allow /etc/at.allow
  chmod 640 /etc/cron.allow /etc/at.allow
  chown root:root /etc/cron.allow /etc/at.allow
  rm -f /etc/cron.deny /etc/at.deny
}

###############################################################################
# 14. REMOVE INSECURE / LEGACY SERVICES
###############################################################################
purge_insecure_services() {
  log INFO "Removing insecure/legacy network services"
  apt-get purge -y \
    telnetd xinetd rsh-server rlogin-server talk-server talkd \
    vsftpd pure-ftpd proftpd-basic \
    nis rsh-client rlogin 2>/dev/null || true
}

###############################################################################
# 15. DISABLE UNNECESSARY SERVICES
###############################################################################
disable_unnecessary_services() {
  log INFO "Disabling unnecessary network/desktop services"
  local services=(
    cups avahi-daemon smbd nmbd
    snmpd rpcbind nfs-server
    bluetooth
  )
  for svc in "${services[@]}"; do
    systemctl disable --now "$svc" 2>/dev/null || log WARN "Could not disable $svc (may not be installed)"
  done
}

###############################################################################
# 16. LINUX MINT SPECIFIC HARDENING
###############################################################################
mint_specific_hardening() {
  log INFO "Applying Linux Mint-specific hardening"

  # Disable Mint Welcome screen autostart for all users
  local welcome=/etc/xdg/autostart/mintWelcome.desktop
  if [[ -f $welcome ]]; then
    echo "Hidden=true" >>"$welcome"
    log INFO "Disabled Mint Welcome autostart"
  fi

  # Ensure mintUpdate checks for security updates automatically
  # (User-level dconf; set defaults for all users)
  mkdir -p /etc/dconf/db/local.d
  cat <<'EOC' >/etc/dconf/db/local.d/00-mint-security
[com/linuxmint/updates]
autorefresh-hours=2
dist-upgrade=true
EOC
  dconf update 2>/dev/null || true

  # LightDM hardening (Mint's default display manager)
  local lightdm=/etc/lightdm/lightdm.conf
  if [[ -d /etc/lightdm ]]; then
    log INFO "Hardening LightDM"
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat <<'EOC' >/etc/lightdm/lightdm.conf.d/99-security.conf
[Seat:*]
allow-guest=false
greeter-hide-users=true
greeter-show-manual-login=true
EOC
  fi

  # Disable autologin if configured
  if [[ -f $lightdm ]] && grep -qi "autologin" "$lightdm"; then
    log INFO "Disabling autologin in LightDM"
    backup_file "$lightdm"
    sed -ri 's/^autologin-user=.*/#autologin-user=/' "$lightdm"
  fi

  # Check for GDM/MDM autologin too
  for dm_conf in /etc/gdm3/custom.conf /etc/mdm/mdm.conf; do
    if [[ -f $dm_conf ]] && grep -qi "AutomaticLogin\|autologin" "$dm_conf"; then
      log INFO "Disabling autologin in $dm_conf"
      backup_file "$dm_conf"
      sed -ri 's/^(AutomaticLoginEnable|TimedLoginEnable)\s*=.*/\1=false/' "$dm_conf"
      sed -ri 's/^autologin-user=.*/#autologin-user=/' "$dm_conf"
    fi
  done

  # Disable Mint's built-in file sharing (Nemo)
  log INFO "Disabling Nemo file sharing for all users"
  mkdir -p /etc/dconf/db/local.d
  cat <<'EOC' >>/etc/dconf/db/local.d/00-mint-security
[org/nemo/preferences]
show-computer-icon-toolbar=false
EOC
  dconf update 2>/dev/null || true

  # Ensure screensaver locks
  cat <<'EOC' >/etc/dconf/db/local.d/01-screensaver-lock
[org/cinnamon/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/mate/screensaver]
lock-enabled=true
idle-activation-enabled=true

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
EOC
  dconf update 2>/dev/null || true
}

###############################################################################
# 17. USER / GROUP AUDITING
###############################################################################
audit_users_and_groups() {
  log INFO "Auditing users and groups"

  # Check for unauthorized UID 0 accounts
  log INFO "Checking for extra UID 0 accounts"
  awk -F: '$3 == 0 && $1 != "root" {print "WARNING: Extra UID 0 account:", $1}' /etc/passwd

  # Check for users with empty passwords
  log INFO "Checking for users with empty passwords"
  awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print "WARNING: Empty/no password for:", $1}' /etc/shadow 2>/dev/null || true

  # List human users (UID >= 1000)
  log INFO "Human user accounts on this system:"
  awk -F: '$3 >= 1000 && $3 < 65534 {print "  UID=" $3, "USER=" $1, "HOME=" $6, "SHELL=" $7}' /etc/passwd

  # Review sudoers for NOPASSWD
  log INFO "Reviewing sudoers for NOPASSWD entries"
  grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || log INFO "No NOPASSWD entries detected"

  # Check for users in sudo/admin groups
  log INFO "Users in sudo/admin groups:"
  getent group sudo 2>/dev/null || true
  getent group adm  2>/dev/null || true
}

###############################################################################
# 18. FILE PERMISSIONS
###############################################################################
enforce_file_permissions() {
  log INFO "Enforcing critical file permissions"
  chmod 644 /etc/passwd
  chmod 640 /etc/shadow
  chmod 644 /etc/group
  chmod 640 /etc/gshadow
  chmod 600 /etc/ssh/ssh_host_*key 2>/dev/null || true
  chmod 644 /etc/ssh/ssh_host_*key.pub 2>/dev/null || true
  chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow

  log INFO "Removing world-writable files under /etc"
  find /etc -perm -002 -type f -exec chmod o-w {} \; || true
}

###############################################################################
# 19. USB STORAGE BLOCK
###############################################################################
block_usb_storage() {
  log INFO "Blocking USB storage module"
  echo "blacklist usb-storage" >/etc/modprobe.d/disable-usb-storage.conf
  echo "install usb-storage /bin/true" >>/etc/modprobe.d/disable-usb-storage.conf
  update-initramfs -u 2>/dev/null || true
}

###############################################################################
# 20. MISC HARDENING
###############################################################################
misc_hardening() {
  log INFO "Applying miscellaneous hardening"

  # Disable Ctrl+Alt+Del reboot
  systemctl mask ctrl-alt-del.target 2>/dev/null || true

  # Restrict core dumps
  cat <<'EOC' >/etc/security/limits.d/99-no-core-dumps.conf
* hard core 0
EOC
  echo "fs.suid_dumpable = 0" >/etc/sysctl.d/99-no-core-dump.conf
  sysctl -w fs.suid_dumpable=0

  # Secure /tmp if not already a separate mount
  if ! mountpoint -q /tmp; then
    log WARN "/tmp is not a separate partition — consider mounting tmpfs"
  fi

  # Reset hosts file
  log INFO "Resetting /etc/hosts to safe defaults"
  {
    echo "127.0.0.1 localhost"
    echo "::1       localhost"
  } >/etc/hosts
}

###############################################################################
# 21. SCAN FOR PROHIBITED / HACKING TOOLS
###############################################################################
scan_prohibited_software() {
  log INFO "Scanning for potentially prohibited software"
  local suspect_packages=(
    netcat ncat nc john john-data hydra hydra-gtk
    aircrack-ng ophcrack ophcrack-cli
    metasploit-framework nikto
    nmap zenmap
    wireshark wireshark-qt tshark
    tcpdump ettercap-text-only ettercap-graphical
    kismet maltego recon-ng hashcat
    sqlmap beef-xss setoolkit
    minetest supertuxkart 0ad freeciv
    aisleriot gnome-mines gnome-sudoku
    steam lutris
  )
  for pkg in "${suspect_packages[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
      log WARN "FOUND prohibited/suspicious package: $pkg"
    fi
  done
}

###############################################################################
# 22. INSPECT CRON JOBS
###############################################################################
audit_cron_jobs() {
  log INFO "Auditing cron jobs for all users"
  for user in $(cut -f1 -d: /etc/passwd); do
    local crontab
    crontab=$(crontab -l -u "$user" 2>/dev/null) || continue
    if [[ -n $crontab ]]; then
      log INFO "Cron jobs for $user:"
      echo "$crontab"
    fi
  done

  log INFO "System cron directories:"
  for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d $d ]]; then
      ls -la "$d" 2>/dev/null
    fi
  done
}

###############################################################################
# 23. CHECK FOR UNAUTHORIZED SUID/SGID BINARIES
###############################################################################
audit_suid_sgid() {
  log INFO "Searching for SUID/SGID binaries (review list for anomalies)"
  find / -perm /4000 -type f 2>/dev/null | sort > /tmp/suid_files.txt
  find / -perm /2000 -type f 2>/dev/null | sort > /tmp/sgid_files.txt
  log INFO "SUID files saved to /tmp/suid_files.txt ($(wc -l < /tmp/suid_files.txt) found)"
  log INFO "SGID files saved to /tmp/sgid_files.txt ($(wc -l < /tmp/sgid_files.txt) found)"
}

###############################################################################
# 24. CHECK LISTENING PORTS
###############################################################################
audit_listening_ports() {
  log INFO "Listing all listening network ports"
  ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || true
}

###############################################################################
# MAIN
###############################################################################
main() {
  log INFO "====== Linux Mint Security Hardening — Starting ======"
  do_updates
  configure_auto_updates
  configure_ufw
  configure_fail2ban
  configure_sysctl
  configure_password_policies
  configure_banners
  harden_sshd
  configure_auditd
  harden_shared_memory
  disable_uncommon_filesystems
  secure_cron_at
  purge_insecure_services
  disable_unnecessary_services
  mint_specific_hardening
  audit_users_and_groups
  enforce_file_permissions
  block_usb_storage
  misc_hardening
  scan_prohibited_software
  audit_cron_jobs
  audit_suid_sgid
  audit_listening_ports
  install_security_tools
  log INFO "====== Linux Mint Security Hardening — Complete ======"
  log INFO "Review the output above for any WARNINGs that need manual attention."
  log INFO "Run 'sudo lynis audit system' for an additional security audit."
}

main "$@"
