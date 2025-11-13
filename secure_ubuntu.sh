#!/usr/bin/env bash
# Ubuntu Security Hardening Script for CyberPatriot-style environments
# This script performs a comprehensive set of hardening actions tailored for Ubuntu Server/Desktop systems.
# It is intended to be run on freshly installed systems and may need adjustments for production environments.

set -euo pipefail

trap 'echo "[ERROR] Command \"${BASH_COMMAND}\" failed at line ${LINENO}." >&2' ERR

if [[ ${EUID} -ne 0 ]]; then
  echo "[ERROR] This script must be run as root." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  distro_codename=${VERSION_CODENAME:-${UBUNTU_CODENAME:-stable}}
else
  distro_codename="stable"
fi

log() {
  local level=$1
  shift
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$*"
}

require_command() {
  local cmd=$1
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log INFO "Installing missing dependency: $cmd"
    apt-get update -y
    apt-get install -y "$cmd"
  fi
}

update_and_upgrade() {
  log INFO "Updating package lists and applying upgrades"
  apt-get update -y
  apt-get upgrade -y
  apt-get dist-upgrade -y
  apt-get autoremove -y
  apt-get autoclean -y
}

configure_unattended_upgrades() {
  log INFO "Configuring unattended security upgrades"
  apt-get install -y unattended-upgrades apt-listchanges
  cat <<EOC >/etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Origins-Pattern {
        "o=Ubuntu,a=stable";
        "o=Ubuntu,a=${distro_codename}-updates";
        "o=Ubuntu,a=${distro_codename}-security";
        "o=UbuntuESMApps";
        "o=UbuntuESM";
};
Unattended-Upgrade::Package-Blacklist {
};
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

configure_ufw() {
  log INFO "Configuring uncomplicated firewall (UFW)"
  apt-get install -y ufw
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow OpenSSH
  ufw enable
  ufw status verbose
}

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

backup_file() {
  local file=$1
  if [[ -f $file ]]; then
    local backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$file" "$backup"
    log INFO "Backup created: $backup"
  fi
}

update_sshd_config_option() {
  local key=$1
  local value=$2
  local file=$3
  if grep -Eq "^[#[:space:]]*${key}\\b" "$file"; then
    sed -ri "s|^[#[:space:]]*${key}\\b.*|${key} ${value}|" "$file"
  else
    echo "${key} ${value}" >>"$file"
  fi
}

harden_sshd() {
  local sshd_config=/etc/ssh/sshd_config
  log INFO "Hardening SSH daemon configuration"
  backup_file "$sshd_config"
  update_sshd_config_option "Protocol" "2" "$sshd_config"
  update_sshd_config_option "PermitRootLogin" "no" "$sshd_config"
  update_sshd_config_option "PasswordAuthentication" "no" "$sshd_config"
  update_sshd_config_option "ChallengeResponseAuthentication" "no" "$sshd_config"
  update_sshd_config_option "UsePAM" "yes" "$sshd_config"
  update_sshd_config_option "X11Forwarding" "no" "$sshd_config"
  update_sshd_config_option "ClientAliveInterval" "300" "$sshd_config"
  update_sshd_config_option "ClientAliveCountMax" "2" "$sshd_config"
  update_sshd_config_option "LoginGraceTime" "30" "$sshd_config"
  update_sshd_config_option "MaxAuthTries" "3" "$sshd_config"
  update_sshd_config_option "AllowTcpForwarding" "no" "$sshd_config"
  update_sshd_config_option "PrintMotd" "no" "$sshd_config"
  update_sshd_config_option "KexAlgorithms" "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" "$sshd_config"
  update_sshd_config_option "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" "$sshd_config"
  update_sshd_config_option "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" "$sshd_config"
  sshd -t
  systemctl restart ssh
}

configure_sysctl() {
  log INFO "Applying kernel hardening settings"
  cat <<'EOC' >/etc/sysctl.d/99-cyberpatriot-hardening.conf
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
net.ipv6.conf.all.disable_ipv6 = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
kernel.yama.ptrace_scope = 1
EOC
  sysctl --system
}

configure_login_defs() {
  log INFO "Hardening password policies"
  local file=/etc/login.defs
  backup_file "$file"
  sed -ri 's/^PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS   90/' "$file"
  sed -ri 's/^PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS   7/' "$file"
  sed -ri 's/^PASS_WARN_AGE\s+.*/PASS_WARN_AGE   14/' "$file"
}

configure_pam_pwquality() {
  log INFO "Enforcing password complexity via PAM"
  apt-get install -y libpam-pwquality
  local file=/etc/pam.d/common-password
  backup_file "$file"
  if grep -Eq '^password\s+requisite\s+pam_pwquality.so' "$file"; then
    sed -ri 's/^password\s+requisite\s+pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' "$file"
  else
    sed -ri 's/^password\s+\[success=1 default=ignore\]\s+pam_unix.so/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n&/' "$file"
  fi
}

configure_banners() {
  log INFO "Setting login banners"
  cat <<'EOC' >/etc/issue.net
*******************************************************************
* WARNING: Authorized Access Only. Unauthorized use is prohibited *
* and may be subject to criminal and/or civil penalties.          *
*******************************************************************
EOC
  cp /etc/issue.net /etc/issue
}

install_security_tools() {
  log INFO "Installing baseline security tools"
  apt-get install -y clamav clamav-daemon rkhunter chkrootkit debsums lynis apparmor apparmor-utils
  systemctl enable --now clamav-freshclam
  freshclam || true
  rkhunter --update || true
}

configure_auditd() {
  log INFO "Configuring auditd rules"
  apt-get install -y auditd audispd-plugins
  systemctl enable --now auditd
  cat <<'EOC' >/etc/audit/rules.d/hardening.rules
-D
-b 8192
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /var/log/auth.log -p wa -k authlog
-w /var/log/sudo.log -p wa -k sudolog
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S execve -k program-execution
-a always,exit -F arch=b32 -S execve -k program-execution
EOC
  augenrules --load
}

harden_shared_memory() {
  log INFO "Hardening shared memory"
  if ! grep -q '/run/shm' /etc/fstab; then
    echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0' >>/etc/fstab
  else
    sed -ri 's#^(tmpfs\s+/run/shm\s+tmpfs\s+).*#\1defaults,noexec,nosuid 0 0#' /etc/fstab
  fi
  mount -o remount,noexec,nosuid /run/shm || true
}

disable_unnecessary_filesystems() {
  log INFO "Disabling uncommon filesystem modules"
  cat <<'EOC' >/etc/modprobe.d/blacklist-uncommon-filesystems.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOC
}

secure_cron_and_at() {
  log INFO "Restricting cron and at access"
  touch /etc/cron.allow /etc/at.allow
  chmod 640 /etc/cron.allow /etc/at.allow
  chown root:root /etc/cron.allow /etc/at.allow
  rm -f /etc/cron.deny /etc/at.deny
}

purge_insecure_services() {
  log INFO "Removing insecure or unused network services"
  apt-get purge -y telnetd xinetd rsh-server rlogin-server talk-server vsftpd || true
}

apply_additional_hardening() {
  log INFO "Applying additional Linux Mint 22 hardening measures"

  log INFO "Disabling unnecessary network services"
  systemctl disable --now cups || log WARN "cups service could not be disabled"
  systemctl disable --now avahi-daemon || log WARN "avahi-daemon service could not be disabled"
  systemctl disable --now smbd nmbd 2>/dev/null || log WARN "Samba services could not be disabled or were not present"

  log INFO "Blocking USB storage modules"
  echo "blacklist usb-storage" >/etc/modprobe.d/disable-usb-storage.conf
  update-initramfs -u

  log INFO "Checking for unauthorized privileged accounts"
  awk -F: '$3 == 0 && $1 != "root" {print "WARNING: Extra UID 0:", $1}' /etc/passwd

  log INFO "Reviewing sudoers for NOPASSWD entries"
  grep -R "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || log INFO "No NOPASSWD entries detected"

  log INFO "Enforcing critical file permissions"
  chmod 640 /etc/shadow
  chmod 644 /etc/passwd
  chmod 600 /etc/ssh/ssh_host_*key 2>/dev/null || true

  log INFO "Disabling Ctrl+Alt+Del reboot sequence"
  systemctl mask ctrl-alt-del.target || log WARN "Failed to mask ctrl-alt-del.target"

  log INFO "Augmenting auditd rules"
  {
    echo "-w /etc/passwd -p wa -k passwd_changes"
    echo "-w /etc/shadow -p wa -k shadow_changes"
    echo "-w /etc/sudoers -p wa -k sudoers_changes"
    echo "-w /usr/bin/sudo -p x -k sudo_exec"
  } >>/etc/audit/rules.d/hardening.rules
  augenrules --load

  log INFO "Scanning for potentially unauthorized security tools"
  dpkg -l | egrep -i "netcat|nc |john|hydra|aircrack|ophcrack|metasploit|nmap|tcpdump|wireshark|nikto" || log INFO "No suspicious packages from list detected"

  log INFO "Removing world-writable files under /etc"
  find /etc -perm -002 -type f -exec chmod o-w {} \; || true

  log INFO "Restoring default hosts file entries"
  {
    echo "127.0.0.1 localhost"
    echo "::1       localhost"
  } >/etc/hosts
}

main() {
  log INFO "Starting Ubuntu security hardening"
  update_and_upgrade
  configure_unattended_upgrades
  configure_ufw
  configure_fail2ban
  configure_sysctl
  configure_login_defs
  configure_pam_pwquality
  configure_banners
  harden_sshd
  configure_auditd
  harden_shared_memory
  disable_unnecessary_filesystems
  secure_cron_and_at
  purge_insecure_services
  apply_additional_hardening
  install_security_tools
  log INFO "Security hardening completed. Review logs for details."
}

main "$@"
