#!/usr/bin/env bash
# Checks that harden.sh fixed everything plant-vulns.sh broke.
pass=0; fail=0
check() {
  local desc=$1; shift
  if bash -c "$*" >/dev/null 2>&1; then echo "PASS  $desc"; pass=$((pass + 1))
  else echo "FAIL  $desc"; fail=$((fail + 1)); fi
}
PW='Cyb3r!Patr1ot#2026'

# users
check "unauthorized user eve deleted"            '! id eve'
check "unauthorized admin mallory deleted"       '! id mallory'
check "hidden root account toor deleted"         '! grep -q "^toor:" /etc/passwd'
check "missing user dave created"                'id dave'
check "alice is still an admin"                  'id -nG alice | grep -qw sudo'
check "bob is not an admin"                      '! id -nG bob | grep -qw sudo'
check "hidden user sysbackup can't log in"       'getent passwd sysbackup | grep -q nologin'
check "carol no longer has an empty password"    '[ -n "$(getent shadow carol | cut -d: -f2)" ]'
check "root password locked"                     'passwd -S root | grep -qE "^root L"'
# passwords and PAM
check "bob's new password works"                 "echo '$PW' | pamtester login bob authenticate"
check "bob's old password is rejected"           "! echo password | pamtester login bob authenticate"
check "PAM backdoor gone (bad password fails)"   "! echo anything | pamtester login dave authenticate"
check "alice (unchanged password) can log in"   "echo password | pamtester login alice authenticate"
check "carol can log in before any failures"     "echo '$PW' | pamtester login carol authenticate"
check "account locks after 5 failures"           "for i in 1 2 3 4 5 6; do echo wrong | pamtester login carol authenticate; done; ! echo '$PW' | pamtester login carol authenticate"
check "PAM order: authsucc after pam_deny"       "awk '/pam_deny/{d=NR} /authsucc/{s=NR} END{exit !(d && s>d)}' /etc/pam.d/common-auth"
check "PASS_MAX_DAYS 90 in login.defs"           'grep -Eq "^PASS_MAX_DAYS[[:space:]]+90" /etc/login.defs'
check "bob's password expires in 90 days"        '[ "$(getent shadow bob | cut -d: -f5)" = 90 ]'
check "pwquality minlen 12"                      'grep -Eq "^minlen = 12" /etc/security/pwquality.conf'
check "password history remember=5"              'grep -Eq "pam_unix\.so.*remember=5" /etc/pam.d/common-password'
check "nullok removed"                           '! grep -E "^[^#]*pam_unix\.so.*nullok" /etc/pam.d/common-auth'
# sudo
check "NOPASSWD removed"                         '! grep -rE "^[^#]*NOPASSWD" /etc/sudoers /etc/sudoers.d'
check "sudo configuration is valid"              'visudo -c'
# files / permissions
check "find is no longer SUID"                   '[ ! -u /usr/bin/find ]'
check "media files deleted"                      '[ ! -e /home/bob/Music/song.mp3 ] && [ ! -e /home/eve/Videos/movie.mp4 ]'
check "/etc/shadow is 640"                       '[ "$(stat -c %a /etc/shadow)" = 640 ]'
check "world-writable file fixed"                '[ "$(stat -c %a /etc/planted-ww.conf)" = 664 ] || [ "$(stat -c %a /etc/planted-ww.conf)" = 644 ]'
# persistence
check "fake google entry disabled in hosts"      '! grep -E "^[^#]*www\.google\.com" /etc/hosts'
check "localhost entry kept in hosts"            'grep -Eq "^127\.0\.0\.1[[:space:]]+localhost" /etc/hosts'
check "malicious system cron job deleted"        '[ ! -e /etc/cron.d/updater ]'
check "unauthorized user's crontab deleted"      '[ ! -e /var/spool/cron/crontabs/eve ]'
check "fake sudo alias disabled"                 '! grep -E "^[[:space:]]*alias sudo=" /home/bob/.bashrc'
check "root's planted SSH key removed"           '[ ! -e /root/.ssh/authorized_keys ]'
check "ld.so.preload disabled"                   '[ ! -e /etc/ld.so.preload ]'
# kernel
check "ASLR setting fixed in sysctl.conf"        'grep -Eq "^kernel\.randomize_va_space = 2" /etc/sysctl.conf'
check "ip_forward override disabled"             '! grep -E "^[^#]*ip_forward" /etc/sysctl.d/60-forward.conf'
# ssh
check "sshd: PermitRootLogin no (effective)"     'mkdir -p /run/sshd; /usr/sbin/sshd -T | grep -qx "permitrootlogin no"'
check "sshd: PermitEmptyPasswords no"            '/usr/sbin/sshd -T | grep -qx "permitemptypasswords no"'
check "sshd config is valid"                     '/usr/sbin/sshd -t'
check "SSH server kept (critical service)"       'dpkg -s openssh-server'
# software
check "nmap removed"                             '! dpkg -s nmap'
check "telnet server removed"                    '! dpkg -s inetutils-telnetd'
check "games removed"                            '! dpkg -s bsdgames'
check "netcat-traditional removed"               '! dpkg -s netcat-traditional'
# apache (critical)
check "apache kept (critical service)"           'dpkg -s apache2'
check "apache ServerTokens Prod"                 'grep -q "^ServerTokens Prod" /etc/apache2/conf-available/security.conf'
check "apache directory listing off"             '! grep -Eq "^[[:space:]]*Options[[:space:]].*[[:space:]]Indexes" /etc/apache2/apache2.conf'
check "apache config is valid"                   'apache2ctl configtest'
# desktop / updates / logging
check "lightdm autologin removed"                '! grep -E "^autologin-user=.+" /etc/lightdm/lightdm.conf'
check "lightdm guest disabled"                   'grep -q "^allow-guest=false" /etc/lightdm/lightdm.conf'
check "automatic updates on"                     'grep -q "Unattended-Upgrade \"1\"" /etc/apt/apt.conf.d/20auto-upgrades'
check "held package released"                    '[ -z "$(apt-mark showhold)" ]'
check "audit rules installed"                    '[ -f /etc/audit/rules.d/50-cyberpatriot.rules ]'
check "backups were made"                        'ls /root/cyberpatriot/backups/*/etc/ssh/sshd_config'

echo
echo "verify: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
