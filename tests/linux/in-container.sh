#!/usr/bin/env bash
# Runs inside a throwaway container (started by run-tests.sh).
set -e
export DEBIAN_FRONTEND=noninteractive

# Optional: go through an HTTPS proxy that needs its own CA certificate.
if [ -f /ca.crt ]; then
  sed -i 's#http://#https://#g' /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true
  echo 'Acquire::https::CAInfo "/ca.crt";' >/etc/apt/apt.conf.d/99test-ca
fi

echo "== Installing the practice image's software"
dpkg -s pamtester >/dev/null 2>&1 || apt-get update -q >/dev/null
dpkg -s pamtester >/dev/null 2>&1 || apt-get install -y -q sudo openssh-server cron procps iproute2 passwd login pamtester nano \
  nmap inetutils-telnetd bsdgames netcat-traditional apache2 dconf-cli >/dev/null
bash /repo/tests/linux/plant-vulns.sh

cd /repo/scripts/linux
CONF=/repo/tests/linux/test.conf
echo "== Audit run (must not change anything)"
watched() {
  find /etc/passwd /etc/shadow /etc/group /etc/ssh /etc/pam.d /etc/sudoers /etc/sudoers.d /etc/sysctl.conf /etc/sysctl.d \
       /usr/lib/sysctl.d /etc/security /etc/lightdm /etc/xdg/lightdm /etc/gdm3 /etc/dconf /etc/hosts /etc/crontab /etc/cron.d \
       /var/spool/cron /etc/apt/apt.conf.d /etc/apache2 /home/bob/.mozilla -type f -exec md5sum {} + 2>/dev/null | sort
  find /etc/systemd/system /etc/dconf /etc/lightdm /home /run/sshd -printf '%p %m %l\n' 2>/dev/null | sort
}
before=$(watched | md5sum)
bash harden.sh --audit --no-color --config "$CONF" >/tmp/audit1.txt 2>&1
after=$(watched | md5sum)
if [ "$before" = "$after" ]; then echo "PASS  audit mode changed nothing"; else echo "FAIL  audit mode changed files"; exit 1; fi
echo "      audit found: $(grep -c '\[WOULD' /tmp/audit1.txt) WOULD, $(grep -c '\[REVIEW' /tmp/audit1.txt) REVIEW"

echo "== No README user list: report only, never delete or demote (SUDO_USER=alice)"
printf 'NEW_PASSWORD="skip"\nENABLE_LOCKOUT="no"\nFULL_UPGRADE="no"\n' >/tmp/no-readme.conf
SUDO_USER=alice bash harden.sh --apply --yes --no-color --only users,sudoers,backdoors --config /tmp/no-readme.conf >/tmp/noreadme.txt 2>&1 || true
nr_fail=0
for c in 'id eve' 'id mallory' 'id -nG mallory | grep -qw sudo' '[ -e /var/spool/cron/crontabs/eve ]' 'grep -q "^bob" /etc/sudoers.d/90-bob'; do
  if bash -c "$c" >/dev/null 2>&1; then echo "PASS  no README list: still true: $c"; else echo "FAIL  no README list: $c"; nr_fail=1; fi
done
[ "$nr_fail" -eq 0 ] || { cat /tmp/noreadme.txt; exit 1; }

echo "== SSH and desktop sections under umask 0000"
# (local.d already exists from plant-vulns.sh; the locks folder and the database are new here)
rm -rf /run/sshd
(umask 0000; SUDO_USER=alice bash harden.sh --apply --yes --no-color --only ssh,desktop --config "$CONF" >/tmp/umask.txt 2>&1) || true
um_fail=0
# shellcheck disable=SC2016  # the checks are run later by bash -c
for c in '! grep -q "validation failed" /tmp/umask.txt' '[ "$(stat -c %a /run/sshd)" = 755 ]' \
         '/usr/sbin/sshd -T | grep -qx "permitrootlogin no"' \
         '[ "$(stat -c %a /etc/dconf/db/local.d/locks)" = 755 ]' '[ "$(stat -c %a /etc/dconf/db/local)" = 644 ]'; do
  if bash -c "$c" >/dev/null 2>&1; then echo "PASS  umask 0000: $c"; else echo "FAIL  umask 0000: $c"; um_fail=1; fi
done
[ "$um_fail" -eq 0 ] || { cat /tmp/umask.txt; exit 1; }

echo "== Apply run"
SUDO_USER=alice bash harden.sh --apply --yes --no-color --config "$CONF" >/tmp/apply.txt 2>&1 || true
grep -E '\[(FAILED)' /tmp/apply.txt | sed 's/^/      /' || true

echo "== Verify"
bash /repo/tests/linux/verify.sh || { echo "---- apply output ----"; cat /tmp/apply.txt; exit 1; }

echo "== Second audit (should find little or nothing left)"
SUDO_USER=alice bash harden.sh --audit --no-color --config "$CONF" >/tmp/audit2.txt 2>&1
grep '\[WOULD' /tmp/audit2.txt | sed 's/^/      /' || true
echo "      remaining WOULD items: $(grep -c '\[WOULD' /tmp/audit2.txt)"

echo "== ssh.socket (Ubuntu 22.10+, Mint 22): fake systemd, SSH only listens through the socket"
# A stand-in systemctl: ssh.socket is listening, ssh.service is not running yet.
mkdir -p /tmp/stub /run/systemd/system
cat >/tmp/stub/systemctl <<'STUB'
#!/bin/bash
echo "$*" >>/tmp/systemctl.log
units="ssh ssh.service ssh.socket apache2 apache2.service"
last=${*: -1}
case "$1" in
  cat) [[ " $units " == *" $last "* ]] ;;
  is-active|is-enabled) [[ $last == ssh.socket || $last == apache2 ]] ;;
  list-units) exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x /tmp/stub/systemctl
sk_fail=0
: >/tmp/systemctl.log
PATH=/tmp/stub:$PATH SUDO_USER=alice bash harden.sh --apply --yes --no-color --only ssh,services --config "$CONF" >/tmp/sock1.txt 2>&1 || true
if grep -q 'starts on demand (ssh.socket is listening' /tmp/sock1.txt && ! grep -Eq '^(enable|start|restart|reload-or-restart) .*ssh' /tmp/systemctl.log; then
  echo "PASS  ssh critical + ssh.socket listening: kept as it is (no 'enable --now ssh')"
else echo "FAIL  ssh critical + ssh.socket: script tried to start ssh.service"; sk_fail=1; fi
# README without SSH: answer "yes" to the (default-no) question through a terminal
sed 's/^CRITICAL_SERVICES=.*/CRITICAL_SERVICES="apache2"/' "$CONF" >/tmp/nossh.conf
: >/tmp/systemctl.log
# A fixed number of answers: script(1) in util-linux 2.37 (Ubuntu 22.04) waits for the end of its input.
printf 'y\n%.0s' $(seq 30) | PATH=/tmp/stub:$PATH SUDO_USER=alice timeout 300 script -qec "bash harden.sh --apply --no-color --only services --config /tmp/nossh.conf" /dev/null >/tmp/sock2.txt 2>&1 || true
if grep -qx 'disable --now ssh.socket' /tmp/systemctl.log && grep -qx 'disable --now ssh' /tmp/systemctl.log; then
  echo "PASS  ssh not needed: both ssh.socket and ssh.service disabled"
else echo "FAIL  ssh not needed: ssh.socket not disabled"; cat /tmp/systemctl.log; sk_fail=1; fi
rm -rf /run/systemd/system
[ "$sk_fail" -eq 0 ] || exit 1
