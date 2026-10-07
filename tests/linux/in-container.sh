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
echo "== Audit run (must not change anything)"
before=$(md5sum /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/pam.d/common-auth | md5sum)
bash harden.sh --audit --no-color --config /repo/tests/linux/test.conf >/tmp/audit1.txt 2>&1
after=$(md5sum /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/pam.d/common-auth | md5sum)
[ "$before" = "$after" ] && echo "PASS  audit mode changed nothing" || { echo "FAIL  audit mode changed files"; exit 1; }
grep -E '^\s+(OK|CHANGED|WOULD|SKIPPED|REVIEW|FAILED) ' /tmp/audit1.txt >/dev/null || true
echo "      audit found: $(grep -c '\[WOULD' /tmp/audit1.txt) WOULD, $(grep -c '\[REVIEW' /tmp/audit1.txt) REVIEW"

echo "== Apply run"
SUDO_USER=alice bash harden.sh --apply --yes --no-color --config /repo/tests/linux/test.conf >/tmp/apply.txt 2>&1 || true
grep -E '\[(FAILED)' /tmp/apply.txt | sed 's/^/      /' || true

echo "== Verify"
bash /repo/tests/linux/verify.sh || { echo "---- apply output ----"; cat /tmp/apply.txt; exit 1; }

echo "== Second audit (should find little or nothing left)"
SUDO_USER=alice bash harden.sh --audit --no-color --config /repo/tests/linux/test.conf >/tmp/audit2.txt 2>&1
grep '\[WOULD' /tmp/audit2.txt | sed 's/^/      /' || true
echo "      remaining WOULD items: $(grep -c '\[WOULD' /tmp/audit2.txt)"
