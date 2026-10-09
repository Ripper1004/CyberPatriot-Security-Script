#!/bin/sh
# =============================================================================
#  Logic tests for scripts/freebsd/harden.sh that run on Linux (no FreeBSD needed).
#
#  Run (as root, from the repo root):   dash tests/freebsd/test-harden-logic.sh
#  Optional argument: another copy of harden.sh to test.
#
#  How it works: it copies the script's functions (everything before the
#  option parsing at the bottom) into a temp folder, moves every /etc,
#  /usr/local/etc and /var/cron path into a fake root inside that folder, and
#  puts small fake versions of the FreeBSD commands (pw, sysrc, service, mount,
#  sysctl, pfctl, audit, stat, id, logname...) first in PATH. The fakes write
#  each call to a log, which the tests then check. Sections that touch real
#  files outside the fake root (permissions, backdoors) only run in audit mode.
#
#  This tests the script's decisions, not FreeBSD itself: the real commands
#  still need a run on a FreeBSD 13 / 14 image.
#  Needs: a POSIX sh, awk, sed, find, mktemp, GNU stat (/usr/bin/stat).
#  As root it also mounts a small tmpfs to test the SUID scan across file
#  systems; without that it skips that one check.
# =============================================================================
# shellcheck disable=SC2016,SC2034  # code in '...' runs later inside check/fakes; variables are read by the loaded script
set -u   # turned off again before the script is loaded (it is not written for set -u)
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=${1:-$HERE/../../scripts/freebsd/harden.sh}
T=$(mktemp -d)
FR=$T/root
REALPATH=$PATH
MNT=""
cleanup() { [ -n "$MNT" ] && /bin/umount "$MNT" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT INT TERM
PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf 'ok    %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }  # check "name" 'shell test'
called()   { grep -qxF -- "$1" "$T/calls"; }               # exact command line was run
result_has() { grep -q -- "$1" "$RESULTS_FILE"; }          # a result line matches (grep regex)

# --- load the script's functions with paths moved into the fake root ---------
grep -q '^while \[ \$# -gt 0 \]; do$' "$SCRIPT" || { echo "Cannot find the option parsing in $SCRIPT"; exit 2; }
sed -e '/^while \[ \$# -gt 0 \]; do$/,$d' \
    -e 's#\([^a-zA-Z0-9_.@]\)/etc/#\1@FR@/etc/#g' \
    -e 's#\([^a-zA-Z0-9_.@]\)/usr/local/etc/#\1@FR@/usr/local/etc/#g' \
    -e 's#\([^a-zA-Z0-9_.@]\)/var/cron/#\1@FR@/var/cron/#g' "$SCRIPT" >"$T/lib.at"
if grep -nE '(^|[^a-zA-Z0-9_.@])/(etc|usr/local/etc|var/cron)/' "$T/lib.at"; then
  echo "Some paths above were not moved into the fake root; refusing to run."; exit 2
fi
sed "s#@FR@#$FR#g" "$T/lib.at" >"$T/lib.sh"

# --- fake FreeBSD commands ---------------------------------------------------
mkdir -p "$T/bin" "$FR/etc/security" "$FR/etc/ssh" "$FR/var/cron/tabs" "$T/work"
mk() { printf '#!/bin/sh\nT=%s; FR=%s\n%s\n' "$T" "$FR" "$2" >"$T/bin/$1"; chmod 755 "$T/bin/$1"; }
mk pw 'echo "pw $*" >>"$T/calls"
case $1 in groupshow) grep "^$2:" "$FR/etc/group" || exit 65 ;; esac
exit 0'
mk sysrc 'if [ "$1" = -n ]; then sed -n "s/^$2=//p" "$T/rc"; exit 0; fi
for a; do echo "sysrc $a" >>"$T/calls"; k=${a%%=*}; grep -v "^$k=" "$T/rc" >"$T/rc.new"; echo "$a" >>"$T/rc.new"; mv "$T/rc.new" "$T/rc"; done'
mk service 'echo "service $*" >>"$T/calls"
case $1 in -e) exit 0 ;; esac
case $2 in status|onestatus) grep -qx "$1" "$T/running"; exit ;; esac
exit 0'
mk mount 'cat "$T/mounts" 2>/dev/null'
mk sysctl 'if [ "$1" = -n ]; then v=$(sed -n "s/^$2=//p" "$T/sysctl"); [ -n "$v" ] && echo "$v" && exit 0; exit 1; fi
echo "sysctl $*" >>"$T/calls"'
mk pkg 'echo "pkg $*" >>"$T/calls"; [ "$1 $2" = "query -e" ] && cat "$T/pkglocked" 2>/dev/null; exit 0'
for c in pfctl audit kldload cap_mkdb sockstat freebsd-update; do mk "$c" "echo \"$c \$*\" >>\"\$T/calls\""; done
mk logname 'echo "${FAKE_LOGNAME:-}"'
mk id 'case $1 in -u) echo 0 ;; -Gn) awk -F: -v u="$2" "{ n = split(\$4, m, \",\"); for (i = 1; i <= n; i++) if (m[i] == u) print \$1 }" "$FR/etc/group" | tr "\n" " "; echo ;;
  *) grep -q "^$1:" "$FR/etc/passwd" ;; esac'
mk stat '[ "$1" = -f ] || exec /usr/bin/stat "$@"
m=$(/usr/bin/stat -c %a "$3"); m=$(printf "%04d" "$m"); L=$(printf "%o" "0${m#?}"); M=$(printf "%o" "0${m%???}")
u=$(/usr/bin/stat -c %U "$3"); g=$(/usr/bin/stat -c %G "$3"); [ "$g" = root ] && g=wheel
printf "%s\n" "$2" | sed "s/%Mp/$M/g; s/%Lp/$L/g; s/%Su/$u/g; s/%Sg/$g/g"'
PATH=$T/bin:$REALPATH; export PATH

set +u
# shellcheck disable=SC1091
. "$T/lib.sh"
WORK_DIR=$T/work; BACKUP_DIR=$T/backup; LOG_FILE=$T/log; REPORT_FILE=$T/report; RESULTS_FILE=$T/results
export FAKE_LOGNAME=""
unset SUDO_USER DOAS_USER   # the script prefers these over logname; under sudo they would replace the fake user

reset_state() { # fresh fake system for every test
  : >"$T/calls"; : >"$T/rc"; : >"$T/running"; : >"$T/mounts"; : >"$RESULTS_FILE"; : >"$T/sysctl"; : >"$T/pkglocked"
  cat >"$FR/etc/master.passwd" <<'EOF'
root::0:0::0:0:Charlie &:/root:/bin/csh
toor:$6$abc$def:0:0::0:0:Bourne-again Superuser:/root:
daemon:*:1:1::0:0:Owner of many system processes:/root:/usr/sbin/nologin
alice:$6$x$y:1001:1001::0:0:alice:/home/alice:/bin/sh
bob:$6$x$y:1002:1002::0:0:bob:/home/bob:/bin/sh
carol::1003:1003::0:0:carol:/home/carol:/bin/sh
EOF
  awk -F: '{ print $1 ":*:" $3 ":" $4 ":" $8 ":" $9 ":" $10 }' "$FR/etc/master.passwd" >"$FR/etc/passwd"
  printf 'wheel:*:0:root,alice,bob\noperator:*:5:root\n' >"$FR/etc/group"
  rm -f "$FR/etc/pf.conf" "$FR/etc/sysctl.conf"
  AUTHORIZED_ADMINS=""; AUTHORIZED_USERS=""; CRITICAL_SERVICES=""; NEW_PASSWORD=skip; EXTRA_PORTS=""
  MODE=apply; ASSUME_YES=1; FAKE_LOGNAME=alice; ADMINS_GIVEN=0; LISTS_GIVEN=0
}

# --- users ------------------------------------------------------------------
echo "== users: no README lists, run by alice (su -), --apply --yes"
reset_state; finalize_readme >/dev/null; SECTION=users; sec_users >/dev/null 2>&1
check "never locks root (empty password)"           '! called "pw lock root"'
check "tells the user to set root a password"       'result_has "REVIEW|users|.*root.*passwd root"'
check "locks carol (empty password, not the user)"  'called "pw lock carol"'
check "never deletes users without a README list"   '! grep -q "pw userdel" "$T/calls"'
check "never removes anyone from wheel without an admin list" '! grep -q "pw groupmod wheel -d" "$T/calls"'
check "reports bob in wheel for a human to decide"  'result_has "REVIEW|users|.*bob.*wheel"'
check "toor with a password is locked with -h -"    'called "pw usermod toor -h -"'

echo "== users: README admins=alice users=carol"
reset_state; AUTHORIZED_ADMINS=alice; AUTHORIZED_USERS=carol; finalize_readme >/dev/null; SECTION=users; sec_users >/dev/null 2>&1
check "removes bob from wheel"                      'called "pw groupmod wheel -d bob"'
check "deletes bob (not in the README)"             'called "pw userdel -n bob"'
check "keeps alice and carol"                       '! grep -Eq "pw userdel -n (alice|carol)" "$T/calls"'

echo "== users: empty password on the user running the script"
reset_state; AUTHORIZED_ADMINS=carol; FAKE_LOGNAME=carol; finalize_readme >/dev/null; SECTION=users; sec_users >/dev/null 2>&1
check "never locks the user running the script"     '! called "pw lock carol"'

echo "== users: toor already locked"
for pwf in '*' '*LOCKED*$6$abc$def' '*LOCKED*'; do
  reset_state; sed -i "s|^toor:[^:]*:|toor:$pwf:|" "$FR/etc/master.passwd"; finalize_readme >/dev/null; SECTION=users; sec_users >/dev/null 2>&1
  check "toor '$pwf' counts as locked"              'result_has "OK|users|toor" && ! grep -q "toor" "$T/calls"'
done

echo "== users: su limited to wheel (pam_group)"
reset_state; mkdir -p "$FR/etc/pam.d"; printf 'auth\t\trequisite\tpam_group.so\t\tno_warn group=wheel root_only fail_safe ruser\n' >"$FR/etc/pam.d/su"
MODE=audit; finalize_readme >/dev/null; SECTION=users; sec_users >/dev/null 2>&1
check "stock /etc/pam.d/su is OK"                    'result_has "OK|users|Only wheel members can use su"'
reset_state; printf '#auth\t\trequisite\tpam_group.so\t\tno_warn group=wheel root_only fail_safe ruser\n' >"$FR/etc/pam.d/su"
MODE=audit; finalize_readme >/dev/null; SECTION=users; sec_users >/dev/null 2>&1
check "commented-out pam_group is reported"          'result_has "REVIEW|users|/.*pam.d/su has no active pam_group"'

# --- firewall / ssh ---------------------------------------------------------
echo "== firewall: new pf.conf"
reset_state; CRITICAL_SERVICES=ssh; SECTION=firewall; sec_firewall >/dev/null 2>&1
check "pf.conf was written"                          '[ -s "$FR/etc/pf.conf" ]'
check "pf.conf has the blacklistd anchor"            'grep -qxF "anchor \"blacklistd/*\" in" "$FR/etc/pf.conf"'
check "anchor comes after block and before pass in"  'awk "/^block in/{b=NR} /^anchor \"blacklistd/{a=NR} /^pass in proto/{p=NR} END{exit !(b && a > b && p > a)}" "$FR/etc/pf.conf"'

echo "== ssh: existing pf.conf without the anchor"
reset_state; CRITICAL_SERVICES=ssh; MODE=audit; echo "sshd_enable=YES" >"$T/rc"; printf 'block in all\npass out all\n' >"$FR/etc/pf.conf"
: >"$FR/etc/ssh/sshd_config"; SECTION=ssh; sec_ssh >/dev/null 2>&1
check "reports the missing blacklistd anchor"        'result_has "REVIEW|ssh|.*blacklistd/\*"'

# --- services / logging -----------------------------------------------------
echo "== services: syslogd -ss is applied now"
reset_state; echo "syslogd_flags=-s" >"$T/rc"; echo syslogd >"$T/running"; SECTION=services; sec_services >/dev/null 2>&1
check "sets syslogd_flags=-ss"                       'called "sysrc syslogd_flags=-ss"'
check "restarts the running syslogd"                 'called "service syslogd onerestart"'
: >"$T/calls"; sec_services >/dev/null 2>&1
check "no restart when -ss was already set"          '! called "service syslogd onerestart"'

echo "== services: a service the README doesn't list"
reset_state; echo "rsyncd_enable=YES" >"$T/rc"; SECTION=services; sec_services >/dev/null 2>&1
check "turns rsyncd off at boot"                     'called "sysrc rsyncd_enable=NO"'
check "stops rsyncd now"                             'called "service rsyncd onestop"'
reset_state; CRITICAL_SERVICES=rsync; echo "rsyncd_enable=YES" >"$T/rc"; SECTION=services; sec_services >/dev/null 2>&1
check "keeps rsyncd when the README needs it"        'result_has "OK|services|Critical service rsyncd" && ! called "sysrc rsyncd_enable=NO"'

echo "== logging: auditd"
reset_state; printf 'dir:/var/audit\nflags:lo\nnaflags:lo\n' >"$FR/etc/security/audit_control"; echo auditd >"$T/running"; SECTION=logging; sec_logging >/dev/null 2>&1
check "sets flags:lo,aa,ad"                          'grep -qx "flags:lo,aa,ad" "$FR/etc/security/audit_control"'
check "leaves naflags alone"                         'grep -qx "naflags:lo" "$FR/etc/security/audit_control"'
check "reloads the running auditd (audit -s)"        'called "audit -s"'
: >"$T/calls"; sec_logging >/dev/null 2>&1
check "no reload when nothing changed"               '! called "audit -s"'
reset_state; printf 'flags:lo\n' >"$FR/etc/security/audit_control"; SECTION=logging; sec_logging >/dev/null 2>&1
check "starts auditd when it is not running"         'called "service auditd start"'

# --- passwords / sudo -------------------------------------------------------
echo "== passwords: pam_passwdqc"
reset_state; mkdir -p "$FR/etc/pam.d"
printf '#password\trequisite\tpam_passwdqc.so\tmin=disabled,disabled,disabled,twelve,ten similar=deny retry=3 enforce=users\npassword\trequired\tpam_unix.so\tno_warn try_first_pass nullok\n' >"$FR/etc/pam.d/passwd"
printf 'default:\\\n\t:passwd_format=sha512:\\\n\t:passwordtime=90d:\\\n\t:umask=022:\n' >"$FR/etc/login.conf"
SECTION=passwords; sec_passwords >/dev/null 2>&1
check "turns on pam_passwdqc before pam_unix"        'awk "/^password.*pam_passwdqc.*enforce=users/{q=NR} /^password.*pam_unix/{u=NR} END{exit !(q && u > q)}" "$FR/etc/pam.d/passwd"'
reset_state; printf 'password\trequired\tpam_krb5.so\n' >"$FR/etc/pam.d/passwd"; cp "$FR/etc/pam.d/passwd" "$T/pam.orig"
SECTION=passwords; sec_passwords >/dev/null 2>&1
check "says FAILED (not CHANGED) when it can't add it" 'result_has "FAILED|passwords|.*pam_passwdqc" && ! result_has "CHANGED|passwords|pam_passwdqc" && cmp -s "$T/pam.orig" "$FR/etc/pam.d/passwd"'

echo "== sudo: doas nopass with other options"
reset_state; MODE=audit; mkdir -p "$FR/usr/local/etc"; echo 'permit persist nopass bob as root' >"$FR/usr/local/etc/doas.conf"
SECTION=sudo; sec_sudo >/dev/null 2>&1
check "finds 'permit persist nopass'"                'result_has "REVIEW|sudo|doas.conf has"'
echo 'permit persist alice as root' >"$FR/usr/local/etc/doas.conf"; : >"$RESULTS_FILE"; sec_sudo >/dev/null 2>&1
check "a rule without nopass is fine"                'result_has "OK|sudo|doas.conf has no nopass"'
rm -f "$FR/usr/local/etc/doas.conf"

echo "== software / updates / firewall: report-only checks"
reset_state; MODE=audit; echo "openssl-3.0.15" >"$T/pkglocked"; SECTION=software; sec_software >/dev/null 2>&1
check "locked packages are reported"                 'result_has "REVIEW|software|Locked packages.*openssl-3.0.15"'
reset_state; MODE=audit; printf '0 3 * * * root /usr/sbin/freebsd-update cron\n' >"$FR/etc/crontab"; SECTION=updates; sec_updates >/dev/null 2>&1
check "freebsd-update cron line is seen"             'result_has "OK|updates|Daily update check"'
reset_state; MODE=audit; printf '#0 3 * * * root /usr/sbin/freebsd-update cron\n' >"$FR/etc/crontab"; SECTION=updates; sec_updates >/dev/null 2>&1
check "a commented-out line is reported"             'result_has "REVIEW|updates|No daily update check"'
rm -f "$FR/etc/crontab"
reset_state; MODE=audit; echo "firewall_enable=YES" >"$T/rc"; SECTION=firewall; sec_firewall >/dev/null 2>&1
check "ipfw being on is reported"                    'result_has "REVIEW|firewall|ipfw is on"'

# --- kernel -----------------------------------------------------------------
echo "== kernel: ip.forwarding applied now"
reset_state; printf 'net.inet.ip.forwarding=1\nnet.inet.tcp.blackhole=0\n' >"$T/sysctl"; SECTION=kernel; sec_kernel >/dev/null 2>&1
check "writes net.inet.ip.forwarding=0"              'grep -qx "net.inet.ip.forwarding=0" "$FR/etc/sysctl.conf"'
check "applies net.inet.ip.forwarding=0 now"         'called "sysctl net.inet.ip.forwarding=0"'
check "applies net.inet.tcp.blackhole=2 now"         'called "sysctl net.inet.tcp.blackhole=2"'

# --- permissions (audit mode only: it reads real paths) ----------------------
echo "== permissions and files: sticky /tmp-style folder, SUID and media scans across file systems"
reset_state; MODE=audit; SECTION=permissions
mkdir -p "$T/sticky"; chmod 1777 "$T/sticky"; mkdir -p "$T/priv"; chmod 600 "$T/priv"
check_perm "$T/sticky" 1777 root wheel >/dev/null
check_perm "$T/priv" 600 root wheel >/dev/null
check "a 1777 folder counts as 1777"                 'result_has "OK|permissions|$T/sticky is 1777"'
check "a 600 file counts as 600"                     'result_has "OK|permissions|$T/priv is 600"'
mkdir -p "$T/fs/root/bin" "$T/fs/root/home"
if [ "$(id -u)" = 0 ] && /bin/mount -t tmpfs -o size=1m cptest "$T/fs/root/home" 2>/dev/null; then
  MNT=$T/fs/root/home
  printf '%s\t\t%s\tufs\trw\t1 1\n' /dev/ada0p2 "$T/fs/root" >"$T/mounts"
  printf '%s\t\t%s\tzfs\trw,nosuid\t0 0\n' zroot/home "$T/fs/root/home" >>"$T/mounts"
  mkdir -p "$MNT/bob"; cp /bin/true "$MNT/bob/find"; chmod 4755 "$MNT/bob/find"
  cp /bin/true "$T/fs/root/bin/vi"; chmod 2755 "$T/fs/root/bin/vi"
  sec_permissions >/dev/null 2>&1
  echo x >"$MNT/bob/song.mp3"; WORK_DIR=$T/work; SECTION=files; sec_files >/dev/null 2>&1
  check "media scan finds a file on the separate home file system" 'result_has "REVIEW|files|Found [0-9]* media" && grep -q "$MNT/bob/song.mp3" "$REPORT_FILE"'

  check "finds SUID find on the separate home file system" 'result_has "DANGEROUS: $MNT/bob/find"'
  check "finds SGID vi on the root file system"            'result_has "DANGEROUS: $T/fs/root/bin/vi"'
else
  echo "skip  SUID scan across file systems (needs root and tmpfs)"
fi

# --- backdoors (audit mode only: it reads real /root) -------------------------
echo "== backdoors: crontabs with no README lists"
reset_state; MODE=audit; finalize_readme >/dev/null; SECTION=backdoors
echo '*/5 * * * * /usr/bin/true' >"$FR/var/cron/tabs/bob"
sec_backdoors >/dev/null 2>&1
check "bob's crontab is not called unauthorized"     '! result_has "unauthorized or deleted user .bob."'
check "bob's crontab is still listed for review"     'result_has "User bob has cron jobs"'
reset_state; MODE=audit; AUTHORIZED_ADMINS=alice; finalize_readme >/dev/null; SECTION=backdoors
echo '*/5 * * * * /usr/bin/true' >"$FR/var/cron/tabs/bob"
sec_backdoors >/dev/null 2>&1
check "with a README list, bob's crontab is unauthorized" 'result_has "unauthorized or deleted user .bob."'

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
