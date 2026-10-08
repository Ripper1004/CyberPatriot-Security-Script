#!/bin/sh
# shellcheck disable=SC2086,SC2013  # name lists are split into words on purpose
# =============================================================================
#  CyberPatriot Toolkit - FreeBSD Hardening Script (FreeBSD 13 / 14)
#
#  READ FIRST: docs/start-here/using-the-scripts.md and docs/checklists/freebsd.md
#
#  The golden rule: THE README DECIDES WHAT IS SAFE. The script asks for the
#  authorized users, admins and critical services before changing anything,
#  and never removes or disables something you list.
#
#  Usage (as root - use "su -" first):
#    sh harden.sh                      interactive menu (starts in AUDIT mode)
#    sh harden.sh --audit              report problems only, change NOTHING
#    sh harden.sh --apply              fix problems (asks before risky steps)
#    sh harden.sh --apply --yes        fix problems without asking
#    sh harden.sh --config FILE        read README info from FILE (same format as the Linux one)
#    sh harden.sh --only users,ssh     run only some sections (see --list)
#
#  Logs and backups: /root/cyberpatriot/
# =============================================================================

VERSION="2.0.0"
MODE=""; ASSUME_YES=0; CONFIG_FILE=""; ONLY=""
AUTHORIZED_USERS=""; AUTHORIZED_ADMINS=""; CRITICAL_SERVICES=""; NEW_PASSWORD=""; FULL_UPGRADE="ask"; EXTRA_PORTS=""
RUN_ID=$(date +%Y%m%d-%H%M%S)
WORK_DIR=/root/cyberpatriot
BACKUP_DIR=$WORK_DIR/backups/$RUN_ID
LOG_FILE=$WORK_DIR/harden-$RUN_ID.log
REPORT_FILE=$WORK_DIR/findings-$RUN_ID.txt
RESULTS_FILE=$WORK_DIR/.results-$RUN_ID
SECTION="setup"
SECTIONS="users passwords firewall ssh services software files kernel permissions sudo backdoors logging updates"

# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
if [ -t 1 ]; then
  RED=$(printf '\033[31m'); GRN=$(printf '\033[32m'); YLW=$(printf '\033[33m'); CYN=$(printf '\033[36m'); DIM=$(printf '\033[2m'); RST=$(printf '\033[0m')
else
  RED=""; GRN=""; YLW=""; CYN=""; DIM=""; RST=""
fi
log()    { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >>"$LOG_FILE" 2>/dev/null; }
info()   { printf '%s  *%s %s\n' "$CYN" "$RST" "$*"; log "INFO $*"; }
why()    { printf '%s      why: %s%s\n' "$DIM" "$*" "$RST"; }
warn()   { printf '%s  ! %s%s\n' "$YLW" "$*" "$RST"; log "WARN $*"; }
header() { printf '\n%s== %s ==%s\n' "$CYN" "$*" "$RST"; log "===== $* ====="; }
result() {
  _st=$1; shift
  case $_st in OK|CHANGED) _c=$GRN ;; WOULD) _c=$CYN ;; SKIPPED) _c=$DIM ;; FAILED) _c=$RED ;; *) _c=$YLW ;; esac
  printf '  %s[%-7s]%s %s\n' "$_c" "$_st" "$RST" "$*"
  printf '%s|%s|%s\n' "$_st" "$SECTION" "$*" >>"$RESULTS_FILE"
  log "$_st $*"
  case $_st in REVIEW|FAILED|WOULD) printf -- '- [ ] %-7s (%s) %s\n' "$_st" "$SECTION" "$*" >>"$REPORT_FILE" ;; esac
}
detail() { printf '        %s\n' "$@" >>"$REPORT_FILE"; }
show_file_list() { # show_file_list FILE MAX - print the first MAX lines, all go to the report
  _n=0
  while IFS= read -r _l; do
    _n=$((_n + 1)); [ "$_n" -le "$2" ] && printf '%s          %s%s\n' "$DIM" "$_l" "$RST"
    detail "$_l"
  done <"$1"
  [ "$_n" -gt "$2" ] && printf '%s          ... and %d more (see %s)%s\n' "$DIM" $((_n - $2)) "$REPORT_FILE" "$RST"
  return 0
}

# ----------------------------------------------------------------------------
# Prompts and actions
# ----------------------------------------------------------------------------
ask() { # ask "question" [y|n] [strict]
  [ "$MODE" = audit ] && return 1
  if [ "$ASSUME_YES" -eq 1 ]; then
    if [ -n "$3" ]; then [ "$2" = y ]; return; fi
    return 0
  fi
  if [ "$2" = y ]; then _h="[Y/n]"; else _h="[y/N]"; fi
  while :; do
    printf '%s  ? %s %s%s ' "$YLW" "$1" "$_h" "$RST"
    read -r _a </dev/tty || _a=""
    [ -z "$_a" ] && _a=${2:-n}
    case $_a in [Yy]|[Yy][Ee][Ss]) log "ASK $1 -> yes"; return 0 ;; [Nn]|[Nn][Oo]) log "ASK $1 -> no"; return 1 ;; esac
  done
}
run() { log "RUN $*"; "$@" >>"$LOG_FILE" 2>&1; }
fix() { # fix "description" command...
  _d=$1; shift
  if [ "$MODE" = audit ]; then result WOULD "$_d"; return 0; fi
  if run "$@"; then result CHANGED "$_d"; return 0; fi
  result FAILED "$_d (see $LOG_FILE)"; return 1
}
backup() {
  for _f in "$@"; do
    [ -e "$_f" ] || continue
    [ -e "$BACKUP_DIR$_f" ] && continue
    mkdir -p "$BACKUP_DIR$(dirname "$_f")" && cp -p "$_f" "$BACKUP_DIR$_f" && log "BACKUP $_f"
  done
}
restore() { [ -e "$BACKUP_DIR$1" ] && cp -p "$BACKUP_DIR$1" "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
in_list() { _w=$1; shift; for _x in "$@"; do [ "$_x" = "$_w" ] && return 0; done; return 1; }
is_critical() { for _k in "$@"; do for _c in $CRITICAL_SERVICES; do [ "$_c" = "$_k" ] && return 0; done; done; return 1; }

# set_conf FILE KEY "NEWLINE" [SEP-REGEX]
#   Replace the first line (commented or not) that sets KEY, comment out later duplicates,
#   or append NEWLINE. Audit mode only reports. Backs up the file first.
set_conf() {
  _file=$1; _key=$2; _new=$3; _sep=${4:-'[[:space:]]'}
  _tmp=$(mktemp)
  [ -f "$_file" ] || : >"$_file.harden-new"
  awk -v key="$_key" -v nl="$_new" -v sep="$_sep" '
    BEGIN { re = "^[[:space:]]*#?[[:space:]]*" key sep; act = "^[[:space:]]*" key sep }
    { line[NR] = $0 }
    END {
      t = 0
      for (i = 1; i <= NR; i++) if (line[i] ~ act) { t = i; break }
      if (!t) for (i = 1; i <= NR; i++) if (line[i] ~ re) { t = i; break }
      for (i = 1; i <= NR; i++) {
        if (i == t) { print nl; continue }
        if (t && i > t && line[i] ~ act) { print "# " line[i] "   # duplicate, disabled by harden.sh"; continue }
        print line[i]
      }
      if (!t) print nl
    }' "$( [ -f "$_file" ] && echo "$_file" || echo "$_file.harden-new" )" >"$_tmp"
  rm -f "$_file.harden-new"
  if [ -f "$_file" ] && cmp -s "$_tmp" "$_file"; then rm -f "$_tmp"; result OK "$_new  ($_file)"; return 0; fi
  if [ "$MODE" = audit ]; then rm -f "$_tmp"; result WOULD "$_new  ($_file)"; return 0; fi
  backup "$_file"
  if [ -f "$_file" ]; then cat "$_tmp" >"$_file"; else install -m 644 "$_tmp" "$_file"; fi
  rm -f "$_tmp"
  result CHANGED "$_new  ($_file)"
}

# sysrc helper: set_rc VAR VALUE "description"
set_rc() {
  _cur=$(sysrc -n "$1" 2>/dev/null)
  if [ "$_cur" = "$2" ]; then result OK "$3"; return 0; fi
  backup /etc/rc.conf
  fix "$3 (rc.conf $1=\"$2\", was \"${_cur:-unset}\")" sysrc "$1=$2"
}

# ----------------------------------------------------------------------------
# README information
# ----------------------------------------------------------------------------
human_users() { awk -F: '$3 >= 1000 && $3 < 65534 { print $1 }' /etc/passwd; }

load_config() {
  [ -r "$1" ] || { echo "Cannot read $1"; exit 1; }
  while IFS= read -r _line || [ -n "$_line" ]; do
    case $_line in ''|'#'*) continue ;; esac
    _k=${_line%%=*}; _v=${_line#*=}
    _k=$(printf '%s' "$_k" | tr -d '[:space:]')
    case $_v in \"*\"*) _v=${_v#\"}; _v=${_v%%\"*} ;; \'*\'*) _v=${_v#\'}; _v=${_v%%\'*} ;; *) _v=${_v%% #*} ;; esac
    case $_k in
      AUTHORIZED_USERS) AUTHORIZED_USERS=$_v ;; AUTHORIZED_ADMINS) AUTHORIZED_ADMINS=$_v ;;
      CRITICAL_SERVICES) CRITICAL_SERVICES=$_v ;; NEW_PASSWORD) NEW_PASSWORD=$_v ;;
      FULL_UPGRADE) FULL_UPGRADE=$_v ;; EXTRA_PORTS) EXTRA_PORTS=$_v ;;
    esac
  done <"$1"
}

prompt_readme() {
  header "README information"
  echo "Users on this machine: $(human_users | tr '\n' ' ')"
  printf '%s  Authorized ADMINS (separate with spaces): %s' "$YLW" "$RST"; read -r AUTHORIZED_ADMINS </dev/tty
  printf '%s  Authorized USERS who are NOT admins:      %s' "$YLW" "$RST"; read -r AUTHORIZED_USERS </dev/tty
  echo "  Critical service keywords: ssh apache nginx mysql postgresql ftp samba dns mail nfs"
  printf '%s  CRITICAL SERVICES (blank if none):        %s' "$YLW" "$RST"; read -r CRITICAL_SERVICES </dev/tty
}

finalize_readme() {
  AUTHORIZED_USERS=$(echo "$AUTHORIZED_USERS" | tr ',;' '  ')
  AUTHORIZED_ADMINS=$(echo "$AUTHORIZED_ADMINS" | tr ',;' '  ')
  CRITICAL_SERVICES=$(echo "$CRITICAL_SERVICES" | tr ',;' '  ' | tr '[:upper:]' '[:lower:]')
  ME=${SUDO_USER:-${DOAS_USER:-$(logname 2>/dev/null)}}
  if [ -n "$ME" ] && [ "$ME" != root ] && ! in_list "$ME" $AUTHORIZED_ADMINS $AUTHORIZED_USERS; then
    AUTHORIZED_ADMINS="$AUTHORIZED_ADMINS $ME"
  fi
  echo "  Admins:            ${AUTHORIZED_ADMINS:-(none given)}"
  echo "  Standard users:    ${AUTHORIZED_USERS:-(none given)}"
  echo "  Critical services: ${CRITICAL_SERVICES:-(none)}"
}

# ============================================================================
# SECTION: users
# ============================================================================
sec_users() {
  _all="$AUTHORIZED_ADMINS $AUTHORIZED_USERS"
  info "Extra root accounts (UID 0)"
  why "Only root (and FreeBSD's built-in, LOCKED 'toor') should have UID 0."
  awk -F: '$3 == 0 && $1 != "root" { print $1 ":" $2 }' /etc/master.passwd | while IFS=: read -r _u _pw; do
    if [ "$_u" = toor ] && [ "$_pw" = "*" ]; then result OK "toor exists but is locked (FreeBSD default)"; continue; fi
    result REVIEW "Account '$_u' has UID 0 and can log in (a hidden root account)"
    if [ "$_u" = toor ]; then ask "Lock the toor account?" y && fix "Locked toor" pw lock toor
    elif ask "Delete the hidden root account '$_u'?" y; then fix "Deleted $_u" pw userdel -n "$_u"; fi
  done

  info "Comparing users with the README"
  why "Every account that is not in the README is a way in for an attacker."
  if [ -z "$(echo "$_all" | tr -d ' ')" ]; then
    result SKIPPED "No README user list - not checking for unauthorized users"
  else
    for _u in $(human_users); do
      in_list "$_u" $_all && continue
      result REVIEW "User '$_u' is NOT in the README"
      ask "Delete unauthorized user '$_u'? (home folder is kept)" y && fix "Deleted user $_u" pw userdel -n "$_u"
    done
    for _u in $_all; do
      id "$_u" >/dev/null 2>&1 && continue
      result REVIEW "User '$_u' is in the README but does not exist"
      ask "Create user '$_u'?" y && fix "Created user $_u" pw useradd -n "$_u" -m -s /bin/sh
    done
  fi

  info "Administrator group (wheel - members can use 'su' to become root)"
  for _m in $(pw groupshow wheel 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
    [ "$_m" = root ] && continue
    in_list "$_m" $AUTHORIZED_ADMINS && continue
    result REVIEW "'$_m' is in the wheel (admin) group but is not an authorized admin"
    ask "Remove '$_m' from wheel?" y && fix "Removed $_m from wheel" pw groupmod wheel -d "$_m"
  done
  for _a in $AUTHORIZED_ADMINS; do
    id "$_a" >/dev/null 2>&1 || continue
    id -Gn "$_a" | tr ' ' '\n' | grep -qx wheel && continue
    result REVIEW "Authorized admin '$_a' is not in wheel"
    ask "Add '$_a' to wheel?" y && fix "Added $_a to wheel" pw groupmod wheel -m "$_a"
  done
  for _m in $(pw groupshow operator 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
    in_list "$_m" $AUTHORIZED_ADMINS || result REVIEW "'$_m' is in the 'operator' group (can shut down and read disks)"
  done

  info "Accounts with no password"
  awk -F: '$2 == "" { print $1 }' /etc/master.passwd | while read -r _u; do
    result REVIEW "Account '$_u' has an EMPTY password"
    ask "Lock '$_u' until it gets a real password?" y && fix "Locked $_u" pw lock "$_u"
  done

  info "Strong passwords for the other users"
  if [ "$MODE" = audit ]; then result REVIEW "Make sure these users have strong passwords: $_all"; return; fi
  if [ "$NEW_PASSWORD" = skip ]; then result SKIPPED "Password changes skipped"; return; fi
  if [ -z "$NEW_PASSWORD" ] && [ "$ASSUME_YES" -eq 0 ]; then
    printf '%s  ? New password for the other users (12+ chars, upper, lower, number, symbol; blank = skip): %s' "$YLW" "$RST"
    stty -echo 2>/dev/null; read -r NEW_PASSWORD </dev/tty; stty echo 2>/dev/null; echo
  fi
  [ -z "$NEW_PASSWORD" ] && { result SKIPPED "No new password given - change them with: passwd USER"; return; }
  case $NEW_PASSWORD in *[A-Z]*) ;; *) result FAILED "Password too weak (needs upper case)"; return ;; esac
  case $NEW_PASSWORD in *[a-z]*) ;; *) result FAILED "Password too weak (needs lower case)"; return ;; esac
  case $NEW_PASSWORD in *[0-9]*) ;; *) result FAILED "Password too weak (needs a number)"; return ;; esac
  [ ${#NEW_PASSWORD} -ge 12 ] || { result FAILED "Password too weak (needs 12+ characters)"; return; }
  for _u in $_all; do
    [ "$_u" = "$ME" ] && continue
    id "$_u" >/dev/null 2>&1 || continue
    log "RUN pw usermod $_u -h 0"
    if printf '%s\n' "$NEW_PASSWORD" | pw usermod "$_u" -h 0 2>>"$LOG_FILE"; then result CHANGED "Set a strong password for $_u"
    else result FAILED "Could not set the password for $_u"; fi
  done
}

# ============================================================================
# SECTION: passwords
# ============================================================================
sec_passwords() {
  info "Password hashing and expiry (/etc/login.conf, 'default' class)"
  why "Passwords must use a strong hash and expire every 90 days."
  _lc=/etc/login.conf
  if grep -q 'passwordtime=90d' "$_lc" && grep -q 'passwd_format=sha512' "$_lc"; then
    result OK "login.conf: sha512 hashing and 90-day password expiry"
  elif [ "$MODE" = audit ]; then
    result WOULD "login.conf: sha512 hashing and 90-day password expiry"
  else
    backup "$_lc"
    _t=$(mktemp)
    awk '
      /^default:/ { indef = 1 }
      indef && /passwd_format=/ { sub(/passwd_format=[^:]*/, "passwd_format=sha512") }
      indef && /passwordtime=/ { sub(/passwordtime=[^:]*/, "passwordtime=90d"); hadpt = 1 }
      indef && !/\\$/ { if (!hadpt) sub(/:$/, ":\\\n\t:passwordtime=90d:"); indef = 0 }
      { print }' "$_lc" >"$_t"
    grep -q 'passwd_format=sha512' "$_t" || sed -i '' 's/^default:\\/default:\\\
	:passwd_format=sha512:\\/' "$_t"
    cat "$_t" >"$_lc"; rm -f "$_t"
    if run cap_mkdb "$_lc"; then result CHANGED "login.conf: sha512 hashing and 90-day password expiry"
    else restore "$_lc"; run cap_mkdb "$_lc"; result FAILED "login.conf change rolled back (see log)"; fi
  fi

  info "Password complexity (pam_passwdqc)"
  why "Rejects short or simple passwords when users change them."
  _pp=/etc/pam.d/passwd
  if grep -Eq '^[[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_passwdqc\.so.*enforce=users' "$_pp"; then
    result OK "pam_passwdqc enforces strong passwords"
  elif [ "$MODE" = audit ]; then
    result WOULD "Turn on pam_passwdqc (min length 12, enforce for users)"
  else
    backup "$_pp"
    _t=$(mktemp)
    awk '
      /^[#[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_passwdqc\.so/ { if (!d) print "password\trequisite\tpam_passwdqc.so\tmin=disabled,disabled,disabled,12,12 similar=deny retry=3 enforce=users"; d = 1; next }
      /^[[:space:]]*password[[:space:]]+required[[:space:]]+pam_unix\.so/ && !d { print "password\trequisite\tpam_passwdqc.so\tmin=disabled,disabled,disabled,12,12 similar=deny retry=3 enforce=users"; d = 1 }
      { print }' "$_pp" >"$_t"
    cat "$_t" >"$_pp"; rm -f "$_t"
    result CHANGED "pam_passwdqc on (min length 12, enforce for users) in $_pp"
  fi
  result REVIEW "FreeBSD has no built-in account lockout. For SSH, 'blacklistd' blocks password guessing (the ssh section turns it on)"
}

# ============================================================================
# SECTION: firewall (pf)
# ============================================================================
crit_ports() {
  _p=""
  is_critical ssh openssh sshd && _p="$_p 22"
  is_critical apache nginx web http https && _p="$_p 80 443"
  is_critical ftp && _p="$_p 21"
  is_critical mysql mariadb database && _p="$_p 3306"
  is_critical postgresql postgres && _p="$_p 5432"
  is_critical samba smb && _p="$_p 139 445"
  is_critical dns bind unbound && _p="$_p 53"
  is_critical mail smtp postfix sendmail && _p="$_p 25"
  is_critical nfs && _p="$_p 111 2049"
  echo "$_p $EXTRA_PORTS" | tr -s ' ' | sed 's/^ //'
}

sec_firewall() {
  info "Packet filter firewall (pf)"
  why "Block every incoming connection except the services the README needs."
  _ports=$(crit_ports)
  _tports=$(echo "$_ports" | tr ' ' '\n' | grep -E '^[0-9]+$' | tr '\n' ' ')
  if [ "$(sysrc -n pf_enable 2>/dev/null)" = YES ] && [ -s /etc/pf.conf ]; then
    result OK "pf is enabled with /etc/pf.conf"
    grep -Ev '^[[:space:]]*(#|$)' /etc/pf.conf >"$WORK_DIR/pf.tmp"; result REVIEW "Existing pf rules - check they only open the README's ports"; show_file_list "$WORK_DIR/pf.tmp" 15; rm -f "$WORK_DIR/pf.tmp"
    return
  fi
  [ -n "$_tports" ] && info "Ports kept open for critical services: $_tports"
  _rules=$(mktemp)
  {
    echo "# /etc/pf.conf - written by the CyberPatriot toolkit (harden.sh)"
    echo "set skip on lo0"
    echo "set block-policy drop"
    echo "scrub in all"
    echo "block in log all"
    echo "pass out all keep state"
    echo "pass in inet proto icmp icmp-type { echoreq, unreach }"
    echo "pass in inet6 proto icmp6"
    [ -n "$_tports" ] && echo "pass in proto { tcp, udp } to port { $(echo "$_tports" | sed 's/ $//; s/ /, /g') } keep state"
  } >"$_rules"
  if [ "$MODE" = audit ]; then result WOULD "Write /etc/pf.conf (block incoming; allow: ${_tports:-nothing}) and enable pf"; rm -f "$_rules"; return; fi
  if ! pfctl -nf "$_rules" >>"$LOG_FILE" 2>&1; then result FAILED "Generated pf rules did not validate (see log)"; rm -f "$_rules"; return; fi
  backup /etc/pf.conf
  install -m 600 "$_rules" /etc/pf.conf; rm -f "$_rules"
  result CHANGED "Wrote /etc/pf.conf (block incoming; allow: ${_tports:-nothing})"
  set_rc pf_enable YES "pf starts at boot"
  set_rc pflog_enable YES "pf logs blocked packets"
  kldload -n pf 2>/dev/null
  fix "Start pf now" sh -c 'service pf start || pfctl -f /etc/pf.conf -e'
}

# ============================================================================
# SECTION: ssh
# ============================================================================
sec_ssh() {
  _c=/etc/ssh/sshd_config
  info "SSH server"
  why "Root login and empty passwords must be off."
  if [ "$(sysrc -n sshd_enable 2>/dev/null)" != YES ]; then result OK "sshd is not enabled"; return; fi
  if ! is_critical ssh openssh sshd; then
    result REVIEW "sshd is enabled but the README doesn't list SSH"
    ask "Disable sshd? (say NO if anyone logs in over SSH)" n strict && { set_rc sshd_enable NO "sshd off at boot"; fix "Stop sshd" service sshd onestop; return; }
  fi
  for _kv in "PermitRootLogin no" "PermitEmptyPasswords no" "X11Forwarding no" "MaxAuthTries 4" "LoginGraceTime 60" \
             "ClientAliveInterval 300" "ClientAliveCountMax 3" "HostbasedAuthentication no" "IgnoreRhosts yes" \
             "PermitUserEnvironment no" "AllowTcpForwarding no" "LogLevel VERBOSE" "UseBlacklist yes"; do
    set_conf "$_c" "${_kv%% *}" "$_kv"
  done
  if [ "$MODE" = apply ]; then
    if ! /usr/sbin/sshd -t >>"$LOG_FILE" 2>&1; then restore "$_c"; result FAILED "sshd config test failed - changes rolled back"; return; fi
    fix "Reload sshd" service sshd reload
  fi
  set_rc blacklistd_enable YES "blacklistd blocks SSH password guessing"
  [ "$MODE" = apply ] && run service blacklistd start
}

# ============================================================================
# SECTION: services
# ============================================================================
sec_services() {
  info "Services enabled in rc.conf"
  why "Every running service is something an attacker can try to break into."
  for _entry in "inetd_enable:inetd:inetd telnet ftp" "ftpd_enable:ftpd:ftp" "rpcbind_enable:rpcbind:nfs rpcbind" "nfs_server_enable:nfsd:nfs" \
                "telnetd_enable:telnetd:telnet" "tftpd_enable:tftpd:tftp" "snmpd_enable:snmpd:snmp" "bsnmpd_enable:bsnmpd:snmp" \
                "samba_server_enable:samba_server:samba smb" "apache24_enable:apache24:apache web http" "nginx_enable:nginx:nginx web http" \
                "mysql_enable:mysql-server:mysql database" "postgresql_enable:postgresql:postgresql database" "named_enable:named:dns bind" \
                "vsftpd_enable:vsftpd:ftp" "proftpd_enable:proftpd:ftp" "cupsd_enable:cupsd:cups print" "avahi_daemon_enable:avahi-daemon:avahi" \
                "x11vnc_enable:x11vnc:vnc" "lpd_enable:lpd:print"; do
    _var=${_entry%%:*}; _rest=${_entry#*:}; _svc=${_rest%%:*}; _keys=${_rest#*:}
    [ "$(sysrc -n "$_var" 2>/dev/null)" = YES ] || continue
    # shellcheck disable=SC2086
    if is_critical $_keys; then result OK "Critical service $_svc is enabled (keeping it)"; continue; fi
    result REVIEW "$_svc is enabled but the README doesn't list it"
    if ask "Disable $_svc?" y; then set_rc "$_var" NO "$_svc off at boot"; fix "Stop $_svc" service "$_svc" onestop; fi
  done
  if [ -f /etc/inetd.conf ] && grep -Ev '^[[:space:]]*(#|$)' /etc/inetd.conf | grep -q .; then
    result REVIEW "inetd.conf has active services: $(grep -Ev '^[[:space:]]*(#|$)' /etc/inetd.conf | awk '{print $1}' | tr '\n' ' ')"
    if ! is_critical inetd telnet ftp && ask "Comment out every service in /etc/inetd.conf?" y; then
      backup /etc/inetd.conf; fix "Disabled all inetd services" sed -i '' -E 's/^([^#[:space:]])/#\1/' /etc/inetd.conf
    fi
  fi
  if ! is_critical mail smtp sendmail postfix; then set_rc sendmail_enable NONE "Sendmail fully off (no mail server needed)"; fi
  set_rc syslogd_flags "-ss" "syslogd does not listen on the network"
  set_rc clear_tmp_enable YES "/tmp is emptied at every boot"
  set_rc dumpdev NO "No crash dumps (they can contain passwords)"
  result REVIEW "All enabled services: $(service -e 2>/dev/null | xargs -n1 basename 2>/dev/null | tr '\n' ' ')"
}

# ============================================================================
# SECTION: software
# ============================================================================
sec_software() {
  info "Prohibited packages (hacking tools, games, file sharing, remote access)"
  why "These are 'prohibited software' on almost every image."
  have pkg || { result SKIPPED "pkg is not set up"; return; }
  _found=$(pkg query '%n' 2>/dev/null | grep -Ei '^(nmap|zenmap|john|hydra|aircrack-ng|hashcat|nikto|sqlmap|wireshark|wireshark-lite|tshark|ettercap|metasploit|ophcrack|medusa|ncrack|netcat|socat|kismet|dsniff|hping3|masscan|crunch|minetest|luanti|supertux|supertuxkart|0ad|freeciv|wesnoth|openttd|xonotic|nethack.*|bsdgames|transmission.*|qbittorrent.*|deluge.*|rtorrent|amule|x11vnc|tigervnc-server|tightvnc|anydesk|teamviewer)$')
  if [ -z "$_found" ]; then result OK "No prohibited packages found"
  else
    for _p in $_found; do
      is_critical "$_p" && { result OK "Keeping $_p (README)"; continue; }
      result REVIEW "Prohibited package: $_p"
      ask "Remove $_p?" y && fix "Removed $_p" pkg delete -y "$_p"
    done
    [ "$MODE" = apply ] && run pkg autoremove -y
  fi
  result REVIEW "/usr/bin/nc (netcat) is part of FreeBSD itself and can't be removed - look for it in cron jobs and running processes instead"
  info "Known security holes in installed packages (pkg audit)"
  pkg audit -F >"$WORK_DIR/pkgaudit.txt" 2>&1
  if grep -q 'is vulnerable' "$WORK_DIR/pkgaudit.txt"; then
    grep 'is vulnerable' "$WORK_DIR/pkgaudit.txt" >"$WORK_DIR/pkgaudit2.txt"
    result REVIEW "Vulnerable packages (the updates section can upgrade them)"; show_file_list "$WORK_DIR/pkgaudit2.txt" 10
  else result OK "pkg audit found no known-vulnerable packages"; fi
  rm -f "$WORK_DIR"/pkgaudit*.txt
}

# ============================================================================
# SECTION: files
# ============================================================================
sec_files() {
  info "Media files and other files that break policy"
  warn "Answer the FORENSICS QUESTIONS first - they sometimes ask about these files!"
  _l=$WORK_DIR/media.txt
  find /home /usr/home /root /tmp /var/tmp /srv /usr/local/www /opt -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.wav' \
    -o -iname '*.flac' -o -iname '*.ogg' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.mov' -o -iname '*.wmv' -o -iname '*.wma' \
    -o -iname '*.m4a' -o -iname '*.aac' -o -iname '*.flv' -o -iname '*.mpg' -o -iname '*.mpeg' -o -iname '*.webm' -o -iname '*.torrent' \) \
    ! -path "$WORK_DIR/*" 2>/dev/null | sort -u >"$_l"
  if [ ! -s "$_l" ]; then result OK "No media files found"
  else
    result REVIEW "Found $(wc -l <"$_l" | tr -d ' ') media/torrent file(s)"; show_file_list "$_l" 20
    if ask "Delete ALL of them?" y; then fix "Deleted media files" sh -c "tr '\n' '\0' <'$_l' | xargs -0 rm -f"; fi
  fi
  rm -f "$_l"
}

# ============================================================================
# SECTION: kernel (sysctl)
# ============================================================================
sec_kernel() {
  info "Kernel security settings (/etc/sysctl.conf)"
  why "Hide other users' processes, block port scans and ICMP redirects, randomize memory layout."
  for _kv in security.bsd.see_other_uids=0 security.bsd.see_other_gids=0 security.bsd.see_jail_proc=0 \
             security.bsd.unprivileged_read_msgbuf=0 security.bsd.unprivileged_proc_debug=0 security.bsd.hardlink_check_uid=1 \
             security.bsd.hardlink_check_gid=1 kern.randompid=1 net.inet.tcp.blackhole=2 net.inet.udp.blackhole=1 \
             net.inet.ip.random_id=1 net.inet.ip.redirect=0 net.inet.icmp.drop_redirect=1 net.inet.ip.sourceroute=0 \
             net.inet.ip.accept_sourceroute=0 net.inet.tcp.drop_synfin=1 net.inet6.ip6.redirect=0 kern.elf64.aslr.enable=1; do
    sysctl -n "${_kv%%=*}" >/dev/null 2>&1 || continue
    set_conf /etc/sysctl.conf "$(echo "${_kv%%=*}" | sed 's/\./\\./g')" "$_kv" '[[:space:]]*='
    [ "$MODE" = apply ] && [ "$(sysctl -n "${_kv%%=*}")" != "${_kv#*=}" ] && run sysctl "$_kv"
  done
  if ! is_critical router forwarding gateway; then
    set_conf /etc/sysctl.conf 'net\.inet\.ip\.forwarding' net.inet.ip.forwarding=0 '[[:space:]]*='
    set_rc gateway_enable NO "This computer is not a router"
  fi
}

# ============================================================================
# SECTION: permissions
# ============================================================================
check_perm() { # PATH MODE OWNER GROUP
  [ -e "$1" ] || return 0
  _cur=$(stat -f '%Lp %Su %Sg' "$1")
  if [ "$_cur" = "$2 $3 $4" ]; then result OK "$1 is $2 $3:$4"; return; fi
  fix "$1 -> $2 $3:$4 (was $_cur)" sh -c "chown $3:$4 '$1' && chmod $2 '$1'"
}
sec_permissions() {
  info "Permissions on important files"
  check_perm /etc/master.passwd 600 root wheel
  check_perm /etc/spwd.db 600 root wheel
  check_perm /etc/passwd 644 root wheel
  check_perm /etc/pwd.db 644 root wheel
  check_perm /etc/group 644 root wheel
  check_perm /etc/login.conf 644 root wheel
  check_perm /etc/ssh/sshd_config 644 root wheel
  check_perm /etc/crontab 644 root wheel
  check_perm /root 700 root wheel
  check_perm /tmp 1777 root wheel
  check_perm /var/tmp 1777 root wheel
  [ -f /usr/local/etc/sudoers ] && check_perm /usr/local/etc/sudoers 440 root wheel
  [ -f /usr/local/etc/doas.conf ] && check_perm /usr/local/etc/doas.conf 640 root wheel
  for _h in $(awk -F: '$3 >= 1000 && $3 < 65534 { print $6 }' /etc/passwd); do
    [ -d "$_h" ] || continue
    _m=$(stat -f '%Lp' "$_h")
    case $_m in *0) result OK "$_h is private ($_m)" ;; *) fix "$_h: remove access for other users (was $_m)" chmod o-rwx "$_h" ;; esac
  done
  info "Programs that run as root for any user (SUID/SGID)"
  _l=$WORK_DIR/suid.txt
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null >"$_l"
  _bad=$(grep -E '/(find|vi|vim|nvi|ex|nano|ee|bash|sh|csh|tcsh|zsh|dash|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|lua[0-9.]*|php[0-9.]*|node|cp|mv|less|more|awk|tar|env|tee|dd|chmod|chown|nmap|nc|socat|curl|fetch|cat|sed|xargs|gdb|truss)$' "$_l")
  for _f in $_bad; do
    result REVIEW "DANGEROUS: $_f has SUID/SGID (lets any user become root)"
    ask "Remove SUID/SGID from $_f?" y && fix "Removed SUID/SGID from $_f" chmod u-s,g-s "$_f"
  done
  [ -z "$_bad" ] && result OK "No dangerous SUID/SGID programs"
  grep -Ev '/(passwd|chpass|chfn|chsh|ypchpass|ypchfn|ypchsh|login|su|crontab|at|atq|atrm|batch|lpr|lpq|lprm|quota|ppp|ping|ping6|traceroute|traceroute6|shutdown|wall|write|fstat|netstat|btsockstat|mount_.*|sudo|sudoedit|doas|Xorg\.wrap|dbus-daemon-launch-helper|polkit-agent-helper-1|pkexec|ssh-keysign|opieinfo|opiepasswd|rcp|rlogin|rsh|kpasswd|ksu|dma|sendmail|man|lock|w|chkpwd|unix_chkpwd)$' "$_l" >"$_l.2"
  [ -s "$_l.2" ] && { result REVIEW "SUID/SGID programs that are not on the normal list - look each one up"; show_file_list "$_l.2" 15; }
  rm -f "$_l" "$_l.2"
}

# ============================================================================
# SECTION: sudo / doas
# ============================================================================
sec_sudo() {
  info "sudo and doas rules"
  why "A rule with NOPASSWD / nopass lets someone become root without a password."
  for _f in /usr/local/etc/sudoers /usr/local/etc/sudoers.d/*; do
    [ -f "$_f" ] || continue
    if grep -Eq '^[^#]*(NOPASSWD|!authenticate)' "$_f"; then
      result REVIEW "$_f has NOPASSWD / !authenticate rules"
      if ask "Remove NOPASSWD and !authenticate from $_f?" y; then
        backup "$_f"
        sed -i '' -E 's/NOPASSWD:[[:space:]]*//; /^[^#]*!authenticate/s/^/# /' "$_f"
        if run visudo -c; then result CHANGED "Removed NOPASSWD from $_f"; else restore "$_f"; result FAILED "visudo check failed - restored $_f"; fi
      fi
    else result OK "$_f has no NOPASSWD rules"; fi
    grep -Ev '^[[:space:]]*(#|$|Defaults|root|%wheel|%sudo|@include)' "$_f" | grep -E '=' | while IFS= read -r _line; do
      _who=$(echo "$_line" | awk '{print $1}')
      in_list "$_who" $AUTHORIZED_ADMINS || result REVIEW "$_f gives '$_who' rights: $_line"
    done
  done
  if [ -f /usr/local/etc/doas.conf ]; then
    if grep -Eq '^[^#]*permit[[:space:]]+nopass' /usr/local/etc/doas.conf; then
      result REVIEW "doas.conf has 'permit nopass' rules"
      if ask "Remove 'nopass' from doas.conf?" y; then
        backup /usr/local/etc/doas.conf
        fix "Removed nopass from doas.conf" sed -i '' -E 's/permit[[:space:]]+nopass/permit/' /usr/local/etc/doas.conf
      fi
    else result OK "doas.conf has no nopass rules"; fi
  fi
}

# ============================================================================
# SECTION: backdoors
# ============================================================================
SUSP='(\bnc\b|ncat|netcat|/dev/tcp|bash -i|sh -i|mkfifo|socat|(curl|fetch|wget)[^|]*\|[[:space:]]*(ba)?sh|base64 -d|b64decode|python[0-9.]* -c|perl -e|chmod [ugoa]*\+s|nohup)'
sec_backdoors() {
  info "Cron jobs"
  for _f in /var/cron/tabs/*; do
    [ -f "$_f" ] || continue
    _u=$(basename "$_f")
    grep -Ev '^[[:space:]]*(#|$)' "$_f" >"$WORK_DIR/cron.tmp"
    [ -s "$WORK_DIR/cron.tmp" ] || continue
    if ! id "$_u" >/dev/null 2>&1 || ! in_list "$_u" root $AUTHORIZED_ADMINS $AUTHORIZED_USERS; then
      result REVIEW "Crontab for unauthorized or deleted user '$_u'"; show_file_list "$WORK_DIR/cron.tmp" 5
      ask "Delete $_u's crontab?" y && fix "Deleted crontab of $_u" rm -f "$_f"
    elif grep -Eq "$SUSP" "$WORK_DIR/cron.tmp"; then
      result REVIEW "SUSPICIOUS cron job(s) for $_u (edit with: crontab -e -u $_u)"; show_file_list "$WORK_DIR/cron.tmp" 5
    else
      result REVIEW "User $_u has cron jobs - make sure they are legitimate"; show_file_list "$WORK_DIR/cron.tmp" 5
    fi
  done
  rm -f "$WORK_DIR/cron.tmp"
  grep -En "$SUSP" /etc/crontab /etc/periodic.conf /etc/rc.local /etc/rc.conf.local 2>/dev/null >"$WORK_DIR/s.tmp" && {
    result REVIEW "Suspicious lines in system start-up/cron files"; show_file_list "$WORK_DIR/s.tmp" 10; }

  info "Start-up scripts that did not come from a package (/usr/local/etc/rc.d)"
  for _f in /usr/local/etc/rc.d/*; do
    [ -f "$_f" ] || continue
    pkg which -q "$_f" >/dev/null 2>&1 || result REVIEW "rc.d script not installed by any package: $_f"
  done

  info "Shell start-up files"
  for _f in /etc/profile /etc/csh.cshrc /etc/csh.login /root/.profile /root/.cshrc /root/.shrc \
            $(awk -F: '$3 >= 1000 && $3 < 65534 { print $6"/.profile "$6"/.shrc "$6"/.cshrc "$6"/.login "$6"/.bashrc" }' /etc/passwd); do
    [ -f "$_f" ] || continue
    grep -Hn -E "$SUSP|^[[:space:]]*alias[[:space:]]+(su|sudo|doas|ls|ps|sockstat|passwd)[[:space:]=]" "$_f" 2>/dev/null
  done >"$WORK_DIR/s.tmp"
  if [ -s "$WORK_DIR/s.tmp" ]; then result REVIEW "Suspicious lines in shell start-up files"; show_file_list "$WORK_DIR/s.tmp" 10
  else result OK "No suspicious shell start-up lines"; fi

  info "SSH keys that allow password-less login"
  for _h in /root $(awk -F: '$3 >= 1000 && $3 < 65534 { print $6 }' /etc/passwd); do
    _f=$_h/.ssh/authorized_keys
    [ -s "$_f" ] || continue
    result REVIEW "$_f has $(grep -cv '^#' "$_f") key(s)"
    _d=n; [ "$_h" = /root ] && _d=y
    ask "Remove $_f?" "$_d" strict && { backup "$_f"; fix "Removed $_f" rm -f "$_f"; }
  done

  info "Programs listening on the network"
  sockstat -46l 2>/dev/null | awk 'NR > 1 { print $2"  "$3"  "$5"  "$6 }' | sort -u >"$WORK_DIR/s.tmp"
  result REVIEW "Listening programs - compare with the README's critical services"; show_file_list "$WORK_DIR/s.tmp" 20
  grep -E '^(nc|ncat|socat|python[0-9.]*|perl|ruby|sh|bash|csh|tcsh) ' "$WORK_DIR/s.tmp" | while read -r _cmd _pid _rest; do
    result REVIEW "POSSIBLE BACKDOOR: $_cmd (PID $_pid) is listening on $_rest"
    ask "Kill process $_pid?" y && fix "Killed $_pid" kill -9 "$_pid"
  done

  info "/etc/hosts entries"
  grep -Ev '^[[:space:]]*(#|$)' /etc/hosts | grep -Ev "^[[:space:]]*(127\.0\.0\.1|::1)[[:space:]]+localhost([[:space:]]+localhost\.my\.domain)?[[:space:]]*$|[[:space:]]$(hostname)([[:space:]]|$)" >"$WORK_DIR/s.tmp"
  if [ -s "$WORK_DIR/s.tmp" ]; then result REVIEW "Unusual /etc/hosts entries (edit with: ee /etc/hosts)"; show_file_list "$WORK_DIR/s.tmp" 10
  else result OK "/etc/hosts only has normal entries"; fi

  info "Kernel modules loaded at boot (/boot/loader.conf)"
  grep -E '_load="?YES' /boot/loader.conf /boot/loader.conf.local 2>/dev/null >"$WORK_DIR/s.tmp"
  [ -s "$WORK_DIR/s.tmp" ] && { result REVIEW "Modules loaded at boot - check each one is expected"; show_file_list "$WORK_DIR/s.tmp" 10; }
  rm -f "$WORK_DIR/s.tmp"

  info "Base system file integrity (freebsd-update IDS)"
  if [ "$MODE" = apply ] && ask "Compare all FreeBSD system files with official checksums? (needs internet, a few minutes)" y; then
    env PAGER=cat freebsd-update IDS 2>/dev/null | grep -v '^Looking\|^Fetching\|^Inspecting\|^Preparing\|^done' | grep '/' >"$WORK_DIR/ids.txt"
    if [ -s "$WORK_DIR/ids.txt" ]; then result REVIEW "System files that differ from the official release (config files in /etc are normal)"; show_file_list "$WORK_DIR/ids.txt" 20
    else result OK "No modified system files reported"; fi
    rm -f "$WORK_DIR/ids.txt"
  else result REVIEW "Run 'freebsd-update IDS' to find modified system programs"; fi
}

# ============================================================================
# SECTION: logging
# ============================================================================
sec_logging() {
  info "System logging and security auditing"
  set_rc syslogd_enable YES "syslogd is on"
  set_rc auditd_enable YES "auditd (security audit log) starts at boot"
  if [ -f /etc/security/audit_control ]; then
    set_conf /etc/security/audit_control 'flags' 'flags:lo,aa,ad' ':'
  fi
  [ "$MODE" = apply ] && run service auditd start
}

# ============================================================================
# SECTION: updates
# ============================================================================
sec_updates() {
  info "Updates"
  why "Security fixes come out regularly; old software is the easiest way in."
  if [ "$MODE" = audit ]; then
    result REVIEW "Run updates: freebsd-update fetch install  and  pkg upgrade"
    return
  fi
  _go=0
  case $FULL_UPGRADE in yes) _go=1 ;; no) ;; *) ask "Install FreeBSD and package updates now? (can take 10+ minutes)" y && _go=1 ;; esac
  [ $_go -eq 1 ] || { result SKIPPED "Updates not installed"; return; }
  fix "FreeBSD base system updates (freebsd-update)" sh -c 'PAGER=cat freebsd-update --not-running-from-cron fetch install || true'
  fix "Package updates (pkg upgrade)" sh -c 'pkg update -f && pkg upgrade -y'
  result REVIEW "If the kernel was updated, reboot once near the end"
}

# ============================================================================
# Main
# ============================================================================
summary() {
  header "Summary"
  for _s in OK CHANGED WOULD SKIPPED REVIEW FAILED; do printf '  %s %s  ' "$_s" "$(grep -c "^$_s|" "$RESULTS_FILE" 2>/dev/null)"; done; echo
  echo "  To-do list: $REPORT_FILE"
  echo "  Log:        $LOG_FILE"
  echo "  Backups:    $BACKUP_DIR"
}
run_section() {
  SECTION=$1
  header "$1   [$(echo "$MODE" | tr '[:lower:]' '[:upper:]')]"
  printf '\n## %s\n\n' "$1" >>"$REPORT_FILE"
  case $1 in
    users) sec_users ;; passwords) sec_passwords ;; firewall) sec_firewall ;; ssh) sec_ssh ;; services) sec_services ;;
    software) sec_software ;; files) sec_files ;; kernel) sec_kernel ;; permissions) sec_permissions ;; sudo) sec_sudo ;;
    backdoors) sec_backdoors ;; logging) sec_logging ;; updates) sec_updates ;; *) warn "Unknown section: $1" ;;
  esac
  SECTION=setup
}
confirm_apply() {
  [ "$MODE" = apply ] || return 0
  [ -n "$CONFIRMED" ] && return 0
  warn "APPLY mode changes this computer. Answer the FORENSICS QUESTIONS first and make sure there is a snapshot."
  if [ "$ASSUME_YES" -eq 1 ] || ask "Ready to make changes?" n; then CONFIRMED=1; return 0; fi
  return 1
}
menu() {
  while :; do
    header "Main menu (mode: $MODE)"
    _i=1; for _s in $SECTIONS; do printf '  %2d) %s\n' $_i "$_s"; _i=$((_i + 1)); done
    echo "   a) all sections   m) switch audit/apply   q) quit"
    printf '%s  Choose: %s' "$YLW" "$RST"; read -r _c </dev/tty || break
    case $_c in
      q) break ;;
      a) confirm_apply && for _s in $SECTIONS; do run_section "$_s"; done ;;
      m) if [ "$MODE" = audit ]; then MODE=apply; else MODE=audit; fi ;;
      *) confirm_apply && for _n in $_c; do _s=$(echo "$SECTIONS" | tr ' ' '\n' | sed -n "${_n}p"); [ -n "$_s" ] && run_section "$_s"; done ;;
    esac
  done
}

while [ $# -gt 0 ]; do
  case $1 in
    --audit) MODE=audit ;; --apply) MODE=apply ;; -y|--yes) ASSUME_YES=1 ;;
    --config) CONFIG_FILE=$2; shift ;; --only) ONLY=$2; shift ;;
    --list) echo "$SECTIONS" | tr ' ' '\n'; exit 0 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "Unknown option $1 (try --help)"; exit 1 ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "Run this as root (use: su -)"; exit 1; }
[ "$(uname -s)" = FreeBSD ] || { echo "This script is for FreeBSD. Use scripts/linux/harden.sh on Linux."; exit 1; }
mkdir -p "$WORK_DIR" && chmod 700 "$WORK_DIR"
: >"$LOG_FILE"; : >"$RESULTS_FILE"
printf '# Findings report - %s\n' "$(date)" >"$REPORT_FILE"
printf '\n%s CyberPatriot Toolkit - FreeBSD hardening v%s%s\n' "$CYN" "$VERSION" "$RST"
echo "  System: $(freebsd-version 2>/dev/null || uname -r)"
if [ -n "$CONFIG_FILE" ]; then load_config "$CONFIG_FILE"; elif [ "$ASSUME_YES" -eq 0 ]; then prompt_readme; fi
finalize_readme
if [ -z "$MODE" ]; then MODE=audit; echo "  Starting in AUDIT mode (nothing changes). Use 'm' to switch to APPLY."; menu
elif confirm_apply; then
  for _s in $(echo "${ONLY:-$SECTIONS}" | tr ',' ' '); do run_section "$_s"; done
fi
summary
rm -f "$RESULTS_FILE"
