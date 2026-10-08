#!/usr/bin/env bash
# shellcheck disable=SC2086,SC2016,SC2013,SC2009  # word lists are split on purpose; some $ are literal
# =============================================================================
#  CyberPatriot Practice Toolkit - Linux Hardening Script
#
#  Works on:  Linux Mint 20 / 21 / 22,  Debian 11 / 12,  Ubuntu 20.04 / 22.04 / 24.04
#
#  READ FIRST: docs/start-here/using-the-scripts.md
#
#  The golden rule: THE README DECIDES WHAT IS SAFE. This script asks you for
#  the authorized users, admins and critical services from the README before it
#  changes anything, and it never removes or disables something you list.
#
#  Usage:
#    sudo bash harden.sh                    interactive menu (recommended)
#    sudo bash harden.sh --audit            report problems only, change NOTHING
#    sudo bash harden.sh --apply            fix problems (asks before risky steps)
#    sudo bash harden.sh --apply --yes      fix problems, answer "yes" to prompts
#    sudo bash harden.sh --config FILE      load README info from a config file
#    sudo bash harden.sh --only users,ssh   run only some sections
#    sudo bash harden.sh --list             list the sections
#    sudo bash harden.sh --help             show this help
#
#  Everything is logged to /root/cyberpatriot/. Every file is backed up before
#  it is edited, to /root/cyberpatriot/backups/<date-time>/<original path>.
# =============================================================================

if [ -z "${BASH_VERSION:-}" ]; then echo "Please run this script with bash:  sudo bash $0" >&2; exit 1; fi

SCRIPT_VERSION="2.0.0"

# ----------------------------------------------------------------------------
# Settings (filled in from the command line, the config file, or prompts)
# ----------------------------------------------------------------------------
MODE=""                  # audit | apply
ASSUME_YES=0             # 1 = answer yes to normal prompts
CONFIG_FILE=""
ONLY_SECTIONS=""
NO_COLOR=0

AUTHORIZED_USERS=""      # standard (non-admin) users from the README
AUTHORIZED_ADMINS=""     # administrators from the README
CRITICAL_SERVICES=""     # services the README says must keep running
NEW_PASSWORD=""          # password to give users (blank = ask, "skip" = don't)
ENABLE_LOCKOUT="ask"     # account lockout after failed logins: yes | no | ask
FULL_UPGRADE="ask"       # run a full apt upgrade: yes | no | ask
SSH_PASSWORD_AUTH="keep" # PasswordAuthentication in sshd: yes | no | keep
EXTRA_PORTS=""           # extra firewall ports to allow, e.g. "8080/tcp 5000"

RUN_ID=$(date +%Y%m%d-%H%M%S)
WORK_DIR="/root/cyberpatriot"
BACKUP_DIR="$WORK_DIR/backups/$RUN_ID"
LOG_FILE="$WORK_DIR/harden-$RUN_ID.log"
REPORT_FILE="$WORK_DIR/findings-$RUN_ID.txt"

export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-y -q -o DPkg::Lock::Timeout=180 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

# Section id | title | function
SECTIONS=(
  "users|Users and groups|sec_users"
  "passwords|Password and lockout policy|sec_passwords"
  "firewall|Firewall (UFW)|sec_firewall"
  "ssh|SSH server|sec_ssh"
  "services|Services|sec_services"
  "software|Prohibited software|sec_software"
  "files|Prohibited files (media etc.)|sec_files"
  "kernel|Kernel and network settings (sysctl)|sec_kernel"
  "permissions|File permissions|sec_permissions"
  "sudoers|Sudo rules|sec_sudoers"
  "backdoors|Backdoors and persistence|sec_backdoors"
  "logging|Logging and auditing|sec_logging"
  "apparmor|AppArmor|sec_apparmor"
  "desktop|Login screen and screen lock|sec_desktop"
  "apps|Critical service hardening (web, database, FTP...)|sec_apps"
  "updates|Updates|sec_updates"
)

# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------
setup_colors() {
  if [[ -t 1 && $NO_COLOR -eq 0 ]]; then
    C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YLW=$'\e[33m'; C_BLU=$'\e[34m'
    C_CYN=$'\e[36m'; C_BLD=$'\e[1m'; C_DIM=$'\e[2m'; C_RST=$'\e[0m'
  else
    C_RED=""; C_GRN=""; C_YLW=""; C_BLU=""; C_CYN=""; C_BLD=""; C_DIM=""; C_RST=""
  fi
}

_log() { printf '%s %s\n' "$(date '+%H:%M:%S')" "$*" >>"$LOG_FILE" 2>/dev/null; }

say()  { printf '%s\n' "$*"; _log "$*"; }
info() { printf '%s  *%s %s\n' "$C_BLU" "$C_RST" "$*"; _log "INFO   $*"; }
why()  { printf '%s      why: %s%s\n' "$C_DIM" "$*" "$C_RST"; _log "WHY    $*"; }
warn() { printf '%s  ! %s%s\n' "$C_YLW" "$*" "$C_RST"; _log "WARN   $*"; }
die()  { printf '%sERROR: %s%s\n' "$C_RED" "$*" "$C_RST" >&2; exit 1; }

header() {
  printf '\n%s%s== %s ==%s\n' "$C_BLD" "$C_CYN" "$*" "$C_RST"
  _log "===== $* ====="
}

# Results: every check/fix records one line. Shown in the summary at the end.
#   OK      already secure          CHANGED  fixed by this script
#   WOULD   audit mode: would fix   SKIPPED  not done (your choice / not relevant)
#   FAILED  tried and failed        REVIEW   a human needs to look at this
RESULTS=()
CURRENT_SECTION="setup"

result() {
  local status=$1; shift
  local color=""
  case $status in
    OK|CHANGED) color=$C_GRN ;;
    WOULD)      color=$C_CYN ;;
    SKIPPED)    color=$C_DIM ;;
    FAILED)     color=$C_RED ;;
    REVIEW)     color=$C_YLW ;;
  esac
  RESULTS+=("$status|$CURRENT_SECTION|$*")
  printf '  %s[%-7s]%s %s\n' "$color" "$status" "$C_RST" "$*"
  _log "$status $*"
  case $status in
    REVIEW|FAILED|WOULD) printf -- '- [ ] %-7s (%s) %s\n' "$status" "$CURRENT_SECTION" "$*" >>"$REPORT_FILE" ;;
  esac
}

# Extra lines (file lists etc.) for the findings report, indented under the last item.
report_detail() {
  local line
  for line in "$@"; do printf '        %s\n' "$line" >>"$REPORT_FILE"; done
}

# Show a list on screen (first N lines) and put all of it in the report.
show_list() {
  local max=${1:-15}; shift
  local count=0 line
  for line in "$@"; do
    count=$((count + 1))
    if (( count <= max )); then printf '%s          %s%s\n' "$C_DIM" "$line" "$C_RST"; fi
  done
  if (( count > max )); then printf '%s          ... and %d more (full list in %s)%s\n' "$C_DIM" $((count - max)) "$REPORT_FILE" "$C_RST"; fi
  report_detail "$@"
}

# ----------------------------------------------------------------------------
# Prompts
# ----------------------------------------------------------------------------
HAVE_TTY=0
if { : </dev/tty; } 2>/dev/null; then HAVE_TTY=1; fi

read_tty() { # read one line from the keyboard into REPLY
  REPLY=""
  if [[ $HAVE_TTY -eq 1 ]]; then IFS= read -r REPLY </dev/tty || REPLY=""; fi
}

# ask "Question?" [y|n default] [strict]
#   audit mode -> always "no" (audit never changes anything)
#   --yes      -> "yes", unless strict (then the default is used)
#   no keyboard -> the default
ask() {
  local q=$1 def=${2:-n} strict=${3:-} hint
  [[ $MODE == audit ]] && return 1
  if [[ $ASSUME_YES -eq 1 ]]; then
    if [[ -n $strict ]]; then [[ $def == y ]]; return; fi
    return 0
  fi
  if [[ $HAVE_TTY -eq 0 ]]; then [[ $def == y ]]; return; fi
  if [[ $def == y ]]; then hint="[Y/n]"; else hint="[y/N]"; fi
  while true; do
    printf '%s  ? %s %s%s ' "$C_YLW" "$q" "$hint" "$C_RST"
    read_tty
    local ans=${REPLY,,}
    [[ -z $ans ]] && ans=$def
    case $ans in
      y|yes) _log "ASK    $q -> yes"; return 0 ;;
      n|no)  _log "ASK    $q -> no";  return 1 ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Running commands
# ----------------------------------------------------------------------------
# run CMD...   run a command (or function); its output goes to the log file only
run() {
  _log "RUN    $*"
  "$@" >>"$LOG_FILE" 2>&1
}

# fix "description" CMD...   audit: report WOULD.  apply: run it, report CHANGED/FAILED
fix() {
  local desc=$1; shift
  if [[ $MODE == audit ]]; then result WOULD "$desc"; return 0; fi
  if run "$@"; then result CHANGED "$desc"; return 0; fi
  result FAILED "$desc (details in $LOG_FILE)"
  return 1
}

# backup FILE...   copy files into the backup folder (only the first time per run)
backup() {
  local f
  for f in "$@"; do
    [[ -e $f ]] || continue
    [[ -e "$BACKUP_DIR$f" ]] && continue
    mkdir -p "$BACKUP_DIR" && cp -a --parents "$f" "$BACKUP_DIR/" 2>>"$LOG_FILE" && _log "BACKUP $f -> $BACKUP_DIR$f"
  done
}

restore() { # restore FILE from this run's backup
  local f=$1
  if [[ -e "$BACKUP_DIR$f" ]]; then cp -a "$BACKUP_DIR$f" "$f" && _log "RESTORE $f"; fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# ----------------------------------------------------------------------------
# Staged file editing
#   stage_begin FILE          start editing a copy of FILE
#   stage_set ...             change lines in the copy (see below)
#   stage_commit "desc" [VALIDATOR CMD...]
#                             compare copy to the real file:
#                               same     -> OK (already correct)
#                               audit    -> WOULD (lists what would change)
#                               apply    -> back up, write, validate; roll back
#                                           if the validator command fails
# ----------------------------------------------------------------------------
STAGE_FILE=""; STAGE_TMP=""; STAGE_CHANGES=()

stage_begin() {
  STAGE_FILE=$1
  STAGE_TMP=$(mktemp)
  STAGE_CHANGES=()
  if [[ -f $STAGE_FILE ]]; then cat "$STAGE_FILE" >"$STAGE_TMP"; fi
}

# _xf_set_line FILE KEYRE NEWLINE STOPRE COMMENTRE
#   Find the first active line whose lowercase text matches ^\s*KEYRE (before any
#   line matching STOPRE). Replace it with NEWLINE and comment out later
#   duplicates. If there is no active line, replace the first commented one.
#   If there is neither, insert NEWLINE before the STOPRE line, or append.
_xf_set_line() {
  local file=$1 out
  out=$(mktemp)
  KEYRE=$2 NEWLINE=$3 STOPRE=$4 CMT=$5 awk '
    BEGIN { keyre=ENVIRON["KEYRE"]; nl=ENVIRON["NEWLINE"]; stop=ENVIRON["STOPRE"]; cmt=ENVIRON["CMT"]; if (cmt=="") cmt="#" }
    { line[NR]=$0 }
    END {
      limit=NR; stopline=0
      if (stop != "") for (i=1;i<=NR;i++) if (tolower(line[i]) ~ stop) { limit=i-1; stopline=i; break }
      target=0; mode=""
      for (i=1;i<=limit;i++) if (tolower(line[i]) ~ ("^[ \t]*" keyre)) { target=i; mode="active"; break }
      if (!target) for (i=1;i<=limit;i++) if (tolower(line[i]) ~ ("^[ \t]*[" cmt "]+[ \t]*" keyre)) { target=i; mode="comment"; break }
      for (i=1;i<=NR;i++) {
        if (!target && stopline && i==stopline) print nl
        if (i==target) { print nl; continue }
        if (mode=="active" && i>target && i<=limit && tolower(line[i]) ~ ("^[ \t]*" keyre)) { print substr(cmt,1,1) " " line[i] "   " substr(cmt,1,1) " (duplicate, disabled by harden.sh)"; continue }
        print line[i]
      }
      if (!target && !stopline) print nl
    }' "$file" >"$out" && cat "$out" >"$file"
  rm -f "$out"
}

# stage_set KEYRE NEWLINE [STOPRE] [COMMENT-CHARS]
#   KEYRE is a lowercase regex for the start of the setting, e.g. "pass_max_days[ \t]"
stage_set() {
  local before
  before=$(md5sum <"$STAGE_TMP")
  _xf_set_line "$STAGE_TMP" "$1" "$2" "${3:-}" "${4:-#}"
  [[ $(md5sum <"$STAGE_TMP") != "$before" ]] && STAGE_CHANGES+=("$2")
}

# stage_ini SECTION KEY VALUE    (for files like lightdm.conf / gdm3 daemon.conf)
stage_ini() {
  local before out
  before=$(md5sum <"$STAGE_TMP")
  out=$(mktemp)
  SEC=$1 KEY=$2 VAL=$3 awk '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function iskey(l,   k) { k=ENVIRON["KEY"]; sub(/^[ \t]*[#;]*[ \t]*/, "", l); return (index(l, k)==1 && substr(l, length(k)+1) ~ /^[ \t]*=/) }
    BEGIN { sec=ENVIRON["SEC"]; key=ENVIRON["KEY"]; val=ENVIRON["VAL"]; insec=0; done=0 }
    /^[ \t]*\[/ {
      if (insec && !done) { print key "=" val; done=1 }
      insec = (trim($0) == "[" sec "]"); print; next
    }
    insec && !done && iskey($0) { print key "=" val; done=1; next }
    insec && done && $0 !~ /^[ \t]*[#;]/ && iskey($0) { next }
    { print }
    END { if (!done) { if (!insec) { print ""; print "[" sec "]" }; print key "=" val } }
  ' "$STAGE_TMP" >"$out" && cat "$out" >"$STAGE_TMP"
  rm -f "$out"
  [[ $(md5sum <"$STAGE_TMP") != "$before" ]] && STAGE_CHANGES+=("[$1] $2=$3")
}

# stage_replace_all SED-EXPRESSION DESCRIPTION   (free-form edit with sed -E)
stage_sed() {
  local before
  before=$(md5sum <"$STAGE_TMP")
  sed -E -i "$1" "$STAGE_TMP"
  [[ $(md5sum <"$STAGE_TMP") != "$before" ]] && STAGE_CHANGES+=("$2")
}

# stage_content < text    (replace the whole file with stdin)
stage_content() {
  local before
  before=$(md5sum <"$STAGE_TMP")
  cat >"$STAGE_TMP"
  [[ $(md5sum <"$STAGE_TMP") != "$before" ]] && STAGE_CHANGES+=("write $STAGE_FILE")
}

stage_commit() {
  local desc=$1; shift
  local file=$STAGE_FILE changes
  if [[ -f $file ]] && cmp -s "$STAGE_TMP" "$file"; then
    rm -f "$STAGE_TMP"; result OK "$desc"; return 0
  fi
  if [[ ! -f $file && ${#STAGE_CHANGES[@]} -eq 0 ]]; then
    rm -f "$STAGE_TMP"; result OK "$desc"; return 0
  fi
  changes=$(printf '%s; ' "${STAGE_CHANGES[@]}"); changes=${changes%; }
  if [[ $MODE == audit ]]; then
    rm -f "$STAGE_TMP"; result WOULD "$desc -> $changes"; return 0
  fi
  backup "$file"
  local existed=1
  [[ -f $file ]] || { existed=0; mkdir -p "$(dirname "$file")"; install -m 644 /dev/null "$file"; }
  cat "$STAGE_TMP" >"$file"
  rm -f "$STAGE_TMP"
  if [[ $# -gt 0 ]] && ! run "$@"; then
    if [[ $existed -eq 1 ]]; then restore "$file"; else rm -f "$file"; fi
    result FAILED "$desc (validation failed, change rolled back - see log)"
    return 1
  fi
  _log "EDITED $file: $changes"
  result CHANGED "$desc -> $changes"
  return 0
}

# ----------------------------------------------------------------------------
# System detection and package / service helpers
# ----------------------------------------------------------------------------
OS_ID="unknown"; OS_NAME="Unknown Linux"; OS_LIKE=""
IS_MINT=0; IS_DEBIAN=0; IS_UBUNTU=0; HAS_SYSTEMD=0; DISPLAY_MANAGER=""; DESKTOP=""

detect_os() {
  local k v
  if [[ -r /etc/os-release ]]; then
    while IFS='=' read -r k v; do
      v=${v#\"}; v=${v%\"}
      case $k in
        ID) OS_ID=$v ;;
        PRETTY_NAME) OS_NAME=$v ;;
        ID_LIKE) OS_LIKE=$v ;;
      esac
    done </etc/os-release
  fi
  case $OS_ID in
    linuxmint) IS_MINT=1 ;;
    ubuntu)    IS_UBUNTU=1 ;;
    debian)    IS_DEBIAN=1 ;;
    *)
      if [[ $OS_LIKE == *ubuntu* ]]; then IS_UBUNTU=1
      elif [[ $OS_LIKE == *debian* ]]; then IS_DEBIAN=1; fi ;;
  esac
  [[ -d /run/systemd/system ]] && HAS_SYSTEMD=1
  if [[ -r /etc/X11/default-display-manager ]]; then
    DISPLAY_MANAGER=$(basename "$(cat /etc/X11/default-display-manager)")
  fi
  if pkg_installed cinnamon || pkg_installed cinnamon-core; then DESKTOP="cinnamon"
  elif pkg_installed mate-session-manager; then DESKTOP="mate"
  elif pkg_installed xfce4-session; then DESKTOP="xfce"
  elif pkg_installed gnome-shell; then DESKTOP="gnome"
  elif pkg_installed plasma-workspace; then DESKTOP="kde"
  fi
}

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }

APT_UPDATED=0
apt_update_once() {
  [[ $APT_UPDATED -eq 1 ]] && return 0
  info "Refreshing the package lists (apt-get update). This can take a minute..."
  if run apt-get "${APT_OPTS[@]}" update; then APT_UPDATED=1; return 0; fi
  warn "apt-get update failed - is the internet working? Package installs may fail."
  return 1
}

# ensure_pkg PKG... "why"   install packages if missing (apply mode only)
ensure_pkg() {
  local reason=${*: -1} missing=() p
  for p in "${@:1:$#-1}"; do pkg_installed "$p" || missing+=("$p"); done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  if [[ $MODE == audit ]]; then result WOULD "Install ${missing[*]} ($reason)"; return 1; fi
  apt_update_once
  fix "Install ${missing[*]} ($reason)" apt-get "${APT_OPTS[@]}" install "${missing[@]}"
}

unit_exists() { [[ $HAS_SYSTEMD -eq 1 ]] && systemctl cat "$1" >/dev/null 2>&1; }
unit_active() { systemctl is-active --quiet "$1" 2>/dev/null; }
unit_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }

# ----------------------------------------------------------------------------
# README information
# ----------------------------------------------------------------------------
normalize_list() { # lowercase-free normalization: commas -> spaces, squeeze, trim
  local s=$*
  s=${s//,/ }; s=${s//;/ }
  # shellcheck disable=SC2086
  set -- $s
  printf '%s' "$*"
}

in_list() { # in_list WORD LIST...
  local w=$1 x; shift
  for x in "$@"; do [[ $x == "$w" ]] && return 0; done
  return 1
}

is_critical() { # is_critical KEYWORD...  -> true if any keyword is in CRITICAL_SERVICES
  local k c
  for k in "$@"; do
    for c in $CRITICAL_SERVICES; do
      [[ ${c,,} == "${k,,}" ]] && return 0
    done
  done
  return 1
}

load_config() {
  local file=$1 line key val
  [[ -r $file ]] || die "Cannot read config file: $file"
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
    key=${BASH_REMATCH[1]}; val=${BASH_REMATCH[2]}
    # Quoted values are taken exactly (a password may contain '#'). Unquoted values
    # may have a trailing " # comment".
    if [[ $val =~ ^\"([^\"]*)\" ]]; then val=${BASH_REMATCH[1]}
    elif [[ $val =~ ^\'([^\']*)\' ]]; then val=${BASH_REMATCH[1]}
    else val=${val%%[[:space:]]#*}; val=${val%"${val##*[![:space:]]}"}; fi
    case $key in
      AUTHORIZED_USERS|AUTHORIZED_ADMINS|CRITICAL_SERVICES|NEW_PASSWORD|ENABLE_LOCKOUT|FULL_UPGRADE|SSH_PASSWORD_AUTH|EXTRA_PORTS)
        printf -v "$key" '%s' "$val" ;;
      *) warn "Unknown setting in config file ignored: $key" ;;
    esac
  done <"$file"
}

list_human_users() { # users with UID in the normal range and a real home
  local min max
  min=$(awk '/^UID_MIN/{print $2}' /etc/login.defs 2>/dev/null); min=${min:-1000}
  max=$(awk '/^UID_MAX/{print $2}' /etc/login.defs 2>/dev/null); max=${max:-60000}
  awk -F: -v min="$min" -v max="$max" '$3>=min && $3<=max {print $1}' /etc/passwd
}

prompt_readme() {
  header "README information"
  say "Open the README on the competition image and find:"
  say "  1) the AUTHORIZED ADMINISTRATORS (sometimes called 'admins')"
  say "  2) the other AUTHORIZED USERS"
  say "  3) any CRITICAL SERVICES that must keep running (e.g. SSH, Apache, MySQL, FTP, Samba)"
  say ""
  say "Users currently on this machine: ${C_BLD}$(list_human_users | tr '\n' ' ')${C_RST}"
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    say "You are logged in as: ${C_BLD}$SUDO_USER${C_RST} (this account is always kept)"
  fi
  say ""
  printf '%s  Authorized ADMINS (separate with spaces): %s' "$C_YLW" "$C_RST"; read_tty; AUTHORIZED_ADMINS=$REPLY
  printf '%s  Authorized USERS who are NOT admins:      %s' "$C_YLW" "$C_RST"; read_tty; AUTHORIZED_USERS=$REPLY
  say "  Critical service keywords this script understands:"
  say "    ssh apache nginx mysql mariadb postgresql php ftp vsftpd proftpd pure-ftpd samba"
  say "    dns bind mail postfix dovecot cups nfs snmp vnc squid dhcp ldap telnet"
  printf '%s  CRITICAL SERVICES (blank if none):        %s' "$C_YLW" "$C_RST"; read_tty; CRITICAL_SERVICES=$REPLY
}

finalize_readme() {
  AUTHORIZED_USERS=$(normalize_list "$AUTHORIZED_USERS")
  AUTHORIZED_ADMINS=$(normalize_list "$AUTHORIZED_ADMINS")
  CRITICAL_SERVICES=$(normalize_list "${CRITICAL_SERVICES,,}")
  CRITICAL_SERVICES=${CRITICAL_SERVICES//.service/}
  EXTRA_PORTS=$(normalize_list "$EXTRA_PORTS")
  ENABLE_LOCKOUT=${ENABLE_LOCKOUT,,}; FULL_UPGRADE=${FULL_UPGRADE,,}; SSH_PASSWORD_AUTH=${SSH_PASSWORD_AUTH,,}
  # The person running the script is always authorized (never lock yourself out).
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    in_list "$SUDO_USER" $AUTHORIZED_USERS $AUTHORIZED_ADMINS || AUTHORIZED_ADMINS="$AUTHORIZED_ADMINS $SUDO_USER"
    AUTHORIZED_ADMINS=$(normalize_list "$AUTHORIZED_ADMINS")
  fi
}

show_readme_summary() {
  say ""
  say "  ${C_BLD}Admins:${C_RST}            ${AUTHORIZED_ADMINS:-(none given)}"
  say "  ${C_BLD}Standard users:${C_RST}    ${AUTHORIZED_USERS:-(none given)}"
  say "  ${C_BLD}Critical services:${C_RST} ${CRITICAL_SERVICES:-(none)}"
  if [[ -z $AUTHORIZED_ADMINS$AUTHORIZED_USERS ]]; then
    warn "No authorized users given: the script will NOT delete or demote anyone."
  fi
}

# ============================================================================
# SECTION: Users and groups
# ============================================================================
delete_user() { # kill the user's processes, then remove the account (home is kept)
  pkill -KILL -u "$1" 2>/dev/null
  sleep 1
  userdel "$1" 2>/dev/null || userdel -f "$1"
}

sec_users() {
  local u g line members m all_auth
  local -a human uid0 hidden
  all_auth=$(normalize_list "$AUTHORIZED_ADMINS $AUTHORIZED_USERS")
  mapfile -t human < <(list_human_users)

  info "Looking for extra 'root' accounts (UID 0)"
  why "Only root should have user ID 0. A second UID-0 account is a hidden copy of root - a classic backdoor."
  mapfile -t uid0 < <(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
  if [[ ${#uid0[@]} -eq 0 ]]; then result OK "Only root has UID 0"; fi
  for u in "${uid0[@]}"; do
    result REVIEW "Account '$u' has UID 0 (it is secretly a root account)"
    if ask "Delete the hidden root account '$u'?" y; then
      fix "Deleted hidden root account $u" userdel -f "$u"
    fi
  done

  info "Comparing user accounts with the README"
  why "Every account that is not in the README is a way in for an attacker."
  if [[ -z $all_auth ]]; then
    result SKIPPED "No README user list given - cannot tell which users are unauthorized"
    result REVIEW "Users on this machine: ${human[*]} (compare with the README by hand)"
  else
    for u in "${human[@]}"; do
      in_list "$u" $all_auth && continue
      result REVIEW "User '$u' is NOT in the README"
      if ask "Delete unauthorized user '$u'? (their home folder is kept for forensics)" y; then
        if fix "Deleted unauthorized user $u" delete_user "$u"; then
          [[ -d /home/$u ]] && say "${C_DIM}          /home/$u was kept. Check it for forensics answers, then: sudo rm -rf /home/$u${C_RST}"
        fi
      fi
    done
    for u in $all_auth; do
      id "$u" >/dev/null 2>&1 && continue
      result REVIEW "User '$u' is in the README but does not exist on this machine"
      if ask "Create user '$u'?" y; then
        fix "Created user $u" useradd -m -s /bin/bash "$u"
      fi
    done
  fi

  info "Looking for hidden users (low UID but a real login shell)"
  why "Attackers create accounts with system-looking IDs (below 1000) so they don't show up in normal user lists."
  mapfile -t hidden < <(awk -F: -v min="$(awk '/^UID_MIN/{print $2}' /etc/login.defs)" '
      $3>0 && $3<(min?min:1000) && $7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7!="" {print $1" (UID "$3", shell "$7", home "$6")"}' /etc/passwd)
  if [[ ${#hidden[@]} -eq 0 ]]; then result OK "No hidden users with login shells"; fi
  for line in "${hidden[@]}"; do
    u=${line%% *}
    if [[ $u == postgres ]]; then continue; fi   # the PostgreSQL account normally has a shell
    result REVIEW "Hidden user with a login shell: $line"
    if ask "Delete '$u'? (say NO if it belongs to an installed program)" n strict; then
      fix "Deleted hidden user $u" delete_user "$u"
    elif ask "Change $u's shell to nologin instead (blocks logins)?" y strict; then
      fix "Set shell of $u to /usr/sbin/nologin" usermod -s /usr/sbin/nologin "$u"
    fi
  done

  info "Checking who has administrator (sudo) rights"
  why "Only the README's administrators should be able to run commands as root."
  local admin_groups=()
  for g in sudo admin wheel; do getent group "$g" >/dev/null && admin_groups+=("$g"); done
  for g in "${admin_groups[@]}"; do
    members=$(getent group "$g" | cut -d: -f4)
    for m in ${members//,/ }; do
      if [[ -z $AUTHORIZED_ADMINS ]]; then result REVIEW "'$m' is in the $g group (no admin list given to compare)"; continue; fi
      if in_list "$m" $AUTHORIZED_ADMINS; then continue; fi
      result REVIEW "'$m' is in the '$g' (admin) group but is NOT an authorized admin"
      if ask "Remove '$m' from the '$g' group?" y; then
        fix "Removed $m from group $g" gpasswd -d "$m" "$g"
      fi
    done
  done
  if getent group sudo >/dev/null; then
    for u in $AUTHORIZED_ADMINS; do
      id "$u" >/dev/null 2>&1 || continue
      if id -nG "$u" | tr ' ' '\n' | grep -qx sudo; then continue; fi
      result REVIEW "Authorized admin '$u' is not in the sudo group"
      if ask "Add '$u' to the sudo group?" y; then
        fix "Added $u to group sudo" usermod -aG sudo "$u"
      fi
    done
    [[ -n $AUTHORIZED_ADMINS ]] && result OK "Admin group membership checked"
  fi

  info "Checking other powerful groups (root, shadow, disk, docker, lxd...)"
  why "Members of these groups can read password hashes, raw disks, or become root another way."
  for g in root shadow disk kmem docker lxd; do
    getent group "$g" >/dev/null || continue
    members=$(getent group "$g" | cut -d: -f4)
    for m in ${members//,/ }; do
      in_list "$m" $AUTHORIZED_ADMINS && continue
      result REVIEW "'$m' is in the powerful '$g' group"
      if ask "Remove '$m' from '$g'?" y; then fix "Removed $m from group $g" gpasswd -d "$m" "$g"; fi
    done
  done

  info "Looking for accounts with NO password"
  why "An account with an empty password can be logged into by anyone."
  local -a empty
  mapfile -t empty < <(awk -F: '$2=="" {print $1}' /etc/shadow)
  if [[ ${#empty[@]} -eq 0 ]]; then result OK "No accounts with empty passwords"; fi
  for u in "${empty[@]}"; do
    result REVIEW "Account '$u' has an EMPTY password"
    if ! in_list "$u" $all_auth; then
      if ask "Lock the password of '$u'?" y; then fix "Locked password of $u" passwd -l "$u"; fi
    fi
  done

  set_user_passwords

  info "Checking the root account"
  why "On Ubuntu/Mint/Debian, admins use sudo, so nobody needs to log in as root directly."
  local rstat
  rstat=$(passwd -S root 2>/dev/null | awk '{print $2}')
  if [[ $rstat == L* ]]; then
    result OK "Root password is locked (use sudo instead)"
  elif [[ -z ${SUDO_USER:-} || $SUDO_USER == root ]]; then
    result SKIPPED "Root is not locked, but you ran this as root without sudo - locking root could lock you out"
  elif ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then
    result SKIPPED "Root is not locked, but $SUDO_USER is not in the sudo group yet - not locking root"
  elif ask "Lock root's password (you will still use sudo)?" y; then
    fix "Locked root's password" passwd -l root
  fi
}

password_is_strong() {
  local p=$1
  [[ ${#p} -ge 12 && $p =~ [A-Z] && $p =~ [a-z] && $p =~ [0-9] && $p =~ [^A-Za-z0-9] ]]
}

set_user_passwords() {
  local u targets=() p1 p2
  info "Setting strong passwords for the other users"
  why "Planted users often have weak passwords like 'password1'. Giving everyone a strong password fixes that."
  for u in $AUTHORIZED_ADMINS $AUTHORIZED_USERS; do
    [[ $u == "${SUDO_USER:-}" ]] && continue
    id "$u" >/dev/null 2>&1 && targets+=("$u")
  done
  if [[ ${#targets[@]} -eq 0 ]]; then result SKIPPED "No other authorized users to set passwords for"; return; fi
  if [[ $MODE == audit ]]; then result REVIEW "Make sure these users have strong passwords (apply mode can set them): ${targets[*]}"; return; fi
  if [[ ${NEW_PASSWORD,,} == skip ]]; then result SKIPPED "Password changes skipped (NEW_PASSWORD=skip)"; return; fi
  if [[ -z $NEW_PASSWORD ]]; then
    if [[ $HAVE_TTY -eq 0 || $ASSUME_YES -eq 1 ]]; then
      result REVIEW "No NEW_PASSWORD given - change passwords for ${targets[*]} by hand (sudo passwd USER)"; return
    fi
    say "  Users that will get the new password: ${targets[*]}"
    say "  (Your own account ${SUDO_USER:-root} is NOT changed.) Write the password down!"
    while true; do
      printf '%s  ? New password (12+ chars, upper, lower, number, symbol; blank = skip): %s' "$C_YLW" "$C_RST"
      IFS= read -rs p1 </dev/tty; echo
      [[ -z $p1 ]] && { result SKIPPED "Password changes skipped"; return; }
      if ! password_is_strong "$p1"; then warn "Too weak. Use 12+ characters with upper, lower, number and symbol."; continue; fi
      printf '%s  ? Type it again: %s' "$C_YLW" "$C_RST"
      IFS= read -rs p2 </dev/tty; echo
      [[ $p1 == "$p2" ]] && break
      warn "They didn't match - try again."
    done
    NEW_PASSWORD=$p1
  elif ! password_is_strong "$NEW_PASSWORD"; then
    result FAILED "NEW_PASSWORD in the config file is too weak (need 12+ chars, upper, lower, number, symbol)"; return
  fi
  for u in "${targets[@]}"; do
    _log "RUN    chpasswd ($u)"
    if printf '%s:%s\n' "$u" "$NEW_PASSWORD" | chpasswd 2>>"$LOG_FILE"; then
      result CHANGED "Set a strong password for $u"
    else
      result FAILED "Could not set password for $u"
    fi
  done
}

# ============================================================================
# SECTION: Password and lockout policy
# ============================================================================
find_pam_module() {
  local d
  for d in /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib/aarch64-linux-gnu/security \
           /usr/lib/aarch64-linux-gnu/security /lib/i386-linux-gnu/security /lib/security /usr/lib/security; do
    [[ -e $d/$1 ]] && return 0
  done
  return 1
}

sec_passwords() {
  local enc u min max warn_age
  info "Password age rules (/etc/login.defs)"
  why "Passwords must expire (max 90 days), can't be changed back instantly (min 7 days), and users get a warning."
  stage_begin /etc/login.defs
  stage_set "pass_max_days[ \t]" "PASS_MAX_DAYS	90"
  stage_set "pass_min_days[ \t]" "PASS_MIN_DAYS	7"
  stage_set "pass_warn_age[ \t]" "PASS_WARN_AGE	14"
  enc=$(awk 'toupper($1)=="ENCRYPT_METHOD"{print toupper($2)}' /etc/login.defs)
  if [[ -z $enc || $enc == DES || $enc == MD5 ]]; then stage_set "encrypt_method[ \t]" "ENCRYPT_METHOD SHA512"; fi
  stage_commit "Password aging defaults (login.defs)"

  info "Applying the age rules to existing users (chage)"
  why "login.defs only affects NEW users. Existing users need chage."
  while IFS=: read -r u _ _ min max warn_age _; do
    id "$u" >/dev/null 2>&1 || continue
    list_human_users | grep -qx "$u" || continue
    if [[ $max == 90 && $min == 7 && $warn_age == 14 ]]; then continue; fi
    fix "Password aging for $u: max 90, min 7, warn 14 days (was max=${max:-none} min=${min:-none})" chage -M 90 -m 7 -W 14 "$u"
  done < <(awk -F: '{print $1":"$2":"$3":"$4":"$5":"$6":"$7}' /etc/shadow)

  info "Password complexity (pam_pwquality)"
  why "Stops users from choosing short or simple passwords."
  ensure_pkg libpam-pwquality "password complexity rules"
  stage_begin /etc/security/pwquality.conf
  stage_set "minlen[ \t]*=" "minlen = 12"
  stage_set "dcredit[ \t]*=" "dcredit = -1"
  stage_set "ucredit[ \t]*=" "ucredit = -1"
  stage_set "lcredit[ \t]*=" "lcredit = -1"
  stage_set "ocredit[ \t]*=" "ocredit = -1"
  stage_set "difok[ \t]*=" "difok = 3"
  stage_set "maxrepeat[ \t]*=" "maxrepeat = 3"
  stage_set "usercheck[ \t]*=" "usercheck = 1"
  stage_set "dictcheck[ \t]*=" "dictcheck = 1"
  stage_set "enforce_for_root" "enforce_for_root"
  stage_commit "Complexity rules in /etc/security/pwquality.conf"

  local cp=/etc/pam.d/common-password
  if [[ -f $cp ]]; then
    info "Password rules in $cp (history, length, complexity)"
    why "remember=5 stops re-using the last 5 passwords. The pwquality line enforces complexity."
    stage_begin "$cp"
    local pwq_args="retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 reject_username enforce_for_root"
    if grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$STAGE_TMP"; then
      stage_sed "s/^([[:space:]]*password[[:space:]]+[^[:space:]]+[[:space:]]+pam_pwquality\.so).*/\1 $pwq_args/" "pam_pwquality.so $pwq_args"
    elif find_pam_module pam_pwquality.so || [[ $MODE == audit ]]; then
      stage_sed "0,/^[[:space:]]*password[[:space:]].*pam_unix\.so/s//password\trequisite\t\t\tpam_pwquality.so $pwq_args\n&/" "add pam_pwquality line"
      stage_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/{/use_authtok/!s/pam_unix\.so/pam_unix.so use_authtok try_first_pass/}' "pam_unix uses the checked password"
    fi
    if grep -Eq '^[[:space:]]*password[[:space:]].*pam_unix\.so.*remember=' "$STAGE_TMP"; then
      stage_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/s/remember=[0-9]+/remember=5/' "pam_unix remember=5"
    else
      stage_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/s/$/ remember=5/' "pam_unix remember=5"
    fi
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_unix\.so.*minlen=' "$STAGE_TMP"; then
      stage_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/s/$/ minlen=12/' "pam_unix minlen=12"
    fi
    stage_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/s/[[:space:]]+md5([[:space:]]|$)/ sha512\1/' "pam_unix uses sha512 instead of md5"
    stage_sed '/^[[:space:]]*password[[:space:]].*pam_unix\.so/s/[[:space:]]nullok(_secure)?//g' "remove nullok from password stack"
    stage_commit "Password history/complexity in common-password"
    [[ -f /etc/security/opasswd ]] || { [[ $MODE == apply ]] && install -m 600 /dev/null /etc/security/opasswd; }
  fi

  local ca=/etc/pam.d/common-auth
  if [[ -f $ca ]]; then
    info "Blocking logins with empty passwords (nullok in $ca)"
    why "'nullok' lets an account with an empty password log in without typing anything."
    stage_begin "$ca"
    stage_sed '/^[[:space:]]*auth[[:space:]].*pam_unix\.so/s/[[:space:]]nullok(_secure)?//g' "remove nullok"
    stage_commit "No empty-password logins (common-auth)"
  fi

  configure_lockout
}

configure_lockout() {
  local ca=/etc/pam.d/common-auth cacct=/etc/pam.d/common-account
  info "Account lockout after failed logins"
  why "Locks an account for 15 minutes after 5 wrong passwords, which stops password guessing."
  [[ -f $ca && -f $cacct ]] || { result SKIPPED "common-auth/common-account not found"; return; }

  if grep -Eq '^[[:space:]]*auth[[:space:]].*pam_(faillock|tally2)\.so' "$ca"; then
    result OK "Account lockout is already configured in common-auth"
    return
  fi
  case $ENABLE_LOCKOUT in
    no) result SKIPPED "Account lockout skipped (ENABLE_LOCKOUT=no)"; return ;;
    yes) ;;
    *)
      if [[ $MODE == audit ]]; then result WOULD "Turn on account lockout (5 tries, 15 min)"; return; fi
      warn "Lockout edits PAM, which controls ALL logins. This script adds the lines in the correct order"
      warn "and keeps a backup, but test afterwards in a NEW terminal: su - <some user>"
      if ! ask "Turn on account lockout?" n strict; then result SKIPPED "Account lockout not turned on (your choice)"; return; fi ;;
  esac
  if [[ $MODE == audit ]]; then result WOULD "Turn on account lockout (5 tries, 15 min)"; return; fi

  if find_pam_module pam_faillock.so; then
    stage_begin /etc/security/faillock.conf
    stage_set "deny[ \t]*=" "deny = 5"
    stage_set "unlock_time[ \t]*=" "unlock_time = 900"
    stage_set "fail_interval[ \t]*=" "fail_interval = 900"
    stage_commit "faillock.conf: 5 tries, 15 minute lock"
    # Standard Debian/Ubuntu layout:  [success=1 default=ignore] pam_unix.so  followed by  requisite pam_deny.so
    if ! awk '/^[[:space:]]*auth[[:space:]]/{n++; if(prev ~ /\[success=1 default=ignore\][[:space:]]+pam_unix\.so/ && $0 ~ /requisite[[:space:]]+pam_deny\.so/) ok=1; prev=$0} END{exit !ok}' "$ca"; then
      result REVIEW "common-auth does not have the standard layout - set up lockout by hand (see the Linux checklist)"
      return
    fi
    stage_begin "$ca"
    local out; out=$(mktemp)
    awk '
      /^[[:space:]]*auth[[:space:]]+\[success=1 default=ignore\][[:space:]]+pam_unix\.so/ && !done {
        print "auth\trequisite\t\t\tpam_faillock.so preauth"
        sub(/\[success=1 default=ignore\]/, "[success=2 default=ignore]"); print
        print "auth\t[default=die]\t\t\tpam_faillock.so authfail"
        done=1; want=1; next }
      # authsucc must come AFTER pam_deny: PAM ignores comment lines when it counts the success=2 jump
      want && /^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_deny\.so/ {
        print; print "auth\toptional\t\t\tpam_faillock.so authsucc"; want=0; next }
      { print }' "$STAGE_TMP" >"$out" && cat "$out" >"$STAGE_TMP"; rm -f "$out"
    STAGE_CHANGES+=("pam_faillock preauth/authfail/authsucc")
    stage_commit "Lockout lines in common-auth (pam_faillock)"
    stage_begin "$cacct"
    grep -q 'pam_faillock\.so' "$STAGE_TMP" || { printf 'account\trequired\t\t\tpam_faillock.so\n' >>"$STAGE_TMP"; STAGE_CHANGES+=("account required pam_faillock.so"); }
    stage_commit "Lockout line in common-account"
  elif find_pam_module pam_tally2.so; then
    stage_begin "$ca"
    stage_sed '0,/^[[:space:]]*auth[[:space:]]/s//auth\trequired\t\t\tpam_tally2.so onerr=fail audit deny=5 unlock_time=900\n&/' "pam_tally2 deny=5 unlock_time=900"
    stage_commit "Lockout line in common-auth (pam_tally2)"
    stage_begin "$cacct"
    grep -q 'pam_tally2\.so' "$STAGE_TMP" || { printf 'account\trequired\t\t\tpam_tally2.so\n' >>"$STAGE_TMP"; STAGE_CHANGES+=("account required pam_tally2.so"); }
    stage_commit "Lockout line in common-account"
  else
    result SKIPPED "Neither pam_faillock nor pam_tally2 is available on this system"
    return
  fi
  warn "Test now: open a NEW terminal and run 'su - <an authorized user>'. Keep this window open until it works."
}

# ============================================================================
# Service catalog: keywords | packages | systemd units | firewall ports | kind
#   kind: bad         - insecure, remove unless the README needs it
#         situational - fine if the README needs it, otherwise disable
#         careful     - ask, never automatic (SSH)
# ============================================================================
SERVICE_CATALOG=(
  "telnet telnetd|telnetd inetutils-telnetd telnetd-ssl||23/tcp|bad"
  "rsh rlogin rexec|rsh-server rsh-redone-server|||bad"
  "talk talkd|talkd inetutils-talkd|||bad"
  "nis yp ypbind|nis|ypbind ypserv||bad"
  "tftp tftpd|tftpd-hpa atftpd tftpd|tftpd-hpa atftpd|69/udp|bad"
  "inetd xinetd|xinetd openbsd-inetd inetutils-inetd|xinetd openbsd-inetd inetutils-inetd||bad"
  "ftp vsftpd|vsftpd|vsftpd|21/tcp|situational"
  "ftp proftpd|proftpd-basic proftpd-core proftpd|proftpd|21/tcp|situational"
  "ftp pure-ftpd pureftpd|pure-ftpd pure-ftpd-common|pure-ftpd|21/tcp|situational"
  "ssh openssh sshd openssh-server|openssh-server|ssh|22/tcp|careful"
  "apache apache2 httpd web webserver http https|apache2|apache2|80/tcp 443/tcp|situational"
  "nginx web webserver http https|nginx nginx-core nginx-full nginx-light|nginx|80/tcp 443/tcp|situational"
  "lighttpd web webserver http|lighttpd|lighttpd|80/tcp 443/tcp|situational"
  "mysql mariadb database sql db|mysql-server mariadb-server|mysql mariadb|3306/tcp|situational"
  "postgresql postgres database sql db|postgresql|postgresql|5432/tcp|situational"
  "samba smb smbd cifs fileshare|samba|smbd nmbd samba-ad-dc|139/tcp 445/tcp|situational"
  "nfs nfs-server|nfs-kernel-server|nfs-server|2049/tcp|situational"
  "rpcbind portmap nfs|rpcbind|rpcbind rpcbind.socket|111|situational"
  "dns bind bind9 named|bind9|named bind9|53|situational"
  "dnsmasq dns dhcp|dnsmasq|dnsmasq|53 67/udp|situational"
  "dhcp isc-dhcp-server|isc-dhcp-server|isc-dhcp-server|67/udp|situational"
  "mail smtp postfix|postfix|postfix|25/tcp|situational"
  "mail smtp exim exim4|exim4-daemon-light exim4-daemon-heavy|exim4|25/tcp|situational"
  "mail smtp sendmail|sendmail-bin|sendmail|25/tcp|situational"
  "mail imap pop pop3 dovecot|dovecot-core|dovecot|110/tcp 143/tcp 993/tcp 995/tcp|situational"
  "snmp snmpd|snmpd|snmpd|161/udp|situational"
  "cups print printing printer|cups cups-daemon|cups cups.socket cups.path|631/tcp|situational"
  "cups-browsed cups print printing printer|cups-browsed|cups-browsed||situational"
  "avahi mdns zeroconf bonjour|avahi-daemon|avahi-daemon avahi-daemon.socket||situational"
  "vnc x11vnc remote-desktop|x11vnc|x11vnc|5900/tcp|situational"
  "vnc vino remote-desktop|vino|vino-server||situational"
  "rdp xrdp remote-desktop|xrdp|xrdp xrdp-sesman|3389/tcp|situational"
  "squid proxy|squid|squid|3128/tcp|situational"
  "ldap slapd openldap|slapd|slapd|389/tcp 636/tcp|situational"
  "memcached|memcached|memcached|11211/tcp|situational"
  "redis|redis-server|redis-server|6379/tcp|situational"
  "irc ircd|inspircd ngircd ircd-hybrid|inspircd ngircd ircd-hybrid|6667/tcp|situational"
)

catalog_installed_pkgs() { # print installed packages of a catalog entry
  local p
  for p in $1; do pkg_installed "$p" && printf '%s ' "$p"; done
}

critical_ports() { # all firewall ports needed by the critical services
  local entry kw pk un po kind out=""
  for entry in "${SERVICE_CATALOG[@]}"; do
    IFS='|' read -r kw pk un po kind <<<"$entry"
    # shellcheck disable=SC2086
    is_critical $kw || continue
    [[ -n $(catalog_installed_pkgs "$pk") ]] || continue
    out="$out $po"
  done
  normalize_list "$out $EXTRA_PORTS" | tr ' ' '\n' | awk 'NF && !seen[$0]++' | tr '\n' ' '
}

# ============================================================================
# SECTION: Firewall
# ============================================================================
sec_firewall() {
  local status added p ports
  info "Firewall (UFW - Uncomplicated Firewall)"
  why "A firewall blocks network connections you didn't ask for. Default: block incoming, allow outgoing."
  if ! have ufw; then
    ensure_pkg ufw "the firewall"
    have ufw || { [[ $MODE == apply ]] && result FAILED "UFW is not available"; return; }
  fi
  ports=$(critical_ports)
  status=$(ufw status verbose 2>/dev/null)
  added=$(ufw show added 2>/dev/null)

  if [[ -n $ports ]]; then info "Ports to keep open for critical services: $ports"; fi
  for p in $ports; do
    if grep -Eq "ufw allow ${p//\//\\/}\$" <<<"$added"; then result OK "Port $p is allowed"; continue; fi
    fix "Allow port $p (needed by a critical service)" ufw allow "$p"
  done

  if grep -q "Default: deny (incoming)" <<<"$status" || grep -q '^DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw 2>/dev/null; then
    result OK "Incoming connections are blocked by default"
  else
    fix "Block incoming connections by default" ufw default deny incoming
  fi
  if grep -q '^DEFAULT_OUTPUT_POLICY="ACCEPT"' /etc/default/ufw 2>/dev/null; then
    result OK "Outgoing connections allowed (needed for updates)"
  else
    fix "Allow outgoing connections by default" ufw default allow outgoing
  fi
  stage_begin /etc/default/ufw
  stage_set "ipv6[ \t]*=" "IPV6=yes"
  stage_commit "UFW also protects IPv6"

  if grep -q "^Status: active" <<<"$status"; then
    result OK "UFW is turned on"
  else
    fix "Turn on UFW" ufw --force enable
  fi
  if grep -Eq "^Logging: on" <<<"$status"; then
    result OK "Firewall logging is on"
  else
    fix "Turn on firewall logging" ufw logging on
  fi

  # Rules someone else added (an attacker may have opened a port)
  local -a others=()
  while read -r line; do
    [[ $line == ufw\ allow* || $line == ufw\ route\ allow* ]] || continue
    local rule=${line#ufw allow }
    local keep=0
    for p in $ports; do [[ $rule == "$p" || $rule == "${p%/*}" ]] && keep=1; done
    [[ $keep -eq 0 ]] && others+=("$line")
  done <<<"$added"
  if [[ ${#others[@]} -gt 0 ]]; then
    result REVIEW "${#others[@]} firewall 'allow' rule(s) are not for a critical service - delete them if the README doesn't need them"
    show_list 10 "${others[@]}"
    say "${C_DIM}          To delete one: sudo ufw status numbered   then   sudo ufw delete <number>${C_RST}"
  fi
}

# ============================================================================
# SECTION: SSH server
# ============================================================================
sshd_test() { mkdir -p /run/sshd; /usr/sbin/sshd -t; }

sec_ssh() {
  local conf=/etc/ssh/sshd_config f key
  info "SSH server settings"
  why "SSH lets people log in over the network. Root login and empty passwords must be off."
  if ! pkg_installed openssh-server || [[ ! -f $conf ]]; then
    result OK "SSH server is not installed"
    return
  fi
  if ! is_critical ssh openssh sshd openssh-server; then
    result REVIEW "SSH server is installed but the README doesn't list SSH as critical (the Services section can turn it off)"
  fi

  local -a settings=(
    "PermitRootLogin no"
    "PermitEmptyPasswords no"
    "HostbasedAuthentication no"
    "IgnoreRhosts yes"
    "X11Forwarding no"
    "MaxAuthTries 4"
    "LoginGraceTime 60"
    "ClientAliveInterval 300"
    "ClientAliveCountMax 3"
    "PermitUserEnvironment no"
    "AllowAgentForwarding no"
    "AllowTcpForwarding no"
    "UsePAM yes"
    "StrictModes yes"
    "LogLevel VERBOSE"
    "Banner /etc/issue.net"
  )
  case $SSH_PASSWORD_AUTH in
    yes) settings+=("PasswordAuthentication yes") ;;
    no)  settings+=("PasswordAuthentication no") ;;
  esac

  stage_begin "$conf"
  for f in "${settings[@]}"; do
    key=${f%% *}
    stage_set "${key,,}[ \t]" "$f" "^[ \t]*match[ \t]"
  done
  stage_commit "sshd_config hardening" sshd_test

  # Files in sshd_config.d are read FIRST, and for SSH the first value wins,
  # so a planted file there can override everything above.
  if grep -Eiq '^[[:space:]]*include[[:space:]].*sshd_config\.d' "$conf"; then
    for f in /etc/ssh/sshd_config.d/*.conf; do
      [[ -f $f ]] || continue
      local s pattern=""
      for s in "${settings[@]}"; do pattern="$pattern|${s%% *}"; done
      pattern=${pattern#|}
      if grep -Eiq "^[[:space:]]*($pattern)[[:space:]]" "$f"; then
        stage_begin "$f"
        stage_sed "s/^([[:space:]]*($pattern)[[:space:]].*)/# \1   # overridden by harden.sh (set in sshd_config)/I" "comment out settings that override sshd_config"
        stage_commit "Override file $(basename "$f")" sshd_test
      fi
    done
  fi

  stage_begin /etc/issue.net
  stage_content <<'EOF'
*******************************************************************
*  WARNING: Authorized users only. All activity may be monitored   *
*  and reported. Disconnect now if you are not authorized.         *
*******************************************************************
EOF
  if grep -qi 'authorized' /etc/issue.net 2>/dev/null; then rm -f "$STAGE_TMP"; result OK "Login warning banner is set"
  else stage_commit "Login warning banner (/etc/issue.net)"; fi

  if [[ $MODE == apply && $HAS_SYSTEMD -eq 1 ]] && unit_active ssh; then
    fix "Reload SSH so the new settings take effect" systemctl reload-or-restart ssh
  fi
}

# ============================================================================
# SECTION: Services
# ============================================================================
sec_services() {
  local entry kw pk un po kind pkgs name u any_unit
  info "Checking network services against the README"
  why "Every running service is something an attacker can try to break into. Keep only what the README needs."
  [[ $HAS_SYSTEMD -eq 1 ]] || warn "systemd is not running here (container?) - can only remove packages, not stop services"

  for entry in "${SERVICE_CATALOG[@]}"; do
    IFS='|' read -r kw pk un po kind <<<"$entry"
    pkgs=$(catalog_installed_pkgs "$pk")
    any_unit=""
    for u in $un; do unit_exists "$u" && any_unit="$any_unit $u"; done
    [[ -z $pkgs && -z $any_unit ]] && continue
    name=${kw%% *}

    # shellcheck disable=SC2086
    if is_critical $kw; then
      for u in $any_unit; do
        [[ $u == *.socket || $u == *.path ]] && continue
        if unit_active "$u"; then result OK "Critical service '$u' is running (keeping it)"
        else fix "Start critical service '$u' (README says it must run)" systemctl enable --now "$u"; fi
      done
      [[ -z $any_unit ]] && result OK "Critical service '$name' is installed (keeping it)"
      continue
    fi

    case $kind in
      bad)
        result REVIEW "'$name' is installed ($pkgs) - it is insecure and the README doesn't list it"
        if [[ -n $pkgs ]] && ask "Remove $name completely ($pkgs)?" y; then
          # shellcheck disable=SC2086
          fix "Removed $name" apt-get "${APT_OPTS[@]}" purge $pkgs
        fi ;;
      careful)
        result REVIEW "'$name' is installed but not listed as critical in the README"
        if ask "Stop and disable $name? (say NO if anyone needs to log in over SSH)" n strict; then
          for u in $any_unit; do fix "Stopped and disabled $u" systemctl disable --now "$u"; done
        fi ;;
      situational)
        result REVIEW "'$name' is installed ($pkgs) but the README doesn't list it as critical"
        if ask "Stop and disable $name?" y; then
          for u in $any_unit; do fix "Stopped and disabled $u" systemctl disable --now "$u"; done
          if [[ -n $pkgs ]] && ask "Also uninstall $name ($pkgs)?" n strict; then
            # shellcheck disable=SC2086
            fix "Removed $name" apt-get "${APT_OPTS[@]}" purge $pkgs
          fi
        fi ;;
    esac
  done

  if [[ $HAS_SYSTEMD -eq 1 ]]; then
    local -a running
    mapfile -t running < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')
    result REVIEW "${#running[@]} services are running - skim the list in the report for anything odd"
    report_detail "${running[@]}"
  fi
}

# ============================================================================
# SECTION: Prohibited software
# ============================================================================
RE_HACKING='^(john|john-data|hydra|hydra-gtk|aircrack-ng|ophcrack|ophcrack-cli|hashcat|nikto|sqlmap|wireshark|wireshark-qt|wireshark-gtk|wireshark-common|tshark|ettercap-common|ettercap-graphical|ettercap-text-only|kismet|dsniff|metasploit-framework|armitage|nmap|zenmap|ncat|medusa|ncrack|crunch|fcrackzip|pdfcrack|rarcrack|reaver|bully|wifite|bettercap|responder|yersinia|netsniff-ng|masscan|zmap|hping3|crackmapexec|enum4linux|smbmap|nbtscan|gobuster|dirb|dirbuster|wfuzz|ffuf|beef-xss|set|maltego|recon-ng|theharvester|weevely|chntpw|samdump2|bloodhound|python3-impacket|impacket-scripts|netcat-traditional|netcat|cryptcat|cewl|macchanger|proxychains|proxychains4|mitmproxy|sslstrip|driftnet|thc-ipv6|thc-hydra|burpsuite|zaproxy|airgeddon|kismet-plugins|pixiewps|mdk3|mdk4|cowpatty|asleap|fern-wifi-cracker|sipcrack|patator|brutespray|dnsenum|dnsrecon|fierce|wpscan|joomscan|commix|routersploit|exploitdb|social-engineer-toolkit|veil|shellter|backdoor-factory|nishang|powersploit|mimikatz|lazagne|freeciv-server)$'
RE_GAMES='^(aisleriot|gnome-mines|gnome-sudoku|gnome-mahjongg|gnome-chess|gnome-robots|gnome-tetravex|gnome-nibbles|gnome-klotski|gnome-taquin|gnome-games|gnome-2048|four-in-a-row|five-or-more|hitori|iagno|lightsoff|quadrapassel|swell-foop|tali|sgt-puzzles|minetest|minetest-server|luanti|supertux|supertuxkart|0ad|freeciv|freeciv-client-gtk3|freeciv-client-gtk4|wesnoth|wesnoth-core|openttd|frozen-bubble|pingus|neverball|neverputt|extremetuxracer|xonotic|armagetronad|chromium-bsu|freedoom|prboom-plus|openarena|nethack-console|nethack-x11|bsdgames|pacman4console|ninvaders|moon-buggy|steam|steam-installer|steam-launcher|lutris|playonlinux|mahjongg|kpat|ksudoku|kmines|kmahjongg|knights|pychess|gnuchess|xboard|tuxpaint|warzone2100|alien-arena|assaultcube|teeworlds|hedgewars|scummvm|dosbox|mame|retroarch|snes9x-gtk|fceux|mupen64plus-ui-console|dolphin-emu|pcsx2|openra|redeclipse|sauerbraten|tuxmath|gbrainy|kobodeluxe|xmoto|mines|solitaire)$'
RE_P2P='^(transmission|transmission-gtk|transmission-qt|transmission-cli|transmission-common|transmission-daemon|deluge|deluged|deluge-gtk|deluge-web|qbittorrent|qbittorrent-nox|ktorrent|vuze|frostwire|rtorrent|amule|amule-daemon|nicotine|gtk-gnutella|bittornado|tixati|fragments|biglybt)$'
RE_REMOTE='^(teamviewer|anydesk|rustdesk|x11vnc|tightvncserver|tigervnc-standalone-server|tigervnc-scraping-server|vino|xrdp|realvnc-vnc-server|nomachine)$'
RE_REVIEW='^(netcat-openbsd|tcpdump|socat|telnet|ftp|tnftp|tor|torbrowser-launcher|aria2|hexchat|irssi|weechat|pidgin|remmina|nfs-common|smbclient|rdesktop|freerdp2-x11|ophcrack-data)$'

# remove_packages "category" pkg...  - simulate first; never remove core desktop/system packages
PROTECTED_RE='^(ubuntu-desktop|ubuntu-desktop-minimal|ubuntu-standard|ubuntu-minimal|ubuntu-server|mint-meta-.*|cinnamon|cinnamon-core|cinnamon-desktop-environment|mate-desktop-environment.*|xubuntu-desktop|xfce4|gnome-shell|gnome-core|task-.*|xorg|xserver-xorg|xserver-xorg-core|linux-image-.*|linux-generic.*|systemd|sudo|apt|dpkg|network-manager|openssh-server|libc6|bash|coreutils|login|passwd|gdm3|lightdm)$'

remove_packages() {
  local category=$1; shift
  local p removed safe=() blocked=()
  for p in "$@"; do
    removed=$(apt-get -s purge "$p" 2>/dev/null | awk '/^(Remv|Purg) /{print $2}')
    if grep -Eq "$PROTECTED_RE" <<<"$removed"; then blocked+=("$p"); else safe+=("$p"); fi
  done
  for p in "${blocked[@]}"; do
    result REVIEW "Not removing '$p' automatically: it would also remove core system packages. Remove it by hand if needed."
  done
  [[ ${#safe[@]} -eq 0 ]] && return 0
  fix "Removed $category: ${safe[*]}" apt-get "${APT_OPTS[@]}" purge "${safe[@]}"
}

sec_software() {
  local -a installed hack games p2p remote review
  info "Looking for hacking tools, games, file-sharing and remote-access programs"
  why "These are 'prohibited software' on almost every image. Attackers use them, and they break company policy."
  mapfile -t installed < <(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null | awk '$NF=="installed"{print $1}')
  mapfile -t hack   < <(printf '%s\n' "${installed[@]}" | grep -E "$RE_HACKING")
  mapfile -t games  < <(printf '%s\n' "${installed[@]}" | grep -E "$RE_GAMES")
  mapfile -t p2p    < <(printf '%s\n' "${installed[@]}" | grep -E "$RE_P2P")
  mapfile -t remote < <(printf '%s\n' "${installed[@]}" | grep -E "$RE_REMOTE")
  mapfile -t review < <(printf '%s\n' "${installed[@]}" | grep -E "$RE_REVIEW")

  _software_group "hacking tools" "${hack[@]}"
  _software_group "games" "${games[@]}"
  _software_group "file-sharing (P2P/torrent) programs" "${p2p[@]}"
  _software_group "remote-access programs" "${remote[@]}"
  if [[ ${#review[@]} -gt 0 ]]; then
    result REVIEW "Programs that are sometimes prohibited (check the README): ${review[*]}"
    say "${C_DIM}          Remove one with: sudo apt purge <name>${C_RST}"
  fi

  if have snap; then
    local -a snaps bad_snaps=()
    mapfile -t snaps < <(snap list 2>/dev/null | awk 'NR>1{print $1}')
    local s
    for s in "${snaps[@]}"; do
      if grep -Eq "$RE_HACKING|$RE_GAMES|$RE_P2P|$RE_REMOTE" <<<"$s"; then bad_snaps+=("$s"); fi
    done
    for s in "${bad_snaps[@]}"; do
      result REVIEW "Prohibited snap package: $s"
      if ask "Remove snap '$s'?" y; then fix "Removed snap $s" snap remove --purge "$s"; fi
    done
  fi
  if have flatpak; then
    local f
    while read -r f; do
      [[ -z $f ]] && continue
      if grep -Eiq 'transmission|qbittorrent|deluge|nicotine|steam|minetest|supertux|wireshark|teamviewer|anydesk|rustdesk|lutris' <<<"$f"; then
        result REVIEW "Prohibited flatpak app: $f"
        if ask "Remove flatpak '$f'?" y; then fix "Removed flatpak $f" flatpak uninstall -y --noninteractive "$f"; fi
      fi
    done < <(flatpak list --app --columns=application 2>/dev/null)
  fi

  info "Looking for hacking tools that were copied in by hand (not installed with apt)"
  local -a loose
  mapfile -t loose < <(find /usr/local/bin /usr/local/sbin /opt /root /home /tmp /var/tmp /srv -xdev -maxdepth 4 -type f \
      \( -iname 'nc' -o -iname 'ncat' -o -iname 'netcat' -o -iname 'nmap' -o -iname 'john' -o -iname 'hydra' -o -iname 'hashcat*' \
         -o -iname 'msfconsole' -o -iname 'msfvenom' -o -iname '*keylog*' -o -iname '*backdoor*' -o -iname '*rootkit*' \
         -o -iname '*reverse*shell*' -o -iname 'linpeas*' -o -iname 'pspy*' -o -iname 'chisel' -o -iname 'mimikatz*' \
         -o -iname '*.exe' -o -iname 'xmrig*' -o -iname '*miner*' \) 2>/dev/null | grep -Ev "$CP_PROTECT_RE")
  if [[ ${#loose[@]} -eq 0 ]]; then
    result OK "No hand-copied hacking tools found"
  else
    result REVIEW "${#loose[@]} suspicious program file(s) found outside the package system"
    show_list 15 "${loose[@]}"
    if ask "Delete these ${#loose[@]} file(s)?" n strict; then
      fix "Deleted ${#loose[@]} suspicious program files" rm -f -- "${loose[@]}"
    fi
  fi
}

_software_group() {
  local label=$1; shift
  if [[ $# -eq 0 ]]; then result OK "No $label found"; return; fi
  result REVIEW "Found $label: $*"
  local keep=() remove=() p
  for p in "$@"; do
    if is_critical "$p"; then keep+=("$p"); else remove+=("$p"); fi
  done
  [[ ${#keep[@]} -gt 0 ]] && result OK "Keeping ${keep[*]} (listed in the README)"
  [[ ${#remove[@]} -eq 0 ]] && return
  if ask "Remove these $label? (${remove[*]})" y; then remove_packages "$label" "${remove[@]}"; fi
}

# ============================================================================
# SECTION: Prohibited files
# ============================================================================
sec_files() {
  local -a media other
  info "Looking for media files (music, videos) and other files that break policy"
  why "Company policy on CyberPatriot images usually bans personal media and hacking data. Each one removed is often worth points."
  warn "Answer the FORENSICS QUESTIONS first - they sometimes ask about these files!"
  local prune=( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /usr/share -o -path /usr/lib \
                -o -path /usr/lib32 -o -path /usr/lib64 -o -path /usr/libx32 -o -path /lib -o -path /lib32 -o -path /lib64 \
                -o -path /var/lib -o -path /boot -o -path /var/cache -o -path /usr/src -o -path /usr/include -o -path /var/log \
                -o -path /etc -o -path "$WORK_DIR" -o -path /usr/bin -o -path /usr/sbin -o -path /bin -o -path /sbin -o -ipath '*cyberpatriot*' )
  mapfile -t media < <(find / -xdev \( "${prune[@]}" \) -prune -o -type f \( \
      -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.m4a' -o -iname '*.m4v' -o -iname '*.wav' -o -iname '*.wma' -o -iname '*.wmv' \
      -o -iname '*.flac' -o -iname '*.aac' -o -iname '*.ogg' -o -iname '*.oga' -o -iname '*.ogv' -o -iname '*.opus' -o -iname '*.avi' \
      -o -iname '*.mkv' -o -iname '*.mov' -o -iname '*.flv' -o -iname '*.mpg' -o -iname '*.mpeg' -o -iname '*.webm' -o -iname '*.3gp' \
      -o -iname '*.aiff' -o -iname '*.mid' -o -iname '*.midi' -o -iname '*.torrent' \) -print 2>/dev/null | sort)
  mapfile -t other < <(find /home /root /srv /opt /tmp /var/tmp /var/www -xdev -type f \( \
      -iname '*.pcap' -o -iname '*.pcapng' -o -iname '*.cap' -o -iname '*password*' -o -iname '*passwd*' -o -iname '*creditcard*' \
      -o -iname '*credit_card*' -o -iname '*ssn*' -o -iname '*.kdbx' -o -iname 'rockyou*' -o -iname '*wordlist*' -o -iname '*hashes*' \) \
      -not -path '*/.mozilla/*' -not -path '*/.cache/*' -not -path '*/.config/*' -not -path "$WORK_DIR/*" -print 2>/dev/null | sort)

  if [[ ${#media[@]} -eq 0 ]]; then
    result OK "No media files found"
  else
    result REVIEW "Found ${#media[@]} media/torrent file(s)"
    show_list 20 "${media[@]}"
    if ask "Delete ALL ${#media[@]} media/torrent files listed above?" y; then
      fix "Deleted ${#media[@]} media/torrent files" rm -f -- "${media[@]}"
    fi
  fi
  if [[ ${#other[@]} -eq 0 ]]; then
    result OK "No password lists, packet captures or similar files found"
  else
    result REVIEW "Found ${#other[@]} file(s) that may hold stolen data or passwords - open and check each one"
    show_list 20 "${other[@]}"
    if ask "Delete these ${#other[@]} files? (only if you've checked them)" n strict; then
      fix "Deleted ${#other[@]} suspicious data files" rm -f -- "${other[@]}"
    fi
  fi
}

# ============================================================================
# SECTION: Kernel and network settings
# ============================================================================
sec_kernel() {
  local -a settings=(
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.tcp_rfc1337=1"
    "kernel.randomize_va_space=2"
    "kernel.kptr_restrict=2"
    "kernel.dmesg_restrict=1"
    "kernel.yama.ptrace_scope=1"
    "kernel.sysrq=0"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
    "fs.suid_dumpable=0"
    "fs.protected_hardlinks=1"
    "fs.protected_symlinks=1"
    "fs.protected_fifos=2"
    "fs.protected_regular=2"
  )
  if ! is_critical router forwarding ip_forward vpn docker; then
    settings+=("net.ipv4.ip_forward=0" "net.ipv6.conf.all.forwarding=0")
  fi
  info "Kernel and network security settings (/etc/sysctl.conf)"
  why "These turn on memory protections (ASLR), stop IP spoofing tricks, and block SYN-flood attacks."

  local s key val re f
  stage_begin /etc/sysctl.conf
  for s in "${settings[@]}"; do
    key=${s%%=*}; val=${s#*=}
    re=${key//./\\.}
    stage_set "${re}[ \t]*=" "$key = $val"
  done
  stage_commit "Security settings in /etc/sysctl.conf"

  # Other sysctl files can override sysctl.conf. Comment out conflicting lines.
  for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf; do
    [[ -f $f && ! -L $f ]] || continue
    local conflicts=()
    for s in "${settings[@]}"; do
      key=${s%%=*}; val=${s#*=}
      if grep -Eq "^[[:space:]]*${key//./\\.}[[:space:]]*=[[:space:]]*" "$f" && \
         ! grep -Eq "^[[:space:]]*${key//./\\.}[[:space:]]*=[[:space:]]*${val}[[:space:]]*$" "$f"; then
        conflicts+=("$key")
      fi
    done
    [[ ${#conflicts[@]} -eq 0 ]] && continue
    stage_begin "$f"
    for key in "${conflicts[@]}"; do
      stage_sed "s/^([[:space:]]*${key//./\\.}[[:space:]]*=.*)/# \1   # overridden by harden.sh/" "disable $key"
    done
    stage_commit "Conflicting settings in $f"
  done

  # Check the values actually in use right now
  local wrong=()
  for s in "${settings[@]}"; do
    key=${s%%=*}; val=${s#*=}
    local cur; cur=$(sysctl -n "$key" 2>/dev/null) || continue
    [[ $cur == "$val" ]] || wrong+=("$key is $cur (want $val)")
  done
  if [[ ${#wrong[@]} -eq 0 ]]; then
    result OK "All kernel settings are active right now"
  elif [[ $MODE == audit ]]; then
    result WOULD "Load ${#wrong[@]} kernel setting(s) that are not active yet"
    show_list 10 "${wrong[@]}"
  else
    run sysctl --system
    local still=()
    for s in "${settings[@]}"; do
      key=${s%%=*}; val=${s#*=}
      local cur; cur=$(sysctl -n "$key" 2>/dev/null) || continue
      [[ $cur == "$val" ]] || still+=("$key")
    done
    if [[ ${#still[@]} -eq 0 ]]; then result CHANGED "Loaded the new kernel settings (sysctl --system)"
    else result FAILED "Some kernel settings could not be loaded now (${still[*]}) - they apply after a reboot"; fi
  fi
}

# ============================================================================
# SECTION: File permissions
# ============================================================================
check_perm() { # check_perm PATH MODE OWNER GROUP
  local path=$1 mode=$2 owner=$3 group=$4 cur
  [[ -e $path ]] || return 0
  cur=$(stat -c '%a %U %G' "$path")
  if [[ $cur == "$mode $owner $group" ]]; then result OK "$path is $mode $owner:$group"; return; fi
  fix "$path: set to $mode $owner:$group (was $cur)" _set_perm "$path" "$mode" "$owner" "$group"
}
_set_perm() { chown "$3:$4" "$1" && chmod "$2" "$1"; }

SAFE_SUID_RE='/(passwd|chsh|chfn|gpasswd|newgrp|su|sudo|sudoedit|mount|umount|fusermount|fusermount3|pkexec|at|crontab|chage|expiry|ssh-agent|wall|write|bsd-write|dotlockfile|mlocate|plocate|locate|unix_chkpwd|pam_extrausers_chkpwd|vmware-user-suid-wrapper|Xorg\.wrap|Xorg|ntfs-3g|ping|ping6|traceroute6\.iputils|mount\.cifs|mount\.nfs|mount\.ecryptfs_private|pppd|dbus-daemon-launch-helper|polkit-agent-helper-1|ssh-keysign|snap-confine|chrome-sandbox|chrome_crashpad_handler|firejail|lxc-user-nic|ksu|staprun|exim4|sendmail|procmail|lockfile|mail-lock|mail-unlock|mail-touchlock|utempter|screen|chkpwd|pt_chown|dmcrypt-get-device|cgexec|newuidmap|newgidmap|landscape-sysinfo|vte-2\.91|gnome-pty-helper|kismet_cap_.*|spice-client-glib-usb-acl-helper|Xvnc|uuidd|mono-sgen|qemu-bridge-helper|cupsd|lppasswd|netreport|usernetctl|userhelper|bwrap|nvidia-modprobe|virtualbox.*|VBox.*|suexec|nfs|rsh|rlogin|rcp)$'
DANGER_SUID_RE='/(find|vi|vim|vim\.basic|vim\.tiny|nano|ed|bash|sh|dash|zsh|ksh|csh|tcsh|fish|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|lua[0-9.]*|php[0-9.]*|node|nodejs|cp|mv|ln|less|more|man|awk|gawk|mawk|nawk|tar|zip|unzip|env|tee|base64|dd|chmod|chown|chgrp|docker|gdb|strace|ltrace|nmap|nc|ncat|netcat|socat|wget|curl|cat|head|tail|sed|xxd|od|hexdump|rsync|scp|ssh|git|make|gcc|cc|busybox|taskset|nice|timeout|xargs|systemctl|journalctl|install|openssl|sqlite3|mysql|emacs|pico|view|rview|rvim|watch|time|stdbuf|flock|ionice|setarch|unshare|nsenter|chroot|runuser|start-stop-daemon|cpulimit|expect|tclsh|wish|gimp|ip|aria2c|rlwrap|script|pkexec_old)$'

sec_permissions() {
  info "Permissions on important system files"
  why "If normal users can read /etc/shadow they can crack everyone's passwords. If they can write /etc/passwd they can make themselves root."
  local shadow_grp=shadow
  getent group shadow >/dev/null || shadow_grp=root
  check_perm /etc/passwd 644 root root
  check_perm /etc/group 644 root root
  check_perm /etc/shadow 640 root "$shadow_grp"
  check_perm /etc/gshadow 640 root "$shadow_grp"
  check_perm /etc/shadow- 640 root "$shadow_grp"
  check_perm /etc/gshadow- 640 root "$shadow_grp"
  check_perm /etc/sudoers 440 root root
  check_perm /etc/sudoers.d 750 root root
  local f
  for f in /etc/sudoers.d/*; do [[ -f $f ]] && check_perm "$f" 440 root root; done
  check_perm /etc/ssh/sshd_config 600 root root
  for f in /etc/ssh/ssh_host_*_key; do [[ -f $f ]] && check_perm "$f" 600 root root; done
  for f in /etc/ssh/ssh_host_*_key.pub; do [[ -f $f ]] && check_perm "$f" 644 root root; done
  check_perm /etc/crontab 600 root root
  for f in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do check_perm "$f" 700 root root; done
  check_perm /etc/hosts 644 root root
  check_perm /etc/fstab 644 root root
  check_perm /etc/login.defs 644 root root
  check_perm /etc/security/opasswd 600 root root
  check_perm /etc/pam.d 755 root root
  check_perm /root 700 root root
  check_perm /tmp 1777 root root
  check_perm /var/tmp 1777 root root
  check_perm /usr/bin/sudo 4755 root root

  info "Home folder permissions"
  why "Other users should not be able to look inside your home folder."
  local u home mode owner
  while read -r u; do
    home=$(getent passwd "$u" | cut -d: -f6)
    [[ -d $home && $home == /home/* ]] || continue
    mode=$(stat -c '%a' "$home"); owner=$(stat -c '%U' "$home")
    if [[ $owner != "$u" ]]; then
      result REVIEW "$home is owned by '$owner', not '$u'"
      if ask "Give $home back to $u?" y; then fix "chown $u $home" chown "$u:" "$home"; fi
    fi
    if (( 8#$mode & 8#007 )); then
      fix "$home: remove access for other users (was $mode)" chmod o-rwx "$home"
    else
      result OK "$home is private ($mode)"
    fi
  done < <(list_human_users)

  local prune=( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /tmp -o -path /var/tmp -o -path /var/crash -o -path /dev/shm -o -ipath '*cyberpatriot*' )
  info "World-writable files (anyone can change them)"
  local -a ww
  mapfile -t ww < <(find / -xdev \( "${prune[@]}" \) -prune -o -type f -perm -0002 -print 2>/dev/null)
  if [[ ${#ww[@]} -eq 0 ]]; then result OK "No world-writable files"; else
    result REVIEW "${#ww[@]} file(s) can be changed by ANY user"
    show_list 15 "${ww[@]}"
    if ask "Remove 'everyone can write' from these files?" y; then fix "Removed world-write from ${#ww[@]} files" chmod o-w -- "${ww[@]}"; fi
  fi
  local -a wwd
  mapfile -t wwd < <(find / -xdev \( "${prune[@]}" \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null)
  if [[ ${#wwd[@]} -eq 0 ]]; then result OK "All world-writable folders have the sticky bit"; else
    result REVIEW "${#wwd[@]} folder(s) are writable by anyone without the 'sticky bit' (users can delete each other's files)"
    show_list 10 "${wwd[@]}"
    if ask "Add the sticky bit to these folders?" y; then fix "Added sticky bit to ${#wwd[@]} folders" chmod +t -- "${wwd[@]}"; fi
  fi

  info "Programs that run as root for any user (SUID/SGID)"
  why "A SUID program always runs as its owner (root). SUID on find, vim, bash or python lets any user become root."
  local -a suid danger unknown
  mapfile -t suid < <(find / -xdev \( "${prune[@]}" \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
  for f in "${suid[@]}"; do
    if [[ $f =~ $DANGER_SUID_RE ]]; then danger+=("$f")
    elif ! [[ $f =~ $SAFE_SUID_RE ]]; then unknown+=("$f"); fi
  done
  if [[ ${#danger[@]} -eq 0 ]]; then result OK "No dangerous SUID/SGID programs"; fi
  for f in "${danger[@]}"; do
    result REVIEW "DANGEROUS: $f has SUID/SGID set (lets any user become root)"
    if ask "Remove SUID/SGID from $f?" y; then fix "Removed SUID/SGID from $f" chmod u-s,g-s "$f"; fi
  done
  if [[ ${#unknown[@]} -gt 0 ]]; then
    result REVIEW "${#unknown[@]} SUID/SGID program(s) not on the normal list - look each one up"
    show_list 15 "${unknown[@]}"
    say "${C_DIM}          Remove with: sudo chmod u-s,g-s <path>   (only if you're sure it shouldn't be SUID)${C_RST}"
  fi

  info "Files with no owner (left behind by deleted users)"
  local -a noown
  mapfile -t noown < <(find / -xdev \( "${prune[@]}" \) -prune -o \( -nouser -o -nogroup \) -print 2>/dev/null | head -200)
  if [[ ${#noown[@]} -eq 0 ]]; then result OK "No orphaned files"; else
    result REVIEW "${#noown[@]} file(s) belong to users that no longer exist - check them for prohibited content"
    show_list 10 "${noown[@]}"
  fi

  if have getcap; then
    info "Programs with special 'capabilities' (a hidden form of SUID)"
    local -a caps
    mapfile -t caps < <(getcap -r / 2>/dev/null | grep -Ev '/(ping|mtr-packet|gst-ptp-helper|arping|clockdiff|rlogin|dumpcap|fping|traceroute6\.iputils) |^/snap/|^/proc/')
    if [[ ${#caps[@]} -eq 0 ]]; then result OK "No unusual file capabilities"; fi
    local c path
    for c in "${caps[@]}"; do
      path=${c%% *}
      if [[ $c =~ cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|chown|fowner) ]]; then
        result REVIEW "Dangerous capability: $c"
        if ask "Remove the capabilities from $path?" y; then fix "Removed capabilities from $path" setcap -r "$path"; fi
      else
        result REVIEW "Unusual capability: $c"
      fi
    done
  fi
}

# ============================================================================
# SECTION: Sudo rules
# ============================================================================
sec_sudoers() {
  local f line u files=()
  info "Sudo rules (/etc/sudoers and /etc/sudoers.d)"
  why "A sudoers rule can let someone run commands as root with no password, or give a normal user full root access."
  if ! have visudo; then
    result REVIEW "sudo is not installed - admins must use 'su'"
    ensure_pkg sudo "lets admins run commands as root without sharing the root password"
    have visudo || return
  fi
  files=(/etc/sudoers)
  for f in /etc/sudoers.d/*; do
    [[ -f $f && $(basename "$f") != *.* && $(basename "$f") != *~ && $(basename "$f") != README ]] && files+=("$f")
  done

  for f in "${files[@]}"; do
    local problems=()
    stage_begin "$f"
    if grep -Eq '^[^#]*NOPASSWD' "$f"; then
      problems+=("NOPASSWD")
      stage_sed 's/^([^#]*)NOPASSWD:[[:space:]]*/\1/' "remove NOPASSWD (sudo must ask for a password)"
    fi
    if grep -Eq '^[^#]*!authenticate' "$f"; then
      problems+=("!authenticate")
      stage_sed 's/^([^#]*!authenticate.*)$/# \1   # disabled by harden.sh/' "disable !authenticate"
    fi
    if grep -Eq '^[[:space:]]*Defaults.*(LD_PRELOAD|LD_LIBRARY_PATH|!env_reset)' "$f"; then
      problems+=("dangerous Defaults")
      stage_sed 's/^([[:space:]]*Defaults.*(LD_PRELOAD|LD_LIBRARY_PATH|!env_reset).*)$/# \1   # disabled by harden.sh/' "disable dangerous Defaults"
    fi
    # User or group rules that are not the normal admin groups. Read them from the
    # staged copy, so the match below sees the line after the edits above
    # (e.g. with NOPASSWD already removed).
    local rules=()
    mapfile -t rules < <(grep -Ev '^[[:space:]]*(#|$)' "$STAGE_TMP" | grep -E '^[[:space:]]*[%A-Za-z0-9_.-]+[[:space:]]+[^=]*=')
    for line in "${rules[@]}"; do
      u=$(awk '{print $1}' <<<"$line")
      case $u in
        root|%sudo|%admin|%wheel|Defaults*|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias|@include*|\#include*) continue ;;
      esac
      if [[ $u != %* ]] && in_list "$u" $AUTHORIZED_ADMINS; then continue; fi
      problems+=("rule for $u")
      result REVIEW "$f gives '$u' sudo rights: $line"
      if ask "Disable this sudo rule?" y; then
        local esc; esc=$(printf '%s' "$line" | sed 's/[][\.*^$/()+?{}|]/\\&/g')
        stage_sed "s/^${esc}\$/# & # disabled by harden.sh/" "disable rule for $u"
      fi
    done
    if [[ ${#problems[@]} -eq 0 ]]; then rm -f "$STAGE_TMP"; result OK "$f looks normal"; continue; fi
    stage_commit "Sudo rules in $f" visudo -c
  done
}

# ============================================================================
# SECTION: Backdoors and persistence
# ============================================================================
SUSPICIOUS_RE='(\bnc\b|\bncat\b|netcat|/dev/tcp/|/dev/udp/|bash -i|sh -i|mkfifo|\bsocat\b|(curl|wget)[^|]*\|[[:space:]]*(sudo )?(ba)?sh|base64 (-d|--decode)|python[0-9.]* -c|perl -e|php -r|ruby -e|chmod [ugoa]*\+s|chmod [0-7]?[4-7][0-7]{3}|\bnohup\b|xmrig|minerd|cryptonight|/tmp/\.|/dev/shm/)'
CP_PROTECT_RE='[Cc][Yy][Bb][Ee][Rr][Pp][Aa][Tt][Rr][Ii][Oo][Tt]|CCS[A-Za-z]*|[Ss]coring'

OWNED_DB=""
build_owned_db() {
  [[ -n $OWNED_DB ]] && return
  OWNED_DB=$(mktemp)
  cat /var/lib/dpkg/info/*.list 2>/dev/null | awk '{
      print
      if ($0 ~ /^\/(lib|lib32|lib64|bin|sbin)\//) print "/usr" $0
      else if ($0 ~ /^\/usr\/(lib|lib32|lib64|bin|sbin)\//) print substr($0, 5)
    }' | sort -u >"$OWNED_DB"
}
# not_owned: read paths on stdin, print the ones that no installed package provides
not_owned() {
  build_owned_db
  awk 'NR==FNR { own[$0]=1; next } !($0 in own)' "$OWNED_DB" - | grep -Ev "$CP_PROTECT_RE"
}

human_homes() { awk -F: '$3>=1000 && $3<60000 {print $6}' /etc/passwd; }

sec_backdoors() {
  local f line u home all_auth n
  all_auth=$(normalize_list "$AUTHORIZED_ADMINS $AUTHORIZED_USERS")

  info "Checking /etc/ld.so.preload (forces a library into every program)"
  why "Rootkits use this file to load themselves into every program, so they can hide files and processes."
  if [[ -s /etc/ld.so.preload ]]; then
    result REVIEW "/etc/ld.so.preload is in use: $(tr '\n' ' ' </etc/ld.so.preload)"
    if ask "Disable /etc/ld.so.preload (rename it)?" y; then
      backup /etc/ld.so.preload
      fix "Disabled /etc/ld.so.preload" mv /etc/ld.so.preload /etc/ld.so.preload.disabled-by-harden
    fi
  else
    result OK "/etc/ld.so.preload is not used"
  fi

  info "Checking the login system (PAM) for backdoors"
  why "One line like 'auth sufficient pam_permit.so' lets ANYONE log in with ANY password."
  local -a pamhits
  mapfile -t pamhits < <(grep -HnE '^[[:space:]]*auth[[:space:]]+(sufficient|\[success=done[^]]*\])[[:space:]]+pam_permit\.so|^[^#]*pam_exec\.so' /etc/pam.d/* 2>/dev/null)
  [[ ${#pamhits[@]} -eq 0 ]] && result OK "No PAM backdoor lines found"
  for line in "${pamhits[@]}"; do
    f=${line%%:*}
    result REVIEW "Suspicious PAM line: $line"
    if [[ $line == *pam_permit* ]] && ask "Disable this line in $f?" y; then
      stage_begin "$f"
      stage_sed 's/^([[:space:]]*auth[[:space:]]+(sufficient|\[success=done[^]]*\])[[:space:]]+pam_permit\.so.*)/# \1   # backdoor disabled by harden.sh/' "disable pam_permit backdoor"
      stage_commit "PAM backdoor in $f"
    fi
  done
  local -a badmods
  mapfile -t badmods < <(find /lib /usr/lib -path '*/security/*.so' -type f 2>/dev/null | not_owned)
  if [[ ${#badmods[@]} -gt 0 ]]; then
    result REVIEW "PAM module file(s) that no package installed (possible password stealer)"
    show_list 10 "${badmods[@]}"
  fi

  info "Scheduled tasks (cron and at)"
  why "Attackers schedule their backdoor to start again every few minutes, even after you kill it."
  local -a crons
  for f in /var/spool/cron/crontabs/*; do
    [[ -f $f ]] || continue
    u=$(basename "$f")
    mapfile -t crons < <(grep -Ev '^[[:space:]]*(#|$)' "$f")
    [[ ${#crons[@]} -eq 0 ]] && continue
    if ! id "$u" >/dev/null 2>&1 || { [[ -n $all_auth && $u != root ]] && ! in_list "$u" $all_auth; }; then
      result REVIEW "Crontab for unauthorized or deleted user '$u'"
      show_list 5 "${crons[@]}"
      if ask "Delete $u's crontab?" y; then fix "Deleted crontab of $u" rm -f "$f"; fi
      continue
    fi
    local -a susp
    mapfile -t susp < <(printf '%s\n' "${crons[@]}" | grep -E "$SUSPICIOUS_RE")
    if [[ ${#susp[@]} -gt 0 ]]; then
      result REVIEW "SUSPICIOUS cron job(s) for $u"
      show_list 5 "${susp[@]}"
      if ask "Remove these suspicious lines from $u's crontab?" y; then
        stage_begin "$f"
        local tmp2; tmp2=$(mktemp); grep -Ev "$SUSPICIOUS_RE" "$STAGE_TMP" >"$tmp2"; cat "$tmp2" >"$STAGE_TMP"; rm -f "$tmp2"
        STAGE_CHANGES+=("removed ${#susp[@]} line(s)")
        stage_commit "Crontab of $u"
      fi
    else
      result REVIEW "User $u has ${#crons[@]} cron job(s) - make sure they're legitimate (sudo crontab -l -u $u)"
      show_list 5 "${crons[@]}"
    fi
  done
  local -a syscron
  mapfile -t syscron < <(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f ! -name '.placeholder' 2>/dev/null | not_owned)
  for f in "${syscron[@]}"; do
    result REVIEW "System cron file not installed by any package: $f"
    mapfile -t crons < <(grep -Ev '^[[:space:]]*(#|$)' "$f" | head -5)
    show_list 5 "${crons[@]}"
    if grep -Eq "$SUSPICIOUS_RE" "$f" && ask "It looks malicious. Delete $f?" y; then
      backup "$f"; fix "Deleted $f" rm -f "$f"
    fi
  done
  mapfile -t crons < <(grep -Ev '^[[:space:]]*(#|$)' /etc/crontab 2>/dev/null | grep -E "$SUSPICIOUS_RE")
  if [[ ${#crons[@]} -gt 0 ]]; then
    result REVIEW "SUSPICIOUS line(s) in /etc/crontab (edit with: sudo nano /etc/crontab)"
    show_list 5 "${crons[@]}"
  fi
  if compgen -G "/var/spool/cron/atjobs/*" >/dev/null; then
    result REVIEW "There are 'at' jobs waiting to run (see: sudo atq   remove: sudo atrm <number>)"
  fi
  [[ -z ${syscron[*]} ]] && result OK "System cron folders contain only package files"

  info "Services and timers that didn't come from a package"
  why "A custom systemd service is a common way to make a backdoor start at every boot."
  local -a units
  mapfile -t units < <(find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /usr/local/lib/systemd/system \
      -maxdepth 1 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) 2>/dev/null | not_owned | sort -u)
  [[ ${#units[@]} -eq 0 ]] && result OK "All systemd services came from packages"
  local exec name
  for f in "${units[@]}"; do
    name=$(basename "$f")
    exec=$(grep -E '^[[:space:]]*Exec(Start|StartPre|StartPost)=' "$f" | head -2 | tr '\n' ' ')
    if grep -Eq "$SUSPICIOUS_RE" <<<"$exec"; then
      result REVIEW "SUSPICIOUS service $name: $exec"
      if [[ $HAS_SYSTEMD -eq 1 ]] && ask "Stop and disable $name?" y; then fix "Stopped and disabled $name" systemctl disable --now "$name"; fi
    else
      result REVIEW "Service not from any package (check it): $f  $exec"
    fi
  done
  for home in /root $(human_homes); do
    for f in "$home"/.config/systemd/user/*.service; do
      [[ -f $f ]] && result REVIEW "Per-user service (starts when that user logs in): $f  $(grep -E '^[[:space:]]*ExecStart=' "$f" | head -1)"
    done
  done

  if [[ -f /etc/rc.local ]] && grep -Ev '^[[:space:]]*(#|$|exit 0)' /etc/rc.local | grep -q .; then
    result REVIEW "/etc/rc.local runs commands at boot - check them"
    mapfile -t crons < <(grep -Ev '^[[:space:]]*(#|$|exit 0)' /etc/rc.local)
    show_list 5 "${crons[@]}"
  fi
  local -a initd
  mapfile -t initd < <(find /etc/init.d -maxdepth 1 -type f 2>/dev/null | not_owned)
  if [[ ${#initd[@]} -gt 0 ]]; then
    result REVIEW "Start-up scripts in /etc/init.d not from any package"
    show_list 10 "${initd[@]}"
  fi

  info "Shell start-up files (run every time someone opens a terminal)"
  why "Attackers hide commands and fake 'aliases' here (e.g. making 'sudo' save your password)."
  local -a rcfiles=(/etc/profile /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile /root/.bash_aliases)
  for f in /etc/profile.d/*.sh; do rcfiles+=("$f"); done
  for home in $(human_homes); do
    rcfiles+=("$home/.bashrc" "$home/.profile" "$home/.bash_profile" "$home/.bash_login" "$home/.bash_logout" "$home/.bash_aliases" "$home/.zshrc")
  done
  local -a rchits
  mapfile -t rchits < <(grep -HnE "$SUSPICIOUS_RE|^[[:space:]]*alias[[:space:]]+(sudo|su|ls|cd|ps|ss|netstat|cat|apt|apt-get|passwd|rm|grep|find|top|kill|systemctl|ufw|history|clear|ssh|id|whoami|crontab)=|LD_PRELOAD|PROMPT_COMMAND" \
      "${rcfiles[@]}" 2>/dev/null | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#' \
      | grep -Ev "alias (ls|grep|fgrep|egrep|dir|vdir)='(ls|grep|fgrep|egrep|dir|vdir) --color=auto'|/etc/profile\.d/(vte|bash_completion|apps-bin-path)")
  if [[ ${#rchits[@]} -eq 0 ]]; then result OK "No suspicious lines in shell start-up files"; fi
  local -A byfile=()
  for line in "${rchits[@]}"; do
    result REVIEW "Suspicious shell start-up line: $line"
    f=${line%%:*}; n=${line#*:}; n=${n%%:*}
    byfile[$f]="${byfile[$f]} $n"
  done
  for f in "${!byfile[@]}"; do
    if ask "Comment out the suspicious line(s) in $f?" y; then
      stage_begin "$f"
      for n in ${byfile[$f]}; do stage_sed "${n}s/^/# disabled by harden.sh: /" "line $n"; done
      stage_commit "Shell start-up file $f"
    fi
  done
  local -a profd
  mapfile -t profd < <(find /etc/profile.d -maxdepth 1 -type f ! -name 'debuginfod.*' ! -name '01-locale-fix.sh' 2>/dev/null | not_owned)
  [[ ${#profd[@]} -gt 0 ]] && { result REVIEW "Files in /etc/profile.d not from any package"; show_list 10 "${profd[@]}"; }

  info "SSH keys that allow password-less login (authorized_keys)"
  why "Anyone who has the matching private key can log in as that user without knowing the password."
  local found_keys=0 owner
  for home in /root $(human_homes); do
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -s $f ]] || continue
      found_keys=1
      n=$(grep -cEv '^[[:space:]]*(#|$)' "$f")
      owner=$(stat -c %U "$f")
      result REVIEW "$f has $n key(s): $(awk '!/^[[:space:]]*(#|$)/{print $NF}' "$f" | tr '\n' ' ')"
      local def=n
      [[ $home == /root ]] && def=y
      if ask "Remove $f (no more key logins as $owner)?" "$def" strict; then
        backup "$f"; fix "Removed $f" rm -f "$f"
      fi
    done
  done
  [[ $found_keys -eq 0 ]] && result OK "No authorized_keys files"

  info "Programs listening for network connections"
  why "A backdoor is often just netcat or a script waiting for the attacker to connect."
  if have ss; then
    local -a listeners
    mapfile -t listeners < <(ss -tulpnH 2>/dev/null)
    local proc pid addr exe
    for line in "${listeners[@]}"; do
      proc=$(grep -oE 'users:\(\("[^"]+"' <<<"$line" | head -1 | cut -d'"' -f2)
      pid=$(grep -oE 'pid=[0-9]+' <<<"$line" | head -1 | cut -d= -f2)
      addr=$(awk '{print $1" "$5}' <<<"$line")
      if [[ $proc =~ ^(nc|ncat|netcat|nc\.openbsd|nc\.traditional|socat|python[0-9.]*|perl|ruby|php[0-9.]*|bash|sh|dash|zsh|node|lua)$ ]]; then
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        result REVIEW "POSSIBLE BACKDOOR: '$proc' (PID $pid, $exe) is listening on $addr"
        if [[ -n $pid ]] && ask "Kill process $pid now? (also find what starts it - cron, services, rc.local)" y; then
          fix "Killed process $pid ($proc)" kill -9 "$pid"
        fi
      fi
    done
    result REVIEW "${#listeners[@]} listening port(s) - compare with the README's critical services (full list in report)"
    mapfile -t listeners < <(awk '{p=$7; gsub(/users:\(\("/,"",p); gsub(/".*/,"",p); print $1"  "$5"  "p}' <<<"$(printf '%s\n' "${listeners[@]}")")
    show_list 25 "${listeners[@]}"
  fi
  local -a procs
  mapfile -t procs < <(ps -eo pid=,user=,args= 2>/dev/null | grep -E "$SUSPICIOUS_RE" | grep -Ev 'grep|harden\.sh')
  if [[ ${#procs[@]} -gt 0 ]]; then
    result REVIEW "Suspicious running process(es) (stop with: sudo kill -9 <PID>)"
    show_list 10 "${procs[@]}"
  fi

  info "Checking /etc/hosts for fake website addresses"
  why "An attacker can point a real website name (like a bank or update server) to their own computer."
  local hn hf; hn=$(hostname 2>/dev/null); hf=$(hostname -f 2>/dev/null)
  local -a badhosts=()
  local -a badnums=()
  n=0
  while IFS= read -r line; do
    n=$((n + 1))
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    local name bad=0
    for name in $(awk '{for(i=2;i<=NF;i++){ if ($i ~ /^#/) break; print $i }}' <<<"$line"); do
      case $name in
        localhost|localhost.localdomain|ip6-localhost|ip6-loopback|ip6-localnet|ip6-mcastprefix|ip6-allnodes|ip6-allrouters|ip6-allhosts) ;;
        "$hn"|"$hf") ;;
        *) bad=1 ;;
      esac
    done
    if [[ $bad -eq 1 ]]; then badhosts+=("line $n: $line"); badnums+=("$n"); fi
  done </etc/hosts
  if [[ ${#badhosts[@]} -eq 0 ]]; then result OK "/etc/hosts only has the normal entries"; else
    result REVIEW "${#badhosts[@]} unusual line(s) in /etc/hosts"
    show_list 10 "${badhosts[@]}"
    if ask "Comment out these line(s) in /etc/hosts?" y; then
      stage_begin /etc/hosts
      for n in "${badnums[@]}"; do stage_sed "${n}s/^/# disabled by harden.sh: /" "line $n"; done
      stage_commit "/etc/hosts"
    fi
  fi

  info "Fake system commands in /usr/local/bin (they run instead of the real ones)"
  local -a shadows=()
  for f in $(find /usr/local/bin /usr/local/sbin -maxdepth 1 -type f 2>/dev/null | not_owned); do
    name=$(basename "$f")
    for d in /usr/bin /bin /usr/sbin /sbin; do
      if [[ -e $d/$name ]]; then shadows+=("$f (hides $d/$name)"); break; fi
    done
  done
  if [[ ${#shadows[@]} -eq 0 ]]; then result OK "No fake system commands"; else
    result REVIEW "Command(s) in /usr/local that take priority over the real system command"
    show_list 10 "${shadows[@]}"
  fi

  info "Desktop programs that start automatically at login"
  local -a autos=()
  mapfile -t autos < <(find /etc/xdg/autostart -maxdepth 1 -name '*.desktop' -type f 2>/dev/null | not_owned)
  for home in /root $(human_homes); do
    for f in "$home"/.config/autostart/*.desktop; do [[ -f $f ]] && autos+=("$f"); done
  done
  if [[ ${#autos[@]} -eq 0 ]]; then result OK "No unusual autostart programs"; fi
  for f in "${autos[@]}"; do
    result REVIEW "Autostart entry: $f -> $(grep -m1 '^Exec=' "$f")"
  done

  if [[ -d /var/www ]]; then
    info "Looking for web shells (hacker control panels hidden in the website)"
    local -a shells
    mapfile -t shells < <(grep -rlE --include='*.php*' '(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|(shell_exec|passthru|system|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)' /var/www 2>/dev/null)
    if [[ ${#shells[@]} -eq 0 ]]; then result OK "No obvious web shells in /var/www"; else
      result REVIEW "Possible web shell file(s) in /var/www"
      show_list 10 "${shells[@]}"
      if ask "Delete these files? (check them first if the website is a critical service)" n strict; then
        fix "Deleted ${#shells[@]} web shell file(s)" rm -f -- "${shells[@]}"
      fi
    fi
  fi

  info "Checking system programs for tampering (dpkg --verify). This takes about a minute..."
  why "Attackers replace programs like 'ls' or 'sudo' with versions that hide them or steal passwords."
  local -a modified
  mapfile -t modified < <(dpkg --verify 2>/dev/null | awk 'NF==2 && $1 ~ /^..5/ {print $2}' | grep -E '^/(usr/)?(s?bin|lib|lib64|libexec)/')
  if [[ ${#modified[@]} -eq 0 ]]; then result OK "System programs match their packages"; else
    result REVIEW "${#modified[@]} system file(s) were changed after installation"
    show_list 10 "${modified[@]}"
    local pkgs
    pkgs=$(for f in "${modified[@]}"; do dpkg -S "$f" 2>/dev/null | cut -d: -f1; done | tr ',' '\n' | awk 'NF && !s[$1]++{print $1}' | tr '\n' ' ')
    if [[ -n $pkgs ]] && ask "Reinstall the package(s) to restore the original files? ($pkgs)" y; then
      apt_update_once
      # shellcheck disable=SC2086
      fix "Reinstalled $pkgs" apt-get "${APT_OPTS[@]}" install --reinstall $pkgs
    fi
  fi
}

# ============================================================================
# SECTION: Logging and auditing
# ============================================================================
last_status() { local r=${RESULTS[-1]}; printf '%s' "${r%%|*}"; }

sec_logging() {
  local p rules
  info "System logs (rsyslog)"
  why "Logs like /var/log/auth.log record every login and sudo command - you need them to spot attackers."
  if pkg_installed rsyslog; then result OK "rsyslog is installed"; else ensure_pkg rsyslog "writes /var/log/auth.log and other log files"; fi
  if [[ $HAS_SYSTEMD -eq 1 ]] && pkg_installed rsyslog; then
    if unit_active rsyslog && unit_enabled rsyslog; then result OK "rsyslog is running"
    else fix "Start rsyslog" systemctl enable --now rsyslog; fi
  fi

  info "Security auditing (auditd)"
  why "auditd records security events like changes to the password files or use of sudo."
  ensure_pkg auditd "security event auditing"
  if pkg_installed auditd || [[ $MODE == audit ]]; then
    if [[ $HAS_SYSTEMD -eq 1 ]] && pkg_installed auditd; then
      if unit_active auditd && unit_enabled auditd; then result OK "auditd is running"
      else fix "Start auditd" systemctl enable --now auditd; fi
    fi
    rules="## Added by the CyberPatriot practice toolkit (harden.sh)"
    for p in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/security/opasswd; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k identity"; done
    for p in /etc/sudoers /etc/sudoers.d; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k sudoers"; done
    for p in /etc/ssh/sshd_config /etc/pam.d; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k auth_config"; done
    for p in /etc/crontab /etc/cron.d /var/spool/cron; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k cron"; done
    for p in /etc/hosts /etc/hostname; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k network"; done
    for p in /var/log/lastlog /var/log/faillog /var/log/wtmp /var/log/btmp; do [[ -e $p ]] && rules+=$'\n'"-w $p -p wa -k logins"; done
    for p in sudo su passwd useradd usermod; do
      p=$(command -v "$p" 2>/dev/null) && p=$(readlink -f "$p") && rules+=$'\n'"-w $p -p x -k privileged"
    done
    for p in insmod rmmod modprobe; do
      p=$(command -v "$p" 2>/dev/null) && p=$(readlink -f "$p") && rules+=$'\n'"-w $p -p x -k modules"
    done
    if [[ $(uname -m) == x86_64 || $(uname -m) == aarch64 ]]; then
      rules+=$'\n'"-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
      rules+=$'\n'"-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change"
    fi
    stage_begin /etc/audit/rules.d/50-cyberpatriot.rules
    stage_content <<<"$rules"
    stage_commit "Audit rules: users, sudo, SSH/PAM config, cron, logins, kernel modules"
    if [[ $(last_status) == CHANGED ]] && have augenrules; then
      fix "Load the audit rules" augenrules --load
    fi
  fi

  info "Log file permissions"
  local -a wwlogs
  mapfile -t wwlogs < <(find /var/log -xdev -type f -perm -o+w 2>/dev/null)
  if [[ ${#wwlogs[@]} -eq 0 ]]; then result OK "No log files can be edited by everyone"; else
    result REVIEW "${#wwlogs[@]} log file(s) can be edited by anyone (an attacker could erase their tracks)"
    show_list 10 "${wwlogs[@]}"
    if ask "Remove 'everyone can write' from these logs?" y; then fix "Fixed ${#wwlogs[@]} log file permissions" chmod o-w -- "${wwlogs[@]}"; fi
  fi
}

# ============================================================================
# SECTION: AppArmor
# ============================================================================
sec_apparmor() {
  info "AppArmor (limits what each program is allowed to do)"
  why "If a program like a web server is hacked, AppArmor stops it from touching files it shouldn't."
  pkg_installed apparmor || ensure_pkg apparmor "program confinement"
  if [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]]; then
    result OK "AppArmor is enabled in the kernel"
  else
    result REVIEW "AppArmor is NOT enabled in the kernel (or this is a container)"
    if [[ -f /etc/default/grub ]] && grep -Eq 'apparmor=0|security=[a-z]+' /etc/default/grub; then
      stage_begin /etc/default/grub
      stage_sed 's/[[:space:]]*(apparmor=0|security=[a-z]+)//g' "remove apparmor=0 / security= from the boot options"
      stage_commit "Boot options in /etc/default/grub"
      if [[ $(last_status) == CHANGED ]]; then fix "Update the boot loader (takes effect after a reboot)" update-grub; fi
    fi
  fi
  if unit_exists apparmor; then
    if unit_enabled apparmor; then result OK "AppArmor service is enabled"
    else fix "Enable the AppArmor service" systemctl enable --now apparmor; fi
  fi
  if have aa-status && aa-status >/dev/null 2>&1; then
    local -a complain
    mapfile -t complain < <(aa-status 2>/dev/null | awk '/profiles are in complain mode/{f=1; next} /profiles are|processes|^[0-9]+ /{f=0} f{gsub(/^[ \t]+/, ""); print}')
    if [[ ${#complain[@]} -eq 0 ]]; then result OK "No AppArmor profiles are in 'complain' (log-only) mode"; fi
    local p
    for p in "${complain[@]}"; do
      result REVIEW "AppArmor profile in complain (log-only) mode: $p"
      if ask "Switch '$p' to enforce mode?" y; then
        have aa-enforce || ensure_pkg apparmor-utils "the aa-enforce command"
        fix "AppArmor profile '$p' set to enforce" aa-enforce "$p"
      fi
    done
  fi
}

# ============================================================================
# SECTION: Login screen and screen lock
# ============================================================================
sec_desktop() {
  local f
  info "Login screen: no guest account and no automatic login"
  why "A guest session or auto-login lets someone use the computer without any password."
  if [[ -d /etc/lightdm ]]; then
    stage_begin /etc/lightdm/lightdm.conf
    stage_ini "Seat:*" allow-guest false
    stage_ini "Seat:*" greeter-allow-guest false
    stage_ini "Seat:*" autologin-guest false
    stage_ini "Seat:*" autologin-user ""
    stage_ini "Seat:*" autologin-user-timeout 0
    stage_ini "Seat:*" greeter-show-manual-login true
    stage_ini "Seat:*" greeter-hide-users true
    stage_commit "LightDM login screen (/etc/lightdm/lightdm.conf)"
    for f in /etc/lightdm/lightdm.conf.d/*.conf /usr/share/lightdm/lightdm.conf.d/*.conf; do
      [[ -f $f ]] || continue
      grep -Eq '^[[:space:]]*(autologin-user[[:space:]]*=[[:space:]]*[^[:space:]]+|allow-guest[[:space:]]*=[[:space:]]*true|autologin-guest[[:space:]]*=[[:space:]]*true)' "$f" || continue
      stage_begin "$f"
      stage_sed 's/^([[:space:]]*(autologin-user[[:space:]]*=[[:space:]]*[^[:space:]]+|allow-guest[[:space:]]*=[[:space:]]*true|autologin-guest[[:space:]]*=[[:space:]]*true).*)/#\1   # disabled by harden.sh/' "disable autologin/guest"
      stage_commit "LightDM override file $f"
    done
  fi

  local gdm=""
  if [[ $IS_UBUNTU -eq 1 && -f /etc/gdm3/custom.conf ]]; then gdm=/etc/gdm3/custom.conf
  elif [[ -f /etc/gdm3/daemon.conf ]]; then gdm=/etc/gdm3/daemon.conf
  elif [[ -f /etc/gdm3/custom.conf ]]; then gdm=/etc/gdm3/custom.conf; fi
  if [[ -n $gdm ]]; then
    stage_begin "$gdm"
    stage_ini daemon AutomaticLoginEnable false
    stage_ini daemon TimedLoginEnable false
    stage_ini security DisallowTCP true
    stage_ini xdmcp Enable false
    stage_commit "GDM login screen ($gdm)"
  fi
  for f in /etc/sddm.conf /etc/sddm.conf.d/*.conf; do
    [[ -f $f ]] || continue
    grep -Eq '^[[:space:]]*User[[:space:]]*=[[:space:]]*[^[:space:]]+' "$f" || continue
    stage_begin "$f"
    stage_ini Autologin User ""
    stage_commit "SDDM auto-login ($f)"
  done
  if [[ -z $gdm && ! -d /etc/lightdm && ! -f /etc/sddm.conf ]]; then result OK "No graphical login screen found"; fi

  info "Automatic screen lock"
  why "An unlocked, unattended screen lets anyone walk up and use your account."
  if ! have dconf; then
    [[ -n $DESKTOP ]] && result REVIEW "dconf is not available - turn on the screen lock by hand in the desktop settings"
    return
  fi
  local mark=${#RESULTS[@]}
  stage_begin /etc/dconf/profile/user
  if [[ ! -s $STAGE_TMP ]]; then
    printf 'user-db:user\nsystem-db:local\n' >"$STAGE_TMP"; STAGE_CHANGES+=("create the dconf user profile")
  elif ! grep -q '^system-db:local' "$STAGE_TMP"; then
    printf 'system-db:local\n' >>"$STAGE_TMP"; STAGE_CHANGES+=("add system-db:local")
  fi
  stage_commit "dconf profile (makes system-wide desktop settings apply)"
  stage_begin /etc/dconf/db/local.d/00-cyberpatriot-screenlock
  stage_content <<'EOF'
# Added by the CyberPatriot practice toolkit (harden.sh)
[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true

[org/gnome/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0

[org/cinnamon/desktop/session]
idle-delay=uint32 300

[org/mate/screensaver]
lock-enabled=true
idle-activation-enabled=true

[org/mate/session]
idle-delay=5
EOF
  stage_commit "Screen locks after 5 idle minutes (GNOME, Cinnamon, MATE)"
  stage_begin /etc/dconf/db/local.d/locks/00-cyberpatriot-screenlock
  stage_content <<'EOF'
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/session/idle-delay
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/desktop/session/idle-delay
/org/mate/screensaver/lock-enabled
/org/mate/session/idle-delay
EOF
  stage_commit "Users can't turn the screen lock off"
  if [[ -f /etc/dconf/profile/gdm ]]; then
    stage_begin /etc/dconf/db/gdm.d/00-cyberpatriot-login-screen
    printf '[org/gnome/login-screen]\ndisable-user-list=true\n' | stage_content
    stage_commit "GDM: don't show the list of users"
  fi
  local r changed=0
  for r in "${RESULTS[@]:mark}"; do [[ ${r%%|*} == CHANGED ]] && changed=1; done
  [[ $changed -eq 1 ]] && fix "Apply the desktop settings (dconf update)" dconf update
  [[ $DESKTOP == xfce ]] && result REVIEW "Xfce doesn't use dconf: set Settings > Xfce Screensaver > Lock Screen by hand"
}

# ============================================================================
# SECTION: Critical service hardening (only services the README lists)
# ============================================================================
changed_since() { local r; for r in "${RESULTS[@]:$1}"; do [[ ${r%%|*} == CHANGED ]] && return 0; done; return 1; }

# restart_or_rollback UNIT FILE...   restart; if it won't come back, restore the files
restart_or_rollback() {
  local unit=$1; shift
  [[ $MODE == apply && $HAS_SYSTEMD -eq 1 ]] || return 0
  if run systemctl restart "$unit" && sleep 2 && unit_active "$unit"; then
    result CHANGED "Restarted $unit with the new settings"; return 0
  fi
  local f; for f in "$@"; do restore "$f"; done
  run systemctl restart "$unit"
  result FAILED "$unit would not start with the new settings - changes rolled back (see log)"
}

reload_unit() { [[ $MODE == apply && $HAS_SYSTEMD -eq 1 ]] && unit_active "$1" && fix "Reloaded $1" systemctl reload-or-restart "$1"; }

harden_apache() {
  local mark=${#RESULTS[@]} f real
  info "Apache web server (critical: hardening it, not removing it)"
  why "Hide the version number, stop directory listings and TRACE requests, and add browser security headers."
  stage_begin /etc/apache2/conf-available/security.conf
  stage_set "servertokens[ \t]" "ServerTokens Prod"
  stage_set "serversignature[ \t]" "ServerSignature Off"
  stage_set "traceenable[ \t]" "TraceEnable Off"
  stage_commit "Apache: hide version, disable TRACE" apache2ctl configtest
  [[ -e /etc/apache2/conf-enabled/security.conf ]] || fix "Enable Apache security.conf" a2enconf -q security
  for f in /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* /etc/apache2/conf-enabled/*; do
    [[ -f $f ]] || continue
    real=$(readlink -f "$f")
    grep -Eiq '^[[:space:]]*Options[[:space:]].*[[:space:]]\+?Indexes([[:space:]]|$)' "$real" || continue
    stage_begin "$real"
    stage_sed '/^[[:space:]]*Options[[:space:]]/I s/([[:space:]])\+?Indexes([[:space:]]|$)/\1\2/Ig' "remove Indexes"
    stage_sed '/^[[:space:]]*Options[[:space:]]*$/I s/Options.*/Options None/I' "empty Options -> None"
    stage_commit "Apache: no directory listings in $(basename "$real")" apache2ctl configtest
  done
  if [[ -e /etc/apache2/mods-enabled/autoindex.load ]]; then
    if fix "Apache: disable the autoindex module (folder listings)" a2dismod -q -f autoindex && [[ $MODE == apply ]] && ! run apache2ctl configtest; then
      run a2enmod -q autoindex; result FAILED "Apache config needs autoindex - re-enabled it"
    fi
  else result OK "Apache autoindex module is off"; fi
  [[ -e /etc/apache2/mods-enabled/userdir.load ]] && fix "Apache: disable user home-page folders (userdir)" a2dismod -q -f userdir
  [[ -e /etc/apache2/mods-enabled/headers.load ]] || fix "Apache: enable the headers module" a2enmod -q headers
  stage_begin /etc/apache2/conf-available/security-headers.conf
  stage_content <<'EOF'
# Added by the CyberPatriot practice toolkit (harden.sh)
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>
EOF
  stage_commit "Apache: browser security headers"
  [[ -e /etc/apache2/conf-enabled/security-headers.conf ]] || fix "Enable security-headers.conf" a2enconf -q security-headers
  if grep -Eq '^[[:space:]]*export[[:space:]]+APACHE_RUN_USER=root' /etc/apache2/envvars 2>/dev/null; then
    result REVIEW "Apache is set to run as root!"
    stage_begin /etc/apache2/envvars
    stage_sed 's/^([[:space:]]*export[[:space:]]+APACHE_RUN_USER=)root/\1www-data/' "APACHE_RUN_USER=www-data"
    stage_sed 's/^([[:space:]]*export[[:space:]]+APACHE_RUN_GROUP=)root/\1www-data/' "APACHE_RUN_GROUP=www-data"
    stage_commit "Apache runs as www-data, not root"
  fi
  if [[ $MODE == apply ]] && changed_since "$mark"; then
    if run apache2ctl configtest; then reload_unit apache2; else result FAILED "Apache config test failed - check: sudo apache2ctl configtest"; fi
  fi
  local -a wwweb
  mapfile -t wwweb < <(find /var/www -xdev \( -user www-data -o -perm -o+w \) -type f 2>/dev/null | head -50)
  if [[ ${#wwweb[@]} -gt 0 ]]; then
    result REVIEW "Website files the web server (or anyone) can modify - a hacked site could rewrite itself"
    show_list 10 "${wwweb[@]}"
  fi
}

harden_nginx() {
  local mark=${#RESULTS[@]} f real
  info "Nginx web server (critical: hardening it, not removing it)"
  why "Hide the version number and turn off folder listings."
  stage_begin /etc/nginx/nginx.conf
  if grep -Eq '^[[:space:]]*#?[[:space:]]*server_tokens' "$STAGE_TMP"; then
    stage_set "server_tokens[ \t]" "	server_tokens off;"
  else
    stage_sed '0,/^[[:space:]]*http[[:space:]]*\{/s//&\n\tserver_tokens off;/' "server_tokens off"
  fi
  stage_commit "Nginx: hide version number" nginx -t
  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
    [[ -f $f ]] || continue
    real=$(readlink -f "$f")
    grep -Eq '^[^#]*autoindex[[:space:]]+on' "$real" || continue
    stage_begin "$real"
    stage_sed 's/autoindex[[:space:]]+on/autoindex off/g' "autoindex off"
    stage_commit "Nginx: no folder listings in $(basename "$real")" nginx -t
  done
  changed_since "$mark" && reload_unit nginx
}

harden_php() {
  local ini mark=${#RESULTS[@]} kv key cur merged
  info "PHP (used by the website)"
  why "Hide the PHP version, don't show errors to visitors, and block functions that let a hacked page run system commands."
  for ini in /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini /etc/php/*/cgi/php.ini; do
    [[ -f $ini ]] || continue
    stage_begin "$ini"
    for kv in "expose_php = Off" "display_errors = Off" "display_startup_errors = Off" "log_errors = On" \
              "allow_url_fopen = Off" "allow_url_include = Off" "session.cookie_httponly = 1" \
              "session.use_strict_mode = 1" "session.use_only_cookies = 1"; do
      key=${kv%% *}
      stage_set "${key//./\\.}[ \t]*=" "$kv" "" ";"
    done
    cur=$(awk -F= '/^[ \t]*disable_functions[ \t]*=/{print $2}' "$ini" | tr -d ' ')
    merged=$(printf '%s,%s' "$cur" "exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,show_source" | tr ',' '\n' | awk 'NF && !s[$0]++' | paste -sd,)
    stage_set "disable_functions[ \t]*=" "disable_functions = $merged" "" ";"
    stage_commit "PHP settings in $ini"
  done
  if changed_since "$mark"; then
    reload_unit apache2
    local u
    for u in $(systemctl list-units --type=service --no-legend --plain 2>/dev/null | awk '/php.*fpm/{print $1}'); do reload_unit "$u"; done
  fi
}

harden_mysql() {
  local cnf="" f unit=""
  info "MySQL / MariaDB database (critical: hardening it, not removing it)"
  why "Remove anonymous and remote root logins, the test database, and the ability to read server files."
  for f in /etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf; do
    [[ -f $f ]] && { cnf=$f; break; }
  done
  unit_exists mariadb && unit=mariadb
  [[ -z $unit ]] && unit_exists mysql && unit=mysql
  if [[ -n $cnf ]]; then
    stage_begin "$cnf"
    stage_ini mysqld local_infile 0
    local bind
    bind=$(awk -F= '/^[ \t]*bind-address/{gsub(/[ \t]/, "", $2); print $2}' "$cnf" | tail -1)
    if [[ $bind == 0.0.0.0 || $bind == '*' || $bind == '::' ]]; then
      result REVIEW "The database accepts connections from the network (bind-address=$bind)"
      if ask "Only accept connections from this computer (127.0.0.1)? Say NO if the README says other computers use it" y strict; then
        stage_ini mysqld bind-address 127.0.0.1
      fi
    fi
    stage_commit "Database server settings ($cnf)"
    [[ $(last_status) == CHANGED && -n $unit ]] && restart_or_rollback "$unit" "$cnf"
  fi
  if ! have mysql; then return; fi
  if ! mysql -NBe 'SELECT 1' >/dev/null 2>&1; then
    result REVIEW "Could not log into the database as root automatically - check its users by hand: sudo mysql -u root -p"
    return
  fi
  local a
  while read -r a; do
    [[ -z $a ]] && continue
    result REVIEW "Anonymous database account: $a"
    if ask "Delete anonymous account $a?" y; then fix "Deleted database account $a" mysql -e "DROP USER $a"; fi
  done < <(mysql -NBe "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user WHERE user=''" 2>/dev/null)
  while read -r a; do
    [[ -z $a ]] && continue
    result REVIEW "Database root can log in from the network: $a"
    if ask "Delete $a (root will still work from this computer)?" y; then fix "Deleted database account $a" mysql -e "DROP USER $a"; fi
  done < <(mysql -NBe "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null)
  if [[ -n $(mysql -NBe "SHOW DATABASES LIKE 'test'" 2>/dev/null) ]]; then
    result REVIEW "The sample 'test' database exists (anyone can usually write to it)"
    if ask "Delete the 'test' database?" y; then fix "Deleted the test database" mysql -e "DROP DATABASE test"; fi
  fi
  local -a nopw users
  mapfile -t nopw < <(mysql -NBe "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND plugin NOT IN ('auth_socket','unix_socket') AND user<>''" 2>/dev/null)
  for a in "${nopw[@]}"; do result REVIEW "Database account with NO password: $a (set one: ALTER USER ... IDENTIFIED BY '...')"; done
  mapfile -t users < <(mysql -NBe "SELECT CONCAT(user,'@',host) FROM mysql.user" 2>/dev/null)
  result REVIEW "Database accounts (compare with the README): ${users[*]}"
  [[ $MODE == apply ]] && run mysql -e "FLUSH PRIVILEGES"
}

harden_vsftpd() {
  local c=/etc/vsftpd.conf kv
  info "vsftpd FTP server (critical: hardening it, not removing it)"
  why "No anonymous logins, users are locked into their home folders, and transfers are logged."
  stage_begin "$c"
  for kv in anonymous_enable=NO anon_upload_enable=NO anon_mkdir_write_enable=NO anon_other_write_enable=NO \
            chroot_local_user=YES allow_writeable_chroot=YES xferlog_enable=YES hide_ids=YES; do
    stage_set "${kv%%=*}[ \t]*=" "$kv"
  done
  local cert key
  cert=$(awk -F= '/^[ \t]*rsa_cert_file/{print $2}' "$c"); key=$(awk -F= '/^[ \t]*rsa_private_key_file/{print $2}' "$c")
  if ! grep -Eq '^[[:space:]]*ssl_enable[[:space:]]*=[[:space:]]*YES' "$c" && [[ -f $cert && -f ${key:-$cert} ]]; then
    result REVIEW "FTP traffic (including passwords) is not encrypted (ssl_enable=NO)"
    if ask "Turn on FTPS encryption? Users then need an FTP client that supports TLS" n strict; then stage_set "ssl_enable[ \t]*=" "ssl_enable=YES"; fi
  fi
  stage_commit "vsftpd settings"
  [[ $(last_status) == CHANGED ]] && restart_or_rollback vsftpd "$c"
}

harden_proftpd() {
  local c=/etc/proftpd/proftpd.conf
  info "ProFTPD FTP server (critical: hardening it, not removing it)"
  stage_begin "$c"
  stage_set "serverident[ \t]" 'ServerIdent on "FTP server ready"'
  stage_set "rootlogin[ \t]" "RootLogin off"
  stage_set "defaultroot[ \t]" "DefaultRoot ~"
  if grep -Eiq '^[[:space:]]*<Anonymous' "$c"; then
    result REVIEW "ProFTPD allows anonymous logins (<Anonymous> block)"
    if ask "Disable the anonymous FTP block?" y; then
      stage_sed '/^[[:space:]]*<Anonymous/I,/^[[:space:]]*<\/Anonymous>/I s/^/# /' "comment out <Anonymous> block"
    fi
  fi
  stage_commit "ProFTPD settings" proftpd -t
  [[ $(last_status) == CHANGED ]] && reload_unit proftpd
}

harden_pureftpd() {
  local mark=${#RESULTS[@]}
  info "Pure-FTPd FTP server (critical: hardening it, not removing it)"
  stage_begin /etc/pure-ftpd/conf/NoAnonymous; printf 'yes\n' | stage_content; stage_commit "Pure-FTPd: no anonymous logins"
  stage_begin /etc/pure-ftpd/conf/ChrootEveryone; printf 'yes\n' | stage_content; stage_commit "Pure-FTPd: lock users in their home folders"
  changed_since "$mark" && restart_or_rollback pure-ftpd /etc/pure-ftpd/conf/NoAnonymous /etc/pure-ftpd/conf/ChrootEveryone
}

harden_samba() {
  local c=/etc/samba/smb.conf u
  info "Samba file sharing (critical: hardening it, not removing it)"
  why "No guest access, no anonymous listing of users and shares, and no old insecure SMB1 protocol."
  stage_begin "$c"
  stage_ini global "restrict anonymous" 2
  stage_ini global "map to guest" never
  stage_ini global "usershare allow guests" no
  stage_ini global "server min protocol" SMB2
  stage_sed 's/^([[:space:]]*(guest ok|public)[[:space:]]*=[[:space:]]*)yes/\1no/I' "shares: no guest access"
  stage_commit "Samba settings" testparm -s
  [[ $(last_status) == CHANGED ]] && reload_unit smbd
  if have pdbedit; then
    while read -r u; do
      [[ -z $u ]] && continue
      in_list "$u" $AUTHORIZED_ADMINS $AUTHORIZED_USERS && continue
      result REVIEW "Samba user '$u' is not an authorized user"
      if ask "Remove '$u' from Samba?" y; then fix "Removed Samba user $u" smbpasswd -x "$u"; fi
    done < <(pdbedit -L 2>/dev/null | cut -d: -f1)
  fi
  local shares; shares=$(testparm -s 2>/dev/null | grep -E '^\[' | tr -d '[]' | tr '\n' ' ')
  [[ -n $shares ]] && result REVIEW "Samba shares: $shares- make sure each one is needed and has the right permissions"
}

harden_bind() {
  local f=/etc/bind/named.conf.options
  info "BIND DNS server (critical: hardening it, not removing it)"
  why "Hide the version number and don't hand out the whole zone (list of all computers) to anyone who asks."
  [[ -f $f ]] || { result REVIEW "$f not found"; return; }
  stage_begin "$f"
  stage_set "version[ \t]" '	version "none";' "^};" "#/"
  stage_set "allow-transfer[ \t]" '	allow-transfer { none; };' "^};" "#/"
  stage_commit "BIND: hide version, block zone transfers" named-checkconf
  [[ $(last_status) == CHANGED ]] && { reload_unit named || reload_unit bind9; }
  if grep -Rqs 'allow-transfer[[:space:]]*{[[:space:]]*any' /etc/bind/; then
    result REVIEW "A zone allows transfers to ANY computer (allow-transfer { any; }) - check /etc/bind/named.conf.local"
  fi
}

harden_postfix() {
  local kv k v cur mark=${#RESULTS[@]}
  info "Postfix mail server (critical: hardening it, not removing it)"
  for kv in "disable_vrfy_command=yes" "smtpd_helo_required=yes" 'smtpd_banner=$myhostname ESMTP'; do
    k=${kv%%=*}; v=${kv#*=}
    cur=$(postconf -h "$k" 2>/dev/null)
    if [[ $cur == "$v" ]]; then result OK "Postfix $k = $v"; else fix "Postfix: $k = $v (was '$cur')" postconf -e "$k=$v"; fi
  done
  if postconf -h mynetworks 2>/dev/null | grep -q '0\.0\.0\.0/0'; then
    result REVIEW "Postfix mynetworks includes 0.0.0.0/0 - it is an OPEN RELAY (anyone can send spam through it)"
  fi
  changed_since "$mark" && reload_unit postfix
}

sec_apps() {
  local did=0
  if is_critical apache apache2 httpd web webserver http https && pkg_installed apache2; then harden_apache; did=1; fi
  if is_critical nginx web webserver http https && [[ -f /etc/nginx/nginx.conf ]]; then harden_nginx; did=1; fi
  if compgen -G "/etc/php/*/*/php.ini" >/dev/null && is_critical php apache apache2 nginx web webserver http https; then harden_php; did=1; fi
  if is_critical mysql mariadb database sql db && { pkg_installed mysql-server || pkg_installed mariadb-server || have mysqld || have mariadbd; }; then harden_mysql; did=1; fi
  if is_critical ftp vsftpd && pkg_installed vsftpd; then harden_vsftpd; did=1; fi
  if is_critical ftp proftpd && [[ -f /etc/proftpd/proftpd.conf ]]; then harden_proftpd; did=1; fi
  if is_critical ftp pure-ftpd pureftpd && [[ -d /etc/pure-ftpd/conf ]]; then harden_pureftpd; did=1; fi
  if is_critical samba smb smbd cifs fileshare && pkg_installed samba; then harden_samba; did=1; fi
  if is_critical dns bind bind9 named && pkg_installed bind9; then harden_bind; did=1; fi
  if is_critical mail smtp postfix && pkg_installed postfix; then harden_postfix; did=1; fi
  [[ $did -eq 0 ]] && result SKIPPED "No critical web, database, FTP, Samba, DNS or mail service is listed (or installed)"
}

# ============================================================================
# SECTION: Updates
# ============================================================================
sec_updates() {
  local f line uri n
  info "Software sources (where updates come from)"
  why "A fake software source can install malware. A missing 'security' source means no security fixes."
  local official='^(cdrom:|https?://([a-z0-9-]+\.)*(archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com|deb\.debian\.org|security\.debian\.org|debian\.org|packages\.linuxmint\.com|linuxmint\.com|archive\.canonical\.com|esm\.ubuntu\.com)(/|$)|https?://mirrors?\.)'
  local -a srcfiles=() unofficial=() insecure=()
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do [[ -f $f ]] && srcfiles+=("$f"); done
  local has_security=0
  for f in "${srcfiles[@]}"; do
    while IFS= read -r line; do
      [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
      [[ $line =~ (-security|security\.debian\.org|security\.ubuntu\.com|debian-security) ]] && has_security=1
      [[ $line =~ (trusted=yes|allow-insecure=yes|Trusted:[[:space:]]*yes) ]] && insecure+=("$f: $line")
      for uri in $(grep -oE '(https?|ftp|cdrom)://[^ ]+|cdrom:\[[^]]*\]/' <<<"$line"); do
        [[ $uri =~ $official ]] || unofficial+=("$f: $uri")
      done
    done <"$f"
  done
  if [[ ${#unofficial[@]} -eq 0 ]]; then result OK "All software sources are official"; else
    result REVIEW "Unofficial software source(s) - remove any the README doesn't need (sudo nano <file>)"
    show_list 10 "${unofficial[@]}"
  fi
  if [[ ${#insecure[@]} -gt 0 ]]; then
    result REVIEW "Software source(s) with signature checking turned OFF (trusted=yes) - anyone could feed you fake packages"
    show_list 10 "${insecure[@]}"
  fi
  if [[ $has_security -eq 1 ]]; then result OK "A security update source is configured"
  else result REVIEW "No security update source found! Add it in Software Sources / Software & Updates"; fi
  local -a aptconf
  mapfile -t aptconf < <(grep -RHiE '^[^/#]*(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories)[[:space:]]+"?(true|1)' /etc/apt/apt.conf /etc/apt/apt.conf.d/ 2>/dev/null)
  for line in "${aptconf[@]}"; do
    f=${line%%:*}
    result REVIEW "APT is allowed to install unsigned packages: $line"
    if ask "Turn that setting off in $f?" y; then
      stage_begin "$f"
      stage_sed 's/^([^/#]*(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories).*)$/\/\/ \1   \/\/ disabled by harden.sh/I' "disable unsigned packages"
      stage_commit "APT setting in $f"
    fi
  done
  local held; held=$(apt-mark showhold 2>/dev/null | tr '\n' ' ')
  if [[ -z ${held// /} ]]; then result OK "No packages are held back from updating"; else
    result REVIEW "Packages are 'held' and will never update: $held"
    # shellcheck disable=SC2086
    if ask "Release the hold so they can update?" y; then fix "Released held packages: $held" apt-mark unhold $held; fi
  fi

  info "Automatic updates"
  why "Security fixes come out every week. Automatic updates install them even when nobody remembers to."
  ensure_pkg unattended-upgrades "automatic security updates"
  stage_begin /etc/apt/apt.conf.d/20auto-upgrades
  stage_set "apt::periodic::update-package-lists[ \t]" 'APT::Periodic::Update-Package-Lists "1";' "" "/"
  stage_set "apt::periodic::unattended-upgrade[ \t]" 'APT::Periodic::Unattended-Upgrade "1";' "" "/"
  stage_set "apt::periodic::download-upgradeable-packages[ \t]" 'APT::Periodic::Download-Upgradeable-Packages "1";' "" "/"
  stage_set "apt::periodic::autocleaninterval[ \t]" 'APT::Periodic::AutocleanInterval "7";' "" "/"
  stage_commit "Check for updates daily and install security updates automatically"
  if [[ -f /etc/apt/apt.conf.d/10periodic ]]; then
    stage_begin /etc/apt/apt.conf.d/10periodic
    stage_set "apt::periodic::update-package-lists[ \t]" 'APT::Periodic::Update-Package-Lists "1";' "" "/"
    stage_set "apt::periodic::download-upgradeable-packages[ \t]" 'APT::Periodic::Download-Upgradeable-Packages "1";' "" "/"
    stage_commit "Daily update check (10periodic)"
  fi
  if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]] && grep -Eq '^[[:space:]]*Unattended-Upgrade::Automatic-Reboot[[:space:]]+"true"' /etc/apt/apt.conf.d/50unattended-upgrades; then
    stage_begin /etc/apt/apt.conf.d/50unattended-upgrades
    stage_set "unattended-upgrade::automatic-reboot[ \t]" 'Unattended-Upgrade::Automatic-Reboot "false";' "" "/"
    stage_commit "Updates never reboot the computer by themselves"
  fi
  if [[ $IS_MINT -eq 1 ]] && have mintupdate-automation; then
    if systemctl is-enabled --quiet mintupdate-automation-upgrade.timer 2>/dev/null; then
      result OK "Mint automatic updates are on"
    else
      fix "Turn on Mint's automatic updates (Update Manager > Preferences > Automation)" mintupdate-automation upgrade enable
    fi
  fi

  info "Installing available updates"
  n=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep -c '^Inst ')
  if [[ $MODE == audit ]]; then
    if [[ $n -gt 0 ]]; then result WOULD "Install $n waiting update(s) (as of the last apt-get update)"; else result OK "No waiting updates (as of the last apt-get update)"; fi
  else
    local go=0
    case $FULL_UPGRADE in
      yes) go=1 ;;
      no)  result SKIPPED "Full upgrade skipped (FULL_UPGRADE=no)" ;;
      *)   say "  Installing all updates can take 5-30 minutes. Watch progress in another terminal: sudo tail -f $LOG_FILE"
           if ask "Install ALL available updates now?" y; then go=1; else result SKIPPED "Updates not installed (your choice)"; fi ;;
    esac
    if [[ $go -eq 1 ]]; then
      apt_update_once
      fix "Installed all available updates (apt-get dist-upgrade)" apt-get "${APT_OPTS[@]}" dist-upgrade
      if have snap && snap list 2>/dev/null | grep -q .; then fix "Updated snap packages (e.g. Firefox on Ubuntu)" snap refresh; fi
    fi
  fi
  [[ -f /var/run/reboot-required ]] && result REVIEW "Some updates need a reboot (e.g. a new kernel). Reboot ONCE near the end, after saving your work"
}

# ============================================================================
# Menu, summary and main
# ============================================================================
print_summary() {
  local r ok=0 ch=0 wo=0 sk=0 fa=0 re=0
  header "Summary"
  for r in "${RESULTS[@]}"; do
    case ${r%%|*} in OK) ok=$((ok+1)) ;; CHANGED) ch=$((ch+1)) ;; WOULD) wo=$((wo+1)) ;; SKIPPED) sk=$((sk+1)) ;; FAILED) fa=$((fa+1)) ;; REVIEW) re=$((re+1)) ;; esac
  done
  say "  ${C_GRN}OK${C_RST} $ok    ${C_GRN}CHANGED${C_RST} $ch    ${C_CYN}WOULD CHANGE${C_RST} $wo    ${C_DIM}SKIPPED${C_RST} $sk    ${C_YLW}REVIEW${C_RST} $re    ${C_RED}FAILED${C_RST} $fa"
  if [[ $fa -gt 0 ]]; then
    say ""; say "  ${C_RED}Failed:${C_RST}"
    for r in "${RESULTS[@]}"; do [[ ${r%%|*} == FAILED ]] && say "    - ${r#*|*|}"; done
  fi
  say ""
  say "  Your to-do list (REVIEW items): ${C_BLD}$REPORT_FILE${C_RST}"
  say "  Full log:                       $LOG_FILE"
  [[ -d $BACKUP_DIR ]] && say "  Backups of edited files:        $BACKUP_DIR"
  say ""
  say "  NEXT: open the Scoring Report on the desktop, then work through the REVIEW items"
  say "  and the checklist for this OS (docs/checklists/)."
}

run_section() {
  local entry id title fn
  for entry in "${SECTIONS[@]}"; do
    IFS='|' read -r id title fn <<<"$entry"
    [[ $id == "$1" ]] || continue
    CURRENT_SECTION=$id
    header "$title   [${MODE^^}]"
    printf '\n## %s\n\n' "$title" >>"$REPORT_FILE"
    "$fn"
    CURRENT_SECTION="setup"
    return 0
  done
  warn "Unknown section '$1' (see --list)"
}

APPLY_CONFIRMED=0
confirm_apply() {
  [[ $MODE == apply ]] || return 0
  [[ $APPLY_CONFIRMED -eq 1 ]] && return 0
  say ""
  warn "APPLY mode changes this computer. Before you continue:"
  say "     1. Have you answered the FORENSICS QUESTIONS? Deleting users and files can destroy the answers."
  say "     2. Did you enter the README's authorized users and critical services correctly?"
  say "     3. Is there a snapshot of this VM you can go back to?"
  if [[ $ASSUME_YES -eq 1 ]] || ask "Ready to make changes?" n; then APPLY_CONFIRMED=1; return 0; fi
  return 1
}

menu() {
  local entry id title fn i n
  while true; do
    header "Main menu   (mode: ${MODE^^})"
    i=1
    for entry in "${SECTIONS[@]}"; do
      IFS='|' read -r id title fn <<<"$entry"
      printf '  %2d) %s\n' "$i" "$title"
      i=$((i + 1))
    done
    say "   a) Run ALL sections"
    if [[ $MODE == audit ]]; then say "   m) Switch to APPLY mode (make changes)"; else say "   m) Switch to AUDIT mode (report only)"; fi
    say "   r) Re-enter the README information"
    say "   s) Show the summary so far"
    say "   q) Quit"
    printf '%s  Choose (examples: 1   or   1 3 5   or   a): %s' "$C_YLW" "$C_RST"
    read_tty
    case ${REPLY,,} in
      q|quit|exit) break ;;
      a|all) if confirm_apply; then for entry in "${SECTIONS[@]}"; do run_section "${entry%%|*}"; done; fi ;;
      m) if [[ $MODE == audit ]]; then MODE=apply; else MODE=audit; fi ;;
      r) prompt_readme; finalize_readme; show_readme_summary ;;
      s) print_summary ;;
      "") ;;
      *)
        local ids=()
        for n in ${REPLY//,/ }; do
          if [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#SECTIONS[@]} )); then ids+=("${SECTIONS[n-1]%%|*}")
          else warn "Not a menu choice: $n"; fi
        done
        if [[ ${#ids[@]} -gt 0 ]] && confirm_apply; then for id in "${ids[@]}"; do run_section "$id"; done; fi ;;
    esac
  done
}

usage() {
  cat <<EOF
CyberPatriot practice toolkit - Linux hardening script v$SCRIPT_VERSION
Supports Linux Mint 20-22, Debian 11-12 and Ubuntu 20.04-24.04.

  sudo bash harden.sh                    interactive menu (starts in AUDIT mode)
  sudo bash harden.sh --audit            report problems only, change nothing
  sudo bash harden.sh --apply            fix problems (asks before risky steps)
  sudo bash harden.sh --apply --yes      fix problems without asking
  sudo bash harden.sh --config FILE      read README info from FILE (see config.example.conf)
  sudo bash harden.sh --only a,b,c       run only these sections (see --list)
  sudo bash harden.sh --list             list the sections
  sudo bash harden.sh --no-color         plain output

Results:  OK = already secure   CHANGED = fixed   WOULD = audit: would fix
          SKIPPED = not done    REVIEW = a human must check   FAILED = see the log
EOF
}

main() {
  local list_only=0 id entry
  while [[ $# -gt 0 ]]; do
    case $1 in
      --audit) MODE=audit ;;
      --apply) MODE=apply ;;
      -y|--yes) ASSUME_YES=1 ;;
      --config) CONFIG_FILE=${2:-}; shift ;;
      --only) ONLY_SECTIONS=${2:-}; shift ;;
      --list) list_only=1 ;;
      --no-color) NO_COLOR=1 ;;
      -h|--help) usage; exit 0 ;;
      *) printf 'Unknown option: %s (try --help)\n' "$1" >&2; exit 1 ;;
    esac
    shift
  done
  setup_colors
  if [[ $list_only -eq 1 ]]; then
    for entry in "${SECTIONS[@]}"; do IFS='|' read -r id title _ <<<"$entry"; printf '  %-12s %s\n' "$id" "$title"; done
    exit 0
  fi
  [[ $EUID -eq 0 ]] || die "Please run this as root:   sudo bash $0"
  mkdir -p "$WORK_DIR" && chmod 700 "$WORK_DIR"
  : >"$LOG_FILE"
  printf '# Findings report - %s\n# Items marked REVIEW need a human decision. WOULD = audit mode found something to fix.\n' "$(date)" >"$REPORT_FILE"

  detect_os
  printf '\n%s%s CyberPatriot Practice Toolkit - Linux hardening v%s %s\n' "$C_BLD" "$C_CYN" "$SCRIPT_VERSION" "$C_RST"
  say "  System: $OS_NAME   Desktop: ${DESKTOP:-none}   Login screen: ${DISPLAY_MANAGER:-none}"
  if [[ $IS_MINT -eq 0 && $IS_DEBIAN -eq 0 && $IS_UBUNTU -eq 0 ]]; then
    warn "This script is made for Linux Mint, Debian and Ubuntu. '$OS_NAME' may not work."
    ask "Continue anyway?" n strict || [[ $MODE == audit ]] || exit 1
  fi

  if [[ -n $CONFIG_FILE ]]; then load_config "$CONFIG_FILE"
  elif [[ $HAVE_TTY -eq 1 && $ASSUME_YES -eq 0 ]]; then prompt_readme; fi
  finalize_readme
  show_readme_summary

  if [[ -z $MODE ]]; then
    [[ $HAVE_TTY -eq 1 ]] || die "No keyboard available. Use --audit or --apply."
    MODE=audit
    say ""
    say "  Starting in ${C_BLD}AUDIT${C_RST} mode: nothing is changed. Press 'm' in the menu to switch to APPLY."
    menu
  else
    confirm_apply || exit 1
    if [[ -n $ONLY_SECTIONS ]]; then
      for id in ${ONLY_SECTIONS//,/ }; do run_section "$id"; done
    else
      for entry in "${SECTIONS[@]}"; do run_section "${entry%%|*}"; done
    fi
  fi
  print_summary
  [[ -n $OWNED_DB ]] && rm -f "$OWNED_DB"
  return 0
}

main "$@"
