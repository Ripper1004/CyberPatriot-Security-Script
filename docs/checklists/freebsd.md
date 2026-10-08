# FreeBSD checklist (13 / 14)

FreeBSD may appear in the **Semifinals** (depending on tier). It's a Unix like Linux, but **many commands and file locations are different**. Use this translation table whenever you get stuck.

## FreeBSD vs. Linux, the quick translation

| Task | Linux | FreeBSD |
|---|---|---|
| Become root | `sudo -i` | `su -` (you must be in the **wheel** group), then type `sh` |
| Admin group | `sudo` | `wheel` |
| Add / delete user | `adduser` / `userdel` | `adduser` (interactive) or `pw useradd` / `pw userdel` |
| User info | `/etc/shadow` | `/etc/master.passwd` (edit with `vipw`, never directly) |
| Install / remove software | `apt install` / `apt purge` | `pkg install` / `pkg delete` |
| Update packages | `apt upgrade` | `pkg upgrade` |
| Update the OS | (part of apt) | `freebsd-update fetch install` |
| Services | `systemctl` | `service <name> start/stop` and `sysrc <name>_enable=YES/NO` |
| Start-up settings | systemd units | `/etc/rc.conf` (change with `sysrc`) |
| Firewall | `ufw` | `pf` (`/etc/pf.conf`) or `ipfw` |
| Kernel settings | `/etc/sysctl.conf` | `/etc/sysctl.conf` (different names) |
| Listening ports | `ss -tulpn` | `sockstat -4 -6 -l` |
| Logs | `/var/log/auth.log`, `journalctl` | `/var/log/auth.log`, `/var/log/messages`, `/var/log/security` |
| Simple editor | `nano` | `ee` (Easy Editor; **Esc** opens the menu) |
| Cron jobs | `/var/spool/cron/crontabs/` | `/var/cron/tabs/` |
| Is a file from a package? | `dpkg -S file` | `pkg which file` |
| Home folders | `/home` | `/home` (on FreeBSD 13 it is a link to `/usr/home`) |

> [!TIP]
> The FreeBSD script (`scripts/freebsd/harden.sh`) does most of this. Run it with `sh harden.sh` as root (after `su -`). Step [0.1 Fast path](#01-fast-path-run-the-hardening-script) shows how, and every step below says what the script already did for you.

> [!IMPORTANT]
> The commands on this page are written for the `sh` shell. On **FreeBSD 13** (and on a 14 that was upgraded from 13) root's shell is `csh`, which reads them differently (for example `2>/dev/null` hides the results instead of the errors). After `su -`, always type `sh` and press Enter; it does no harm if you were already in `sh`.

---

## 0. Before you start

- [ ] Read the README; write down admins, users, critical services.
- [ ] Take a VMware snapshot.
- [ ] Become root: `su -` (or `sudo -i` / `doas -s` if those are installed), then type `sh` (see the box above).
- [ ] Answer the forensics questions ([guide](../guides/forensics-questions.md)). `sha256 file` hashes a file on FreeBSD (`sha256sum` may not exist).

### 0.1 Fast path: run the hardening script
- [ ] Done

**What:** Let the script fix the easy things first, then do only the steps it leaves for you. Answer the **forensics questions first**: the script can delete files and users they ask about.

**Why it matters:** The script does in a few minutes what takes an hour by hand, and its findings report is a ready-made to-do list.

**Typing:** become root, get the script onto the image (open [Download the scripts](/downloads/) on this website and run the **FreeBSD** command there; it saves `harden.sh` in `~/cp`), then type these lines one at a time (`su -` waits for a password, so don't paste them all at once):
```sh
su -                                    # asks for the ROOT password
sh                                      # switch to sh (root may be using csh)
cd ~/cp
sh harden.sh --audit                    # report only, changes NOTHING; read every REVIEW line
sh harden.sh --audit --config my.conf   # optional: README info from a file (make it with the README config builder on the website and save it in `~/cp`)
sh harden.sh --apply                    # now fix things (add --config my.conf if you made one)
cat /root/cyberpatriot/findings-*.txt   # the findings report: your to-do list
```
The script asks for the README's admins, users and critical services first (unless you use `--config`). Type the names carefully. At the end it prints the path of the findings report (`/root/cyberpatriot/findings-<date-time>.txt`). Read it.

Now skip every step marked **Script: ✅** below (on the website, press **Tick the script's ✅ steps** at the top of the page). Do the 🔎 and ✋ steps.

**Check it worked:** the summary at the end shows `CHANGED` items and a `To-do list:` path, `ls /root/cyberpatriot/` shows the findings report, and the Scoring Report shows new points.

> [!WARNING]
> Any `FAILED` line means the script could not do that fix: do it by hand with the steps below. The FreeBSD script **has not been run on a real FreeBSD system yet**, so always run `--audit` first and check the Scoring Report after `--apply`. If your score goes down, undo the change from `/root/cyberpatriot/backups/`.

---

## 1. Users and groups

### 1.1 List users
- [ ] Done

**Script:** 🔎 Lists the users and reports every one that is not in your README list; you still read the list yourself.

```sh
awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd
```

### 1.2 Delete unauthorized users, add missing ones
- [ ] Done

**Script:** 🔎 Deletes users missing from your README list and creates missing ones (it asks first, and only if you gave the user lists); double-check the names.

```sh
pw userdel mallory              # add -r to also delete their home folder
adduser                         # interactive: asks for name, shell, password...
pw useradd erin -m -s /bin/sh   # or without questions: creates erin with a home folder...
passwd erin                     # ...then give erin a password
```

### 1.3 Admins = the `wheel` group
- [ ] Done

**Script:** 🔎 Removes non-admins from `wheel` and adds the README admins (only works if you gave AUTHORIZED_ADMINS); you still check sudo/doas rules and the `operator` group it reports.

```sh
pw groupshow wheel
pw groupmod wheel -d bob        # remove bob
pw groupmod wheel -m alice      # add alice
```
If `sudo` or `doas` is installed, also check their rules (section 7).

### 1.4 Hidden root accounts
- [ ] Done

**Script:** 🔎 Locks `toor` if it has a password and offers to delete any other UID-0 account; run the check again to be sure only `root` and a locked `toor` are left.

```sh
awk -F: '$3 == 0 {print $1, $2}' /etc/master.passwd
```
FreeBSD normally has **`root`** and **`toor`** with UID 0. `toor` is fine **only if** its password field is `*` or starts with `*LOCKED*` (that is what `pw lock` adds). If `toor` has a real password, remove it:
```sh
pw usermod toor -h -            # sets toor's password field to * (no password login)
pw userdel mallory              # any OTHER UID-0 account is a backdoor: delete it (no -r: its home may be /root)
```

### 1.5 Empty passwords and weak passwords
- [ ] Done

**Script:** 🔎 Locks accounts with an empty password and sets your NEW_PASSWORD for the README users if you give one; otherwise set strong passwords yourself with `passwd`.

```sh
awk -F: '$2 == "" {print $1}' /etc/master.passwd     # accounts with NO password
passwd bob                                           # set a strong password
pw lock mallory                                      # or lock an account nobody should log in to
```

> [!CAUTION]
> If **`root`** is on the empty-password list, give it a password with `passwd root`. **Never lock root**: you would lose `su -`. (The script's lock question includes root too; answer **n** for root.)

### 1.6 System accounts that can log in
- [ ] Done

**Script:** ✋ Not done by the script.

**What:** System accounts (UID below 1000, like `daemon`, `www`, `games`) never log in, so their shell is `/usr/sbin/nologin`. An attacker who gives one a real shell (and a password) has a hidden login.
```sh
awk -F: '$3 < 1000 && $7 != "/usr/sbin/nologin" {print $1, $3, $7}' /etc/passwd
pw usermod mallory -s /usr/sbin/nologin    # mallory = the account you found
```
Normal output: `root`, `toor` (empty shell) and `uucp` (its own `uucico` program), plus accounts that a README service's package made (for example `postgres`). Anything else with `/bin/sh`, `/bin/csh` or `/usr/local/bin/bash` is suspicious, and so is an account name you don't recognize.

---

## 2. Password policy

### 2.1 Strong hashing and password expiry (`/etc/login.conf`)
- [ ] Done

**Script:** ✅ Done by the script (`passwords` section).

```sh
ee /etc/login.conf
```
In the **`default:`** block, make sure these lines exist:
```
	:passwd_format=sha512:\
	:passwordtime=90d:\
```
Every line in the block except the last ends with `\`. Then **rebuild the database** (required!):
```sh
cap_mkdb /etc/login.conf
```
Both settings only apply to passwords set **after** this: if you already changed passwords in 1.5, set them again (`passwd bob`). `minpasswordlen` and `mixpasswordcase` in `login.conf` do nothing on FreeBSD (the manual lists them as "not implemented"); password length is set in 2.2.

### 2.2 Password complexity (`pam_passwdqc`)
- [ ] Done

**Script:** ✅ Done by the script (`passwords` section).

```sh
ee /etc/pam.d/passwd
```
Make sure this line is active (no `#` in front) and comes **before** the `pam_unix.so` line:
```
password	requisite	pam_passwdqc.so	min=disabled,disabled,disabled,12,12 similar=deny retry=3 enforce=users
```
This asks for 12+ characters using at least three kinds (lower case, upper case, digits, symbols). `enforce=users` does not check root, so test it as a normal user: `su - bob`, then `passwd` (it asks for bob's current password first), try a weak password (it must be refused), then `exit`.

---

## 3. Firewall (pf)

### 3.1 Write a pf ruleset
- [ ] Done

**Script:** 🔎 Writes `/etc/pf.conf` that only opens your CRITICAL_SERVICES ports (plus EXTRA_PORTS) and turns pf on, but if pf was already on it only shows the rules; check the open ports match the README.

```sh
ee /etc/pf.conf
```
```
set skip on lo0
block in log all
pass out all keep state
pass in inet proto icmp icmp-type { echoreq, unreach }
anchor "blacklistd/*" in                         # lets blacklistd (step 5.1) block password guessers
pass in proto tcp to port { 22 } keep state      # ONLY the README's critical ports (22=SSH, 80/443=web, 21=FTP...)
```
If the README lists no network services, delete the last line (an empty `{ }` is an error).
Check it, then turn it on:
```sh
pfctl -nf /etc/pf.conf          # check for mistakes (no output = OK)
sysrc pf_enable=YES pflog_enable=YES
service pf start                # or: pfctl -f /etc/pf.conf -e
pfctl -sr                       # show the rules in use
```
**Check it worked:** `pfctl -s info | head -1` says `Status: Enabled`.

---

## 4. Services

### 4.1 See what starts at boot
- [ ] Done

**Script:** 🔎 Lists every enabled service and listening program in the findings report; you still compare them with the README.

```sh
service -e                      # every enabled service
sysrc -a | grep enable          # every *_enable setting
sockstat -4 -6 -l               # what's listening
```

### 4.2 Turn off what the README doesn't need
- [ ] Done

**Script:** 🔎 Offers to turn off common services (telnet, ftp, inetd, samba, web, databases...) that are not in CRITICAL_SERVICES; you still decide about anything else on the list.

```sh
sysrc ftpd_enable=NO    ; service ftpd onestop
sysrc inetd_enable=NO   ; service inetd onestop       # inetd starts telnet, ftp, tftp...
sysrc nfs_server_enable=NO rpcbind_enable=NO           # NFS file sharing (only if the README doesn't need it)
service nfsd onestop ; service mountd onestop ; service rpcbind onestop
```
Do the same for anything else in the 4.1 lists that the README doesn't need, for example `sysrc apache24_enable=NO ; service apache24 onestop`. The `sysrc` name is the one from `sysrc -a`; the `service` name is the last part of the `service -e` path (e.g. `nginx`, `mysql-server`, `samba_server`).
Also check `/etc/inetd.conf`: any line without `#` starts a service (telnet, ftp...). Comment them out. (There is no `telnetd_enable`: the telnet server runs through inetd, and FreeBSD 14 only has it as a package, `freebsd-telnetd`.)

### 4.3 Safer defaults in `/etc/rc.conf`
- [ ] Done

**Script:** ✅ Done by the script (`services` section).

```sh
sysrc sendmail_enable=NONE      # no mail server (unless the README needs mail)
sysrc syslogd_flags="-ss"       # logging doesn't listen on the network
sysrc clear_tmp_enable=YES      # empty /tmp at every boot
sysrc dumpdev=NO                # no crash dumps (they contain memory, i.e. passwords)
```
**Check it worked:** `sysrc sendmail_enable syslogd_flags clear_tmp_enable dumpdev` shows `NONE`, `-ss`, `YES`, `NO`. These take effect at the next boot; `service syslogd restart` applies the syslogd one now (the script does not restart it).

---

## 5. SSH

### 5.1 Secure sshd_config
- [ ] Done

**Script:** 🔎 Sets the safe sshd_config values, reloads sshd and turns on blacklistd, but does not add a `Banner` or turn SSH off for you; if SSH is not critical, disable it yourself.

Only if SSH is critical; otherwise `sysrc sshd_enable=NO; service sshd stop`.
```sh
ee /etc/ssh/sshd_config
```
Same settings as the [Linux Mint SSH table](linux-mint.md#92-needed-make-it-safe), plus `UseBlacklist yes`. Then:
```sh
sshd -t && service sshd reload
sysrc blacklistd_enable=YES && service blacklistd start      # blocks password guessing
```
blacklistd blocks through pf, so it only works if `/etc/pf.conf` has the `anchor "blacklistd/*" in` line from 3.1 (the script's pf rules don't include it: add it and run `pfctl -f /etc/pf.conf`).

---

## 6. Software and updates

### 6.1 Remove prohibited packages
- [ ] Done

**Script:** 🔎 Offers to remove packages from its list of hacking tools, games, torrent and remote-access apps; you still look through `pkg info` for anything else.

```sh
pkg info                        # everything installed
pkg info | grep -Ei 'nmap|john|hydra|wireshark|aircrack|hashcat|nikto|sqlmap|ettercap|netcat|minetest|supertux|transmission|qbittorrent|x11vnc'
pkg delete -y nmap
pkg autoremove -y
```
> [!NOTE]
> `/usr/bin/nc` (netcat) is **part of FreeBSD itself** and can't be removed. Look for it in cron jobs and running processes instead.

### 6.2 Known security holes
- [ ] Done

**Script:** 🔎 Runs `pkg audit -F` and lists vulnerable packages (the updates section upgrades them); check nothing is still listed afterwards.

```sh
pkg audit -F                    # lists installed packages with known vulnerabilities
```

### 6.3 Updates
- [ ] Done

**Script:** 🔎 Installs `freebsd-update` and `pkg` updates in --apply if you say yes (or set FULL_UPGRADE=yes); check they finished and reboot if the kernel changed.

```sh
freebsd-update fetch install    # OS updates (press q if a list appears)
pkg update && pkg upgrade -y    # package updates
freebsd-version -kr             # installed kernel, then running kernel
```
If those two lines differ, reboot so the new kernel runs. If `pkg update` fails, look for a fake repository in `/etc/pkg/FreeBSD.conf` and `/usr/local/etc/pkg/repos/`.

### 6.4 Media files
- [ ] Done

**Script:** 🔎 Finds media and torrent files and offers to delete them all; check the list against the forensics questions before saying yes.

```sh
find /home /usr/home /root /tmp -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.avi' -o -iname '*.mkv' -o -iname '*.wav' -o -iname '*.flac' \)
```

---

## 7. sudo / doas rules

### 7.1 No password-less root
- [ ] Done

**Script:** 🔎 Removes `NOPASSWD`/`!authenticate` (sudo) and `nopass` (doas) and reports rules for users who are not README admins; you remove those rules yourself.

```sh
cat /usr/local/etc/sudoers /usr/local/etc/sudoers.d/* 2>/dev/null   # edit with: visudo
cat /usr/local/etc/doas.conf 2>/dev/null
```
Remove `NOPASSWD` (sudo) and `nopass` (doas). Only the README admins (or `%wheel`) should have rules.

---

## 8. Kernel security settings

### 8.1 /etc/sysctl.conf
- [ ] Done

**Script:** 🔎 Writes every setting to `/etc/sysctl.conf` and applies most of them now; run `service sysctl restart` so `net.inet.ip.forwarding=0` takes effect too.

Open the file with `ee /etc/sysctl.conf` and make sure it has these lines (change a line that already sets the same name instead of adding a second one):
```
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
security.bsd.see_jail_proc=0
security.bsd.unprivileged_read_msgbuf=0
security.bsd.unprivileged_proc_debug=0
security.bsd.hardlink_check_uid=1
security.bsd.hardlink_check_gid=1
kern.randompid=1
net.inet.tcp.blackhole=2
net.inet.udp.blackhole=1
net.inet.ip.random_id=1
net.inet.icmp.drop_redirect=1
net.inet.ip.redirect=0
net.inet.ip.sourceroute=0
net.inet.ip.accept_sourceroute=0
net.inet.tcp.drop_synfin=1
net.inet.ip.forwarding=0
net.inet6.ip6.redirect=0
kern.elf64.aslr.enable=1
```
Apply right away: `service sysctl restart`. `see_other_uids=0` means users can't see each other's processes.

**Check it worked:** `sysctl security.bsd.see_other_uids net.inet.tcp.blackhole` shows `0` and `2`.

### 8.2 Ask for the root password in single-user mode
- [ ] Done

**Script:** ✋ Not done by the script.

**What:** Anyone at the keyboard can reboot into single-user mode and get a root shell **without a password** unless the `console` line in `/etc/ttys` says `insecure`. This is the "Enable console password prompt" choice of the FreeBSD installer's hardening menu.
```sh
grep '^console' /etc/ttys                     # default: console none unknown off secure
sed -i '' '/^console/s/off secure/off insecure/' /etc/ttys
grep '^console' /etc/ttys                     # now ends in: off insecure
```
Change **only** the `console` line. Making the `ttyv` lines insecure stops root from logging in at the screen.

While you are at boot settings, the installer's other hardening choice is "Disallow DTrace destructive-mode". It goes in `/boot/loader.conf` and works after a reboot:
```sh
grep -q allow_destructive_dtrace /boot/loader.conf || echo 'security.bsd.allow_destructive_dtrace=0' >> /boot/loader.conf
```

### 8.3 Kernel securelevel (optional, do it LAST)
- [ ] Done

**Script:** ✋ Not done by the script.

**What:** At securelevel 1 nobody, not even root, can load kernel modules, remove the "system immutable" file flag or write to raw memory and mounted disks. It only takes effect at the next boot.
```sh
sysrc kern_securelevel_enable=YES kern_securelevel=1
```
**Check it worked (after a reboot):** `sysctl kern.securelevel` shows `1`.

> [!CAUTION]
> Once it is on, `freebsd-update install` refuses to run ("Updates cannot be installed when the system securelevel is greater than zero"), and the level can't be lowered without setting `kern_securelevel_enable=NO` and rebooting. Do it only after all updates (6.3) are done, and only if the README doesn't say you need to load kernel modules or install updates later.

---

## 9. Permissions

### 9.1 Important files and SUID programs
- [ ] Done

**Script:** 🔎 Fixes the permissions on the important files and offers to remove SUID from dangerous programs; you still look up the other unusual SUID programs it reports.

```sh
ls -l /etc/master.passwd /etc/spwd.db      # must be -rw------- root wheel
chmod 600 /etc/master.passwd
find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null   # SUID/SGID programs (no -xdev: /home is often a separate ZFS file system)
chmod u-s,g-s /usr/bin/find                    # if find/vi/sh/python etc. are SUID or SGID
ls -ld /home/*                                 # home folders: no access for others (drwx------ or drwxr-x---)
chmod 700 /home/bob                            # fix one that is open to everyone
```

---

## 10. Backdoors

### 10.1 Cron, start-up scripts, shell files, keys, hosts
- [ ] Done

**Script:** 🔎 Reports cron jobs, rc.d scripts, shell aliases, SSH keys, listening programs, /etc/hosts and boot modules and offers to remove the obvious ones; you still check and fix every REVIEW line.

```sh
ls -la /var/cron/tabs/ ; grep -Hv '^#' /var/cron/tabs/* 2>/dev/null   # every user's cron jobs (file name = user)
cat /etc/crontab
cat /etc/rc.local /etc/rc.conf.local 2>/dev/null
ls /etc/cron.d /usr/local/etc/cron.d /var/at/jobs 2>/dev/null   # more cron files and "at" jobs
cat /etc/periodic.conf /etc/daily.local 2>/dev/null ; ls /usr/local/etc/periodic/*/ 2>/dev/null   # periodic jobs run daily as root (look for *_local= or odd scripts)
ls /usr/local/etc/rc.d/ ; for f in /usr/local/etc/rc.d/*; do pkg which -q "$f" >/dev/null || echo "NOT FROM A PACKAGE: $f"; done
grep -n alias /root/.cshrc /root/.shrc /home/*/.shrc /home/*/.cshrc 2>/dev/null
find / -name authorized_keys 2>/dev/null
cat /etc/hosts
sockstat -4 -6 -l
kldstat                          # loaded kernel modules
grep _load /boot/loader.conf     # modules loaded at boot
```
FreeBSD's own `.cshrc`/`.shrc` have harmless aliases like `h`, `j`, `la`, `lf`, `ll`. An alias that changes `su`, `sudo`, `ls`, `ps` or `passwd` is a trap.

### 10.2 Tampered system files
- [ ] Done

**Script:** 🔎 In --apply it offers to run `freebsd-update IDS` and lists changed system files; you still decide which programs were tampered with.

```sh
freebsd-update IDS | less        # lists system files that differ from the official release
```
(Changed config files in `/etc` are normal; changed programs in `/bin`, `/sbin`, `/usr/bin` are **not**.)

---

## 11. Logging

### 11.1 Security auditing on
- [ ] Done

**Script:** ✅ Done by the script (`logging` section).

```sh
sysrc auditd_enable=YES && service auditd start
grep ^flags /etc/security/audit_control       # e.g. flags:lo,aa,ad
```
**Check it worked:** `service auditd status` says it is running (if it was already running before the flags changed, `audit -s` reloads them; the script does not do that), and `praudit /var/audit/current | tail` shows recent events (logins, `su`).

---

## 12. Final checks
- [ ] Critical services still running (`service <name> status`)
- [ ] `pfctl -s info` → Status: Enabled
- [ ] You can still `su -`
- [ ] Scoring Report: no penalties
