# Roadmap: rebuilding the CyberPatriot practice toolkit

This is the plan for turning this repo into a complete, beginner-friendly practice toolkit for the IT class. It covers what was wrong with the old material, what this season's images are, how the new scripts work, how the checklists are written, and how the website will work.

---

## 1. Which operating systems to cover

**CyberPatriot 19 (2026–27) official image lineup** (from uscyberpatriot.org → Challenges and Scoring Values):

| Round | Dates | Images |
|---|---|---|
| Practice Round | Oct 7–20, 2026 | Windows 11, Windows Server 2022, Linux Mint 21 |
| Round 1 | Oct 22–25, 2026 | Windows 11, Linux Mint 21 |
| Round 2 | Nov 12–15, 2026 | Windows 11, Windows Server 2022, Debian 12 |
| State Round | Dec 10–13, 2026 | Windows Server 2022, Linux Mint 21, Debian 12 |
| Semifinals | Jan 21–23, 2027 | Linux Mint 21, Windows Server 2022, Debian 12 / FreeBSD (by tier) |

**This season is Windows 11, Windows Server 2022, Linux Mint 21, Debian 12 and FreeBSD.** Ubuntu and Windows 10 are not in the lineup this year.

The class practices on **older images**, which are very likely to include Windows 10, Server 2019 and Ubuntu 20/22. So the toolkit covers both:

| OS family | Versions covered | Script | Checklist |
|---|---|---|---|
| Windows desktop | 10, 11 | `scripts/windows/Harden.ps1` | `docs/checklists/windows-10-11.md` |
| Windows Server | 2016, 2019, 2022 (incl. Domain Controllers) | `scripts/windows/Harden.ps1` (same script, detects Server/DC) | `docs/checklists/windows-server.md` |
| Linux Mint | 20, 21, 22 | `scripts/linux/harden.sh` | `docs/checklists/linux-mint.md` |
| Debian | 11, 12 | `scripts/linux/harden.sh` (same script, detects distro) | `docs/checklists/debian.md` |
| Ubuntu | 20.04, 22.04, 24.04 | `scripts/linux/harden.sh` | `docs/checklists/ubuntu.md` |
| FreeBSD | 13, 14 | `scripts/freebsd/harden.sh` | `docs/checklists/freebsd.md` |

---

## 2. What was wrong with the old material

The old scripts were a reasonable start, but several things in them **lose points or break the image**. CyberPatriot images almost always have "critical services" listed in the README that must stay running, and the old scripts disabled them blindly.

### Things that could break an image or lose points
| Old script | Problem | Why it's bad |
|---|---|---|
| `Windows_Server_22.ps1` | Disabled the `NTDS` service | `NTDS` *is* Active Directory. On a Domain Controller image, this kills the domain. |
| `Windows_Server_22.ps1` | `icacls C:\Windows /reset /T` | Resetting permissions on all of `C:\Windows` can break Windows Update, services and logins. |
| `Windows_Server_22.ps1` | `Enable-BitLocker` on C: | In a VM with no TPM this fails or, worse, leaves you with a drive you can't unlock. |
| `Windows_Server_22.ps1` | Disabled the built-in Administrator | If you're logged in as Administrator, or it's the only admin, you can lock yourself out. |
| Both Windows scripts | Disabled RDP, IIS (`W3SVC`), FTP, print spooler and file sharing unconditionally | If the README says "this is a web server" or "RDP must stay on", you lose points for each one. |
| `secure_windows.ps1` | Password policy via text search-and-replace on `secedit` output | Only worked if the current value was *exactly* the default, so it often silently did nothing. |
| Linux scripts | `set -euo pipefail` | One harmless failure (a missing package, a missing service) **aborted the whole script halfway**. |
| Linux scripts | `PasswordAuthentication no` for SSH | Nobody has SSH keys on a competition image, so this locks every user out of SSH, and SSH is often a critical service. |
| Linux scripts | `ufw --force reset` then allow only SSH | Blocks Apache, MySQL, FTP, Samba and so on, even when the README requires them. |
| Linux scripts | Purged or disabled `vsftpd`, `smbd`, `cups`, `avahi` with no check | Same problem: they're sometimes required. |
| Linux scripts | Overwrote `/etc/hosts` with two lines | Deletes the hostname line, so `sudo` prints "unable to resolve host" warnings. |
| Linux scripts | Unattended-upgrades with **automatic reboot** | Rebooting mid-competition is a bad idea. |
| Linux scripts | PAM `pam_faillock` lines inserted in the wrong order | You removed PAM lockout in PR #6 because of this. A later commit re-added it. Wrong PAM order can stop **everyone** from logging in. |
| Mint script | dconf settings with no dconf profile | The screen-lock settings never actually applied. |
| Mint script | "Empty password" check flagged `!` | `!` means *locked*, not *empty*, so it reported false alarms. |

### What was missing entirely
- **User management against the README**, which is the single biggest source of points. The old scripts never asked who is supposed to be on the system.
- Media file hunting (`.mp3`, `.mp4` and so on), which shows up on nearly every image.
- Defender exclusions, UAC, user rights assignment, security options, and browser settings on Windows.
- Backdoor and persistence hunting (startup items, scheduled tasks, services in odd paths, `authorized_keys`, `ld.so.preload`, shell aliases).
- Any notion of "audit first, then fix", which beginners need so they can see what will happen before it happens.

### The old checklists
They were mostly lists of commands, with little explanation of **why** or **how to check it worked**. Some steps were risky without context, for example deleting `/var/www/html/index.html`, enforcing every AppArmor profile, and a hard-coded password. They also targeted Ubuntu and Windows 10 rather than this season's images.

---

## 3. New script design

The scripts are rebuilt from scratch around one idea: **the README decides what's safe**.

### Design rules (every script follows these)
1. **README first.** Before changing anything, the script asks for:
   - authorized users
   - authorized administrators
   - critical services (from the README)

   You can type these in, or put them in a config file. The script never removes an authorized user and never disables a critical service.
2. **Audit mode and apply mode.**
   - `audit` only reports what it would change and what looks suspicious. It's safe to run any time.
   - `apply` makes the changes.
   - Risky actions (deleting a user, removing software, deleting files) always ask first unless you pass `--yes`.
3. **Menu or all-at-once.** Run every section, or pick sections from a numbered menu, for example "just do users and passwords".
4. **Never aborts halfway.** Each section runs on its own. If one fails, the script logs it and moves on. A summary table at the end shows `OK`, `CHANGED`, `SKIPPED`, `FAILED` or `REVIEW`.
5. **Backs up everything it edits.** Every file is copied to a timestamped backup folder before it's touched, so you can always undo.
6. **Explains itself.** Every step prints what it's doing and why in plain English, so the scripts double as a learning tool.
7. **Findings report.** Things a human has to decide are written to a report file:
   - suspicious files
   - unknown users
   - odd scheduled tasks
   - listening ports

   The report is formatted as a to-do list.
8. **Safe defaults.**
   - No automatic reboots.
   - SSH password login stays on.
   - The firewall opens ports for critical services *before* it turns on.
   - Domain Controller services are never touched.
   - No BitLocker.
   - No permission resets on system folders.
9. **Idempotent.** Running a script twice gives the same result. It never adds duplicate config lines.
10. **One file per OS family**, so it's easy to download and run on a competition image.

### Linux script: `scripts/linux/harden.sh` (Mint, Debian, Ubuntu)
Detects the distro from `/etc/os-release` and adjusts automatically. Mint gets LightDM and Cinnamon handling, Debian gets GDM and `sudo` checks, and so on.

| # | Section | What it does |
|---|---|---|
| 1 | Users and groups | <ul><li>Compares real users against the README list.</li><li>Offers to remove unauthorized users.</li><li>Creates missing users.</li><li>Fixes `sudo`/`adm`/`wheel` membership.</li><li>Finds extra UID-0 accounts and hidden users with login shells.</li><li>Finds empty passwords.</li><li>Sets strong passwords.</li><li>Locks root.</li></ul> |
| 2 | Password policy | <ul><li>`login.defs` aging, applied to existing users with `chage`.</li><li>`pwquality.conf` complexity.</li><li>Password history (`remember=5`).</li><li>Optional, *correctly ordered* account lockout through the distro's own `pam-auth-update` system.</li></ul> |
| 3 | Updates | <ul><li>Turns on automatic security updates (no auto-reboot).</li><li>Fixes the Mint Update Manager.</li><li>Fixes broken or malicious apt sources.</li><li>Optionally runs a full upgrade.</li></ul> |
| 4 | Firewall | <ul><li>UFW deny-incoming.</li><li>Allows the ports for each critical service first.</li><li>Turns on logging.</li></ul> |
| 5 | SSH | <ul><li>Writes a drop-in config file (`sshd_config.d/`) instead of editing the main file.</li><li>Tests it with `sshd -t` and rolls back if the test fails.</li><li>Root login off, empty passwords off, `MaxAuthTries` limit and so on.</li></ul> |
| 6 | Services | <ul><li>Lists everything running.</li><li>Disables known-risky services (telnet, FTP, rsh, NIS, SNMP, NFS and others) **unless they're critical**.</li><li>Asks about anything it isn't sure of.</li></ul> |
| 7 | Prohibited software | <ul><li>Finds hacking tools, games, P2P clients and remote-access tools (apt, snap and flatpak).</li><li>Offers to remove them.</li></ul> |
| 8 | Prohibited files | <ul><li>Finds media files and other suspicious files in home folders and elsewhere.</li><li>Lists them and offers to delete them.</li></ul> |
| 9 | Kernel (sysctl) | Network and kernel hardening via a drop-in file: redirects, syncookies, ASLR, `ptrace` and so on. |
| 10 | File permissions | <ul><li>`shadow`, `passwd`, `sudoers` and home folder permissions.</li><li>World-writable files.</li><li>Unusual SUID binaries.</li></ul> |
| 11 | Sudoers | <ul><li>Finds `NOPASSWD`, `!authenticate` and non-admins with full sudo.</li><li>Validates with `visudo -c` before saving.</li></ul> |
| 12 | Backdoors and persistence | <ul><li>Cron jobs and systemd timers.</li><li>`rc.local`, `/etc/profile.d`, shell aliases.</li><li>`authorized_keys`, `ld.so.preload`.</li><li>Netcat listeners.</li><li>Suspicious `/etc/hosts` entries (reports them, never wipes the file).</li></ul> |
| 13 | Logging | Turns on `auditd` and `rsyslog`, and checks log permissions. |
| 14 | AppArmor | Makes sure it's running, without force-enforcing every profile. |
| 15 | Desktop / login screen | <ul><li>No guest login, no autologin.</li><li>Screen lock that actually applies, with a correct dconf profile.</li><li>LightDM (Mint) and GDM (Ubuntu/Debian).</li></ul> |
| 16 | Critical service hardening | Only for services the README lists: Apache, Nginx, MySQL/MariaDB, PHP, vsftpd/ProFTPD/Pure-FTPd, Samba, BIND, Postfix. |

### Windows script: `scripts/windows/Harden.ps1` (10, 11, Server 2016–2022)
Detects whether it's a workstation, a member server or a **Domain Controller**, and what roles are installed. On a DC it uses Active Directory commands for users and **never touches** AD, DNS, Kerberos, Netlogon, SYSVOL or DFSR.

| # | Section | What it does |
|---|---|---|
| 1 | Users and groups | <ul><li>Local (or AD) users vs. the README.</li><li>Disables Guest and DefaultAccount.</li><li>Sets passwords.</li><li>Clears "password never expires" and "password not required".</li><li>Fixes Administrators, Remote Desktop Users, Backup Operators and similar groups.</li></ul> |
| 2 | Account policies | <ul><li>Password length, history, age, complexity and lockout.</li><li>Builds a proper `secedit` template instead of search-and-replace.</li><li>On a DC: `Set-ADDefaultDomainPasswordPolicy`.</li></ul> |
| 3 | Security options | <ul><li>UAC.</li><li>Don't display last user name.</li><li>Blank-password restriction.</li><li>Anonymous enumeration off.</li><li>LM hash off, NTLMv2 only.</li><li>SMB signing.</li><li>Ctrl+Alt+Del.</li><li>Logon banner.</li></ul> |
| 4 | User rights | Removes Everyone, Guests and other non-admins from dangerous rights (debug, take ownership, act as OS and so on). |
| 5 | Audit policy | Advanced audit subcategories for success and failure, plus forcing subcategory settings. |
| 6 | Defender | <ul><li>Real-time, cloud, behavior, PUA, script scanning.</li><li>**Removes exclusions**, a common planted vulnerability.</li><li>Updates signatures.</li></ul> |
| 7 | Firewall | <ul><li>All profiles on, block inbound.</li><li>Keeps rules for critical services.</li><li>Logging on.</li></ul> |
| 8 | Services | <ul><li>Disables risky services unless critical.</li><li>Makes sure core security services are running.</li><li>DC-safe allow-list.</li></ul> |
| 9 | Windows features | SMBv1, Telnet/TFTP client and PowerShell v2 off. IIS and FTP only if they're not critical. |
| 10 | Remote access | RDP off unless critical. If it's critical: Network Level Authentication and high encryption. Remote Assistance off. |
| 11 | Shares | Lists non-default shares and offers to remove them. On a DC, keeps `NETLOGON` and `SYSVOL`. |
| 12 | Prohibited software | Reads the installed-programs list and flags hacking tools, games, P2P and remote-access tools. |
| 13 | Prohibited files | Media files and other suspicious files in user folders. |
| 14 | Backdoors and persistence | <ul><li>Run keys, startup folders.</li><li>Non-Microsoft scheduled tasks.</li><li>Services in odd folders.</li><li>WMI subscriptions.</li><li>`hosts` file.</li><li>Accessibility-tool hijacks (sticky keys and similar).</li></ul> |
| 15 | Updates | Windows Update service plus auto-update policy, and starts a scan. |
| 16 | Misc and browsers | <ul><li>AutoPlay off, SmartScreen on.</li><li>Screen-saver lock.</li><li>LLMNR and NetBIOS off.</li><li>Firefox, Chrome and Edge security policies.</li></ul> |

### FreeBSD script: `scripts/freebsd/harden.sh`
Same rules, adapted to FreeBSD:
- users (`pw`), passwords (`login.conf`), `sshd`
- `pf` firewall, services (`sysrc`), updates (`pkg audit`, `freebsd-update`)
- security sysctls, `periodic` security reports, cron, SUID checks

FreeBSD only appears in the Semifinals, so it's the lowest priority.

### How the scripts get tested
- **Linux:** `shellcheck` clean. Real runs (audit and apply) in Debian 12, Ubuntu 22.04 and Linux Mint 21 containers.
- **Windows:** parsed with PowerShell 7 and PSScriptAnalyzer. Windows-only commands can't run on the test machine, so the class should do a dry run in `audit` mode on a practice image first.
- **FreeBSD:** `shellcheck` in POSIX-sh mode.

---

## 4. New checklist design

The checklists are for **people who have never done this before**. Every OS gets its own page that you can follow top to bottom without jumping around.

### Every checklist item has the same shape
> **☐ Item name**
> - **What:** one sentence, plain English.
> - **Why it matters:** what an attacker could do if you skip it.
> - **How (clicking):** the GUI path, step by step.
> - **How (typing):** the command, with every part explained.
> - **Check it worked:** a command or screen that proves it's done.
> - **⚠️ Careful:** when *not* to do it, for example "skip this if the README says FTP is required".

### Order of each checklist (the order points are usually won in)
0. **Before you touch anything:** read the README, take a snapshot, and split up the work.
1. **Forensics questions first,** because fixing things can destroy the evidence.
2. Users and groups.
3. Password and lockout policy.
4. Updates (start early, they're slow).
5. Firewall.
6. Services.
7. Prohibited software and files.
8. OS-specific security settings.
9. Critical service hardening (web, database, FTP, SSH and so on).
10. Backdoor hunting.
11. Final checks, and what to do when you're stuck.

### Supporting guides (shared by all OSes)
- **Start here:** what CyberPatriot is, how scoring works, how a 4-hour round goes, and team roles.
- **Reading the README:** how to pull out authorized users, admins, critical services and "policy" hints.
- **Terminal basics (Linux)** and **PowerShell basics (Windows):** for people who have never typed a command.
- **Forensics questions:** common question types and how to answer each (hashes, base64, finding a file, finding who did what).
- **Things that lose points:** the classic mistakes, like deleting an authorized user, stopping a critical service, or breaking SSH.
- **Using the scripts safely.**
- **Glossary:** every acronym (PAM, UAC, SMB, LLMNR and so on) explained in one or two sentences.

### Formatting choices (so they work on GitHub *and* the future website)
- Warnings use GitHub alert syntax (`> [!WARNING]`). It renders nicely on GitHub today and on the website later.
- Checkboxes use `- [ ]`, so they're clickable on the website.
- No tabs or other site-only features, so everything still reads well on GitHub.

---

## 5. Website plan (later phase)

**Goal:** teammates open a normal web link and get a clean, searchable site. They never need to understand GitHub.

**Recommended approach: MkDocs Material, published by GitHub Pages**
- The site is generated from the `docs/` folder already in this repo, so the checklists live in one place.
- A GitHub Action rebuilds the site automatically every time something is merged into `main`. Nobody has to "deploy" anything.
- Free hosting at `https://ripper1004.github.io/CyberPatriot-Security-Script/`. Free GitHub Pages requires the repo to stay public.
- Features:
  - search box
  - dark mode
  - left-side navigation by OS
  - copy buttons on every command
  - printable pages
  - warning boxes
- Extra beginner features to add:
  - **progress-saving checkboxes:** checked items are remembered in your browser, with a "reset" button for a new practice image
  - **"Start here" landing page** with big buttons per OS
  - **printable one-page cheat sheets** per OS

**Alternatives considered:**
- **Google Sites:** easy to edit, but it would mean keeping two copies of everything in sync.
- **Notion:** same problem.
- **A custom React app:** more work to maintain and no real benefit for documentation.

**Steps when we get there:**
1. Add `mkdocs.yml` and a `requirements.txt`.
2. Add `.github/workflows/pages.yml`.
3. Turn on Pages in repo Settings → Pages → Source: GitHub Actions.
4. Add the checkbox-progress script and the landing page.

---

## 6. Order of work

1. ✅ Close the superseded PRs (#1 and #3).
2. ✅ Linux script. It passes 54/54 checks in Debian 12, Ubuntu 22.04 and Mint 21.3 containers.
3. ✅ Windows script. It passes 38/38 logic tests, parses cleanly, and is PS 5.1-compatible. **Still needs a real run in Audit mode on a Windows practice image.**
4. ✅ Checklists and guides for all six OSes, plus beginner guides.
5. ✅ FreeBSD script (shellcheck clean). **Still needs a real run on FreeBSD.**
6. ✅ New README; the old scripts and checklists are removed (they stay in the git history).
7. ⏳ *(Next)* Website.

## 7. Things the repo owner needs to do by hand
- **Delete the 8 stale branches.** This session can't delete branches. Go to GitHub → the repo → **Branches** and click the 🗑️ next to:
  - `Server`
  - all five `codex/...` branches
  - `claude/cyber-patriot-scripts-checklists-CYd7Q`
- **If the school competes again:** the CyberPatriot 19 rules (3010.4) prohibit using AI-written scripts during a competition round, and (3011.5) prohibit publicly posting scripts made for CyberPatriot. If you register a team in a future season:
  - make the repo private
  - treat this toolkit as practice material only
  - have the team write its own competition scripts
