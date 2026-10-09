# Roadmap

Where the CyberPatriot Toolkit stands, how it's designed, and what's left. For how to *use* it, see the [README](README.md) or the website, **https://cp-toolkit.pages.dev/**.

---

## 1. Status

The toolkit is **feature complete** for class use. What's left is mostly testing on real images and yearly upkeep (section 6).

| Part | State |
|---|---|
| Checklists (6 OSes) | Done. Linux ones run command by command in containers; Windows and FreeBSD ones syntax-checked only. |
| Linux script | Done. Tested on Debian 12, Ubuntu 22.04, Ubuntu 24.04 and Linux Mint 21.3. |
| Windows script | Done. Logic-tested only: **never run on a real Windows image.** |
| FreeBSD script | Done. Logic-tested only: **never run on a real FreeBSD system.** |
| Website | Live on Cloudflare Pages, behind a Cloudflare Access login (`@lposd.org` emails, one-time PIN). Script downloads under `/files/` stay open so images can fetch them from a terminal. |

---

## 2. Which operating systems are covered

**CyberPatriot 19 (2026–27) image lineup:**

| Round | Dates | Images |
|---|---|---|
| Practice Round | Oct 7–20, 2026 | Windows 11, Windows Server 2022, Linux Mint 21 |
| Round 1 | Oct 22–25, 2026 | Windows 11, Linux Mint 21 |
| Round 2 | Nov 12–15, 2026 | Windows 11, Windows Server 2022, Debian 12 |
| State Round | Dec 10–13, 2026 | Windows Server 2022, Linux Mint 21, Debian 12 |
| Semifinals | Jan 21–23, 2027 | Linux Mint 21, Windows Server 2022, Debian 12 / FreeBSD (by tier) |

The class practices on **older images** too (Windows 10, Server 2019, Ubuntu), so the toolkit covers both:

| OS family | Versions | Script | Checklist |
|---|---|---|---|
| Windows desktop | 10, 11 | `scripts/windows/Harden.ps1` | `docs/checklists/windows-10-11.md` |
| Windows Server | 2016, 2019, 2022 (incl. Domain Controllers) | `scripts/windows/Harden.ps1` (detects Server/DC) | `docs/checklists/windows-server.md` |
| Linux Mint | 20, 21, 22 | `scripts/linux/harden.sh` | `docs/checklists/linux-mint.md` |
| Debian | 11, 12 | `scripts/linux/harden.sh` (detects distro) | `docs/checklists/debian.md` |
| Ubuntu | 20.04, 22.04, 24.04 | `scripts/linux/harden.sh` | `docs/checklists/ubuntu.md` |
| FreeBSD | 13, 14 | `scripts/freebsd/harden.sh` | `docs/checklists/freebsd.md` |

Mint and Windows 10/11 are the full checklists. Debian, Ubuntu and Windows Server cover what's different and link back to them for anything identical.

---

## 3. Script design

The old scripts (still in the git history) broke images: they disabled Active Directory on Domain Controllers, stopped services the README required, locked users out of SSH, reset the firewall to SSH-only, and aborted halfway on the first error. They also never checked users against the README, which is the biggest source of points. The new scripts are built around one idea: **the README decides what's safe**.

### Rules every script follows
1. **README first.** It asks for authorized admins, users and critical services (typed in, or from a config file). It never removes an authorized user or disables a critical service. **With no user list, user removals are report-only.**
2. **Audit, then Apply.** Audit reports and changes nothing. Apply asks before anything risky (deleting a user, removing software, deleting files) unless you pass `--yes`.
3. **Menu or all at once.** Run every section, or pick one.
4. **Never aborts halfway.** Each section runs on its own; failures are logged and the summary shows `OK`, `CHANGED`, `WOULD`, `SKIPPED`, `REVIEW` or `FAILED`.
5. **Backs up everything** it edits, into a timestamped folder.
6. **Findings report:** a to-do list of what a human has to decide.
7. **Safe defaults:** no reboots, SSH password login stays on, firewall ports for critical services open *before* the firewall turns on, Domain Controller services never touched, no BitLocker, no permission resets on system folders.
8. **Idempotent:** running it twice gives the same result.
9. **One file per OS family**, easy to download onto an image.

### Sections
| Script | Sections |
|---|---|
| Linux | users, passwords, firewall (UFW), SSH, services, prohibited software, prohibited files, kernel (sysctl), file permissions, sudo rules, backdoors, logging, AppArmor, login screen and screen lock, critical service hardening (web, database, FTP, Samba…), updates, Firefox |
| Windows | users, password and lockout policy, security options, user rights, audit policy, Defender, firewall, services, Windows features, remote access, shares, prohibited software, prohibited files, backdoors, other hardening, browsers, server roles (IIS, FTP, DNS, AD), updates |
| FreeBSD | users, passwords, firewall (pf), SSH, services, software, files, kernel (sysctl), permissions, sudo, backdoors, logging, updates |

### Tests
| Script | How it's tested |
|---|---|
| Linux | `tests/linux/run-tests.sh` plants ~30 problems in Debian 12, Ubuntu 22.04, Ubuntu 24.04 and Mint 21.3 containers, runs the script and checks 73 results. It also checks that audit mode changes nothing, that nothing is deleted without a README list, `umask 0000`, and real logins with `pamtester`. |
| Windows | `tests/windows/Test-HardenLogic.ps1`: 64 logic tests with a fake `secedit`. Parses cleanly, no PSScriptAnalyzer findings, PowerShell 5.1 compatible. |
| FreeBSD | `tests/freebsd/test-harden-logic.sh`: 50 tests under `dash` with fake FreeBSD commands. `shellcheck -s sh` clean. |

---

## 4. Checklist design

Written for people who have never done this before. Every step has the same shape:

- **What:** one plain sentence.
- **Why it matters:** what an attacker could do if you skip it.
- **Clicking** and **Typing:** the GUI path and the command, with every part explained.
- **Check it worked:** a command or screen that proves it.
- **Careful:** when *not* to do it.
- **Script:** ✅ the script does it, 🔎 it checks and you decide, ✋ by hand.

Sections follow the order points are usually won: read the README, forensics questions, run the script, users, passwords, updates, firewall, services, software and files, OS settings, critical services, backdoors, final checks.

**Rules for editing checklists** (the website and saved progress depend on them):
- A step's heading number is its identity: **add new steps at the end of a section, never renumber.**
- Don't change headings other pages link to.
- Use the example names alice, bob, carol, erin and mallory.
- Run `python3 tests/checklists/check-format.py`, `bash tests/checklists/check-shell.sh` and, for Linux, `python3 tests/checklists/linux_lab.py <checklist>`.

---

## 5. Website

Astro + Starlight in [`site/`](site/), built and hosted by Cloudflare Pages on every merge into `main` (each pull request gets a preview link). `docs/` is the single source: `site/scripts/sync-docs.mjs` turns it into pages at build time, so **edit `docs/` and the site updates itself**. Setup: [`site/README.md`](site/README.md).

- **Toolkit** section for experienced students (dashboard, checklists, tools, downloads, reference) and **Learn** section for beginners (7 lessons, glossary, quiz, mentor guide).
- Interactive checklists: progress, next step, hide finished, compact view, print, reset, **Tick the script's ✅ steps**, and your README names filled into commands.
- Tools: README config builder, round timer, round log, findings to-do list, command finder, forensics helper, glossary and networking quizzes, Cisco guide, downloads with checksums, progress export/import.
- No accounts or tracking: progress is saved in the browser.
- `npm test` builds the site and checks every link, anchor, step id and download checksum. `.github/workflows/site.yml` runs it on every pull request.

---

## 6. What's left

### Needs a real machine
- [ ] Run `Harden.ps1 -Mode Audit` on a real **Windows 11** practice image, then on **Server 2022** (ideally a Domain Controller). Fix anything that errors before trusting Apply mode.
- [ ] Run `scripts/freebsd/harden.sh` in audit mode on a **FreeBSD 14** VM.
- [ ] Walk through the Windows and FreeBSD checklists on those images; only their syntax has been checked so far.

### Every season
- [ ] Update the round dates and images in `site/src/data/catalog.mjs` and the table in section 2.
- [ ] Check the new rules book and image lineup for OS changes (for example a new Mint or Debian version) and adjust the checklists.

### Nice to have
- [ ] A mentor script that plants practice problems on a VM (like `tests/linux/plant-vulns.sh`, but for a real practice image), so the class can make its own images.
- [ ] A Windows version of that test harness, if a Windows VM becomes available.
