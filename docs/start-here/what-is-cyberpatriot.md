# What is CyberPatriot? (Start here if you're new)

CyberPatriot is a cyber **defense** competition for middle and high school students. You are not hacking anything. You are the IT person who has been handed a computer that was set up badly and maybe broken into, and your job is to **find and fix the security problems**.

## How a practice image works

1. You get a **virtual machine** (VM): a whole computer running inside a program like VMware. It is called an **image**.
2. On the desktop there is a **README**. It describes the "company", who is allowed to use the computer, and what it must keep doing (for example, "this is the company web server").
3. On the desktop there are **Forensics Questions**: small puzzles about the computer, each worth points.
4. Somewhere on the image a **scoring engine** is running. Every time you fix a problem it checks, your score goes up and the **Scoring Report** on the desktop shows it.
5. If you make the computer *less* secure, or break something the README needs, you get a **penalty** (points taken away).

You don't know in advance which problems are scored. The checklists in this toolkit cover the problems that show up again and again.

## What gets scored (the usual categories)

After each round CyberPatriot publishes the general categories of problems. They are almost always these:

| Category | Examples |
|---|---|
| Forensics questions | "What is the SHA-256 hash of the file in Bob's Documents?" |
| User auditing | Delete users who aren't in the README. Remove admin rights from people who shouldn't have them. |
| Account policies | Password length and complexity. Lock accounts after failed logins. |
| Local policies | Audit logging. Security options like "don't show the last user name". |
| Defensive countermeasures | Firewall on. Antivirus on. |
| Uncategorized OS settings | Screen lock. Secure boot settings. Remote Desktop off. |
| Service auditing | Turn off services the README doesn't need (FTP, Telnet...). |
| Operating system updates | Install updates and turn on automatic updates. |
| Application updates | Update Firefox, Chrome, and the programs the README mentions. |
| Prohibited files | Delete music, videos, password lists and hacking tools. |
| Unwanted software | Uninstall games, hacking tools, torrent programs. |
| Malware | Find backdoors, bad scheduled tasks, fake programs. |
| Application security | Harden the critical services: web server, database, FTP, SSH settings. |

## This season's images (CyberPatriot 19, 2026-27)

| Round | Images |
|---|---|
| Round 1 | Windows 11, Linux Mint 21 |
| Round 2 | Windows 11, Windows Server 2022, Debian 12 |
| State | Windows Server 2022, Linux Mint 21, Debian 12 |
| Semifinals | Linux Mint 21, Windows Server 2022, Debian 12 or FreeBSD |

Older practice images may also be Windows 10, Windows Server 2019, or Ubuntu. There is a checklist for each.

## How a round works

- Each team gets **one 4-hour block**. The clock starts when the first image is powered on.
- Up to 5 people work at once. Usually each person takes one image or one task.
- There is also a **Cisco networking** part (a quiz and a Packet Tracer activity). This toolkit doesn't cover it.

## Where to go next

1. [Reading the README](reading-the-readme.md). Always do this first.
2. [Round game plan](round-game-plan.md): what to do in your 4 hours, minute by minute.
3. If you've never used a terminal: [Linux terminal basics](linux-terminal-basics.md) or [PowerShell basics](powershell-basics.md).
4. Pick your OS checklist:
   - [Windows 10 / 11](../checklists/windows-10-11.md)
   - [Windows Server](../checklists/windows-server.md)
   - [Linux Mint](../checklists/linux-mint.md)
   - [Debian](../checklists/debian.md)
   - [Ubuntu](../checklists/ubuntu.md)
   - [FreeBSD](../checklists/freebsd.md)
5. [Things that lose points](../guides/things-that-lose-points.md). Read this before you touch anything.
6. [Forensics questions](../guides/forensics-questions.md)
7. [Glossary](../guides/glossary.md), if a word confuses you.

> [!NOTE]
> **About the rules.** This toolkit is for **practice**. If your school registers a team again, the CyberPatriot 19 rules (section 3010.4) do **not** allow scripts that were written with AI help during a competition round. They also don't allow (section 3011.5) posting scripts made for CyberPatriot publicly. Use these scripts and checklists to **learn**, then write your team's own competition materials.
