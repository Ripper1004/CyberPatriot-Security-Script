# CyberPatriot Toolkit

Step-by-step checklists, beginner guides and hardening scripts for practicing **CyberPatriot** image challenges.

## New here? Start with these (in order)

1. [What is CyberPatriot?](start-here/what-is-cyberpatriot.md): how images, the README and scoring work
2. [Things that lose points](guides/things-that-lose-points.md): read this **before** touching an image
3. [Reading the README](start-here/reading-the-readme.md): the most important 10 minutes of a round
4. [Round game plan](start-here/round-game-plan.md): what to do in your 4 hours
5. Never used a terminal? [Linux terminal basics](start-here/linux-terminal-basics.md) · [PowerShell basics](start-here/powershell-basics.md)

## Pick your checklist

| Operating system | CyberPatriot 19 rounds | Checklist |
|---|---|---|
| **Windows 11** (and 10) | Round 1, Round 2 | [Windows 10 / 11](checklists/windows-10-11.md) |
| **Windows Server 2022** (2016/2019) | Round 2, State, Semifinals | [Windows Server](checklists/windows-server.md) |
| **Linux Mint 21** | Round 1, State, Semifinals | [Linux Mint](checklists/linux-mint.md) |
| **Debian 12** | Round 2, State, Semifinals | [Debian](checklists/debian.md) |
| **FreeBSD** | Semifinals (some tiers) | [FreeBSD](checklists/freebsd.md) |
| Ubuntu (older images) | — | [Ubuntu](checklists/ubuntu.md) |

## Guides

- [Forensics questions](guides/forensics-questions.md): hashes, decoding, finding files, reading logs
- [Linux critical service hardening](guides/linux-service-hardening.md): Apache, Nginx, PHP, MySQL, FTP, Samba, DNS, Postfix
- [Cisco networking and Packet Tracer](guides/cisco-networking.md): IOS commands, subnetting, ports
- [Glossary](guides/glossary.md): every acronym explained
- [For mentors and teachers](guides/for-mentors-and-teachers.md): running practice sessions with this toolkit

## Scripts

- [Using the scripts safely](start-here/using-the-scripts.md): **audit first, then apply**
- `scripts/linux/harden.sh`: Linux Mint, Debian, Ubuntu
- `scripts/windows/Harden.ps1`: Windows 10/11, Windows Server (Domain Controller aware)
- `scripts/freebsd/harden.sh`: FreeBSD
