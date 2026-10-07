# CyberPatriot Practice Toolkit

Beginner-friendly **checklists**, **guides** and **hardening scripts** for practicing CyberPatriot image challenges on Windows, Windows Server, Linux Mint, Debian, Ubuntu and FreeBSD.

> **New to this?** Start at **[docs/index.md](docs/index.md)**. It walks you through everything in order.

---

## What's in here

### Checklists (one per operating system)
Every item says **what** to do, **why** it matters, how to do it by **clicking** and by **typing**, and how to **check it worked**.

| OS | CyberPatriot 19 (2026-27) rounds | Checklist |
|---|---|---|
| Windows 11 / 10 | Round 1, Round 2 | [docs/checklists/windows-10-11.md](docs/checklists/windows-10-11.md) |
| Windows Server 2022 / 2019 / 2016 | Round 2, State, Semifinals | [docs/checklists/windows-server.md](docs/checklists/windows-server.md) |
| Linux Mint 21 | Round 1, State, Semifinals | [docs/checklists/linux-mint.md](docs/checklists/linux-mint.md) |
| Debian 12 | Round 2, State, Semifinals | [docs/checklists/debian.md](docs/checklists/debian.md) |
| FreeBSD | Semifinals (some tiers) | [docs/checklists/freebsd.md](docs/checklists/freebsd.md) |
| Ubuntu | older practice images | [docs/checklists/ubuntu.md](docs/checklists/ubuntu.md) |

### Beginner guides
- [What is CyberPatriot?](docs/start-here/what-is-cyberpatriot.md) · [Reading the README](docs/start-here/reading-the-readme.md) · [Round game plan](docs/start-here/round-game-plan.md)
- [Linux terminal basics](docs/start-here/linux-terminal-basics.md) · [PowerShell basics](docs/start-here/powershell-basics.md)
- [Things that lose points](docs/guides/things-that-lose-points.md) · [Forensics questions](docs/guides/forensics-questions.md) · [Linux service hardening](docs/guides/linux-service-hardening.md) · [Glossary](docs/guides/glossary.md)

### Scripts
| Script | Works on |
|---|---|
| [`scripts/linux/harden.sh`](scripts/linux/harden.sh) | Linux Mint 20–22, Debian 11–12, Ubuntu 20.04–24.04 |
| [`scripts/windows/Harden.ps1`](scripts/windows/Harden.ps1) | Windows 10/11, Windows Server 2016–2022 (Domain Controller aware) |
| [`scripts/freebsd/harden.sh`](scripts/freebsd/harden.sh) | FreeBSD 13–14 |

**How they work** (full guide: [Using the scripts safely](docs/start-here/using-the-scripts.md)):
1. They ask for the README's **authorized admins, users and critical services**, and never remove or disable anything you list.
2. **Audit mode** reports problems and changes nothing. **Apply mode** fixes them and asks before risky steps.
3. Every changed file or setting is **backed up** first.
4. You get a **findings report**: a to-do list of the things a human must decide.

```bash
# Linux
sudo bash scripts/linux/harden.sh
```
```powershell
# Windows (PowerShell as Administrator)
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Harden.ps1
```

---

## How the scripts are tested

| Script | Tests |
|---|---|
| Linux | [`tests/linux/run-tests.sh`](tests/linux/run-tests.sh) builds a practice "image" in a **Debian 12, Ubuntu 22.04 and Linux Mint 21.3** container, plants ~30 vulnerabilities (hidden root account, PAM backdoor, cron reverse shell, SUID `find`, fake sudo alias…), runs the script, and checks **54 results**, including real logins with `pamtester`. All pass. |
| Windows | [`tests/windows/Test-HardenLogic.ps1`](tests/windows/Test-HardenLogic.ps1) loads the script's functions with fake `secedit.exe` and checks 38 behaviours. The script also parses cleanly and has no PSScriptAnalyzer findings or PowerShell 5.1 syntax problems. **It has not been run on a real Windows image yet.** Try **Audit** mode on a practice image first. |
| FreeBSD | `shellcheck -s sh` clean. **Not yet run on a real FreeBSD system.** |

```bash
bash tests/linux/run-tests.sh                 # needs Docker
pwsh tests/windows/Test-HardenLogic.ps1       # needs PowerShell 7
```

---

## Plans
See [ROADMAP.md](ROADMAP.md): what was wrong with the old scripts, the design of the new ones, and the plan for a **website** version of these checklists (MkDocs + GitHub Pages) so teammates never need to use GitHub.

## Contributing
- Keep the checklist item format: **What · Why it matters · Clicking · Typing · Check it worked · Warning**.
- Write for someone who has never done this before. Short sentences, explain every acronym.
- Script changes: add a planted problem to `tests/linux/plant-vulns.sh` and a check to `tests/linux/verify.sh`, then run the tests.
- Older versions of the scripts and checklists are in the git history.

## Important: competition rules
This toolkit is for **practice and learning**. The CyberPatriot 19 Rules Book says:
- **3010.4:** scripts created with the help of AI may **not** be used during a competition round. Paid AI tools may not be used in connection with the competition.
- **3011.5:** publicly posting scripts or resources made for CyberPatriot is **prohibited**.

If your school registers a team again: make this repository **private**, and have the team write its own competition materials.

## License and disclaimer
Provided "as is", for training on practice virtual machines only. Never run these scripts on a computer you don't own or aren't authorized to change.
