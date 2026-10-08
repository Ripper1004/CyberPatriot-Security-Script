# CyberPatriot Practice Toolkit

Beginner-friendly **checklists**, **guides** and **hardening scripts** for practicing CyberPatriot image challenges on Windows, Windows Server, Linux Mint, Debian, Ubuntu and FreeBSD.

> **New to this?** Use the website: **https://cp-toolkit.pages.dev/**, or start at **[docs/index.md](docs/index.md)** here on GitHub. Both walk you through everything in order.

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
- [For mentors and teachers](docs/guides/for-mentors-and-teachers.md): running practice sessions with this toolkit

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

## Website

**https://cp-toolkit.pages.dev/**: [`site/`](site/) turns everything above into a website for people who don't use GitHub. It's built with Astro + Starlight and hosted on Cloudflare Pages.

- **Two sections:** **Toolkit** (dashboard, checklists, tools, scripts, reference: no introductions) for people who know the game, and **Learn** (welcome, 7 lessons, glossary) for beginners. Switch with the tabs at the top.
- **Interactive checklists:** tick off steps, see your progress, jump to the next step, print, reset for a new image, and **Compact view** to hide the beginner explanations.
- **A 7-lesson learning path** for beginners.
- **Tools:**
  - README config builder: paste the README and get the script's config file
  - round timer with game-plan phases
  - command finder
  - glossary quiz
  - script downloads with checksums
  - a progress page with export/import
- **Search, dark mode, mobile layout.** No accounts and no tracking: progress is saved in the browser.

The pages are generated from `docs/` at build time, so **edit `docs/` and the website updates itself**. Setup and local preview: [site/README.md](site/README.md).

---

## How the scripts are tested

| Script | Tests |
|---|---|
| Linux | [`tests/linux/run-tests.sh`](tests/linux/run-tests.sh) builds a practice "image" in a **Debian 12, Ubuntu 22.04 and Linux Mint 21.3** container, plants ~30 vulnerabilities (hidden root account, PAM backdoor, cron reverse shell, SUID `find`, fake sudo alias…), runs the script, and checks **55 results**, including real logins with `pamtester`. All pass. |
| Windows | [`tests/windows/Test-HardenLogic.ps1`](tests/windows/Test-HardenLogic.ps1) loads the script's functions with fake `secedit.exe` and checks 38 behaviours. The script also parses cleanly and has no PSScriptAnalyzer findings or PowerShell 5.1 syntax problems. **It has not been run on a real Windows image yet.** Try **Audit** mode on a practice image first. |
| FreeBSD | `shellcheck -s sh` clean. **Not yet run on a real FreeBSD system.** |

```bash
bash tests/linux/run-tests.sh                 # needs Docker
pwsh tests/windows/Test-HardenLogic.ps1       # needs PowerShell 7
```

---

## Plans
See [ROADMAP.md](ROADMAP.md): what was wrong with the old scripts, the design of the new ones, and how the website works.

## Contributing
- Keep the checklist item format: **What · Why it matters · Clicking · Typing · Check it worked · Warning**.
- Under each step's `- [ ] Done`, keep one `**Script:**` line saying what the hardening script does for it: `✅` it does it fully, `🔎` it checks but a person decides, `✋` by hand. The website build stops if a checklist step has none. Only use ✅ if Apply mode really finishes the step.
- Write for someone who has never done this before. Short sentences, explain every acronym.
- Website changes: `cd site && npm install && npm test` (builds the site and checks every link). See [site/README.md](site/README.md).
- Script changes: add a planted problem to `tests/linux/plant-vulns.sh` and a check to `tests/linux/verify.sh`, then run the tests.
- Older versions of the scripts and checklists are in the git history.

## Important: competition rules
This toolkit is for **practice and learning**. The CyberPatriot 19 Rules Book says:
- **3010.4:** scripts created with the help of AI may **not** be used during a competition round. Paid AI tools may not be used in connection with the competition.
- **3011.5:** publicly posting scripts or resources made for CyberPatriot is **prohibited**.

If your school registers a team again: make this repository **private**, and have the team write its own competition materials.

## License and disclaimer
Provided "as is", for training on practice virtual machines only. Never run these scripts on a computer you don't own or aren't authorized to change.
