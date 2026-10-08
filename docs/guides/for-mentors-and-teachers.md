# For mentors and teachers

How to run practice sessions with this toolkit in a class or club, even if your students have never touched Linux or a command line.

## What your students get

- **Lessons** (the "Start here" pages): seven short reads, about an hour in total, that explain how an image, the README and scoring work.
- **Checklists**, one per operating system. Every step says what to do, why it matters, how to do it by clicking and by typing, and how to check it worked. On the website, students tick steps off and see their progress.
- **Tools** on the website: a README config builder, a round timer, a command finder, a glossary quiz and a progress page.
- **Hardening scripts** that show what can be automated. Students should learn the checklist first, so they understand what a script is doing.

## Before the first session

1. **Install VMware Workstation** (or the VM software your images were made for) on every student computer. Make sure virtualization is enabled in the BIOS.
2. **Copy the practice images** onto each computer, or onto a share students can copy from. Old competition images work well.
3. **Take a snapshot called `clean`** of each image before students touch it. To reuse an image, revert to `clean`.
4. **Open the website** on the student computers and check that progress is saved (tick a step, reload the page).

> [!TIP]
> If your school computers wipe browser data at logout, students lose their ticks. Have them use **My progress → Export** at the end of each session and **Import** at the start of the next.

## A suggested six-session plan

| Session | Goal | Use |
|---|---|---|
| 1 | Understand the game | Lessons 1–2 ([What is CyberPatriot?](../start-here/what-is-cyberpatriot.md), [Things that lose points](things-that-lose-points.md)), then the glossary quiz |
| 2 | Read a README, use a terminal | Lessons 3 and 5 ([Reading the README](../start-here/reading-the-readme.md), [Linux terminal basics](../start-here/linux-terminal-basics.md)), the README config builder |
| 3 | First Linux image: users, passwords, firewall | [Linux Mint checklist](../checklists/linux-mint.md) sections 0–4 |
| 4 | Linux, continued: services, software, files, backdoors, forensics | Mint checklist sections 5–17, [Forensics questions](forensics-questions.md) |
| 5 | Windows | Lesson 6 ([PowerShell basics](../start-here/powershell-basics.md)), [Windows 10 / 11 checklist](../checklists/windows-10-11.md) |
| 6 | A full practice round | [Round game plan](../start-here/round-game-plan.md), the round timer in full-screen mode, the scripts in **Audit** mode |

After that, rotate students through Windows Server and Debian, using their checklists.

## Running a session

- **One student per image.** Pairs work well if one person drives and the other reads the checklist aloud.
- **Projector:** the round timer has a full-screen mode that shows the current phase of the game plan in large text.
- **Paper copies:** every checklist has a **Print** button that produces a clean copy with tick boxes.
- **Fresh start:** when a student reverts to the `clean` snapshot, they press **Reset for a new image** on the checklist.
- **Handing in work:** **My progress → Export** creates a small file with the student's name and every step they ticked.

## Making your own practice problems

If you're comfortable with Linux, you can plant problems in a throwaway VM yourself: add an unauthorized user, give someone sudo rights, install a "hacking tool", put an MP3 in a home folder, add a cron job. Take a snapshot first. [`tests/linux/plant-vulns.sh`](../../tests/linux/plant-vulns.sh) lists about 30 example problems that the automated tests use. It is written for test containers, so read it and pick ideas from it rather than running it on a VM as-is.

## Keeping the material up to date

Everything on the website comes from the `docs/` folder of the GitHub repository. Edit a page there (or use the **Edit page** link at the bottom of any lesson or checklist on the website) and the website rebuilds itself within a few minutes.
