# Round game plan

A good plan matters more than speed. Teams lose the most points by rushing and breaking something the README needed.

## Before the round (the day before)

- [ ] Everyone knows which image they own (e.g. Alex → Windows, Sam → Linux, Jordan → Cisco).
- [ ] VMware Workstation works on every computer, and virtualization is enabled in the BIOS.
- [ ] Everyone has read [Things that lose points](../guides/things-that-lose-points.md).
- [ ] Printed or downloaded copies of the checklists for your OS.

## The 4 hours

| Time | What to do |
|---|---|
| **0:00–0:15** | Open your image. **Read the README twice** and write down admins, users, critical services and prohibited items ([how](reading-the-readme.md)). **Take a VMware snapshot** (VM menu → Snapshot → Take Snapshot). |
| **0:15–0:45** | **Forensics questions.** Answer as many as you can *before* changing anything ([how](../guides/forensics-questions.md)). Skip any that take more than 10 minutes and come back later. |
| **0:45–1:00** | **Start updates** (they're slow, so let them run in the background). Run the script: **Audit** first, read the REVIEW lines, then **Apply**. Check the Scoring Report. |
| **1:00–2:30** | Work through the checklist from the top: users → passwords → firewall → services → software → files → OS settings → critical services. If the script ran, **skip the steps marked Script: ✅** and do the 🔎 and ✋ ones. **Check the Scoring Report after every few fixes.** |
| **2:30–3:30** | Backdoor hunting, the harder checklist items, the leftover forensics questions, and application updates (Firefox etc.). |
| **3:30–3:50** | Final checks: critical services still working? Any **penalties** on the Scoring Report? Fix them. |
| **3:50–4:00** | Stop making risky changes. Make sure your score is saved (the scoring report shows the latest time). |

## How to use the Scoring Report

- Open it from the desktop. It refreshes every minute or two.
- It shows **how many** problems you've fixed and their point values, not which ones are left.
- If your score **goes down**, you just caused a penalty. Undo your last change.
- If a fix you made doesn't add points, it might not be scored on this image. That's normal, so move on.

## Team rules

- **One person per image.** Two people changing the same computer causes chaos.
- **Say it out loud** before you do something risky ("I'm going to delete user mallory").
- **Write down what you change**, so you can undo it if the score drops.
- **Don't get stuck.** If something takes more than 10 minutes, skip it and come back.
- **Ask a teammate** before uninstalling anything the README might need.

## Using the scripts in a practice round

The scripts are a fast way to catch the common problems, but they don't replace thinking.

1. Run them in **Audit** mode first. Read every `REVIEW` line.
2. Run **Apply** only after the forensics questions are done and the README info is entered correctly.
3. Then open your checklist. Skip the steps marked **Script: ✅** (on the website, press **Tick the script's ✅ steps**) and work through the 🔎 and ✋ steps: the things the script can't decide for you.

See [Using the scripts safely](using-the-scripts.md).
