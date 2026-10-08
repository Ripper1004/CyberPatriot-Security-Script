# Using the scripts safely

There is one script per OS family:

| Script | Works on |
|---|---|
| `scripts/linux/harden.sh` | Linux Mint 20–22, Debian 11–12, Ubuntu 20.04–24.04 |
| `scripts/windows/Harden.ps1` | Windows 10, Windows 11, Windows Server 2016 / 2019 / 2022 (including Domain Controllers) |
| `scripts/freebsd/harden.sh` | FreeBSD 13 / 14 |

All three work the same way:

1. They ask you for the README info first: **admins, users, critical services**.
2. **Audit mode** only *reports* problems. It changes nothing, so it's safe to run any time.
3. **Apply mode** fixes problems. It asks before anything risky (deleting a user, uninstalling a program, deleting files).
4. Every file or setting is **backed up** before it's changed.
5. At the end you get a **summary** and a **findings report**, your to-do list of things a human has to decide.

> [!IMPORTANT]
> The scripts never delete or disable anything you list as authorized or critical. But **they only know what you type in.** If you misspell a user's name, the script thinks that user is unauthorized. Double-check the names!

## What the results mean

| Result | Meaning |
|---|---|
| `OK` | Already secure. Nothing to do. |
| `CHANGED` | The script fixed it. |
| `WOULD` | (Audit mode) The script would fix this in Apply mode. |
| `SKIPPED` | Not done, because you said no or it didn't apply. |
| `REVIEW` | **A human needs to look at this.** It's in the findings report. |
| `FAILED` | It tried and failed. The log file says why. Fix it by hand using the checklist. |

> [!TIP]
> **No internet on the image?** Download the files on another computer (same page) and copy them over with a USB drive or a shared folder into `~/cp` (Linux, FreeBSD) or `C:\cp` (Windows). You can also download the whole project as a ZIP from the GitHub page (**Code → Download ZIP**) and find the scripts in its `scripts` folder.

---

## Linux (Mint / Debian / Ubuntu)

### 1. Get the script onto the image
Open [Download the scripts](/downloads/) on this website (on the image, in Firefox) and copy the **Linux** download commands into a terminal. They save `harden.sh` and an example config in the `cp` folder inside your home folder. Then:
```bash
cd ~/cp
```

### 2. Run it
```bash
sudo bash harden.sh
```
On **Debian**, if `sudo` says you're not allowed, use `su -` first (it asks for the **root** password), then run `bash harden.sh` without `sudo`.

The script asks for the README info, then shows a menu. It starts in **AUDIT** mode:
```
 1) Users and groups
 2) Password and lockout policy
 ...
 a) Run ALL sections
 m) Switch to APPLY mode (make changes)
```
- Type `a` to audit everything. Read the output.
- Type `m` to switch to APPLY mode, then `a` again (or a number like `1` to do one section).

### 3. Optional: use a config file instead of typing
```bash
cp config.example.conf my.conf
nano my.conf            # fill in the names from the README, save with Ctrl+O, exit with Ctrl+X
sudo bash harden.sh --audit --config my.conf
sudo bash harden.sh --apply --config my.conf
```

### 4. Read the results
```bash
sudo cat /root/cyberpatriot/findings-*.txt      # your to-do list
sudo less /root/cyberpatriot/harden-*.log       # everything that happened (q to quit)
```

### Undoing a change
Every edited file is copied to `/root/cyberpatriot/backups/<date-time>/` with its full path. To put one back:
```bash
sudo cp -a /root/cyberpatriot/backups/20261022-140501/etc/ssh/sshd_config /etc/ssh/sshd_config
```

---

## Windows

### 1. Get the script onto the image
Open [Download the scripts](/downloads/) on this website (on the image, in Edge) and copy the **Windows** download commands into PowerShell. They save `Harden.ps1` and an example config in `C:\cp`.

### 2. Open PowerShell as Administrator
Click **Start**, type `powershell`, then choose **Run as administrator**.

### 3. Run it
```powershell
cd C:\cp
powershell -ExecutionPolicy Bypass -File .\Harden.ps1
```
`-ExecutionPolicy Bypass` lets this one script run without changing the computer's script policy.

The menu works like the Linux one: it starts in **Audit** mode, `a` runs everything, and `m` switches to Apply.

### 4. Optional: config file
```powershell
copy config.example.psd1 my-readme.psd1
notepad my-readme.psd1
powershell -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Audit -Config .\my-readme.psd1
powershell -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Apply -Config .\my-readme.psd1
```

### 5. Read the results
Everything is in `C:\harden-toolkit\`:
- `findings-*.txt`: your to-do list
- `harden-*.log`: everything that happened
- `backups\<date-time>\`: registry exports (`.reg` files: double-click one to put the old settings back) and the old security policy.

---

## FreeBSD

Open [Download the scripts](/downloads/) on this website and run the **FreeBSD** command there as root. It saves `harden.sh` in `~/cp`. Then:

```sh
su -
cd ~/cp
sh harden.sh
```

---

## Golden rules
1. **Forensics questions first**, then the script.
2. **Audit before Apply.** Read the REVIEW items.
3. **Check the Scoring Report** after running Apply. If the score went **down**, find the change that caused it (the log has a timestamp for every change) and undo it from the backups.
4. The script is a starting point. **Use the checklist** for everything it marks REVIEW and for things scripts can't detect.
5. **Every checklist step is tagged** with what the script does for it:
   - **Script: ✅** the script does it. After a clean Apply run you can skip it. On the website, **Tick the script's ✅ steps** ticks them all at once.
   - **Script: 🔎** the script checks it and lists it under REVIEW, but you decide.
   - **Script: ✋** the script doesn't do it. Do it by hand.
