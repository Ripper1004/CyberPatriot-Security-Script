# Ubuntu checklist (20.04 / 22.04 / 24.04)

Ubuntu isn't in this season's CyberPatriot lineup, but it's very common on **older practice images**. Linux Mint is built on Ubuntu, so **follow the [Linux Mint checklist](linux-mint.md)**. Everything works the same except the items below.

> [!TIP]
> The Linux script (`scripts/linux/harden.sh`) detects Ubuntu automatically. To run it first, follow [step 1.2 of the Mint checklist](linux-mint.md#12-fast-path-run-the-hardening-script).

---

## Differences from Linux Mint

### Users: GNOME Settings instead of "Users and Groups"
- [ ] Done

**Script:** 🔎 The script does most of Mint section 2 (see the tags there); use these Settings screens for anything left.

**Settings → Users** → **Unlock**. Add or remove users, and toggle **Administrator**. The terminal commands are the same as Mint section 2.

### Updates: "Software & Updates" instead of "Update Manager"
- [ ] Done

**Script:** 🔎 The script turns on daily checks and automatic security updates, installs everything only with FULL_UPGRADE=yes (or a yes answer), and only lists PPAs under REVIEW.

**Clicking:** open **Software & Updates** → **Updates** tab:
- **Subscribed to:** All updates
- **Automatically check for updates:** **Daily**
- **When there are security updates:** **Download and install automatically**

Then open **Software Updater** and install everything.

On the **Other Software** tab, untick any PPA the README doesn't need.

> [!NOTE]
> Ubuntu 24.04 keeps its sources in **`/etc/apt/sources.list.d/ubuntu.sources`** (a newer format with `URIs:` and `Suites:` lines) instead of `/etc/apt/sources.list`.

### Firefox (and other apps) are "snaps"
- [ ] Done

**Script:** 🔎 The script runs `snap refresh` only when it installs all updates, and removes prohibited snaps it knows; check `snap list` yourself.

On Ubuntu 22.04+, Firefox is a **snap** package, so `apt` doesn't update it:
```bash
snap list                       # every snap app
sudo snap refresh               # update all snaps (including Firefox)
sudo snap remove <name>         # remove a prohibited snap app
```

### Firewall: UFW is installed but OFF
- [ ] Done

**Script:** 🔎 The script turns UFW on (Mint 4.1); still check the ports and extra rules (Mint 4.2 and 4.3).

Same commands as Mint section 4. There's no graphical firewall tool by default; install one with `sudo apt install gufw`.

### Login screen: GDM instead of LightDM
- [ ] Done

**Script:** ✅ Done by the script (`desktop` section).

**Settings → Users** → turn off **Automatic Login**. Or edit `/etc/gdm3/custom.conf` (Ubuntu's name for it), under `[daemon]`:
```
AutomaticLoginEnable=false
TimedLoginEnable=false
```

### Screen lock: GNOME settings
- [ ] Done

**Script:** 🔎 The script sets a 5-minute screen lock for all users with dconf; run the `gsettings` check, and set it by hand if the script says REVIEW.

**Settings → Privacy (& Security) → Screen** (or **Screen Lock**): **Automatic Screen Lock: On**, **Blank Screen Delay: 5 minutes**.
```bash
gsettings get org.gnome.desktop.screensaver lock-enabled      # true
```

### Remote access: GNOME "Sharing"
- [ ] Done

**Script:** 🔎 The script can stop SSH and VNC if the README doesn't need them, but it doesn't change GNOME's Sharing / Remote Desktop settings; turn those off here.

**Settings → Sharing** (24.04: **Settings → System → Remote Desktop / Secure Shell**). Turn off **Screen Sharing / Remote Desktop**, **Remote Login** (SSH), and **Media Sharing** unless the README needs them.

### SSH on Ubuntu 22.10 and newer
- [ ] Done

**Script:** 🔎 The script can disable `ssh.service` (it asks, default no) but not `ssh.socket`; if SSH isn't needed, run this command yourself.

SSH may be started **on demand** by `ssh.socket`. To turn it off completely:
```bash
sudo systemctl disable --now ssh.socket ssh.service
```

### Ubuntu 20.04: no pam_faillock
- [ ] Done

**Script:** 🔎 The script uses `pam_tally2` automatically on 20.04, but only if ENABLE_LOCKOUT=yes or you answer yes.

Use `pam_tally2` for account lockout (see the note in Mint section 3.6).

### Default games and apps
- [ ] Done

**Script:** 🔎 The script removes these when it finds them (it asks first); check its REVIEW lines for any it wouldn't remove.

A normal Ubuntu desktop install includes **AisleRiot Solitaire, Mahjongg, Mines, Sudoku** and **Transmission** (torrents). Remove them unless the README needs them:
```bash
sudo apt purge aisleriot gnome-mahjongg gnome-mines gnome-sudoku transmission-gtk transmission-common
```
