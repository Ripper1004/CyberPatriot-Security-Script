# Ubuntu checklist (20.04 / 22.04 / 24.04)

Ubuntu isn't in this season's CyberPatriot lineup, but it's very common on **older practice images**. Linux Mint is built on Ubuntu, so **follow the [Linux Mint checklist](linux-mint.md)**. Everything works the same except the items below.

> [!TIP]
> The Linux script (`scripts/linux/harden.sh`) detects Ubuntu automatically.

---

## Differences from Linux Mint

### Users: GNOME Settings instead of "Users and Groups"
- [ ] Done

**Settings → Users** → **Unlock**. Add or remove users, and toggle **Administrator**. The terminal commands are the same as Mint section 2.

### Updates: "Software & Updates" instead of "Update Manager"
- [ ] Done

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

On Ubuntu 22.04+, Firefox is a **snap** package, so `apt` doesn't update it:
```bash
snap list                       # every snap app
sudo snap refresh               # update all snaps (including Firefox)
sudo snap remove <name>         # remove a prohibited snap app
```

### Firewall: UFW is installed but OFF
- [ ] Done

Same commands as Mint section 4. There's no graphical firewall tool by default; install one with `sudo apt install gufw`.

### Login screen: GDM instead of LightDM
- [ ] Done

**Settings → Users** → turn off **Automatic Login**. Or edit `/etc/gdm3/custom.conf` (Ubuntu's name for it), under `[daemon]`:
```
AutomaticLoginEnable=false
TimedLoginEnable=false
```

### Screen lock: GNOME settings
- [ ] Done

**Settings → Privacy (& Security) → Screen** (or **Screen Lock**): **Automatic Screen Lock: On**, **Blank Screen Delay: 5 minutes**.
```bash
gsettings get org.gnome.desktop.screensaver lock-enabled      # true
```

### Remote access: GNOME "Sharing"
- [ ] Done

**Settings → Sharing** (24.04: **Settings → System → Remote Desktop / Secure Shell**). Turn off **Screen Sharing / Remote Desktop**, **Remote Login** (SSH), and **Media Sharing** unless the README needs them.

### SSH on Ubuntu 22.10 and newer
- [ ] Done

SSH may be started **on demand** by `ssh.socket`. To turn it off completely:
```bash
sudo systemctl disable --now ssh.socket ssh.service
```

### Ubuntu 20.04: no pam_faillock
- [ ] Done

Use `pam_tally2` for account lockout (see the note in Mint section 3.6).

### Default games and apps
- [ ] Done

A normal Ubuntu desktop install includes **AisleRiot Solitaire, Mahjongg, Mines, Sudoku** and **Transmission** (torrents). Remove them unless the README needs them:
```bash
sudo apt purge aisleriot gnome-mahjongg gnome-mines gnome-sudoku transmission-gtk transmission-common
```
