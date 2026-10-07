# Debian checklist (Debian 11 / 12)

Debian 12 ("bookworm") is in **Round 2, the State round and the Semifinals** this season.

Debian is Ubuntu's and Linux Mint's "parent", so most commands are the same as the [Linux Mint checklist](linux-mint.md). This page walks through the whole job and explains **the Debian differences** that trip people up. Where a step is exactly the same as Mint, it links there.

> [!IMPORTANT]
> **The five big Debian differences**
> 1. **`sudo` may not work.** If a root password was set when Debian was installed, your user isn't an admin yet. Use **`su -`** to become root (step 0.3).
> 2. **No firewall is installed.** You must install `ufw` (section 4).
> 3. **No `/var/log/auth.log`.** Debian 12 keeps logs in the **journal**, so use `journalctl` for forensics (section 1).
> 4. **Automatic updates are not installed** (section 5).
> 5. The desktop is usually **GNOME**, so the settings are in **Settings**, not Mint's tools.

---

## 0. Before you touch anything

### 0.1 Read the README, take a snapshot, open the Scoring Report
- [ ] Done

See [Reading the README](../start-here/reading-the-readme.md). In VMware: **VM → Snapshot → Take Snapshot**.

### 0.2 Open a terminal
- [ ] Done

GNOME: press the **Super (Windows) key**, type `terminal`, press Enter.

### 0.3 Become an administrator: `sudo` or `su -`
- [ ] Done

```bash
sudo -v
```
- **No error:** good, use `sudo` like on Mint.
- **"user is not in the sudoers file"** or **"sudo: command not found":** use the **root password** from the README:
  ```bash
  su -               # note the dash! it asks for ROOT's password
  ```
  Your prompt changes to `root@...#`. Now run every command **without** `sudo`.

> [!WARNING]
> Use `su -` **with the dash**. Plain `su` keeps your normal PATH, so commands like `usermod` or `ufw` give "command not found".

Optional, to make life easier: give the README's admins working `sudo` (this is often scored too):
```bash
apt install sudo
usermod -aG sudo alice       # every README admin
```
They must **log out and back in** before `sudo` works for them.

---

## 1. Forensics questions (FIRST)

### 1.1 Answer them before changing anything
- [ ] Done

Same tools as [Mint section 1](linux-mint.md#1-forensics-questions-do-these-first), **except the logs:**
```bash
journalctl _COMM=sshd | tail -50              # SSH logins
journalctl _COMM=sudo                         # every sudo command
journalctl -u cron --since "2 days ago"       # cron jobs that ran
journalctl --list-boots                       # boot history
last -a | head -20                            # recent logins
```
`/var/log/auth.log` only exists if `rsyslog` is installed.

---

## 2. Users and groups

### 2.1 List users
- [ ] Done

**Clicking (GNOME):** **Settings → Users** → click **Unlock** (top right) and enter a password.

**Typing:**
```bash
awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd
```

### 2.2 Delete users who are not in the README
- [ ] Done

**Clicking:** **Settings → Users** → **Unlock** → click the user → **Remove User…**

**Typing:**
```bash
sudo deluser mallory              # or as root: deluser mallory
```

### 2.3 Add missing users
- [ ] Done

```bash
sudo adduser erin
```

### 2.4 Fix administrators (the `sudo` group)
- [ ] Done

**Clicking:** **Settings → Users** → click the user → toggle **Administrator**.

**Typing:**
```bash
getent group sudo
sudo deluser bob sudo
sudo usermod -aG sudo alice
```

### 2.5 Hidden root accounts, hidden users, powerful groups, weak passwords
- [ ] Done

Same as [Mint 2.5 – 2.7](linux-mint.md#25-look-for-hidden-root-accounts-and-hidden-users).

### 2.6 The root account
- [ ] Done

On Debian, **root may have a password** (Mint and Ubuntu lock it).
```bash
sudo passwd -S root       # P = has a password, L = locked
```
- If the README's admins can use `sudo` (0.3), lock root: `sudo passwd -l root`
- If you still need `su -`, **don't lock root**. Just make sure its password is strong: `passwd root`

---

## 3. Password and lockout policy

### 3.1 Same as Mint
- [ ] Done

Follow [Mint section 3](linux-mint.md#3-password-and-lockout-policy). Debian 12 has `pam_faillock`, and its `common-auth` has the same layout (including the comment line between `pam_unix` and `pam_deny`, which is why the order in Mint 3.6 matters).

`libpam-pwquality` isn't installed by default:
```bash
sudo apt install libpam-pwquality
```

---

## 4. Firewall

### 4.1 Install and turn on UFW
- [ ] Done

**Why:** Debian ships **without** a firewall turned on.

```bash
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp            # ONLY if SSH is critical; add other critical ports (Mint 4.2)
sudo ufw enable
sudo ufw logging on
sudo ufw status verbose
```
Prefer clicking? `sudo apt install gufw`, then open **Firewall Configuration**.

---

## 5. Updates

### 5.1 Check the software sources
- [ ] Done

```bash
cat /etc/apt/sources.list; ls /etc/apt/sources.list.d/
```
For Debian 12 you should see **`deb.debian.org/debian bookworm`**, **`bookworm-updates`** and **`security.debian.org/debian-security bookworm-security`**. A missing **security** line means no security updates. Anything else (especially with `[trusted=yes]`) should be removed unless the README needs it.

### 5.2 Install all updates
- [ ] Done

```bash
sudo apt update
sudo apt full-upgrade -y
```
(GNOME's **Software** app also shows updates.)

### 5.3 Turn on automatic updates
- [ ] Done

```bash
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades       # answer Yes
cat /etc/apt/apt.conf.d/20auto-upgrades               # both lines should be "1"
```

### 5.4 Held packages
- [ ] Done

```bash
apt-mark showhold; sudo apt-mark unhold <name>
```

---

## 6. Services

### 6.1 GNOME "Sharing" settings
- [ ] Done

**Clicking:** **Settings → Sharing** (GNOME 43: **Settings → System → Sharing** on newer versions). Turn **off** anything the README doesn't need: **Remote Desktop / Screen Sharing**, **Remote Login** (that's SSH), **File Sharing**, **Media Sharing**.

### 6.2 Turn off services that aren't needed
- [ ] Done

Same table and commands as [Mint section 6](linux-mint.md#6-services):
```bash
systemctl list-units --type=service --state=running
sudo ss -tulpn
sudo systemctl disable --now <service>
sudo apt purge <package>
```

---

## 7. Prohibited software and files

### 7.1 Same as Mint
- [ ] Done

Follow [Mint section 7](linux-mint.md#7-prohibited-software-and-files). Debian's GNOME install can include games (`gnome-games`, `aisleriot`, `gnome-mines`, `gnome-sudoku`…):
```bash
dpkg -l | grep -Ei 'gnome-games|aisleriot|mines|sudoku|mahjongg|chess|robots|tetravex|nibbles|klotski|quadrapassel|swell-foop|tali|four-in-a-row|five-or-more|hitori|iagno|lightsoff'
sudo apt purge gnome-games && sudo apt autoremove
```

---

## 8. Login screen and screen lock

### 8.1 No automatic login (GDM)
- [ ] Done

**Clicking:** **Settings → Users** → **Unlock** → turn off **Automatic Login** for every user.

**Typing:**
```bash
sudo nano /etc/gdm3/daemon.conf
```
In `[daemon]`:
```
AutomaticLoginEnable=false
TimedLoginEnable=false
```
In `[security]`: `DisallowTCP=true`.

### 8.2 Screen lock
- [ ] Done

**Clicking:** **Settings → Privacy (& Security) → Screen Lock**: **Automatic Screen Lock: On**, **Automatic Screen Lock Delay: Screen Turns Off**. Then **Settings → Power → Screen Blank: 5 minutes**.

**Check:**
```bash
gsettings get org.gnome.desktop.screensaver lock-enabled     # true
gsettings get org.gnome.desktop.session idle-delay           # uint32 300
```

---

## 9. SSH, kernel, permissions, sudo rules, backdoors

These are the same on Debian. Follow the Mint sections:

- [ ] [9. SSH server](linux-mint.md#9-ssh-server-only-if-installed)
- [ ] [10. Kernel and network settings](linux-mint.md#10-kernel-and-network-settings-sysctl)
- [ ] [11. File permissions](linux-mint.md#11-file-permissions)
- [ ] [12. Sudo rules](linux-mint.md#12-sudo-rules)
- [ ] [13. Backdoors and malware](linux-mint.md#13-backdoors-and-malware)

---

## 10. Logging and auditing

### 10.1 Install rsyslog and auditd
- [ ] Done

**Why:** Without `rsyslog`, there's no `/var/log/auth.log`. Many people (and some scoring checks) expect it.
```bash
sudo apt install rsyslog auditd
sudo systemctl enable --now rsyslog auditd
```
Audit rules: same as [Mint 14.1](linux-mint.md#14-logging-and-auditing).

### 10.2 AppArmor
- [ ] Done

Debian has AppArmor turned on by default. Check it's still on: `sudo aa-status`.

---

## 11. Critical services

Follow the [Linux service hardening guide](../guides/linux-service-hardening.md) for every service the README lists.

---

## 12. Final checks

- [ ] Critical services running (`systemctl status <name>`)
- [ ] The README admins can use `sudo` (or you can still `su -`)
- [ ] `sudo ufw status` → active
- [ ] Scoring Report shows **no penalties**
- [ ] Forensics answers saved, final snapshot taken
