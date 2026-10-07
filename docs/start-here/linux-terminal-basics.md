# Linux terminal basics (for people who have never typed a command)

The **terminal** is a window where you type commands instead of clicking. On Linux most security work is faster in the terminal, and many settings can *only* be changed there.

**Open it:** press **Ctrl + Alt + T**, or open the menu and search for "Terminal".

## How a command looks

```bash
sudo userdel bob
```
- `sudo` = "do this as the administrator (root)". It asks for **your** password. Nothing shows while you type it, which is normal.
- `userdel` = the command (delete a user).
- `bob` = what to do it to.

Press **Enter** to run it. If it worked, Linux often prints **nothing**. No news is good news.

## Keys that save time
| Key | What it does |
|---|---|
| **Tab** | Auto-complete a file or command name. Press it twice to see the choices. |
| **↑ / ↓** | Bring back earlier commands. |
| **Ctrl + C** | Stop the command that is running. |
| **Ctrl + Shift + C / V** | Copy / paste *inside the terminal* (plain Ctrl+C means "stop"!). |
| **q** | Quit a viewer like `less` or `man`. |

## The 20 commands you'll actually use
| Command | What it does | Example |
|---|---|---|
| `pwd` | Show which folder you're in | `pwd` |
| `ls -la` | List files, including hidden ones (names starting with `.`) | `ls -la /home/bob` |
| `cd` | Go to a folder | `cd /etc` |
| `cat` | Print a file | `cat /etc/passwd` |
| `less` | Read a long file (q to quit, / to search) | `less /var/log/auth.log` |
| `nano` | Simple text editor (Ctrl+O save, Ctrl+X exit) | `sudo nano /etc/ssh/sshd_config` |
| `grep` | Find lines containing a word | `grep -i bob /etc/group` |
| `find` | Find files | `sudo find /home -iname "*.mp3"` |
| `rm` | Delete a file (no recycle bin!) | `sudo rm /home/bob/song.mp3` |
| `cp` | Copy | `sudo cp file file.bak` |
| `sudo` | Run as administrator | `sudo apt update` |
| `apt` | Install / remove / update software | `sudo apt purge nmap` |
| `systemctl` | Start / stop / check services | `systemctl status ssh` |
| `ss -tulpn` | Show what's listening on the network | `sudo ss -tulpn` |
| `ps aux` | Show running programs | `ps aux \| grep nc` |
| `id` | Show a user's groups | `id bob` |
| `passwd` | Change a password | `sudo passwd bob` |
| `chmod` / `chown` | Change permissions / owner | `sudo chmod 640 /etc/shadow` |
| `history` | Show your past commands | `history` |
| `man` | The manual for a command | `man userdel` |

## Reading permissions
```
-rw-r----- 1 root shadow 1234 Oct 22 10:00 /etc/shadow
 ^^^ owner can read+write
    ^^^ group can read
       ^^^ others: nothing
```
Numbers: r=4, w=2, x=1. So `640` = owner rw (6), group r (4), others none (0).

## Paths you'll see a lot
| Path | What's there |
|---|---|
| `/etc/` | Settings files for almost everything |
| `/home/<user>/` | Each user's files (Desktop, Documents, Downloads...) |
| `/var/log/` | Log files |
| `/tmp/` | Temporary files (attackers like hiding things here) |
| `/root/` | The root user's home folder |

## Safety tips
- **Read the command before pressing Enter**, especially anything with `rm`.
- Before editing a settings file, **copy it**: `sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak`
- If a command asks `[Y/n]`, read what it's about to remove before answering.
- `sudo` mistakes can't be undone. When unsure, ask a teammate.
