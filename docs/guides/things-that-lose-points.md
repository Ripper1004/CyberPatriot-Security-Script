# Things that lose points

The scoring engine gives **penalties** (negative points) when you make things worse. These are the mistakes teams make most. Each one is easy to avoid if you know about it.

## The README mistakes

| Mistake | Instead |
|---|---|
| Deleting an **authorized user** (typo, or you skimmed the list) | Copy names from the README exactly. Check twice before deleting. |
| Removing admin rights from an **authorized admin** | Admins in the README stay admins, even if it looks like a lot of admins. |
| Stopping or uninstalling a **critical service** | Write the critical services down first. Harden them, never remove them. |
| Uninstalling **required software** | "Users need X" in the README means keep it (and update it). |
| Blocking a critical service with the **firewall** | Allow its port *before* turning the firewall on. |
| Ignoring special instructions ("don't change user X's password") | Read the README twice. Highlight anything unusual. |

## Locking yourself out

| Mistake | What happens | Instead |
|---|---|---|
| Removing **yourself** from sudo / Administrators | You can't fix anything else | Never touch your own account's admin rights |
| Changing **your own password** and forgetting it | Screen lock and sudo lock you out | Leave your password alone unless told to |
| Locking the **root** account on Debian when sudo isn't set up | No way to become admin | Check `sudo -v` works first |
| A mistake in **PAM** files (`common-auth`) | Nobody can log in | Keep a root terminal open, back up the file, test with `su - user` |
| A mistake in **sudoers** | `sudo` stops working for everyone | Always edit with `visudo` |
| `PasswordAuthentication no` in SSH | Nobody can log in over SSH (no one has keys) | Leave it `yes` unless the README says otherwise |
| Disabling the built-in Administrator **while logged in as it** | You lose admin | Check `whoami` first |
| Turning on **BitLocker** | You may never get back into the VM | Don't |
| Disabling the network adapter | Scoring stops updating | Don't |

## Breaking the computer

| Mistake | Instead |
|---|---|
| Disabling **NTDS / DNS / Netlogon / Kerberos** on a Domain Controller | Never touch these services on a DC |
| Resetting permissions on `C:\Windows` or `/etc` recursively | Fix individual files only |
| `apt purge` that also removes the desktop (it asks `Do you want to continue?`) | **Read the list of packages** apt will remove before answering Y |
| `apt autoremove` right after removing a big package | Read the list first |
| Deleting files in `/usr`, `/lib`, `C:\Windows` because they "look odd" | Look them up first (`dpkg -S file`) |
| Touching anything named **CyberPatriot** or the **scoring** service | Never. It's how you get points. |
| Rebooting in the middle of updates | Reboot at most once, near the end |
| Deleting the README, forensics files or the Scoring Report shortcut | Leave the desktop files alone |

## Losing points you already earned

| Mistake | Instead |
|---|---|
| Undoing your own fix later (e.g. a second script run re-enabling something) | Check the Scoring Report after each big change. If it drops, undo the last change. |
| Answering forensics after deleting the evidence | Forensics first |
| Two teammates working on the same image | One person per image |

## If your score goes down
1. **Stop.** What was the last thing you changed?
2. Undo it (the script's backups are in `/root/cyberpatriot/backups/` or `C:\harden-toolkit\backups\`).
3. Refresh the Scoring Report.
4. Still down? Revert to your last VMware snapshot. Points already earned **stay earned**.
