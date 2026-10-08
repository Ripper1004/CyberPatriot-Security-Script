# PowerShell basics

**PowerShell** is Windows' command window. You can do most CyberPatriot fixes by clicking, but PowerShell is much faster for checking things, like listing every user or every service at once.

## Open it as Administrator (important!)
1. Click **Start** and type `powershell`.
2. Click **Run as administrator** and say **Yes**.
3. The title bar should say **Administrator: Windows PowerShell**. Without that, most fixes fail with "Access denied".

## How a command looks
```powershell
Get-LocalUser
```
PowerShell commands are **Verb-Noun**: `Get-` reads things, `Set-` changes them, `Remove-` deletes them, `Disable-` turns them off.

```powershell
Disable-LocalUser -Name "Guest"
```
`-Name "Guest"` is a **parameter**: it tells the command what to work on.

## Keys that save time
| Key | What it does |
|---|---|
| **Tab** | Auto-complete commands, parameters and file names. Press again to cycle. |
| **↑ / ↓** | Earlier commands. |
| **Ctrl + C** | Stop the running command. |
| Right-click | Paste (in the classic console). |
| `cls` | Clear the screen. |

## Commands you'll actually use
| Command | What it does |
|---|---|
| `Get-LocalUser` | List users (Enabled = True/False) |
| `Get-LocalGroupMember Administrators` | Who is an admin |
| `Remove-LocalUser -Name bob` | Delete a user |
| `Remove-LocalGroupMember -Group Administrators -Member bob` | Take away admin rights |
| `net accounts` | Show the password and lockout policy |
| `Get-Service \| Where-Object Status -eq Running` | Running services |
| `Stop-Service -Name Spooler -Force` | Stop a service |
| `Set-Service -Name Spooler -StartupType Disabled` | Stop it from starting again |
| `Get-NetFirewallProfile` | Is the firewall on? |
| `Get-MpComputerStatus` | Is Defender on? |
| `Get-SmbShare` | Shared folders |
| `Get-ScheduledTask \| Where-Object TaskPath -notlike '\Microsoft\*'` | Scheduled tasks that aren't from Microsoft |
| `Get-NetTCPConnection -State Listen` | Ports that are listening |
| `Get-ChildItem C:\Users -Recurse -Include *.mp3,*.mp4 -Force -ErrorAction SilentlyContinue` | Find media files |
| `Get-FileHash .\file.txt -Algorithm SHA256` | Hash a file (forensics) |
| `Get-Help Get-LocalUser -Examples` | Examples for any command |

## The `|` (pipe)
`|` sends the output of one command into the next:
```powershell
Get-Service | Where-Object Status -eq Running | Sort-Object DisplayName
```
Read it as: get services → keep the running ones → sort them by name.

## Useful "run" shortcuts (Win + R)
Press **Windows key + R**, type one of these, press Enter:

| Type | Opens |
|---|---|
| `lusrmgr.msc` | Local Users and Groups |
| `secpol.msc` | Local Security Policy (passwords, audit, user rights, security options) |
| `gpedit.msc` | Group Policy Editor |
| `services.msc` | Services |
| `wf.msc` | Windows Firewall (advanced) |
| `taskschd.msc` | Task Scheduler |
| `eventvwr.msc` | Event Viewer (logs) |
| `compmgmt.msc` | Computer Management (users, shares, disks...) |
| `fsmgmt.msc` | Shared Folders |
| `appwiz.cpl` | Uninstall programs |
| `optionalfeatures` | Turn Windows features on or off |
| `regedit` | Registry Editor (be careful!) |
| `SystemPropertiesRemote` | Remote Desktop / Remote Assistance settings |

## Safety tips
- PowerShell does what you ask **immediately**. There's no undo for `Remove-` commands.
- Before changing the registry, export the key: in regedit, right-click the key → **Export**.
- If you're not sure what a command does, add `-WhatIf` to see what *would* happen: `Remove-LocalUser -Name bob -WhatIf`
