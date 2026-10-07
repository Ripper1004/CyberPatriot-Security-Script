# Windows 10 / 11 checklist

Windows 11 is in **Round 1 and Round 2** this season. Windows 10 is the same except where noted.

**How to use this page**
- Work **top to bottom**.
- Each item has: **What** · **Why it matters** · **Clicking** · **Typing** (PowerShell **as Administrator**) · **Check it worked** · ⚠️ warnings.
- New to PowerShell? Read [PowerShell basics](../start-here/powershell-basics.md) first.
- The script `scripts/windows/Harden.ps1` does most of this automatically. See [Using the scripts](../start-here/using-the-scripts.md).
- `alice`, `bob` etc. are examples. **Use the names in your README.**

---

## 0. Before you touch anything

### 0.1 Read the README
- [ ] Done

Write down the admins, users, critical services, required software and prohibited items. See [Reading the README](../start-here/reading-the-readme.md).

### 0.2 Take a VMware snapshot
- [ ] Done

**VM → Snapshot → Take Snapshot…**

### 0.3 Open PowerShell as Administrator
- [ ] Done

**Start** → type `powershell` → **Run as administrator**. The title must say **Administrator**.

### 0.4 Open the Scoring Report
- [ ] Done

Double-click it on the desktop and refresh it as you work.

---

## 1. Forensics questions (FIRST)

### 1.1 Answer every forensics question before fixing things
- [ ] Done

Open each `Forensics Question N.txt` on the desktop, put your answer after `ANSWER:`, and save.

**Useful tools:**
```powershell
Get-FileHash C:\Users\bob\Documents\file.txt -Algorithm SHA256     # hash a file
Get-ChildItem C:\Users -Recurse -Force -Filter *secret* -ErrorAction SilentlyContinue   # find files by name
Select-String -Path C:\Users\*\Documents\* -Pattern "password"     # find text inside files
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8='))   # decode base64
```
More: [Forensics questions guide](../guides/forensics-questions.md).

---

## 2. Users and groups

### 2.1 List every user
- [ ] Done

**Clicking:** **Win + R** → `lusrmgr.msc` → **Users**. (Or **Settings → Accounts → Other users**.)

**Typing:**
```powershell
Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordExpires, LastLogon
```

### 2.2 Delete users who are not in the README
- [ ] Done

**Why it matters:** Extra accounts are how attackers get back in.

**Clicking:** In `lusrmgr.msc` → **Users**, right-click the user → **Delete**.

**Typing:**
```powershell
Remove-LocalUser -Name mallory
```

> [!CAUTION]
> Don't delete the built-in accounts (**Administrator, Guest, DefaultAccount, WDAGUtilityAccount**): *disable* them instead (2.6). Never delete yourself or anyone on the README.

### 2.3 Create users the README says should exist
- [ ] Done

**Clicking:** `lusrmgr.msc` → **Users** → **Action → New User…** → untick "User must change password" only if the README says so.

**Typing:**
```powershell
New-LocalUser -Name erin -Password (Read-Host -AsSecureString "Password for erin")
Add-LocalGroupMember -Group Users -Member erin
```

### 2.4 Fix the Administrators group
- [ ] Done

**What:** Only the README's admins should be in **Administrators**.

**Clicking:** `lusrmgr.msc` → **Groups** → double-click **Administrators** → remove the wrong people / **Add…** the right ones.

**Typing:**
```powershell
Get-LocalGroupMember Administrators
Remove-LocalGroupMember -Group Administrators -Member bob
Add-LocalGroupMember -Group Administrators -Member alice
```

### 2.5 Check the other powerful groups
- [ ] Done

Open these groups in `lusrmgr.msc` and remove anyone the README doesn't say should be there:
**Backup Operators** (can read every file), **Power Users**, **Remote Desktop Users** (keep only if RDP is needed), **Remote Management Users**, **Hyper-V Administrators**, **Event Log Readers**, **Network Configuration Operators**.

```powershell
foreach ($g in 'Backup Operators','Power Users','Remote Desktop Users','Remote Management Users','Hyper-V Administrators') {
  "--- $g"; Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name }
```

### 2.6 Disable the Guest account (and the other built-ins)
- [ ] Done

**Clicking:** `lusrmgr.msc` → **Users** → right-click **Guest** → **Properties** → tick **Account is disabled**.

**Typing:**
```powershell
Disable-LocalUser -Name Guest
Get-LocalUser Guest, DefaultAccount, WDAGUtilityAccount | Format-Table Name, Enabled
```
The built-in **Administrator** should usually be disabled too, **unless you're logged in as it** or the README says to keep it.

### 2.7 Fix weak password settings on accounts
- [ ] Done

**What:** No account should have **Password never expires**, **User cannot change password**, or *no password required*.

**Clicking:** `lusrmgr.msc` → double-click each user → untick **Password never expires** and **User cannot change password**.

**Typing:**
```powershell
Get-LocalUser | Where-Object { $_.Enabled } | Format-Table Name, PasswordExpires, UserMayChangePassword, PasswordRequired
Set-LocalUser -Name bob -PasswordNeverExpires $false
net user bob /passwordreq:yes
```

### 2.8 Give users strong passwords
- [ ] Done

**Clicking:** `lusrmgr.msc` → right-click the user → **Set Password…**

**Typing:**
```powershell
Set-LocalUser -Name bob -Password (Read-Host -AsSecureString "New password for bob")
```
Use 12+ characters with upper case, lower case, a number and a symbol. **Don't change your own password** unless the README says so.

---

## 3. Account policies (passwords and lockout)

**Clicking:** **Win + R** → `secpol.msc` → **Account Policies**.

### 3.1 Password Policy
- [ ] Done

| Setting | Set to |
|---|---|
| Enforce password history | **24** passwords remembered |
| Maximum password age | **90** days (or what the README says) |
| Minimum password age | **1** day |
| Minimum password length | **12** characters |
| Password must meet complexity requirements | **Enabled** |
| Store passwords using reversible encryption | **Disabled** |

**Typing (everything except complexity and reversible encryption):**
```powershell
net accounts /uniquepw:24 /maxpwage:90 /minpwage:1 /minpwlen:12
```

### 3.2 Account Lockout Policy
- [ ] Done

| Setting | Set to |
|---|---|
| Account lockout threshold | **5** invalid attempts (set this first) |
| Account lockout duration | **30** minutes |
| Reset account lockout counter after | **30** minutes |
| Allow Administrator account lockout (Windows 11) | **Enabled** |

```powershell
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
net accounts                     # check everything
```

---

## 4. Local policies

### 4.1 Audit Policy (record security events)
- [ ] Done

**Why:** Without auditing there's no record of logins, account changes, or policy changes.

**Clicking:** `secpol.msc` → **Local Policies → Audit Policy**. Set **every** item to **Success and Failure**.

**Typing:**
```powershell
auditpol /set /category:* /success:enable /failure:enable
auditpol /get /category:*
```
Also: **Security Options → Audit: Force audit policy subcategory settings… to override audit policy category settings → Enabled**.

### 4.2 User Rights Assignment
- [ ] Done

**Clicking:** `secpol.msc` → **Local Policies → User Rights Assignment**. Double-click a right to see who has it.

| Right | Should be |
|---|---|
| Access Credential Manager as a trusted caller | **No one** |
| Access this computer from the network | Administrators, Users (**remove Everyone and Guest**) |
| Act as part of the operating system | **No one** |
| Allow log on locally | Administrators, Users |
| Allow log on through Remote Desktop Services | Administrators, Remote Desktop Users (or nobody if RDP isn't needed) |
| Back up files and directories | Administrators, Backup Operators |
| Create a token object | **No one** |
| Debug programs | **Administrators** only |
| Deny access to this computer from the network | **Guests** |
| Deny log on locally | **Guests** |
| Deny log on through Remote Desktop Services | **Guests** |
| Load and unload device drivers | Administrators |
| Manage auditing and security log | Administrators |
| Take ownership of files or other objects | Administrators |

> [!WARNING]
> Look carefully at the **Deny** rights. A planted "Deny log on locally: **Users**" locks every normal user out.

### 4.3 Security Options
- [ ] Done

**Clicking:** `secpol.msc` → **Local Policies → Security Options**.

| Setting | Set to |
|---|---|
| Accounts: Guest account status | **Disabled** |
| Accounts: Limit local account use of blank passwords to console logon only | **Enabled** |
| Interactive logon: Do not require CTRL+ALT+DEL | **Disabled** |
| Interactive logon: Don't display last signed-in | **Enabled** |
| Interactive logon: Machine inactivity limit | **900** seconds |
| Interactive logon: Message title / text for users attempting to log on | A warning, e.g. "Authorized users only" |
| Microsoft network client: Digitally sign communications (always) | **Enabled** |
| Microsoft network client: Send unencrypted password to third-party SMB servers | **Disabled** |
| Microsoft network server: Digitally sign communications (always) | **Enabled** |
| Network access: Allow anonymous SID/Name translation | **Disabled** |
| Network access: Do not allow anonymous enumeration of SAM accounts | **Enabled** |
| Network access: Do not allow anonymous enumeration of SAM accounts and shares | **Enabled** |
| Network access: Do not allow storage of passwords and credentials for network authentication | **Enabled** |
| Network access: Let Everyone permissions apply to anonymous users | **Disabled** |
| Network security: Do not store LAN Manager hash value on next password change | **Enabled** |
| Network security: LAN Manager authentication level | **Send NTLMv2 response only. Refuse LM & NTLM** |
| Shutdown: Allow system to be shut down without having to log on | **Disabled** |
| User Account Control: Admin Approval Mode for the Built-in Administrator account | **Enabled** |
| User Account Control: Behavior of the elevation prompt for administrators… | **Prompt for consent on the secure desktop** |
| User Account Control: Run all administrators in Admin Approval Mode | **Enabled** |
| User Account Control: Switch to the secure desktop when prompting for elevation | **Enabled** |

---

## 5. Microsoft Defender antivirus

### 5.1 Turn every protection on
- [ ] Done

**Clicking:** **Start → Windows Security → Virus & threat protection → Manage settings**. Turn **on**: Real-time protection, Cloud-delivered protection, Automatic sample submission, **Tamper Protection**.

**Typing:**
```powershell
Get-MpComputerStatus | Format-List AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureAge
Set-MpPreference -DisableRealtimeMonitoring $false -PUAProtection Enabled -MAPSReporting Advanced
```

### 5.2 Remove planted exclusions
- [ ] Done

**Why:** Attackers tell Defender to ignore their folder.

**Clicking:** **Manage settings → Exclusions → Add or remove exclusions**. Remove anything you didn't add.

**Typing:**
```powershell
Get-MpPreference | Format-List ExclusionPath, ExclusionExtension, ExclusionProcess
Remove-MpPreference -ExclusionPath "C:\Users\Public\tools"
```

### 5.3 No policy that turns Defender off
- [ ] Done

**Clicking:** **Win + R** → `gpedit.msc` → **Computer Configuration → Administrative Templates → Windows Components → Microsoft Defender Antivirus** → **Turn off Microsoft Defender Antivirus** must be **Not configured** (or Disabled). Check **Real-time Protection** in the same place.

### 5.4 Update and scan
- [ ] Done

```powershell
Update-MpSignature
Start-MpScan -ScanType QuickScan
Get-MpThreatDetection           # anything found
```

---

## 6. Firewall

### 6.1 Firewall on for every network type
- [ ] Done

**Clicking:** **Windows Security → Firewall & network protection**. **Domain**, **Private** and **Public** must all say *Firewall is on*.

**Typing:**
```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction
```

### 6.2 Check the inbound rules
- [ ] Done

**Clicking:** **Win + R** → `wf.msc` → **Inbound Rules**. Sort by **Enabled**. Look for **allow** rules for strange programs (in `C:\Users\`, `C:\Temp`), strange ports (4444, 1337), or rules called something like "Windows Update Helper" that point at an odd program.

**Typing:**
```powershell
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { -not $_.DisplayGroup } |
  ForEach-Object { "{0} -> {1}" -f $_.DisplayName, ($_ | Get-NetFirewallApplicationFilter).Program }
Disable-NetFirewallRule -DisplayName "Evil Rule"
```

---

## 7. Windows Update

### 7.1 Install all updates
- [ ] Done

**Clicking:** **Settings → Windows Update → Check for updates** → install everything. If updates are **paused**, click **Resume updates**.

### 7.2 Automatic updates on
- [ ] Done

**Clicking:** `gpedit.msc` → **Computer Configuration → Administrative Templates → Windows Components → Windows Update** (on Windows 11: **→ Manage end user experience**) → **Configure Automatic Updates** → **Enabled**, option **4 – Auto download and schedule the install**.

**Typing (check):**
```powershell
Get-Service wuauserv | Format-Table Name, Status, StartType        # StartType must not be Disabled
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
```
`NoAutoUpdate = 1` there means updates are switched off. Set it to `0`.

### 7.3 Update the other programs
- [ ] Done

Firefox (**≡ → Help → About Firefox**), Chrome (**⋮ → Help → About Google Chrome**), and anything the README lists (e.g. Notepad++, 7-Zip, VLC). Old versions are a scored problem.

---

## 8. Services

**Clicking:** **Win + R** → `services.msc`. To turn a service off: double-click it → **Startup type: Disabled** → **Stop** → **OK**.

**Typing:**
```powershell
Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled
```

### 8.1 Turn off risky services (unless the README needs them)
- [ ] Done

| Service (name) | Usually |
|---|---|
| Remote Registry (`RemoteRegistry`) | **Disable** |
| Telnet (`TlntSvr`) | **Disable** |
| SNMP Service (`SNMP`) | **Disable** |
| SSDP Discovery (`SSDPSRV`) | Disable |
| UPnP Device Host (`upnphost`) | Disable |
| Microsoft FTP Service (`FTPSVC`) | Disable unless FTP is needed |
| World Wide Web Publishing (`W3SVC`) | Disable unless a website is needed |
| Remote Desktop Services (`TermService`) | Disable unless RDP is needed |
| Routing and Remote Access (`RemoteAccess`) | Disable |
| Internet Connection Sharing (`SharedAccess`) | Disable |
| Print Spooler (`Spooler`) | Disable unless printing is needed |
| Xbox services (`XblAuthManager`, `XblGameSave`, `XboxNetApiSvc`) | Disable |
| Remote-control tools (TeamViewer, AnyDesk, VNC) | Disable **and** uninstall |

### 8.2 Make sure the security services are running
- [ ] Done

Windows Defender (`WinDefend`), Windows Defender Firewall (`mpssvc`), Windows Event Log (`EventLog`), Windows Update (`wuauserv`, Manual is fine), Security Center (`wscsvc`). None of these may be **Disabled**.

---

## 9. Windows features

### 9.1 Turn off old, insecure features
- [ ] Done

**Clicking:** **Win + R** → `optionalfeatures` → **untick**:
- **SMB 1.0/CIFS File Sharing Support** (the WannaCry hole)
- **Telnet Client**
- **TFTP Client**
- **Windows PowerShell 2.0**
- **Internet Information Services** (only if the README doesn't need a website/FTP)
- **Internet Explorer 11** (Windows 10)

**Typing:**
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Get-WindowsOptionalFeature -Online | Where-Object State -eq Enabled | Select-Object FeatureName
```

---

## 10. Remote access

### 10.1 Remote Assistance off
- [ ] Done

**Clicking:** **Win + R** → `SystemPropertiesRemote` → untick **Allow Remote Assistance connections to this computer**.

### 10.2 Remote Desktop off (or secured)
- [ ] Done

**Not needed:** **Settings → System → Remote Desktop → Off**.

**Needed (README says so):** keep it on, but tick **Require devices to use Network Level Authentication to connect**, and make sure only the right users are in **Remote Desktop Users**.

---

## 11. Shared folders

### 11.1 Remove shares that aren't needed
- [ ] Done

**Clicking:** **Win + R** → `fsmgmt.msc` → **Shares**. Right-click a share → **Stop Sharing**.

**Typing:**
```powershell
Get-SmbShare
Remove-SmbShare -Name Secret -Force
```
> [!CAUTION]
> Leave the built-in shares alone: **ADMIN$, C$, IPC$** (and **print$**).

---

## 12. Prohibited software

### 12.1 Uninstall hacking tools, games, torrent and remote-control programs
- [ ] Done

**Clicking:** **Settings → Apps → Installed apps** (or **Win + R → appwiz.cpl**). Sort by name and read the **whole** list.

Look for:
- **Hacking:** Wireshark, Npcap/WinPcap, Nmap, Cain & Abel, John the Ripper, Hashcat, Cheat Engine, keyloggers, "password recovery" tools
- **Games:** Steam, Epic, Minecraft, Roblox, Solitaire, Candy Crush
- **File-sharing:** uTorrent, BitTorrent, qBittorrent, Vuze, FrostWire
- **Remote control:** TeamViewer, AnyDesk, VNC, RustDesk

**Typing (to see the list):**
```powershell
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object DisplayName | Sort-Object DisplayName | Format-Table DisplayName, DisplayVersion, Publisher
```

### 12.2 Store apps and games
- [ ] Done

```powershell
Get-AppxPackage -AllUsers | Where-Object Name -match 'Solitaire|CandyCrush|Minecraft|Roblox|king.com' | Select-Object Name
Get-AppxPackage -AllUsers *Solitaire* | Remove-AppxPackage -AllUsers
```

### 12.3 "Portable" tools that aren't installed
- [ ] Done

Hacking tools are often just an `.exe` sitting in a folder: look in **Downloads**, **Desktop**, `C:\Users\Public`, `C:\Temp`, and `C:\` itself.
```powershell
Get-ChildItem C:\Users, C:\Temp -Recurse -Force -Include nc.exe,ncat.exe,nmap.exe,mimikatz*,*keylog*,psexec*,john*.exe,hashcat*.exe -ErrorAction SilentlyContinue
```

---

## 13. Prohibited files

### 13.1 Show hidden files first
- [ ] Done

**File Explorer → View → Show → Hidden items** (Windows 10: **View → Hidden items**). Also tick **File name extensions**.

### 13.2 Find media files
- [ ] Done

```powershell
Get-ChildItem C:\Users -Recurse -Force -Include *.mp3,*.mp4,*.wav,*.wma,*.wmv,*.avi,*.mkv,*.mov,*.flac,*.m4a,*.aac,*.ogg,*.torrent -ErrorAction SilentlyContinue |
  Select-Object FullName
Remove-Item "C:\Users\bob\Music\song.mp3"
```
Also look in other folders on `C:\` that aren't part of Windows (e.g. `C:\Media`, `C:\Share`), and **empty the Recycle Bin** when forensics is done.

### 13.3 Password lists and other data
- [ ] Done

```powershell
Get-ChildItem C:\Users -Recurse -Force -Include *password*,*creditcard*,*.pcap,*.kdbx -ErrorAction SilentlyContinue | Select-Object FullName
```

---

## 14. Backdoors and malware

### 14.1 Programs that start at logon
- [ ] Done

**Clicking:** **Task Manager (Ctrl+Shift+Esc) → Startup apps**. Also open these folders with **Win + R**: `shell:startup` and `shell:common startup`.

**Typing:**
```powershell
Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, Location -AutoSize
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run, HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Remove-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Updater"
```
Red flags: `powershell -enc ...`, `-WindowStyle Hidden`, `nc.exe`, `mshta`, `.vbs`/`.bat`/`.ps1` files, anything in `C:\Users\Public` or `Temp`.

### 14.2 Scheduled tasks
- [ ] Done

**Clicking:** **Win + R** → `taskschd.msc` → **Task Scheduler Library**. Check each task's **Actions** tab. Non-Microsoft tasks are usually in the top folder.

**Typing:**
```powershell
Get-ScheduledTask | Where-Object TaskPath -notlike '\Microsoft\*' |
  ForEach-Object { "{0}{1} -> {2} {3}" -f $_.TaskPath, $_.TaskName, $_.Actions.Execute, $_.Actions.Arguments }
Unregister-ScheduledTask -TaskName "BadTask" -Confirm:$false
```

### 14.3 Services that run strange programs
- [ ] Done

```powershell
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'Windows\\|Program Files' } | Format-Table Name, State, PathName -AutoSize
```

### 14.4 Sticky Keys / Utility Manager backdoor
- [ ] Done

**Why:** Replacing `sethc.exe` (press Shift 5 times) or `utilman.exe` (the accessibility button) with `cmd.exe` gives anyone a SYSTEM command prompt **at the login screen**.

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  Where-Object { $_.GetValue('Debugger') } | ForEach-Object { "$($_.PSChildName) -> $($_.GetValue('Debugger'))" }
(Get-Item C:\Windows\System32\sethc.exe).VersionInfo.OriginalFilename      # must be sethc.exe(.mui), not Cmd.Exe
```
**Fix:** delete the `Debugger` value. If the file itself was replaced, run `sfc /scanfile=C:\Windows\System32\sethc.exe`.

### 14.5 The hosts file
- [ ] Done

```powershell
notepad C:\Windows\System32\drivers\etc\hosts
```
Only comment lines (starting with `#`) are normal. Delete lines that send real websites to other addresses.

### 14.6 Programs listening for connections
- [ ] Done

```powershell
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess, @{n='Process';e={(Get-Process -Id $_.OwningProcess).ProcessName}} | Sort-Object LocalPort
```
`nc`, `ncat`, `powershell` or `python` listening on a port is a backdoor. Stop it (`Stop-Process -Id <PID> -Force`), then find what starts it (14.1–14.3).

---

## 15. Other settings

### 15.1 User Account Control
- [ ] Done

**Start** → type **Change User Account Control settings** → move the slider to the **top** (**Always notify**).

### 15.2 AutoPlay off
- [ ] Done

**Settings → Bluetooth & devices → AutoPlay** (Windows 10: **Devices → AutoPlay**) → **Use AutoPlay for all media and devices: Off**.

### 15.3 Screen saver with password
- [ ] Done

**Settings → Personalization → Lock screen → Screen saver** → pick one, **Wait: 10 minutes**, tick **On resume, display logon screen**.

### 15.4 Turn off LLMNR
- [ ] Done

`gpedit.msc` → **Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution → Enabled**.

### 15.5 SmartScreen on
- [ ] Done

**Windows Security → App & browser control → Reputation-based protection settings** → turn everything **on**.

> [!WARNING]
> **Do not turn on BitLocker** on a practice image. Without the recovery key you can lock yourself out of the whole VM.

---

## 16. Web browsers

### 16.1 Microsoft Edge
- [ ] Done

**⋯ → Settings → Privacy, search, and services** → **Microsoft Defender SmartScreen: On**, **Block potentially unwanted apps: On**. **Cookies and site permissions → Pop-ups and redirects → Block**.

### 16.2 Firefox (if installed)
- [ ] Done

**≡ → Settings → Privacy & Security**:
- **Block pop-up windows** ✔
- **Warn you when websites try to install add-ons** ✔
- **Block dangerous and deceptive content** ✔ (all three boxes)
- **HTTPS-Only Mode** → Enable in all windows

Then **≡ → Help → About Firefox** to update. Also check **Add-ons and themes** for extensions you don't recognise.

### 16.3 Chrome (if installed)
- [ ] Done

**⋮ → Settings → Privacy and security → Security → Standard (or Enhanced) protection**. **Site settings → Pop-ups and redirects → Don't allow**. Update via **Help → About Google Chrome**.

---

## 17. Critical services

If the README says this computer runs a website, FTP or file shares, harden them instead of removing them. See the IIS/FTP sections of the [Windows Server checklist](windows-server.md#9-critical-server-roles-only-if-the-readme-lists-them). They work the same on Windows 10/11.

---

## 18. Final checks

- [ ] Critical services still running (`services.msc`)
- [ ] You can still log in and open an admin PowerShell
- [ ] Scoring Report shows **no penalties**
- [ ] Forensics answers saved
- [ ] Final snapshot
- [ ] Reboot **once** at the end only if updates need it, then check the Scoring Report again
