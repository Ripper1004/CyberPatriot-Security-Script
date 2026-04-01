# Windows 10 CyberPatriot Competition Checklist

> **Usage**: Work through each section in order. Items marked `[SCRIPT]` are handled by `secure_windows.ps1` — verify they applied. Items marked `[MANUAL]` require human judgment. Always run PowerShell as Administrator.

---

## Phase 0 — Read the README / Scenario

- [ ] **Read the competition README completely** before touching anything `[MANUAL]`
- [ ] Note which users are authorized and their roles (admin vs standard)
- [ ] Note which services must remain running
- [ ] Note any required software or configurations
- [ ] Identify the forensic question(s) and begin researching answers
- [ ] **Take a VM snapshot / checkpoint** before making changes

---

## Phase 1 — Forensic Questions

- [ ] Read each forensic question carefully `[MANUAL]`
- [ ] Check common locations:
  - Desktop folders for all users
  - `C:\Users\<user>\Documents\`, `Downloads\`, `AppData\`
  - Recycle Bin: `C:\$Recycle.Bin\`
  - Browser history (Edge, Chrome, Firefox)
  - Event Viewer logs (Security, Application, System)
  - Recent files: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\`
  - PowerShell history: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- [ ] Submit forensic answers as you find them

---

## Phase 2 — User & Group Management

### 2.1 User Account Audit
- [ ] Open **Computer Management** > Local Users and Groups > Users `[MANUAL]`
- [ ] Or use PowerShell: `Get-LocalUser | Select Name, Enabled, LastLogon`
- [ ] Compare against README authorized user list
- [ ] **Remove unauthorized users**: `Remove-LocalUser -Name "<username>"`
- [ ] **Create missing users**: `New-LocalUser -Name "<username>" -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)`
- [ ] **Disable Guest account**: `Disable-LocalUser -Name "Guest"` `[SCRIPT]`
- [ ] **Disable DefaultAccount**: `Disable-LocalUser -Name "DefaultAccount"` `[SCRIPT]`

### 2.2 Group Membership
- [ ] Check Administrators group: `Get-LocalGroupMember "Administrators"` `[MANUAL]`
- [ ] Remove unauthorized admins: `Remove-LocalGroupMember -Group "Administrators" -Member "<user>"`
- [ ] Add authorized admins: `Add-LocalGroupMember -Group "Administrators" -Member "<user>"`
- [ ] Check Remote Desktop Users: `Get-LocalGroupMember "Remote Desktop Users"`
- [ ] Check Power Users: `Get-LocalGroupMember "Power Users"`
- [ ] Remove unauthorized members from all sensitive groups

### 2.3 Password Changes
- [ ] Set strong passwords for all authorized users `[MANUAL]`
- [ ] Force password change on next logon: `net user <username> /logonpasswordchg:yes`
- [ ] Ensure no passwords are blank: `Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false }`

---

## Phase 3 — Password & Account Policies

### 3.1 Password Policy (secpol.msc or script)
- [ ] **Minimum password length**: 12+ characters `[SCRIPT]`
- [ ] **Password complexity**: Enabled `[SCRIPT]`
- [ ] **Maximum password age**: 90 days (or per README)
- [ ] **Minimum password age**: 1 day
- [ ] **Password history**: 24 passwords remembered
- [ ] **Reversible encryption**: Disabled
- [ ] Verify: `secpol.msc` > Account Policies > Password Policy

### 3.2 Account Lockout Policy
- [ ] **Lockout threshold**: 5 invalid attempts `[SCRIPT]`
- [ ] **Lockout duration**: 30 minutes
- [ ] **Reset lockout counter**: 30 minutes
- [ ] Verify: `secpol.msc` > Account Policies > Account Lockout Policy

### 3.3 Local Security Policies (secpol.msc)
- [ ] **Interactive logon: Do not display last username**: Enabled `[MANUAL]`
- [ ] **Interactive logon: Message text for users**: Set warning banner
- [ ] **Interactive logon: Message title for users**: Set title
- [ ] **Accounts: Rename administrator account**: Consider renaming
- [ ] **Accounts: Rename guest account**: Consider renaming
- [ ] **Network access: Do not allow anonymous enumeration of SAM accounts**: Enabled
- [ ] **Network access: Do not allow anonymous enumeration of SAM accounts and shares**: Enabled

---

## Phase 4 — Audit Policy Configuration

### 4.1 Basic Audit Policies (auditpol)
- [ ] Account Logon — Success & Failure `[SCRIPT]`
- [ ] Account Management — Success & Failure `[SCRIPT]`
- [ ] Logon/Logoff — Success & Failure `[SCRIPT]`
- [ ] Policy Change — Success & Failure `[SCRIPT]`
- [ ] Object Access — Success & Failure `[SCRIPT]`
- [ ] Privilege Use — Success & Failure
- [ ] System — Success & Failure
- [ ] Detailed Tracking — Success & Failure
- [ ] DS Access — Success & Failure
- [ ] Verify: `auditpol /get /category:*`

### 4.2 Advanced Audit Configuration
- [ ] Enable process command-line logging `[SCRIPT]`
- [ ] Enable PowerShell script block logging `[SCRIPT]`
- [ ] Enable PowerShell module logging `[SCRIPT]`
- [ ] Enable LSA protection (RunAsPPL) `[SCRIPT]`

### 4.3 Event Log Settings
- [ ] Increase Security log max size: 80+ MB
- [ ] Increase Application log max size: 32+ MB
- [ ] Increase System log max size: 32+ MB
- [ ] Set retention method: "Overwrite events as needed"

---

## Phase 5 — Windows Defender & Antimalware

- [ ] **Real-time protection**: Enabled `[SCRIPT]`
- [ ] **Cloud-delivered protection**: Enabled
- [ ] **Automatic sample submission**: Configured
- [ ] **Controlled Folder Access**: Enabled `[SCRIPT]`
- [ ] **Attack Surface Reduction (ASR) rules**: Enabled `[SCRIPT]`
- [ ] **PUA protection**: Enabled
  ```powershell
  Set-MpPreference -PUAProtection Enabled
  ```
- [ ] **Run quick scan**: `Start-MpScan -ScanType QuickScan`
- [ ] **Update definitions**: `Update-MpSignature`
- [ ] Verify: `Get-MpPreference` and `Get-MpComputerStatus`

---

## Phase 6 — Firewall Configuration

- [ ] **All profiles (Domain/Private/Public) enabled** `[SCRIPT]`
- [ ] **Default inbound**: Block `[SCRIPT]`
- [ ] **Default outbound**: Allow `[SCRIPT]`
- [ ] Verify: `Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction`
- [ ] Review firewall rules: `[MANUAL]`
  ```powershell
  Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Select DisplayName, Direction, Action
  ```
- [ ] Disable unnecessary inbound allow rules
- [ ] **Disable File and Printer Sharing** (unless required): `[SCRIPT]`
  ```powershell
  Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled False
  ```

---

## Phase 7 — Service Management

### 7.1 Disable Unnecessary Services
- [ ] **Remote Registry**: Disabled `[SCRIPT]`
- [ ] **Remote Desktop Services (TermService)**: Disabled (unless required) `[SCRIPT]`
- [ ] **SSDP Discovery**: Disabled `[SCRIPT]`
- [ ] **UPnP Device Host**: Disabled
- [ ] **Windows Search (WSearch)**: Disabled (optional) `[SCRIPT]`
- [ ] **Routing and Remote Access**: Disabled `[SCRIPT]`
- [ ] **Telnet**: Disabled `[SCRIPT]`
- [ ] **Print Spooler**: Disabled (unless printing required) `[SCRIPT]`
- [ ] **WebClient**: Disabled `[SCRIPT]`
- [ ] **WinRM**: Disabled `[SCRIPT]`
- [ ] **Fax**: Disabled `[SCRIPT]`
- [ ] **Xbox services**: Disabled
- [ ] **Secondary Logon**: Disabled
- [ ] **SNMP**: Disabled
- [ ] **IIS (W3SVC)**: Disabled `[SCRIPT]`
- [ ] **FTP (FTPSVC)**: Disabled `[SCRIPT]`

### 7.2 Verify Critical Services Running
- [ ] **Windows Update (wuauserv)**: Running, Automatic `[SCRIPT]`
- [ ] **Windows Defender (WinDefend)**: Running
- [ ] **Windows Firewall (mpssvc)**: Running
- [ ] **Event Log (EventLog)**: Running
- [ ] Any services required by README

### 7.3 Check All Services
```powershell
Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Running'} | Select Name, DisplayName
```

---

## Phase 8 — Windows Features & Roles

### 8.1 Disable Unnecessary Features
- [ ] **SMBv1**: Disabled `[SCRIPT]`
  ```powershell
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
  ```
- [ ] **Telnet Client**: Disabled
  ```powershell
  Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient -NoRestart
  ```
- [ ] **TFTP Client**: Disabled
- [ ] **Internet Explorer** (if present): Disabled
- [ ] **Windows Subsystem for Linux**: Disabled (unless required)
- [ ] Check installed features: `[MANUAL]`
  ```powershell
  Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'} | Select FeatureName
  ```

---

## Phase 9 — Network Protocol Hardening

- [ ] **Disable LLMNR** `[SCRIPT]`
  - Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` → `EnableMulticast = 0`
- [ ] **Disable NetBIOS over TCP/IP** `[SCRIPT]`
- [ ] **Disable WPAD** (Web Proxy Auto-Discovery) `[MANUAL]`
  ```powershell
  New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name WpadOverride -Value 1 -Type DWord -Force
  ```
- [ ] **Enable SMB signing** `[MANUAL]`
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -Value 1
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -Value 1
  ```
- [ ] **Disable NBT-NS** `[SCRIPT]`

---

## Phase 10 — Registry Hardening

### 10.1 AutoRun / AutoPlay
- [ ] **Disable AutoRun**: `NoDriveTypeAutoRun = 255` `[SCRIPT]`
- [ ] **Disable AutoPlay**: `NoAutoPlay = 1` `[SCRIPT]`

### 10.2 Remote Access
- [ ] **Disable Remote Assistance**: `fAllowToGetHelp = 0` `[SCRIPT]`
- [ ] **Disable Remote Desktop** (unless required):
  ```powershell
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
  ```

### 10.3 USB Storage
- [ ] **Disable USB storage**: `USBSTOR\Start = 4` `[SCRIPT]`

### 10.4 Windows Installer
- [ ] **Disable Windows Installer always elevated**:
  ```powershell
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -Value 0
  Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -Value 0
  ```

### 10.5 Screen Lock
- [ ] **Enable screen saver password**: `[MANUAL]`
  ```powershell
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveActive -Value 1
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -Value 1
  Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut -Value 600
  ```

---

## Phase 11 — Prohibited Software Removal

- [ ] **Adobe Flash Player**: Remove `[SCRIPT]`
- [ ] **Java** (old versions): Remove `[SCRIPT]`
- [ ] Check Programs and Features / Apps & Features `[MANUAL]`
- [ ] Search for unauthorized software:
  ```powershell
  Get-Package | Select Name, Version | Sort Name
  ```
- [ ] Look for:
  - Hacking tools (Wireshark, Nmap, Cain & Abel, Metasploit)
  - Remote access (TeamViewer, AnyDesk, VNC)
  - Games (Steam, Minecraft, etc.)
  - P2P / Torrent clients (BitTorrent, uTorrent, qBittorrent)
  - Media software not needed (VLC, iTunes unless required)
  - Old/vulnerable software (outdated browsers, Office versions)
- [ ] Check startup programs: `[MANUAL]`
  ```powershell
  Get-CimInstance Win32_StartupCommand | Select Name, Command, Location
  ```
- [ ] Check Task Manager > Startup tab for unauthorized startup items

---

## Phase 12 — Scheduled Task & Startup Audit

### 12.1 Scheduled Tasks
- [ ] Review all scheduled tasks: `[MANUAL]`
  ```powershell
  Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName, TaskPath, State
  ```
- [ ] Look for suspicious tasks (encoded commands, downloads, reverse shells)
- [ ] Check task actions:
  ```powershell
  Get-ScheduledTask | ForEach-Object { $task = $_; $_.Actions | Select @{N='Task';E={$task.TaskName}}, Execute, Arguments }
  ```
- [ ] Disable/remove malicious scheduled tasks

### 12.2 Startup Locations
- [ ] Check: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` `[MANUAL]`
- [ ] Check: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- [ ] Check: `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- [ ] Check: `HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- [ ] Check: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`
- [ ] Check: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
- [ ] Remove any suspicious entries

---

## Phase 13 — Backdoor & Malware Hunting

### 13.1 Suspicious Processes
- [ ] Open Task Manager or use: `Get-Process | Sort CPU -Descending` `[MANUAL]`
- [ ] Look for suspicious process names or high CPU/memory usage
- [ ] Check for netcat, reverse shells, or encoded PowerShell

### 13.2 Suspicious Network Connections
- [ ] Check connections: `netstat -ano` or `Get-NetTCPConnection` `[MANUAL]`
- [ ] Look for unexpected ESTABLISHED or LISTENING connections
- [ ] Trace suspicious PIDs: `Get-Process -Id <PID>`

### 13.3 Suspicious Files
- [ ] Check `C:\`, `C:\Windows\Temp\`, `C:\Users\Public\` for unauthorized files `[MANUAL]`
- [ ] Check each user's Desktop, Downloads, Documents
- [ ] Look for executables in unusual locations:
  ```powershell
  Get-ChildItem C:\Users\*\Desktop\*.exe, C:\Users\*\Downloads\*.exe -Recurse -ErrorAction SilentlyContinue
  ```
- [ ] Check hosts file for redirects: `type C:\Windows\System32\drivers\etc\hosts`

### 13.4 Windows Defender Scan
- [ ] Run full scan: `Start-MpScan -ScanType FullScan`
- [ ] Check quarantine: `Get-MpThreatDetection`

---

## Phase 14 — Windows Update

- [ ] **Enable Windows Update service**: `[SCRIPT]`
- [ ] **Set automatic updates**: `[SCRIPT]`
- [ ] **Check for updates**: Settings > Update & Security > Check for updates `[MANUAL]`
- [ ] **Install all available updates**
- [ ] Verify update settings:
  ```powershell
  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
  ```

---

## Phase 15 — Shares & Permissions

- [ ] List all shares: `Get-SmbShare` or `net share` `[MANUAL]`
- [ ] Remove unnecessary shares: `Remove-SmbShare -Name "<share>" -Force`
- [ ] Check share permissions: `Get-SmbShareAccess -Name "<share>"`
- [ ] Disable administrative shares if not needed:
  ```powershell
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name AutoShareWks -Value 0
  ```

---

## Phase 16 — Final Verification

- [ ] Re-check all user accounts match README `[MANUAL]`
- [ ] Re-check all services required by README are running
- [ ] Verify firewall is enabled on all profiles
- [ ] Verify Windows Defender is active
- [ ] Verify Windows Update is working
- [ ] Check scoring engine — verify points are being awarded
- [ ] **Do NOT reboot unless necessary**
- [ ] Take another VM snapshot

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| List users | `Get-LocalUser` |
| List groups | `Get-LocalGroup` |
| Group members | `Get-LocalGroupMember "Administrators"` |
| List services | `Get-Service \| Sort Status` |
| Running services | `Get-Service \| Where Status -eq Running` |
| Listening ports | `netstat -ano \| findstr LISTENING` |
| Firewall status | `Get-NetFirewallProfile` |
| Audit policy | `auditpol /get /category:*` |
| Installed software | `Get-Package \| Sort Name` |
| Scheduled tasks | `Get-ScheduledTask` |
| Startup items | `Get-CimInstance Win32_StartupCommand` |
| Windows features | `Get-WindowsOptionalFeature -Online \| Where State -eq Enabled` |
| Processes | `Get-Process \| Sort CPU -Desc` |
| Network connections | `Get-NetTCPConnection \| Where State -eq Listen` |
| Check Defender | `Get-MpComputerStatus` |
| Update Defender | `Update-MpSignature` |
| Run scan | `Start-MpScan -ScanType QuickScan` |
| Shares | `Get-SmbShare` |
| Password policy | `net accounts` |
| Security export | `secedit /export /cfg C:\temp\secpol.cfg` |
