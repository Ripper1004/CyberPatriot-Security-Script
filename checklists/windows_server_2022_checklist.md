# Windows Server 2022 CyberPatriot Competition Checklist

> **Usage**: Work through each section in order. Items marked `[SCRIPT]` are handled by `Windows_Server_22.ps1`. Items marked `[MANUAL]` require human judgment. Always run PowerShell as Administrator.

---

## Phase 0 — Read the README / Scenario

- [ ] **Read the competition README completely** before touching anything `[MANUAL]`
- [ ] Note authorized users, their roles (Domain Admin, standard user, etc.)
- [ ] Note required services (AD DS, DNS, DHCP, IIS, File Server, etc.)
- [ ] Note any specific configurations required
- [ ] Identify forensic questions
- [ ] **Take a VM snapshot / checkpoint**

---

## Phase 1 — Forensic Questions

- [ ] Read each forensic question carefully `[MANUAL]`
- [ ] Check common locations:
  - User Desktops and Documents
  - Event Viewer (Security, Application, System, DNS Server)
  - `C:\Windows\Temp\`, `C:\Users\Public\`
  - IIS logs: `C:\inetpub\logs\LogFiles\`
  - DNS logs, DHCP logs
  - PowerShell history
  - Active Directory logs (if AD DS role installed)
- [ ] Submit forensic answers as you find them

---

## Phase 2 — User & Group Management

### 2.1 Local Users (Standalone Server)
- [ ] List all local users: `Get-LocalUser` `[MANUAL]`
- [ ] Remove unauthorized users: `Remove-LocalUser -Name "<user>"`
- [ ] Disable Guest account `[SCRIPT]`
- [ ] Review Administrator account — consider disabling if alternate admin exists `[SCRIPT]`
- [ ] Set strong passwords for all accounts

### 2.2 Active Directory Users (if AD DS role)
- [ ] List all AD users: `Get-ADUser -Filter * | Select Name, Enabled, LastLogonDate` `[MANUAL]`
- [ ] Disable unauthorized accounts: `Disable-ADAccount -Identity "<user>"`
- [ ] Remove unauthorized accounts: `Remove-ADUser -Identity "<user>"`
- [ ] Check for stale accounts (no recent logon)
- [ ] Force password change: `Set-ADUser -Identity "<user>" -ChangePasswordAtLogon $true`

### 2.3 Group Membership
- [ ] Check Administrators: `Get-LocalGroupMember "Administrators"` `[MANUAL]`
- [ ] Check Domain Admins (AD): `Get-ADGroupMember "Domain Admins"`
- [ ] Check Enterprise Admins (AD): `Get-ADGroupMember "Enterprise Admins"`
- [ ] Check Schema Admins (AD): `Get-ADGroupMember "Schema Admins"`
- [ ] Check Remote Desktop Users: `Get-LocalGroupMember "Remote Desktop Users"`
- [ ] Check Server Operators, Backup Operators, Account Operators
- [ ] Remove unauthorized members from privileged groups

---

## Phase 3 — Password & Account Policies

### 3.1 Password Policy
- [ ] **Minimum password length**: 14 characters `[SCRIPT]`
- [ ] **Maximum password age**: 30 days `[SCRIPT]`
- [ ] **Minimum password age**: 1 day `[SCRIPT]`
- [ ] **Password history**: 24 unique passwords `[SCRIPT]`
- [ ] **Password complexity**: Enabled `[SCRIPT]`
- [ ] **Reversible encryption**: Disabled

### 3.2 Account Lockout Policy
- [ ] **Lockout threshold**: 5 attempts `[SCRIPT]`
- [ ] **Lockout duration**: 30 minutes `[SCRIPT]`
- [ ] **Reset counter**: 30 minutes `[SCRIPT]`

### 3.3 AD Group Policy (if AD DS)
- [ ] Open **Group Policy Management** `[MANUAL]`
- [ ] Edit Default Domain Policy > Computer Configuration > Policies > Windows Settings > Security Settings
- [ ] Verify password and lockout policies are set at the domain level
- [ ] Create/link GPOs as needed for organizational units

### 3.4 User Rights Assignment (secpol.msc or GPO)
- [ ] **Access this computer from the network**: Administrators, Authenticated Users only `[MANUAL]`
- [ ] **Allow log on locally**: Authorized users only
- [ ] **Deny log on as a batch job**: Guests
- [ ] **Deny log on through Remote Desktop**: Guests
- [ ] **Shut down the system**: Administrators only
- [ ] **Debug programs**: Administrators only (or remove all)

---

## Phase 4 — Audit Policy Configuration

- [ ] Enable **all** audit categories for success and failure `[SCRIPT]`
  ```powershell
  auditpol /set /category:* /success:enable /failure:enable
  ```
- [ ] Verify: `auditpol /get /category:*`

### 4.1 Event Log Configuration
- [ ] Application log: 32+ MB `[SCRIPT]`
- [ ] Security log: 80+ MB `[SCRIPT]`
- [ ] System log: 32+ MB `[SCRIPT]`
- [ ] DNS Server log (if applicable): 32+ MB
- [ ] Set retention to "Overwrite events as needed"

### 4.2 Advanced Logging
- [ ] Enable process creation auditing:
  ```powershell
  reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
  ```
- [ ] Enable PowerShell logging:
  ```powershell
  reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
  reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
  ```

---

## Phase 5 — Windows Defender

- [ ] **Real-time monitoring**: Enabled `[SCRIPT]`
- [ ] **IOAV protection**: Enabled `[SCRIPT]`
- [ ] **Behavior monitoring**: Enabled `[SCRIPT]`
- [ ] **Intrusion prevention**: Enabled `[SCRIPT]`
- [ ] **Script scanning**: Enabled `[SCRIPT]`
- [ ] **Sample submission**: Configured `[SCRIPT]`
- [ ] **PUA protection**: Enabled
  ```powershell
  Set-MpPreference -PUAProtection Enabled
  ```
- [ ] **Update definitions**: `Update-MpSignature`
- [ ] **Run quick scan**: `Start-MpScan -ScanType QuickScan`

---

## Phase 6 — Firewall Configuration

- [ ] **All profiles enabled** `[SCRIPT]`
- [ ] **Default inbound**: Block `[SCRIPT]`
- [ ] **Default outbound**: Allow `[SCRIPT]`
- [ ] **Logging enabled** `[SCRIPT]`
- [ ] Review and disable unnecessary inbound rules `[MANUAL]`
- [ ] Ensure required services have allow rules (DNS:53, DHCP:67/68, LDAP:389, Kerberos:88, etc.)
- [ ] Verify:
  ```powershell
  Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction
  Get-NetFirewallRule | Where {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} | Select DisplayName, Action
  ```

---

## Phase 7 — Service Management

### 7.1 Disable Unnecessary Services
- [ ] **Xbox services** (XblAuthManager, XblGameSave, XboxGipSvc, XboxNetApiSvc) `[SCRIPT]`
- [ ] **Remote Registry** `[SCRIPT]`
- [ ] **Telemetry** `[SCRIPT]`
- [ ] **Print Spooler** (unless print server role)
- [ ] **Fax Service**
- [ ] **SNMP** (unless required for monitoring)
- [ ] **Windows Search** (usually not needed on servers)
- [ ] **WebClient**
- [ ] **Secondary Logon**
- [ ] **UPnP Device Host**
- [ ] **SSDP Discovery**
- [ ] All legacy protocol services `[SCRIPT]`

### 7.2 Verify Required Services
- [ ] If **AD DS**: `NTDS`, `kdc`, `DNS`, `Netlogon`, `DFSR` `[MANUAL]`
- [ ] If **DNS**: `DNS` service
- [ ] If **DHCP**: `DHCPServer` service
- [ ] If **IIS**: `W3SVC` service (harden separately)
- [ ] If **File Server**: `LanmanServer` (with SMB hardening)
- [ ] **Windows Update**: wuauserv running
- [ ] **Windows Defender**: WinDefend running
- [ ] **Windows Firewall**: mpssvc running
- [ ] **Event Log**: EventLog running

---

## Phase 8 — Registry Hardening

### 8.1 Remote Access
- [ ] **Disable Remote Desktop** (unless required) `[SCRIPT]`
  ```
  HKLM:\System\CurrentControlSet\Control\Terminal Server → fDenyTSConnections = 1
  ```
- [ ] **Disable Remote Assistance**
  ```
  HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance → fAllowToGetHelp = 0
  ```

### 8.2 Network Protocols
- [ ] **Enable SMB signing** (server and client) `[SCRIPT]`
  ```
  HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters → RequireSecuritySignature = 1
  HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters → RequireSecuritySignature = 1
  ```
- [ ] **Disable LLMNR** `[SCRIPT]`
- [ ] **Disable NetBIOS** `[SCRIPT]`
- [ ] **Disable SMBv1** `[SCRIPT]`
- [ ] **Disable WPAD**

### 8.3 Security Settings
- [ ] **Enable LSA protection (RunAsPPL)** `[MANUAL]`
  ```powershell
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
  ```
- [ ] **Disable LM hash storage**:
  ```powershell
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
  ```
- [ ] **Set LAN Manager authentication level to NTLMv2 only**:
  ```powershell
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f
  ```
- [ ] **Disable anonymous SID/Name translation**
- [ ] **Restrict anonymous access to named pipes and shares**

### 8.4 AutoRun / USB
- [ ] **Disable AutoRun for all drives**: `NoDriveTypeAutoRun = 255`
- [ ] **Disable AutoPlay**: `NoAutoPlay = 1`
- [ ] **Disable USB storage** (if not needed):
  ```
  HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR → Start = 4
  ```

---

## Phase 9 — Windows Features & Roles

### 9.1 Remove Unnecessary Features
- [ ] **Internet Explorer**: Remove `[SCRIPT]`
- [ ] **Telnet Client**: Remove `[SCRIPT]`
- [ ] **TFTP Client**: Remove `[SCRIPT]`
- [ ] **SMB 1.0/CIFS**: Remove `[SCRIPT]`
- [ ] **SimpleTCP**: Remove `[SCRIPT]`
- [ ] **PowerShell 2.0**: Remove (prevents downgrade attacks)
  ```powershell
  Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
  ```
- [ ] List installed features: `[MANUAL]`
  ```powershell
  Get-WindowsFeature | Where-Object {$_.Installed -eq $true} | Select Name, DisplayName
  ```

### 9.2 Role-Specific Hardening

#### Active Directory Domain Services
- [ ] Ensure SYSVOL and NETLOGON shares have correct permissions `[MANUAL]`
- [ ] Check for unauthorized GPOs: `Get-GPO -All | Select DisplayName, ModificationTime`
- [ ] Review OU structure and delegation
- [ ] Check Protected Users group membership for privileged accounts
- [ ] Enable AD Recycle Bin if not enabled
- [ ] Verify LDAP signing: `reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f`

#### DNS Server
- [ ] Restrict zone transfers: only to authorized servers `[MANUAL]`
- [ ] Disable recursion if not needed (or restrict to internal)
- [ ] Secure dynamic updates: "Secure only"
- [ ] Review DNS zones for suspicious records
- [ ] Enable DNS logging

#### DHCP Server
- [ ] Verify scope settings are correct `[MANUAL]`
- [ ] Check reservations for unauthorized entries
- [ ] Enable DHCP audit logging
- [ ] Verify authorized DHCP servers in AD

#### IIS Web Server
- [ ] Remove default website if not needed `[MANUAL]`
- [ ] Disable directory browsing
- [ ] Remove unnecessary IIS modules
- [ ] Configure request filtering
- [ ] Set custom error pages (don't expose stack traces)
- [ ] Disable WebDAV if not needed
- [ ] Run application pools with least privilege
- [ ] Enable HTTPS and configure TLS properly

---

## Phase 10 — BitLocker & Encryption

- [ ] **Enable BitLocker on OS drive** `[SCRIPT]`
- [ ] Use AES-256 encryption `[SCRIPT]`
- [ ] Store recovery key securely
- [ ] Verify: `Get-BitLockerVolume`

---

## Phase 11 — Windows Update

- [ ] **Enable automatic updates** `[SCRIPT]`
- [ ] **Schedule install time**: 03:00 `[SCRIPT]`
- [ ] Check for and install available updates `[MANUAL]`
- [ ] Verify WSUS settings if applicable

---

## Phase 12 — Scheduled Task & Startup Audit

- [ ] Review all scheduled tasks: `[MANUAL]`
  ```powershell
  Get-ScheduledTask | Where {$_.State -ne 'Disabled'} | Select TaskName, TaskPath
  ```
- [ ] Check task actions for malicious commands
- [ ] Review startup registry keys:
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- [ ] Check services for unusual executable paths:
  ```powershell
  Get-WmiObject Win32_Service | Select Name, PathName, StartMode | Where {$_.PathName -notmatch "System32|SysWOW64"}
  ```

---

## Phase 13 — Backdoor & Malware Hunting

- [ ] Check running processes: `Get-Process | Sort CPU -Desc` `[MANUAL]`
- [ ] Check network connections: `Get-NetTCPConnection | Where State -eq Listen`
- [ ] Check hosts file: `type C:\Windows\System32\drivers\etc\hosts`
- [ ] Check for unauthorized shares: `Get-SmbShare`
- [ ] Look for files in unusual locations (`C:\`, `C:\Windows\Temp\`)
- [ ] Check services with unusual binaries (outside System32)
- [ ] Run Windows Defender full scan
- [ ] Check for encoded PowerShell in tasks/startup

---

## Phase 14 — Shares & File Permissions

- [ ] List all SMB shares: `Get-SmbShare` `[MANUAL]`
- [ ] Review share permissions: `Get-SmbShareAccess -Name "<share>"`
- [ ] Remove unnecessary shares
- [ ] Verify NTFS permissions on sensitive directories
- [ ] Disable administrative shares if not needed
- [ ] File system permissions reset (carefully) `[SCRIPT]`

---

## Phase 15 — Group Policy (AD Environments)

- [ ] Review all GPOs: `Get-GPO -All` `[MANUAL]`
- [ ] Check Default Domain Policy for correct security settings
- [ ] Create hardening GPO if needed with:
  - Password policy
  - Account lockout policy
  - Audit policy
  - User rights assignment
  - Security options
  - Windows Firewall rules
- [ ] Run `gpupdate /force` after changes
- [ ] Verify: `gpresult /r`

---

## Phase 16 — Final Verification

- [ ] All user accounts match README `[MANUAL]`
- [ ] All required services/roles are running
- [ ] Firewall enabled on all profiles
- [ ] Windows Defender active and updated
- [ ] Windows Update configured
- [ ] Audit policies enabled
- [ ] Check scoring engine for points
- [ ] **Be careful with restarts** — may require restart for some changes
- [ ] Take another VM snapshot

---

## Quick Reference Commands

| Task | Command |
|------|---------|
| List local users | `Get-LocalUser` |
| List AD users | `Get-ADUser -Filter *` |
| Group members | `Get-LocalGroupMember "Administrators"` |
| AD group members | `Get-ADGroupMember "Domain Admins"` |
| List services | `Get-Service \| Sort Status` |
| Server roles | `Get-WindowsFeature \| Where Installed` |
| Listening ports | `Get-NetTCPConnection \| Where State -eq Listen` |
| Firewall status | `Get-NetFirewallProfile` |
| Audit policy | `auditpol /get /category:*` |
| Scheduled tasks | `Get-ScheduledTask` |
| GPO list | `Get-GPO -All` |
| Shares | `Get-SmbShare` |
| BitLocker status | `Get-BitLockerVolume` |
| Defender status | `Get-MpComputerStatus` |
| Password policy | `net accounts` |
| DNS zones | `Get-DnsServerZone` |
| DHCP scopes | `Get-DhcpServerv4Scope` |
| Event logs | `Get-EventLog -LogName Security -Newest 50` |
