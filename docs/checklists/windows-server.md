# Windows Server checklist (2016 / 2019 / 2022)

Windows Server 2022 is in **Round 2, the State round and the Semifinals** this season.

Most of the [Windows 10/11 checklist](windows-10-11.md) also applies to servers. This page covers **what's different** and the **server roles** (Active Directory, DNS, IIS, FTP, file shares) that make servers harder.

**How to use this page:** work top to bottom. When a step says "same as Windows 10/11", follow that section of the other checklist. The script `scripts/windows/Harden.ps1` detects servers and Domain Controllers automatically.

---

## 0. Before you touch anything

- [ ] **Read the README twice.** Servers usually have **critical services** (AD, DNS, IIS, FTP, file shares). Write every one down. See [Reading the README](../start-here/reading-the-readme.md).
- [ ] **Take a VMware snapshot.**
- [ ] **Open PowerShell as Administrator.**
- [ ] **Open the Scoring Report.**
- [ ] **Answer the forensics questions** ([guide](../guides/forensics-questions.md)).

---

## 1. Is this a Domain Controller?

### 1.1 Find out what kind of server it is
- [ ] Done

**Script:** 🔎 The script detects a Domain Controller by itself (it prints the Role at the top); still list the installed roles so you know what's there.

**Why it matters:** On a **Domain Controller** (DC), users and password rules live in **Active Directory** and **Group Policy**, not on the local computer. If you change the local settings on a DC, nothing happens.

**Clicking:** **Server Manager → Dashboard**. If **AD DS** appears in the left list, it's a Domain Controller. **Server Manager → Local Server** also shows **Domain:** if the computer is in a domain.

**Typing:**
```powershell
(Get-CimInstance Win32_OperatingSystem).ProductType    # 1 = workstation, 2 = DOMAIN CONTROLLER, 3 = server
Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName     # every installed role
```

| ProductType | Users are in | Password policy is in |
|---|---|---|
| **2 (Domain Controller)** | Active Directory Users and Computers (`dsa.msc`) | **Default Domain Policy** (Group Policy, `gpmc.msc`) |
| **3 (member or standalone server)** | Local Users and Groups (`lusrmgr.msc`) | Local Security Policy (`secpol.msc`) |

### 1.2 Fast path: run the hardening script
- [ ] Done

**What:** After the forensics questions are answered, run `Harden.ps1`: Audit mode first, then Apply mode. The commands are in [Windows 10/11 step 1.2](windows-10-11.md#12-fast-path-run-the-hardening-script). Put every critical service from the README into the config (keywords like `ad`, `dns`, `iis`, `ftp`, `smb`, `rdp`).

**Why it matters:** The script detects servers and Domain Controllers by itself. On a DC it works on the **domain** users, the Default Domain Policy and the DNS zones, and it **never** disables Active Directory, DNS, Netlogon, Kerberos or the other services in 6.2.

**Check it worked:** The top of the output says `Role: Domain Controller` or `Role: Server`. The Scoring Report went up. Every line in `C:\harden-toolkit\findings-*.txt` is a job for you.

Now skip every step marked **Script: ✅** below (on the website, press **Tick the script's ✅ steps** at the top of the page). Do the 🔎 and ✋ steps.

> [!WARNING]
> - Any `FAILED` line in the summary: do that step by hand.
> - If the score **drops**, undo the change from `C:\harden-toolkit\backups\` (see [Using the scripts](../start-here/using-the-scripts.md)).
> - The Windows script **hasn't been tested on a real Windows image yet**. Always run Audit first.

---

## 2. Users and groups

### 2.1 Standalone / member server
- [ ] Done

**Script:** 🔎 The script does part of Windows 10/11 section 2; follow the Script lines there for what's left.

Same as [Windows 10/11 section 2](windows-10-11.md#2-users-and-groups).

### 2.2 Domain Controller: domain users
- [ ] Done

**Script:** ✅ Done by the script (`users` section).

**Clicking:** **Win + R** → `dsa.msc` (**Active Directory Users and Computers**). Users are usually in the **Users** folder, but check **every OU** (folder). Turn on **View → Advanced Features** to see everything.
- Delete a user: right-click → **Delete**.
- Disable a user: right-click → **Disable Account**.
- New user: right-click the folder → **New → User**.

**Typing:**
```powershell
Get-ADUser -Filter * -Properties Enabled, LastLogonDate | Format-Table SamAccountName, Enabled, DistinguishedName -AutoSize
Remove-ADUser -Identity mallory
New-ADUser -Name erin -SamAccountName erin -AccountPassword (Read-Host -AsSecureString "Password") -Enabled $true
Disable-ADAccount -Identity Guest
```

> [!CAUTION]
> **Never delete or change these built-in accounts:** `Administrator` (unless the README says so), `krbtgt` (Active Directory breaks without it), and computer accounts (names ending in `$`). Disable `Guest`.

### 2.3 Domain Controller: powerful groups
- [ ] Done

**Script:** 🔎 The script removes users who aren't README admins from these groups and adds README admins to Domain Admins (asks first); check for nested groups and anyone the README puts there on purpose.

Check the members of each group. Remove anyone the README doesn't say should be an admin.

| Group | Can… |
|---|---|
| **Domain Admins** | Control every computer in the domain |
| **Enterprise Admins** | Control the whole forest |
| **Schema Admins** | Change the structure of AD |
| **Administrators** (Builtin folder) | Control the Domain Controllers |
| **Account Operators** | Create and change most users |
| **Backup Operators** | Read every file, log on to DCs |
| **Server Operators** | Log on to DCs, change services |
| **Print Operators** | Load drivers on DCs |
| **DnsAdmins** | Can make the DNS server run any program (easy path to domain admin) |
| **Group Policy Creator Owners** | Create Group Policies |

**Typing:**
```powershell
foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners') {
  "--- $g"; (Get-ADGroupMember $g -ErrorAction SilentlyContinue).SamAccountName }
Remove-ADGroupMember -Identity 'Domain Admins' -Members bob -Confirm:$false
Add-ADGroupMember -Identity 'Domain Admins' -Members alice
```

### 2.4 Domain Controller: risky account settings
- [ ] Done

**Script:** ✅ Done by the script (`users` section).

**Clicking:** in `dsa.msc`, double-click a user → **Account** tab → **Account options**. These should all be **unticked**:
- Password never expires
- Store password using reversible encryption
- Do not require Kerberos preauthentication (lets attackers crack the password offline)
- Password not required (not shown here; use PowerShell)

**Typing:**
```powershell
Get-ADUser -Filter 'Enabled -eq $true' -Properties PasswordNeverExpires, PasswordNotRequired, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth |
  Where-Object { $_.PasswordNeverExpires -or $_.PasswordNotRequired -or $_.AllowReversiblePasswordEncryption -or $_.DoesNotRequirePreAuth } |
  Format-Table SamAccountName, PasswordNeverExpires, PasswordNotRequired, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth
Set-ADUser bob -PasswordNeverExpires $false -PasswordNotRequired $false -AllowReversiblePasswordEncryption $false
Set-ADAccountControl bob -DoesNotRequirePreAuth $false
```

### 2.5 Strong passwords
- [ ] Done

**Script:** 🔎 The script resets every README user's password except yours only if you put NewPassword in the config or type one when asked; otherwise do it by hand.

```powershell
Set-ADAccountPassword -Identity bob -Reset -NewPassword (Read-Host -AsSecureString "New password")
```

---

## 3. Password and lockout policy

### 3.1 Standalone / member server
- [ ] Done

**Script:** 🔎 The script does Windows 10/11 3.1 and most of 3.2; set "Allow Administrator account lockout" yourself.

Same as [Windows 10/11 section 3](windows-10-11.md#3-account-policies-passwords-and-lockout).

### 3.2 Domain Controller: edit the Default Domain Policy
- [ ] Done

**Script:** ✅ Done by the script (`passwords` section).

**Clicking:**
1. **Win + R** → `gpmc.msc` (**Group Policy Management**).
2. Open **Forest → Domains → (your domain) → Group Policy Objects**.
3. Right-click **Default Domain Policy → Edit**.
4. Go to **Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies**.
5. Set **Password Policy** and **Account Lockout Policy** with the same values as [Windows 10/11 section 3](windows-10-11.md#3-account-policies-passwords-and-lockout) (history 24, max age 90, min age 1, length 12, complexity on, reversible off; lockout 5 / 30 / 30).
6. Close the editor and run `gpupdate /force`.

**Check it worked:**
```powershell
Get-ADDefaultDomainPasswordPolicy
net accounts /domain
```

> [!NOTE]
> `Get-ADFineGrainedPasswordPolicy -Filter *` lists **fine-grained password policies**. These override the domain policy for some users. A planted weak one is a sneaky problem.

---

## 4. Audit policy, user rights and security options

### 4.1 Standalone / member server
- [ ] Done

**Script:** 🔎 The script does Windows 10/11 4.1 and 4.3; still check User Rights Assignment (4.2) by hand.

Same as [Windows 10/11 section 4](windows-10-11.md#4-local-policies).

### 4.2 Domain Controller: Default Domain Controllers Policy
- [ ] Done

**Script:** 🔎 The script sets many of these on the DC's own registry and local policy but doesn't edit the Default Domain Controllers Policy; set them in gpmc.msc so Group Policy can't undo them.

On a DC, these come from the **Default Domain Controllers Policy** GPO. In `gpmc.msc`, right-click it → **Edit** → **Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies** (Audit Policy, User Rights Assignment, Security Options). Use the tables in the Windows 10/11 checklist, plus these DC settings:

| Security Option | Set to |
|---|---|
| Domain controller: LDAP server signing requirements | **Require signing** |
| Domain controller: Allow server operators to schedule tasks | **Disabled** |
| Domain controller: Refuse machine account password changes | **Disabled** |
| Domain member: Digitally encrypt or sign secure channel data (always) | **Enabled** |
| Network security: LDAP client signing requirements | **Negotiate signing** |

Detailed audit settings are under **Security Settings → Advanced Audit Policy Configuration**. Set the account logon, account management, logon/logoff, policy change, privilege use, DS access and system categories to **Success and Failure**.

### 4.3 Look for planted bad Group Policies
- [ ] Done

**Script:** 🔎 On a DC the script lists every GPO, newest first; open each one and look for planted settings.

**Why:** An attacker can create or change a GPO to turn off the firewall, add an admin, or run a script on every computer.

**Clicking:** In `gpmc.msc`, click each GPO → **Settings** tab (it shows a report). Look for anything that weakens security. Check the **Scope** tab to see where it's linked.

**Typing:**
```powershell
Get-GPO -All | Sort-Object ModificationTime -Descending | Format-Table DisplayName, ModificationTime
Get-GPOReport -All -ReportType Html -Path C:\gpo-report.html; Start-Process C:\gpo-report.html
```

---

## 5. Defender, firewall and updates

### 5.1 Microsoft Defender
- [ ] Done

**Script:** 🔎 The script does part of Windows 10/11 section 5 and offers to install Defender if it's missing; turn on Tamper Protection and run a scan yourself.

Same as [Windows 10/11 section 5](windows-10-11.md#5-microsoft-defender-antivirus). If Defender isn't installed: **Server Manager → Add Roles and Features → Features → Microsoft Defender Antivirus**.

### 5.2 Firewall
- [ ] Done

**Script:** 🔎 The script turns the firewall on for every profile and never disables the built-in DC rule groups; still review the custom inbound rules (Windows 10/11 6.2).

Same as [Windows 10/11 section 6](windows-10-11.md#6-firewall).

> [!CAUTION]
> On a Domain Controller, **don't disable** the built-in rule groups **Active Directory Domain Services**, **DNS Service**, **Kerberos Key Distribution Center**, **Netlogon Service** or **DFS Replication**. Clients need them.

### 5.3 Windows Update
- [ ] Done

**Script:** 🔎 The script installs updates only if InstallUpdates is 'yes' (or you answer yes); otherwise install them here by hand.

**Server Manager → Local Server → Windows Update** (or **Settings → Update & Security**). On Server Core: run `sconfig` and choose **Install updates**.

### 5.4 IE Enhanced Security Configuration
- [ ] Done

**Script:** ✋ Not done by the script. Do this by hand.

**Server Manager → Local Server → IE Enhanced Security Configuration** must be **On** for Administrators and Users.

---

## 6. Services

### 6.1 Turn off what the README doesn't need
- [ ] Done

**Script:** 🔎 The script disables the risky services the README doesn't list (asks first; WinRM and Remote Desktop default to No); decide those yourself.

Same list as [Windows 10/11 section 8](windows-10-11.md#8-services), plus:
- **Print Spooler**: disable on Domain Controllers unless this is the print server (PrintNightmare).
- **Windows Remote Management (WinRM)**: Server Manager uses it, so keep it on servers unless the README says otherwise, and lock it down (section 8).

### 6.2 Never touch these on a Domain Controller
- [ ] Done

**Script:** 🔎 The script never changes these services on a Domain Controller, but doesn't check they're running; run the check command.

| Service | Name |
|---|---|
| Active Directory Domain Services | `NTDS` |
| DNS Server | `DNS` |
| Kerberos Key Distribution Center | `Kdc` |
| Netlogon | `Netlogon` |
| DFS Replication | `DFSR` |
| Windows Time | `W32Time` |
| Active Directory Web Services | `ADWS` |
| Intersite Messaging | `IsmServ` |

```powershell
Get-Service NTDS, DNS, Kdc, Netlogon, DFSR, W32Time, ADWS | Format-Table Name, Status, StartType
```
All should be **Running** and **Automatic**.

---

## 7. Roles and features

### 7.1 Remove roles and features that aren't needed
- [ ] Done

**Script:** 🔎 The script removes SMBv1, Telnet, TFTP, PowerShell 2.0, SNMP and Simple TCP/IP (asks first) and asks about IIS with default No; decide other roles yourself.

**Clicking:** **Server Manager → Manage → Remove Roles and Features**. Untick unneeded **features**: Telnet Client, TFTP Client, SMB 1.0/CIFS File Sharing Support, Windows PowerShell 2.0 Engine, SNMP Service, Simple TCP/IP Services. Remove **roles** only if the README clearly doesn't need them (e.g. Web Server (IIS) on a plain DC).

**Typing:**
```powershell
Get-WindowsFeature | Where-Object Installed | Format-Table Name, DisplayName
Uninstall-WindowsFeature -Name Telnet-Client, TFTP-Client, FS-SMB1, PowerShell-V2
```

> [!CAUTION]
> **Never** remove **AD DS**, **DNS Server**, or any role the README mentions.

---

## 8. Remote access

### 8.1 Remote Desktop and Remote Assistance
- [ ] Done

**Script:** 🔎 The script does part of Windows 10/11 section 10 (Remote Assistance off, RDP off or NLA on); still check who is in Remote Desktop Users.

Same as [Windows 10/11 section 10](windows-10-11.md#10-remote-access). Servers often **need** RDP; if so, keep it on with Network Level Authentication, and control who's in **Remote Desktop Users**.

### 8.2 Lock down WinRM
- [ ] Done

**Script:** 🔎 The script sets the WinRM policies (no Basic authentication, no unencrypted traffic); run the winrm command to confirm.

```powershell
winrm get winrm/config/service       # AllowUnencrypted = false, Basic = false
```
Or with `gpedit.msc` → **Administrative Templates → Windows Components → Windows Remote Management (WinRM) → WinRM Service**: **Allow Basic authentication: Disabled**, **Allow unencrypted traffic: Disabled**.

---

## 9. Critical server roles (only if the README lists them)

### 9.1 IIS web server
- [ ] Done

**Script:** 🔎 If your config lists iis, the script turns off directory browsing, hides version headers, turns on logging and fixes LocalSystem app pools; you still check authentication, request filtering and web shells.

**Clicking:** **Win + R** → `inetmgr` (IIS Manager). For the server **and each site**:
- **Directory Browsing** → **Disable** (Actions pane).
- **HTTP Response Headers** → remove **X-Powered-By**.
- **Request Filtering** → check nothing dangerous is allowed. **Edit Feature Settings** → untick **Allow unlisted file name extensions** only if the site still works afterwards.
- **Logging** → enabled.
- **Authentication** → **Basic Authentication** disabled unless the site uses HTTPS and needs it. **Anonymous Authentication** only if the site is public.
- **Application Pools** → **Advanced Settings → Identity**: should be **ApplicationPoolIdentity**, not **LocalSystem**.
- Look in the site folder (`C:\inetpub\wwwroot` or wherever **Basic Settings** points) for web shells: `.aspx`, `.asp` or `.php` files you don't recognise, e.g. `cmd.aspx` or `shell.aspx`.

```powershell
Import-Module WebAdministration
Get-Website | Format-Table Name, State, PhysicalPath
Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter system.webServer/directoryBrowse -Name enabled -Value $false
Get-ChildItem C:\inetpub -Recurse -Include *.aspx,*.asp,*.php | Select-String -Pattern 'cmd.exe|Process.Start|eval\(|exec\(' | Select-Object Path -Unique
```

### 9.2 IIS FTP server
- [ ] Done

**Script:** 🔎 If your config lists ftp, the script turns off anonymous FTP (asks first) and warns if SSL isn't required; you still do authorization rules, user isolation and logging.

In `inetmgr`, click the FTP site:
- **FTP Authentication** → **Anonymous Authentication: Disabled** (unless the README needs anonymous FTP).
- **FTP Authorization Rules** → no "Allow All Users / Anonymous Read, Write" unless needed.
- **FTP SSL Settings** → **Require SSL connections** (only if a certificate is selected).
- **FTP User Isolation** → isolate users (so they can't see each other's files).
- **FTP Logging** → enabled.

### 9.3 DNS server
- [ ] Done

**Script:** 🔎 The script blocks zone transfers (asks first) and sets secure-only updates on AD-integrated zones; you still check the records and non-AD zones.

**Clicking:** **Win + R** → `dnsmgmt.msc`. For each **Forward Lookup Zone**, right-click → **Properties**:
- **General → Dynamic updates:** **Secure only** (for AD-integrated zones).
- **Zone Transfers:** untick **Allow zone transfers**, or choose **Only to the following servers** if the README mentions a secondary DNS server.

Look through the records for anything suspicious, e.g. a record for `update.microsoft.com` or `www.bank.com` pointing to a strange IP.

**Typing:**
```powershell
Get-DnsServerZone | Format-Table ZoneName, ZoneType, DynamicUpdate, SecureSecondaries, IsDsIntegrated
Set-DnsServerPrimaryZone -Name corp.local -SecureSecondaries NoTransfer -DynamicUpdate Secure
Get-DnsServerResourceRecord -ZoneName corp.local | Format-Table HostName, RecordType, RecordData
```

### 9.4 Active Directory
- [ ] Done

**Script:** 🔎 The script offers to turn on the AD Recycle Bin and lists unconstrained delegation; you still do Protected Users, SYSVOL scripts and the machine account quota.

- **AD Recycle Bin:** **Active Directory Administrative Center (`dsac.exe`)** → click the domain → **Enable Recycle Bin…** (it can't be turned off later, which is fine).
- **Protected Users group:** admins in it get extra protection. Add only if the README doesn't forbid it.
- **Logon scripts in SYSVOL:** look in `C:\Windows\SYSVOL\domain\scripts` and `C:\Windows\SYSVOL\domain\Policies\*\Machine\Scripts` / `User\Scripts` for scripts you don't recognise.
- **Unconstrained delegation:** `Get-ADComputer -Filter 'TrustedForDelegation -eq $true'`. Only DCs should be listed.
- **Who can add computers:** `Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota`. Setting it to 0 stops normal users joining computers (optional).

### 9.5 DHCP server
- [ ] Done

**Script:** ✋ Not done by the script. Do this by hand.

`dhcpmgmt.msc`: check the scopes and reservations against the README, and make sure **Enable DHCP audit logging** is ticked (server → **Properties**).

### 9.6 File server shares
- [ ] Done

**Script:** 🔎 If your config lists smb, the script removes Everyone's write access from shares (asks first); you still check the other share and NTFS permissions.

**Clicking:** `fsmgmt.msc` → **Shares**. For each share the README needs: **Properties → Share Permissions** shouldn't give **Everyone: Full Control**, and on the **Security** tab (NTFS), only the right groups should have **Modify / Full control**.

```powershell
Get-SmbShare | ForEach-Object { "--- $($_.Name) $($_.Path)"; Get-SmbShareAccess $_.Name | Format-Table AccountName, AccessRight }
Revoke-SmbShareAccess -Name Data -AccountName Everyone -Force
```
On a Domain Controller, leave **NETLOGON** and **SYSVOL** alone.

---

## 10. The rest

Use the [Windows 10/11 checklist](windows-10-11.md) for:
- [ ] Prohibited software (section 12)
- [ ] Prohibited files (section 13)
- [ ] Backdoors and malware (section 14)
- [ ] Other settings (section 15)
- [ ] Browsers (section 16)

---

## 11. Final checks

- [ ] Every critical role still works (e.g. `nslookup <domain>` for DNS, open the website for IIS)
- [ ] On a DC: `dcdiag /q` prints no errors (no output = good)
- [ ] Scoring Report shows **no penalties**
- [ ] Forensics answers saved
- [ ] Final snapshot
