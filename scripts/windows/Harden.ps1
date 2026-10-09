<#
.SYNOPSIS
    CyberPatriot Toolkit - Windows hardening script.
    Works on Windows 10, Windows 11, and Windows Server 2016 / 2019 / 2022
    (including Domain Controllers).

.DESCRIPTION
    READ FIRST: docs/start-here/using-the-scripts.md

    The golden rule: THE README DECIDES WHAT IS SAFE. The script asks for the
    authorized users, administrators and critical services from the README
    before it changes anything, and never removes or disables something you list.

    - Audit mode reports problems and changes NOTHING.
    - Apply mode fixes problems and asks before risky steps.
    - Every registry key and policy is backed up before it is changed.
    - Everything is logged to C:\harden-toolkit\

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Harden.ps1
    Interactive menu (starts in Audit mode).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Audit -Config .\my-readme.psd1
    Report only, using README info from a config file.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Apply -Config .\my-readme.psd1 -Yes
    Fix everything without asking.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Harden.ps1 -Mode Apply -Only users,passwords,firewall
    Run only some sections (see -List).
#>
[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Apply')]
    [string]$Mode,
    [switch]$Yes,
    [string]$Config,
    [string[]]$Only,
    [switch]$List
)

$ScriptVersion = '2.0.0'
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Sections: id, title, function
# ---------------------------------------------------------------------------
$Sections = @(
    @{ Id = 'users';     Title = 'Users and groups';                                   Fn = 'Invoke-Users' }
    @{ Id = 'passwords'; Title = 'Password and lockout policy';                        Fn = 'Invoke-Passwords' }
    @{ Id = 'security';  Title = 'Security options (UAC, logon screen, network logons)'; Fn = 'Invoke-SecurityOptions' }
    @{ Id = 'rights';    Title = 'User rights assignment';                             Fn = 'Invoke-UserRights' }
    @{ Id = 'audit';     Title = 'Audit policy and event logs';                        Fn = 'Invoke-AuditPolicy' }
    @{ Id = 'defender';  Title = 'Microsoft Defender antivirus';                       Fn = 'Invoke-Defender' }
    @{ Id = 'firewall';  Title = 'Windows Firewall';                                   Fn = 'Invoke-Firewall' }
    @{ Id = 'services';  Title = 'Services';                                           Fn = 'Invoke-Services' }
    @{ Id = 'features';  Title = 'Windows features (SMBv1, Telnet, PowerShell 2...)';  Fn = 'Invoke-Features' }
    @{ Id = 'remote';    Title = 'Remote access (Remote Desktop, Remote Assistance, WinRM)'; Fn = 'Invoke-RemoteAccess' }
    @{ Id = 'shares';    Title = 'File shares';                                        Fn = 'Invoke-Shares' }
    @{ Id = 'software';  Title = 'Prohibited software';                                Fn = 'Invoke-Software' }
    @{ Id = 'files';     Title = 'Prohibited files (media etc.)';                      Fn = 'Invoke-Files' }
    @{ Id = 'backdoors'; Title = 'Backdoors and persistence';                          Fn = 'Invoke-Backdoors' }
    @{ Id = 'misc';      Title = 'Other hardening (AutoPlay, SmartScreen, LLMNR, screen lock...)'; Fn = 'Invoke-Misc' }
    @{ Id = 'browsers';  Title = 'Web browser security (Edge, Chrome, Firefox)';       Fn = 'Invoke-Browsers' }
    @{ Id = 'roles';     Title = 'Critical server roles (IIS, FTP, DNS, Active Directory)'; Fn = 'Invoke-Roles' }
    @{ Id = 'updates';   Title = 'Windows Update';                                     Fn = 'Invoke-Updates' }
)

if ($List) {
    foreach ($s in $Sections) { Write-Host ('  {0,-10} {1}' -f $s.Id, $s.Title) }
    return
}

# ---------------------------------------------------------------------------
# Must run as Administrator
# ---------------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script must run as Administrator. Opening an elevated window...' -ForegroundColor Yellow
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
    if ($Mode)   { $relaunch += @('-Mode', $Mode) }
    if ($Yes)    { $relaunch += '-Yes' }
    if ($Config) { $relaunch += @('-Config', "`"$((Resolve-Path $Config).Path)`"") }
    if ($Only)   { $relaunch += @('-Only', ($Only -join ',')) }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $relaunch
    return
}

# ---------------------------------------------------------------------------
# Settings (from the config file or the prompts)
# ---------------------------------------------------------------------------
$script:AuthAdmins   = @()
$script:AuthUsers    = @()
$script:Critical     = @()
$script:NewPassword  = ''
$script:EnableLockout = 'yes'
$script:InstallUpdates = 'ask'
$script:Mode = $Mode
$script:AssumeYes = [bool]$Yes
$script:ApplyConfirmed = $false

$RunId     = Get-Date -Format 'yyyyMMdd-HHmmss'
$WorkDir   = Join-Path $env:SystemDrive 'harden-toolkit'
$BackupDir = Join-Path $WorkDir "backups\$RunId"
$LogFile   = Join-Path $WorkDir "harden-$RunId.log"
$ReportFile = Join-Path $WorkDir "findings-$RunId.txt"
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

$script:Results = New-Object System.Collections.Generic.List[object]
$script:CurrentSection = 'setup'
$script:BackedUpKeys = @{}
$script:Me = $env:USERNAME

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-HardenLog([string]$Text) {
    Add-Content -Path $LogFile -Value ('{0} {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text) -ErrorAction SilentlyContinue
}
function Write-Info([string]$Text) { Write-Host "  * $Text" -ForegroundColor Cyan; Write-HardenLog "INFO   $Text" }
function Write-Why([string]$Text)  { Write-Host "      why: $Text" -ForegroundColor DarkGray; Write-HardenLog "WHY    $Text" }
function Write-Warn([string]$Text) { Write-Host "  ! $Text" -ForegroundColor Yellow; Write-HardenLog "WARN   $Text" }
function Write-Header([string]$Text) {
    Write-Host ''
    Write-Host "== $Text ==" -ForegroundColor Cyan
    Write-HardenLog "===== $Text ====="
}

# Results: OK (already secure), CHANGED (fixed), WOULD (audit: would fix),
#          SKIPPED (not done), FAILED (see log), REVIEW (a human must check)
function Add-Result([string]$Status, [string]$Text) {
    $script:Results.Add([pscustomobject]@{ Status = $Status; Section = $script:CurrentSection; Text = $Text })
    $color = switch ($Status) { 'OK' { 'Green' } 'CHANGED' { 'Green' } 'WOULD' { 'Cyan' } 'SKIPPED' { 'DarkGray' } 'FAILED' { 'Red' } 'REVIEW' { 'Yellow' } default { 'White' } }
    Write-Host ('  [{0,-7}] {1}' -f $Status, $Text) -ForegroundColor $color
    Write-HardenLog "$Status $Text"
    if ($Status -in @('REVIEW', 'FAILED', 'WOULD')) {
        Add-Content -Path $ReportFile -Value ('- [ ] {0,-7} ({1}) {2}' -f $Status, $script:CurrentSection, $Text)
    }
}
function Add-ReportDetail([string[]]$Lines) {
    foreach ($l in $Lines) { Add-Content -Path $ReportFile -Value "        $l" }
}
function Show-List([object[]]$Items, [int]$Max = 15) {
    $items = @($Items)
    $i = 0
    foreach ($item in $items) {
        $i++
        if ($i -le $Max) { Write-Host "          $item" -ForegroundColor DarkGray }
    }
    if ($items.Count -gt $Max) { Write-Host ("          ... and {0} more (full list in {1})" -f ($items.Count - $Max), $ReportFile) -ForegroundColor DarkGray }
    Add-ReportDetail ($items | ForEach-Object { "$_" })
}

# ---------------------------------------------------------------------------
# Prompts
#   Audit mode -> always "no". -Yes -> "yes" (unless strict: then the default).
# ---------------------------------------------------------------------------
function Confirm-Step([string]$Question, [string]$Default = 'n', [switch]$Strict) {
    if ($script:Mode -eq 'Audit') { return $false }
    if ($script:AssumeYes) { if ($Strict) { return ($Default -eq 'y') } else { return $true } }
    $hint = if ($Default -eq 'y') { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        try { $answer = Read-Host "  ? $Question $hint" } catch { return ($Default -eq 'y') }
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
        switch -Regex ($answer.Trim().ToLower()) {
            '^(y|yes)$' { Write-HardenLog "ASK    $Question -> yes"; return $true }
            '^(n|no)$'  { Write-HardenLog "ASK    $Question -> no";  return $false }
        }
    }
}

# Invoke-Fix "description" { action }  - audit: WOULD; apply: run it -> CHANGED / FAILED
function Invoke-Fix([string]$Description, [scriptblock]$Action) {
    if ($script:Mode -eq 'Audit') { Add-Result 'WOULD' $Description; return $true }
    try {
        Write-HardenLog "RUN    $Description"
        $out = & $Action 2>&1
        if ($out) { Write-HardenLog ($out | Out-String) }
        Add-Result 'CHANGED' $Description
        return $true
    } catch {
        Add-Result 'FAILED' "$Description - $($_.Exception.Message)"
        return $false
    }
}

# ---------------------------------------------------------------------------
# Registry helpers (every key is exported to the backup folder before a change)
# ---------------------------------------------------------------------------
function ConvertTo-RegExePath([string]$Path) {
    return ($Path -replace '^.*Registry::', '' -replace '^HKLM:\\', 'HKLM\' -replace '^HKCU:\\', 'HKCU\' -replace '^HKU:\\', 'HKU\')
}
function Backup-RegKey([string]$Path) {
    if ($script:BackedUpKeys.ContainsKey($Path)) { return }
    $script:BackedUpKeys[$Path] = $true
    if (-not (Test-Path $Path)) { return }
    $file = Join-Path $BackupDir (('reg-' + ($Path -replace '[\\/:*?"<>| ]', '_')) + '.reg')
    & reg.exe export (ConvertTo-RegExePath $Path) $file /y 2>&1 | Out-Null
}
function Get-RegValue([string]$Path, [string]$Name) {
    # .GetValue() treats the name literally (a value can be called '*')
    # An empty REG_MULTI_SZ must come back as an empty array, not $null (return ,$v), or Set-Reg rewrites it on every run
    try { $v = (Get-Item -LiteralPath $Path -ErrorAction Stop).GetValue($Name, $null) } catch { return $null }
    if ($v -is [array]) { return ,$v }
    return $v
}

# Set-Reg PATH NAME VALUE [TYPE] "description"
function Set-Reg([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord', [string]$Description) {
    if (-not $Description) { $Description = "$Name = $Value" }
    $cur = Get-RegValue $Path $Name
    if ($null -ne $cur -and "$cur" -eq "$Value") { Add-Result 'OK' $Description; return }
    $was = if ($null -eq $cur) { 'not set' } else { "$cur" }
    if ($script:Mode -eq 'Audit') { Add-Result 'WOULD' "$Description (now: $was)"; return }
    Backup-RegKey $Path
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        Add-Result 'CHANGED' "$Description (was: $was)"
    } catch {
        Add-Result 'FAILED' "$Description - $($_.Exception.Message)"
    }
}

# Remove-RegValue PATH NAME "description"   (for planted values that weaken security)
function Remove-RegValue([string]$Path, [string]$Name, [string]$Description) {
    $cur = Get-RegValue $Path $Name
    if ($null -eq $cur) { Add-Result 'OK' $Description; return }
    if ($script:Mode -eq 'Audit') { Add-Result 'WOULD' "$Description (found: $Name = $cur)"; return }
    Backup-RegKey $Path
    try {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        Add-Result 'CHANGED' "$Description (removed $Name = $cur)"
    } catch {
        Add-Result 'FAILED' "$Description - $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Local security policy helpers (secedit)
# ---------------------------------------------------------------------------
function Get-SecPolicy {
    $file = Join-Path $env:TEMP "harden-secpol-$RunId.inf"
    & secedit.exe /export /cfg $file /quiet 2>&1 | Out-Null
    $policy = @{}
    $section = ''
    if (-not (Test-Path $file)) { return $policy }
    foreach ($line in (Get-Content -Path $file)) {
        if ($line -match '^\s*\[(.+)\]\s*$') { $section = $Matches[1]; $policy[$section] = [ordered]@{}; continue }
        if ($section -and $line -match '^\s*([^=]+?)\s*=\s*(.*)$') { $policy[$section][$Matches[1]] = $Matches[2].Trim() }
    }
    Remove-Item $file -Force -ErrorAction SilentlyContinue
    return $policy
}

function Backup-SecPolicy {
    $file = Join-Path $BackupDir 'secpol-before.inf'
    if (-not (Test-Path $file)) { & secedit.exe /export /cfg $file /quiet 2>&1 | Out-Null }
}

# Set-SecPolicy SECTION @{key=value} AREA "description"
#   Compares wanted values with the current policy and applies only the differences.
function Set-SecPolicy([string]$Section, [System.Collections.IDictionary]$Wanted, [string]$Area, [string]$Description) {
    $current = Get-SecPolicy
    $cur = if ($current.ContainsKey($Section)) { $current[$Section] } else { @{} }
    $diff = [ordered]@{}
    # secedit /export leaves out a right that nobody holds, so "missing" counts as "" (No One)
    foreach ($k in $Wanted.Keys) {
        $have = if ($cur.Contains($k)) { "$($cur[$k])" } else { '' }
        if (-not $cur.Contains($k) -and "$($Wanted[$k])" -ne '') { $have = $null }
        if ($have -ne "$($Wanted[$k])") { $diff[$k] = $Wanted[$k] }
    }
    if ($diff.Count -eq 0) { Add-Result 'OK' $Description; return $true }
    $changes = ($diff.Keys | ForEach-Object {
        $was = if ($cur.Contains($_)) { $cur[$_] } else { 'not set' }
        "$_=$($diff[$_]) (was $was)"
    }) -join '; '
    if ($script:Mode -eq 'Audit') { Add-Result 'WOULD' "$Description -> $changes"; return $true }
    Backup-SecPolicy
    $inf = Join-Path $env:TEMP "harden-apply-$RunId.inf"
    $db  = Join-Path $env:TEMP "harden-apply-$RunId.sdb"
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', "[$Section]")
    foreach ($k in $diff.Keys) { $lines += "$k = $($diff[$k])" }
    $lines | Out-File -FilePath $inf -Encoding Unicode -Force
    $out = & secedit.exe /configure /db $db /cfg $inf /areas $Area /quiet 2>&1
    Write-HardenLog ($out | Out-String)
    Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
    $after = Get-SecPolicy
    $still = @($diff.Keys | Where-Object {
        $now = if ($after.ContainsKey($Section) -and $after[$Section].Contains($_)) { "$($after[$Section][$_])" } elseif ("$($diff[$_])" -eq '') { '' } else { $null }
        $now -ne "$($diff[$_])" })
    if ($still.Count -eq 0) { Add-Result 'CHANGED' "$Description -> $changes"; return $true }
    Add-Result 'FAILED' "$Description - these did not apply: $($still -join ', ') (a Group Policy may be overriding them)"
    return $false
}

# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$script:OsName   = $os.Caption
$script:IsDC     = ($os.ProductType -eq 2)
$script:IsServer = ($os.ProductType -ne 1)
$script:InDomain = [bool]$cs.PartOfDomain
if ($script:IsDC) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }
$script:HasAD = [bool](Get-Command Get-ADUser -ErrorAction SilentlyContinue)

# Services that must NEVER be touched on a Domain Controller
$DcProtectedServices = @('NTDS', 'DNS', 'Netlogon', 'Kdc', 'DFSR', 'W32Time', 'ADWS', 'IsmServ', 'LanmanServer', 'LanmanWorkstation', 'RpcSs', 'SamSs', 'DHCPServer', 'CertSvc')

# The CyberPatriot scoring software must never be touched
$CpProtectRegex = 'cyberpatriot|\bccs\b|ccsclient|scoring'

# ---------------------------------------------------------------------------
# README information
# ---------------------------------------------------------------------------
function Split-Names([object]$Value) {
    if ($null -eq $Value) { return @() }
    return @(@($Value) -join ' ' -split '[\s,;]+' | Where-Object { $_ } | ForEach-Object { $_.Trim() })
}

function Import-ReadmeConfig([string]$Path) {
    if (-not (Test-Path $Path)) { throw "Config file not found: $Path" }
    $data = Import-PowerShellDataFile -Path $Path
    $script:AuthAdmins = Split-Names $data.AuthorizedAdmins
    $script:AuthUsers  = Split-Names $data.AuthorizedUsers
    $script:Critical   = Split-Names $data.CriticalServices | ForEach-Object { $_.ToLower() }
    if ($data.ContainsKey('NewPassword'))    { $script:NewPassword = [string]$data.NewPassword }
    if ($data.ContainsKey('EnableLockout'))  { $script:EnableLockout = ([string]$data.EnableLockout).ToLower() }
    if ($data.ContainsKey('InstallUpdates')) { $script:InstallUpdates = ([string]$data.InstallUpdates).ToLower() }
}

function Get-CurrentUserNames {
    if ($script:IsDC -and $script:HasAD) {
        return @(Get-ADUser -Filter * | Where-Object { $_.SamAccountName -notin @('krbtgt', 'Guest') } | ForEach-Object { $_.SamAccountName })
    }
    return @(Get-LocalUser | Where-Object { $_.Enabled } | ForEach-Object { $_.Name })
}

function Read-ReadmeInfo {
    Write-Header 'README information'
    Write-Host 'Open the README on the desktop and find:'
    Write-Host '  1) the AUTHORIZED ADMINISTRATORS'
    Write-Host '  2) the other AUTHORIZED USERS'
    Write-Host '  3) any CRITICAL SERVICES that must keep working (e.g. Remote Desktop, IIS, FTP, DNS)'
    Write-Host ''
    Write-Host ('Users on this computer now: ' + ((Get-CurrentUserNames) -join ' '))
    Write-Host "You are logged in as: $script:Me (this account is always kept)"
    Write-Host ''
    $script:AuthAdmins = Split-Names (Read-Host '  Authorized ADMINS (separate with spaces)')
    $script:AuthUsers  = Split-Names (Read-Host '  Authorized USERS who are NOT admins')
    Write-Host '  Critical service keywords this script understands:'
    Write-Host '    rdp iis web ftp smb fileshare dns dhcp ad winrm ssh print sql mysql apache snmp telnet vnc'
    $script:Critical = Split-Names (Read-Host '  CRITICAL SERVICES (blank if none)') | ForEach-Object { $_.ToLower() }
}

function Complete-ReadmeInfo {
    if ($script:Me -and ($script:AuthAdmins + $script:AuthUsers) -notcontains $script:Me) { $script:AuthAdmins += $script:Me }
    Write-Host ''
    Write-Host ('  Admins:            ' + $(if ($script:AuthAdmins) { $script:AuthAdmins -join ' ' } else { '(none given)' }))
    Write-Host ('  Standard users:    ' + $(if ($script:AuthUsers) { $script:AuthUsers -join ' ' } else { '(none given)' }))
    Write-Host ('  Critical services: ' + $(if ($script:Critical) { $script:Critical -join ' ' } else { '(none)' }))
    if (-not ($script:AuthAdmins.Count -gt 1 -or $script:AuthUsers.Count -gt 0)) {
        Write-Warn 'No README user list given: the script will NOT delete or demote anyone.'
    }
}

function Test-Critical([string[]]$Keywords) {
    foreach ($k in $Keywords) { if ($script:Critical -contains $k.ToLower()) { return $true } }
    return $false
}
function Test-Authorized([string]$Name) { return (($script:AuthAdmins + $script:AuthUsers) -contains $Name) }
function Test-HaveUserList { return ($script:AuthUsers.Count -gt 0 -or $script:AuthAdmins.Count -gt 1) }

# ===========================================================================
# Passwords for users
# ===========================================================================
function Test-StrongPassword([string]$Pw) {
    return ($Pw.Length -ge 12 -and $Pw -cmatch '[A-Z]' -and $Pw -cmatch '[a-z]' -and $Pw -match '[0-9]' -and $Pw -match '[^A-Za-z0-9]')
}

function Get-NewPasswordPlain {
    if ($script:NewPassword -eq 'skip') { return $null }
    if ($script:NewPassword) {
        if (Test-StrongPassword $script:NewPassword) { return $script:NewPassword }
        Add-Result 'FAILED' 'NewPassword in the config file is too weak (need 12+ chars with upper, lower, number, symbol)'
        $script:NewPassword = 'skip'; return $null
    }
    if ($script:AssumeYes) { return $null }
    while ($true) {
        $s1 = Read-Host '  ? New password for the other users (12+ chars, upper, lower, number, symbol; blank = skip)' -AsSecureString
        $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1))
        if (-not $p1) { $script:NewPassword = 'skip'; return $null }
        if (-not (Test-StrongPassword $p1)) { Write-Warn 'Too weak. Use 12+ characters with upper, lower, number and symbol.'; continue }
        $s2 = Read-Host '  ? Type it again' -AsSecureString
        $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2))
        if ($p1 -ceq $p2) { $script:NewPassword = $p1; Write-Warn 'Write this password down!'; return $p1 }
        Write-Warn "They didn't match - try again."
    }
}

# ===========================================================================
# SECTION: Users and groups
# ===========================================================================
function Get-GroupMembers([string]$Group) {
    # Returns objects: Short (name only), Full (DOMAIN\name), IsLocal, Class
    $result = @()
    try {
        foreach ($m in @(Get-LocalGroupMember -Group $Group -ErrorAction Stop)) {
            $result += [pscustomobject]@{ Short = ($m.Name -split '\\')[-1]; Full = $m.Name; IsLocal = ($m.PrincipalSource -eq 'Local' -or $m.Name -like "$env:COMPUTERNAME\*"); Class = $m.ObjectClass }
        }
        return $result
    } catch {
        # Get-LocalGroupMember fails when a group contains a deleted (orphaned) account - fall back to "net localgroup"
        $lines = & net.exe localgroup "$Group" 2>$null
        $inList = $false
        foreach ($line in $lines) {
            if ($line -match '^-{5,}') { $inList = $true; continue }
            if ($line -match '^The command completed') { break }
            if ($inList -and $line.Trim()) {
                $full = $line.Trim()
                $result += [pscustomobject]@{ Short = ($full -split '\\')[-1]; Full = $full; IsLocal = ($full -notmatch '\\' -or $full -like "$env:COMPUTERNAME\*"); Class = 'Unknown' }
            }
        }
        return $result
    }
}

function Remove-GroupMember([string]$Group, [string]$Member) {
    try { Remove-LocalGroupMember -Group $Group -Member $Member -ErrorAction Stop }
    catch { & net.exe localgroup "$Group" "$Member" /delete | Out-Null; if ($LASTEXITCODE -ne 0) { throw "net localgroup failed ($LASTEXITCODE)" } }
}

function Invoke-Users {
    if ($script:IsDC) { Invoke-UsersAD; return }
    $special = @{ '500' = 'Administrator'; '501' = 'Guest'; '503' = 'DefaultAccount'; '504' = 'WDAGUtilityAccount' }
    $all = @(Get-LocalUser)
    $builtinAdmin = ($all | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1)

    Write-Info 'Comparing user accounts with the README'
    Write-Why 'Every account that is not in the README is a way in for an attacker.'
    if (-not (Test-HaveUserList)) {
        Add-Result 'SKIPPED' 'No README user list given - cannot tell which users are unauthorized'
        Add-Result 'REVIEW' ("Users on this computer: " + (($all | Where-Object { -not $special.ContainsKey(($_.SID.Value -split '-')[-1]) }).Name -join ' '))
    } else {
        foreach ($u in $all) {
            if ($special.ContainsKey(($u.SID.Value -split '-')[-1])) { continue }
            if (Test-Authorized $u.Name) { continue }
            Add-Result 'REVIEW' ("User '{0}' is NOT in the README{1}" -f $u.Name, $(if (-not $u.Enabled) { ' (disabled)' } else { '' }))
            if (Confirm-Step "Delete unauthorized user '$($u.Name)'? (their files in C:\Users are kept)" 'y') {
                $victim = $u.Name
                Invoke-Fix "Deleted user $victim" { Remove-LocalUser -Name $victim -ErrorAction Stop } | Out-Null
            }
        }
        foreach ($name in @($script:AuthAdmins + $script:AuthUsers | Select-Object -Unique)) {
            if (@($all.Name) -contains $name) { continue }
            Add-Result 'REVIEW' "User '$name' is in the README but does not exist on this computer"
            if (Confirm-Step "Create user '$name'?" 'y') {
                $pw = Get-NewPasswordPlain
                if (-not $pw) { $pw = 'Tmp-' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '!aA1'; Write-Warn "Temporary password for ${name}: $pw  (change it!)" }
                $newName = $name
                Invoke-Fix "Created user $newName" {
                    New-LocalUser -Name $newName -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop | Out-Null
                    Add-LocalGroupMember -Group 'Users' -Member $newName -ErrorAction SilentlyContinue
                } | Out-Null
            }
        }
        foreach ($u in $all) {
            if ((Test-Authorized $u.Name) -and -not $u.Enabled) {
                Add-Result 'REVIEW' "Authorized user '$($u.Name)' is disabled"
                if (Confirm-Step "Enable '$($u.Name)'?" 'y') { $en = $u.Name; Invoke-Fix "Enabled $en" { Enable-LocalUser -Name $en -ErrorAction Stop } | Out-Null }
            }
        }
    }

    Write-Info 'Built-in accounts (Guest, DefaultAccount, Administrator)'
    Write-Why 'The Guest account needs no password. Attackers love it.'
    foreach ($u in @(Get-LocalUser)) {
        $rid = ($u.SID.Value -split '-')[-1]
        if ($rid -in @('501', '503', '504')) {
            if ($u.Enabled) {
                $acct = $u.Name
                Invoke-Fix "Disabled the built-in '$acct' account" { Disable-LocalUser -Name $acct -ErrorAction Stop } | Out-Null
            } else { Add-Result 'OK' "Built-in '$($u.Name)' account is disabled" }
        }
    }
    if ($builtinAdmin -and $builtinAdmin.Enabled -and $builtinAdmin.Name -ne $script:Me) {
        Add-Result 'REVIEW' "The built-in Administrator account ('$($builtinAdmin.Name)') is enabled"
        if (Confirm-Step "Disable the built-in Administrator? (say NO if the README says to keep it)" 'n' -Strict) {
            $ba = $builtinAdmin.Name
            Invoke-Fix "Disabled the built-in Administrator ($ba)" { Disable-LocalUser -Name $ba -ErrorAction Stop } | Out-Null
        }
    }

    Write-Info 'Checking who is an Administrator'
    Write-Why 'Only the README administrators should have admin rights.'
    $admins = Get-GroupMembers 'Administrators'
    foreach ($m in $admins) {
        if ($builtinAdmin -and $m.Short -eq $builtinAdmin.Name) { continue }
        if ($m.Short -in @('Domain Admins', 'Enterprise Admins')) { continue }
        if ($script:AuthAdmins -contains $m.Short) { continue }
        if ($m.Short -eq $script:Me) { Add-Result 'REVIEW' "You ($($m.Full)) are an Administrator but the README list has you as a normal user - not removing you (you would lose admin rights). Check the README."; continue }
        if (-not (Test-HaveUserList)) { Add-Result 'REVIEW' "'$($m.Full)' is an Administrator (no README list to compare)"; continue }
        Add-Result 'REVIEW' "'$($m.Full)' is an Administrator but NOT an authorized admin"
        if (Confirm-Step "Remove '$($m.Full)' from Administrators?" 'y') {
            $who = $m.Full
            Invoke-Fix "Removed $who from Administrators" { Remove-GroupMember 'Administrators' $who } | Out-Null
        }
    }
    foreach ($a in $script:AuthAdmins) {
        if (-not (Get-LocalUser -Name $a -ErrorAction SilentlyContinue)) { continue }
        if (@($admins.Short) -contains $a) { Add-Result 'OK' "$a is an Administrator"; continue }
        Add-Result 'REVIEW' "Authorized admin '$a' is not in the Administrators group"
        if (Confirm-Step "Add '$a' to Administrators?" 'y') { $who = $a; Invoke-Fix "Added $who to Administrators" { Add-LocalGroupMember -Group 'Administrators' -Member $who -ErrorAction Stop } | Out-Null }
    }

    Write-Info 'Checking other powerful groups'
    Write-Why 'Backup Operators can read any file, Power Users and Hyper-V Administrators can take over the computer.'
    $rdpCritical = Test-Critical @('rdp', 'remotedesktop', 'remote-desktop', 'termservice')
    foreach ($g in @('Backup Operators', 'Power Users', 'Hyper-V Administrators', 'Remote Management Users', 'Network Configuration Operators', 'Cryptographic Operators', 'Distributed COM Users', 'Event Log Readers', 'Remote Desktop Users')) {
        if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) { continue }
        foreach ($m in (Get-GroupMembers $g)) {
            if ($script:AuthAdmins -contains $m.Short) { continue }
            $default = 'y'
            if ($g -eq 'Remote Desktop Users' -and $rdpCritical -and (Test-Authorized $m.Short)) { $default = 'n' }
            Add-Result 'REVIEW' "'$($m.Full)' is in the '$g' group"
            if (Confirm-Step "Remove '$($m.Full)' from '$g'?" $default) {
                $who = $m.Full; $grp = $g
                Invoke-Fix "Removed $who from $grp" { Remove-GroupMember $grp $who } | Out-Null
            }
        }
    }

    Write-Info 'Password settings on each account'
    Write-Why '"Password never expires" and "password not required" are weak settings planted on many images.'
    foreach ($u in @(Get-LocalUser | Where-Object { $_.Enabled })) {
        $n = $u.Name
        if ($u.PasswordNeverExpires) { Invoke-Fix "$n - password will now expire" { Set-LocalUser -Name $n -PasswordNeverExpires $false -ErrorAction Stop } | Out-Null }
        if (-not $u.UserMayChangePassword) { Invoke-Fix "$n - may now change their own password" { Set-LocalUser -Name $n -UserMayChangePassword $true -ErrorAction Stop } | Out-Null }
        if (-not $u.PasswordRequired) { Invoke-Fix "$n - a password is now required" { & net.exe user $n /passwordreq:yes | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'net user failed' } } | Out-Null }
    }

    Write-Info 'Setting strong passwords for the other users'
    Write-Why "Planted users often have weak passwords like 'Password1'."
    $targets = @($script:AuthAdmins + $script:AuthUsers | Select-Object -Unique | Where-Object { $_ -ne $script:Me -and (Get-LocalUser -Name $_ -ErrorAction SilentlyContinue) })
    if ($targets.Count -eq 0) { Add-Result 'SKIPPED' 'No other authorized users to set passwords for'; return }
    if ($script:Mode -eq 'Audit') { Add-Result 'REVIEW' "Make sure these users have strong passwords (Apply mode can set them): $($targets -join ' ')"; return }
    $pw = Get-NewPasswordPlain
    if (-not $pw) { Add-Result 'REVIEW' "Passwords not changed - set strong ones by hand for: $($targets -join ' ')"; return }
    foreach ($t in $targets) {
        $who = $t
        Invoke-Fix "Set a strong password for $who" { Set-LocalUser -Name $who -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop } | Out-Null
    }
}

function Invoke-UsersAD {
    if (-not $script:HasAD) { Add-Result 'FAILED' 'This is a Domain Controller but the ActiveDirectory PowerShell module is missing'; return }
    $builtin = @('Administrator', 'Guest', 'krbtgt', 'DefaultAccount')
    $all = @(Get-ADUser -Filter * -Properties Enabled, PasswordNeverExpires, PasswordNotRequired, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, TrustedForDelegation)

    Write-Info 'Comparing DOMAIN user accounts with the README (this is a Domain Controller)'
    Write-Why 'Every account that is not in the README is a way in for an attacker.'
    if (-not (Test-HaveUserList)) {
        Add-Result 'SKIPPED' 'No README user list given - cannot tell which users are unauthorized'
    } else {
        foreach ($u in $all) {
            if ($builtin -contains $u.SamAccountName) { continue }
            if (Test-Authorized $u.SamAccountName) { continue }
            Add-Result 'REVIEW' "Domain user '$($u.SamAccountName)' is NOT in the README"
            if (Confirm-Step "Delete domain user '$($u.SamAccountName)'?" 'y') {
                $victim = $u.DistinguishedName; $vn = $u.SamAccountName
                Invoke-Fix "Deleted domain user $vn" { Remove-ADUser -Identity $victim -Confirm:$false -ErrorAction Stop } | Out-Null
            }
        }
        foreach ($name in @($script:AuthAdmins + $script:AuthUsers | Select-Object -Unique)) {
            if (@($all.SamAccountName) -contains $name) { continue }
            Add-Result 'REVIEW' "User '$name' is in the README but does not exist in the domain"
            if (Confirm-Step "Create domain user '$name'?" 'y') {
                $pw = Get-NewPasswordPlain
                if (-not $pw) { $pw = 'Tmp-' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '!aA1'; Write-Warn "Temporary password for ${name}: $pw  (change it!)" }
                $newName = $name
                Invoke-Fix "Created domain user $newName" { New-ADUser -Name $newName -SamAccountName $newName -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true -ErrorAction Stop } | Out-Null
            }
        }
    }
    $guest = Get-ADUser -Identity 'Guest' -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) { Invoke-Fix 'Disabled the domain Guest account' { Disable-ADAccount -Identity 'Guest' -ErrorAction Stop } | Out-Null }
    elseif ($guest) { Add-Result 'OK' 'Domain Guest account is disabled' }

    Write-Info 'Checking powerful domain groups'
    Write-Why 'Members of Domain Admins, Enterprise Admins, Schema Admins and the Operator groups control the whole domain.'
    $groups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Key Admins', 'Enterprise Key Admins')
    foreach ($g in $groups) {
        $members = @(Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' })
        foreach ($m in $members) {
            if ($m.SamAccountName -eq 'Administrator' -or $script:AuthAdmins -contains $m.SamAccountName) { continue }
            if ($m.SamAccountName -eq $script:Me) { Add-Result 'REVIEW' "You ($($m.SamAccountName)) are in '$g' but the README list has you as a normal user - not removing you. Check the README."; continue }
            if (-not (Test-HaveUserList)) { Add-Result 'REVIEW' "'$($m.SamAccountName)' is in '$g' (no README list to compare)"; continue }
            Add-Result 'REVIEW' "'$($m.SamAccountName)' is in '$g' but is NOT an authorized admin"
            if (Confirm-Step "Remove '$($m.SamAccountName)' from '$g'?" 'y') {
                $grp = $g; $who = $m.DistinguishedName; $wn = $m.SamAccountName
                Invoke-Fix "Removed $wn from $grp" { Remove-ADGroupMember -Identity $grp -Members $who -Confirm:$false -ErrorAction Stop } | Out-Null
            }
        }
    }
    $da = @(Get-ADGroupMember -Identity 'Domain Admins' -ErrorAction SilentlyContinue).SamAccountName
    foreach ($a in $script:AuthAdmins) {
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$a'" -ErrorAction SilentlyContinue)) { continue }
        if ($da -contains $a) { Add-Result 'OK' "$a is a Domain Admin"; continue }
        Add-Result 'REVIEW' "Authorized admin '$a' is not in Domain Admins"
        if (Confirm-Step "Add '$a' to Domain Admins?" 'y') { $who = $a; Invoke-Fix "Added $who to Domain Admins" { Add-ADGroupMember -Identity 'Domain Admins' -Members $who -ErrorAction Stop } | Out-Null }
    }

    Write-Info 'Risky settings on domain accounts'
    foreach ($u in @(Get-ADUser -Filter 'Enabled -eq $true' -Properties PasswordNeverExpires, PasswordNotRequired, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, TrustedForDelegation)) {
        if ($u.SamAccountName -eq 'krbtgt') { continue }
        $id = $u.DistinguishedName; $n = $u.SamAccountName
        if ($u.PasswordNeverExpires) { Invoke-Fix "$n - password will now expire" { Set-ADUser -Identity $id -PasswordNeverExpires $false -ErrorAction Stop } | Out-Null }
        if ($u.PasswordNotRequired) { Invoke-Fix "$n - a password is now required" { Set-ADUser -Identity $id -PasswordNotRequired $false -ErrorAction Stop } | Out-Null }
        if ($u.AllowReversiblePasswordEncryption) { Invoke-Fix "$n - password no longer stored with reversible encryption" { Set-ADUser -Identity $id -AllowReversiblePasswordEncryption $false -ErrorAction Stop } | Out-Null }
        if ($u.DoesNotRequirePreAuth) { Invoke-Fix "$n - Kerberos pre-authentication required again (stops AS-REP roasting)" { Set-ADAccountControl -Identity $id -DoesNotRequirePreAuth $false -ErrorAction Stop } | Out-Null }
        if ($u.TrustedForDelegation) { Add-Result 'REVIEW' "$n is trusted for delegation (it can impersonate other users) - remove unless the README needs it" }
    }

    Write-Info 'Setting strong passwords for the other users'
    $targets = @($script:AuthAdmins + $script:AuthUsers | Select-Object -Unique | Where-Object { $_ -ne $script:Me -and (Get-ADUser -Filter "SamAccountName -eq '$_'" -ErrorAction SilentlyContinue) })
    if ($targets.Count -eq 0) { Add-Result 'SKIPPED' 'No other authorized users to set passwords for'; return }
    if ($script:Mode -eq 'Audit') { Add-Result 'REVIEW' "Make sure these users have strong passwords (Apply mode can set them): $($targets -join ' ')"; return }
    $pw = Get-NewPasswordPlain
    if (-not $pw) { Add-Result 'REVIEW' "Passwords not changed - set strong ones by hand for: $($targets -join ' ')"; return }
    foreach ($t in $targets) {
        $who = $t
        Invoke-Fix "Set a strong password for $who" { Set-ADAccountPassword -Identity $who -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -ErrorAction Stop } | Out-Null
    }
}

# ===========================================================================
# SECTION: Password and lockout policy
# ===========================================================================
function Invoke-Passwords {
    Write-Info 'Password rules and account lockout'
    Write-Why 'Long, complex passwords that expire, cannot be re-used, and lock the account after 5 wrong guesses.'
    $wanted = [ordered]@{
        MinimumPasswordAge    = 1
        MaximumPasswordAge    = 90
        MinimumPasswordLength = 12
        PasswordComplexity    = 1
        PasswordHistorySize   = 24
        ClearTextPassword     = 0
    }
    if ($script:EnableLockout -ne 'no') {
        $wanted['LockoutBadCount'] = 5
        $wanted['ResetLockoutCount'] = 30
        $wanted['LockoutDuration'] = 30
    }
    Set-SecPolicy 'System Access' $wanted 'SECURITYPOLICY' 'Local password and lockout policy' | Out-Null
    if ($script:IsDC) { Update-DomainPasswordPolicy $wanted }
}

function Update-DomainPasswordPolicy([System.Collections.IDictionary]$Wanted) {
    Write-Info 'Domain password policy (Default Domain Policy)'
    Write-Why 'On a Domain Controller, password rules for domain users come from the Default Domain Policy, not the local policy.'
    if (-not $script:HasAD) { Add-Result 'FAILED' 'ActiveDirectory module missing - set the Default Domain Policy by hand (see the Server checklist)'; return }
    $domain = Get-ADDomain
    $p = Get-ADDefaultDomainPasswordPolicy
    $ok = ($p.MinPasswordLength -ge 12 -and $p.ComplexityEnabled -and $p.PasswordHistoryCount -ge 24 -and -not $p.ReversibleEncryptionEnabled `
           -and $p.MaxPasswordAge.TotalDays -le 90 -and $p.MaxPasswordAge.TotalDays -gt 0 -and $p.MinPasswordAge.TotalDays -ge 1)
    if ($Wanted.Contains('LockoutBadCount')) { $ok = $ok -and $p.LockoutThreshold -gt 0 -and $p.LockoutThreshold -le 5 }
    if ($ok) { Add-Result 'OK' 'Domain password policy is strong' }
    else {
        Invoke-Fix 'Domain password policy: length 12, complexity, history 24, max age 90, min age 1, lockout 5' {
            $params = @{ Identity = $domain.DNSRoot; MinPasswordLength = 12; ComplexityEnabled = $true; PasswordHistoryCount = 24
                         MaxPasswordAge = (New-TimeSpan -Days 90); MinPasswordAge = (New-TimeSpan -Days 1); ReversibleEncryptionEnabled = $false; ErrorAction = 'Stop' }
            if ($Wanted.Contains('LockoutBadCount')) {
                $params['LockoutThreshold'] = 5; $params['LockoutDuration'] = (New-TimeSpan -Minutes 30); $params['LockoutObservationWindow'] = (New-TimeSpan -Minutes 30)
            }
            Set-ADDefaultDomainPasswordPolicy @params
        } | Out-Null
    }

    # Also write the values into the Default Domain Policy GPO, otherwise the
    # next Group Policy refresh puts the old values back.
    $guid = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
    $gpoDir = Join-Path $env:SystemRoot "SYSVOL\domain\Policies\$guid"
    if (-not (Test-Path $gpoDir)) { $gpoDir = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\$guid" }
    $inf = Join-Path $gpoDir 'MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
    if (-not (Test-Path $inf)) { Add-Result 'REVIEW' "Default Domain Policy template not found - check it in Group Policy Management"; return }
    $lines = [System.Collections.Generic.List[string]](Get-Content -Path $inf -Encoding Unicode)
    $start = $lines.FindIndex([Predicate[string]] { param($l) $l -match '^\s*\[System Access\]\s*$' })
    if ($start -lt 0) { $lines.Add('[System Access]'); $start = $lines.Count - 1 }
    $end = $start + 1
    while ($end -lt $lines.Count -and $lines[$end] -notmatch '^\s*\[') { $end++ }
    $changed = @()
    foreach ($k in $Wanted.Keys) {
        $found = $false
        for ($i = $start + 1; $i -lt $end; $i++) {
            if ($lines[$i] -match "^\s*$k\s*=\s*(.*)$") {
                $found = $true
                if ($Matches[1].Trim() -ne "$($Wanted[$k])") { $lines[$i] = "$k = $($Wanted[$k])"; $changed += "$k=$($Wanted[$k])" }
            }
        }
        if (-not $found) { $lines.Insert($end, "$k = $($Wanted[$k])"); $end++; $changed += "$k=$($Wanted[$k])" }
    }
    if ($changed.Count -eq 0) { Add-Result 'OK' 'Default Domain Policy GPO already has these password settings'; return }
    if ($script:Mode -eq 'Audit') { Add-Result 'WOULD' "Default Domain Policy GPO -> $($changed -join '; ')"; return }
    try {
        Copy-Item $inf (Join-Path $BackupDir 'DefaultDomainPolicy-GptTmpl.inf') -Force
        $lines | Out-File -FilePath $inf -Encoding Unicode -Force
        # Bump the GPO version (computer part) in GPT.INI and in Active Directory so every DC re-applies it.
        $gptIni = Join-Path $gpoDir 'GPT.INI'
        Copy-Item $gptIni (Join-Path $BackupDir 'DefaultDomainPolicy-GPT.INI') -Force
        $gpt = Get-Content $gptIni
        $ver = 0
        foreach ($l in $gpt) { if ($l -match '^\s*Version\s*=\s*(\d+)') { $ver = [int64]$Matches[1] } }
        $newVer = $ver + 1
        ($gpt | ForEach-Object { if ($_ -match '^\s*Version\s*=') { "Version=$newVer" } else { $_ } }) | Set-Content $gptIni
        $dn = "CN=$guid,CN=Policies,CN=System,$($domain.DistinguishedName)"
        Set-ADObject -Identity $dn -Replace @{ versionNumber = $newVer } -ErrorAction Stop
        & gpupdate.exe /target:computer /force | Out-Null
        Add-Result 'CHANGED' "Default Domain Policy GPO -> $($changed -join '; ')"
    } catch {
        Add-Result 'FAILED' "Could not update the Default Domain Policy GPO - $($_.Exception.Message). Set it in Group Policy Management (see the Server checklist)."
    }
}

# ===========================================================================
# SECTION: Security options
# ===========================================================================
function Invoke-SecurityOptions {
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Write-Info 'User Account Control (UAC)'
    Write-Why 'UAC makes programs ask before they get admin rights, so malware cannot silently take over.'
    Set-Reg $sys 'EnableLUA' 1 'DWord' 'UAC is turned on'
    Set-Reg $sys 'ConsentPromptBehaviorAdmin' 2 'DWord' 'UAC: admins must approve on the secure desktop'
    Set-Reg $sys 'ConsentPromptBehaviorUser' 1 'DWord' 'UAC: standard users must enter admin credentials on the secure desktop'
    Set-Reg $sys 'PromptOnSecureDesktop' 1 'DWord' 'UAC: prompts appear on the secure desktop'
    Set-Reg $sys 'FilterAdministratorToken' 1 'DWord' 'UAC: also protects the built-in Administrator'
    Set-Reg $sys 'EnableInstallerDetection' 1 'DWord' 'UAC: detect installers and ask for elevation'
    Set-Reg $sys 'EnableSecureUIAPaths' 1 'DWord' 'UAC: only elevate UIAccess apps from secure folders'
    Set-Reg $sys 'EnableVirtualization' 1 'DWord' 'UAC: virtualize file and registry write failures'

    Write-Info 'Logon screen'
    Write-Why "Don't show who logged in last, require Ctrl+Alt+Del, and lock idle computers."
    Set-Reg $sys 'DontDisplayLastUserName' 1 'DWord' "Logon screen doesn't show the last user name"
    Set-Reg $sys 'DisableCAD' 0 'DWord' 'Ctrl+Alt+Del is required to log on'
    Set-Reg $sys 'InactivityTimeoutSecs' 900 'DWord' 'Computer locks after 15 idle minutes'
    Set-Reg $sys 'ShutdownWithoutLogon' 0 'DWord' 'Cannot shut down from the logon screen without logging in'
    if (-not (Get-RegValue $sys 'LegalNoticeText')) {
        Set-Reg $sys 'LegalNoticeCaption' 'Authorized use only' 'String' 'Logon warning title'
        Set-Reg $sys 'LegalNoticeText' 'This computer is for authorized users only. Activity may be monitored and reported.' 'String' 'Logon warning text'
    } else { Add-Result 'OK' 'Logon warning message is set' }
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-Reg $wl 'AutoAdminLogon' '0' 'String' 'Automatic logon is off'
    Remove-RegValue $wl 'DefaultPassword' 'No password stored in the registry for automatic logon'
    if (-not $script:IsDC) { Set-Reg $wl 'CachedLogonsCount' '4' 'String' 'Remember at most 4 cached domain logons' }

    Write-Info 'Network authentication and anonymous access'
    Write-Why 'Stops anonymous users listing accounts and shares, and blocks old, crackable password hashes (LM/NTLMv1).'
    Set-Reg $lsa 'LimitBlankPasswordUse' 1 'DWord' 'Accounts with blank passwords can only log on at the keyboard'
    Set-Reg $lsa 'RestrictAnonymous' 1 'DWord' 'No anonymous listing of accounts and shares'
    Set-Reg $lsa 'RestrictAnonymousSAM' 1 'DWord' 'No anonymous listing of accounts'
    Set-Reg $lsa 'EveryoneIncludesAnonymous' 0 'DWord' "Anonymous users don't get 'Everyone' permissions"
    Set-Reg $lsa 'NoLMHash' 1 'DWord' 'Do not store LAN Manager password hashes'
    Set-Reg $lsa 'LmCompatibilityLevel' 5 'DWord' 'Only allow NTLMv2 (refuse LM and NTLM)'
    # 537395200 = 0x20080000 = "Require NTLMv2 session security" + "Require 128-bit encryption"
    Set-Reg "$lsa\MSV1_0" 'NTLMMinClientSec' 537395200 'DWord' 'NTLM clients: require NTLMv2 session security and 128-bit encryption'
    Set-Reg "$lsa\MSV1_0" 'NTLMMinServerSec' 537395200 'DWord' 'NTLM servers: require NTLMv2 session security and 128-bit encryption'
    Set-Reg $lsa 'ForceGuest' 0 'DWord' 'Network logons use their own identity, not Guest'
    Set-Reg $lsa 'DisableDomainCreds' 1 'DWord' "Don't store network passwords in Credential Manager"
    Set-Reg $lsa 'RunAsPPL' 1 'DWord' 'LSA protection on (blocks password-dumping tools; full effect after reboot)'
    if (-not $script:IsDC) { Set-Reg $lsa 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' 'String' 'Only admins may query accounts remotely' }
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 'DWord' 'WDigest off (no plain-text passwords in memory)'
    Set-SecPolicy 'System Access' ([ordered]@{ LSAAnonymousNameLookup = 0; EnableGuestAccount = 0 }) 'SECURITYPOLICY' 'No anonymous SID/name translation; Guest account off' | Out-Null

    Write-Info 'SMB (file sharing) signing and secure channel'
    Write-Why 'Signing stops attackers tampering with or relaying file-sharing traffic.'
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    Set-Reg $srv 'RequireSecuritySignature' 1 'DWord' 'SMB server: always sign'
    Set-Reg $srv 'EnableSecuritySignature' 1 'DWord' 'SMB server: sign if the client agrees'
    Set-Reg $srv 'RestrictNullSessAccess' 1 'DWord' 'SMB server: no anonymous (null session) access'
    Set-Reg $srv 'EnableForcedLogOff' 1 'DWord' 'SMB server: disconnect users when logon hours expire'
    if (-not $script:IsDC) {
        Set-Reg $srv 'NullSessionPipes' ([string[]]@()) 'MultiString' 'SMB server: no pipes open to anonymous users'
        Set-Reg $srv 'NullSessionShares' ([string[]]@()) 'MultiString' 'SMB server: no shares open to anonymous users'
    }
    Set-Reg $wks 'RequireSecuritySignature' 1 'DWord' 'SMB client: always sign'
    Set-Reg $wks 'EnableSecuritySignature' 1 'DWord' 'SMB client: sign if the server agrees'
    Set-Reg $wks 'EnablePlainTextPassword' 0 'DWord' 'SMB client: never send plain-text passwords'
    $nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    Set-Reg $nl 'RequireSignOrSeal' 1 'DWord' 'Secure channel: always sign or encrypt'
    Set-Reg $nl 'SealSecureChannel' 1 'DWord' 'Secure channel: encrypt when possible'
    Set-Reg $nl 'SignSecureChannel' 1 'DWord' 'Secure channel: sign when possible'
    Set-Reg $nl 'RequireStrongKey' 1 'DWord' 'Secure channel: require a strong session key'
    Set-Reg $nl 'DisablePasswordChange' 0 'DWord' 'Computer account password changes are allowed'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1 'DWord' 'LDAP client: request signing'
    if ($script:IsDC) {
        Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity' 2 'DWord' 'Domain Controller: require LDAP signing'
        Set-Reg $nl 'RefusePasswordChange' 0 'DWord' 'Domain Controller: allow computer account password changes'
        Set-Reg $nl 'FullSecureChannelProtection' 1 'DWord' 'Domain Controller: Zerologon enforcement mode on (KB4557222)'
    }

    Write-Info 'Other system protections'
    $inst = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
    Set-Reg $inst 'AlwaysInstallElevated' 0 'DWord' 'Installers do NOT always run as admin (HKLM)'
    Set-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 'DWord' 'Installers do NOT always run as admin (current user)'
    Set-Reg $inst 'EnableUserControl' 0 'DWord' "Users can't change installer options"
    # PrintNightmare (KB5005010, KB5005652): only admins install printer drivers, and Point and Print always warns
    $pp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    Set-Reg $pp 'RestrictDriverInstallationToAdministrators' 1 'DWord' 'Printer drivers: only administrators can install them (PrintNightmare)'
    Set-Reg $pp 'NoWarningNoElevationOnInstall' 0 'DWord' 'Point and Print: warn and ask for elevation when installing a driver'
    Set-Reg $pp 'UpdatePromptSettings' 0 'DWord' 'Point and Print: warn and ask for elevation when updating a driver'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' 1 'DWord' 'Stronger permissions on system objects'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1 'DWord' 'Safe DLL search order'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0 'DWord' 'SEHOP exploit protection on'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DisableIPSourceRouting' 2 'DWord' 'IPv4 source routing off'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0 'DWord' 'Ignore ICMP redirects'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisableIPSourceRouting' 2 'DWord' 'IPv6 source routing off'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NoNameReleaseOnDemand' 1 'DWord' 'Ignore NetBIOS name release requests'
}

# ===========================================================================
# SECTION: User rights assignment
# ===========================================================================
function Resolve-SidName([string]$Entry) {
    $sid = $Entry.TrimStart('*')
    try { return ([System.Security.Principal.SecurityIdentifier]$sid).Translate([System.Security.Principal.NTAccount]).Value } catch { return $Entry }
}

function Invoke-UserRights {
    Write-Info 'Who is allowed to do powerful things (debug programs, act as the OS, take ownership...)'
    Write-Why "Rights like 'Debug programs' given to Everyone or a normal user let them take over the computer."
    if ($script:IsDC) { Add-Result 'REVIEW' 'On a Domain Controller, user rights also come from the Default Domain Controllers Policy - check it in Group Policy Management' }
    $policy = Get-SecPolicy
    $pr = if ($policy.ContainsKey('Privilege Rights')) { $policy['Privilege Rights'] } else { @{} }
    $badPrincipals = @('*S-1-1-0', '*S-1-5-32-545', '*S-1-5-32-546', '*S-1-5-11', '*S-1-5-7', '*S-1-5-4', '*S-1-5-32-547')
    $dangerous = @('SeTcbPrivilege', 'SeDebugPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege',
                   'SeCreateTokenPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeSecurityPrivilege', 'SeSystemEnvironmentPrivilege', 'SeManageVolumePrivilege',
                   'SeCreatePermanentPrivilege', 'SeLockMemoryPrivilege', 'SeRemoteShutdownPrivilege', 'SeEnableDelegationPrivilege', 'SeImpersonatePrivilege',
                   'SeCreateGlobalPrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeIncreaseQuotaPrivilege', 'SeRelabelPrivilege', 'SeSyncAgentPrivilege',
                   'SeCreateSymbolicLinkPrivilege', 'SeSystemtimePrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeSystemProfilePrivilege', 'SeCreatePagefilePrivilege')
    $logonRights = @('SeNetworkLogonRight', 'SeInteractiveLogonRight', 'SeRemoteInteractiveLogonRight', 'SeBatchLogonRight', 'SeServiceLogonRight')
    $denyRights = @('SeDenyNetworkLogonRight', 'SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight')
    $wanted = [ordered]@{}
    $notes = @()
    foreach ($right in $dangerous) {
        if (-not $pr.Contains($right)) { continue }
        $entries = @("$($pr[$right])" -split ',' | Where-Object { $_ })
        $keep = @()
        foreach ($e in $entries) {
            $isBad = $badPrincipals -contains $e
            # A single local or domain account (RID 1000+) that is not an authorized admin
            if (-not $isBad -and $e -match '^\*?S-1-5-21-[\d-]+-(\d+)$' -and [int64]$Matches[1] -ge 1000) {
                $nm = (Resolve-SidName $e) -split '\\' | Select-Object -Last 1
                if ($script:AuthAdmins -notcontains $nm) { $isBad = $true }
            }
            if ($isBad) { $notes += "$right : remove $(Resolve-SidName $e)" } else { $keep += $e }
        }
        if ($keep.Count -ne $entries.Count) { $wanted[$right] = ($keep -join ',') }
    }
    foreach ($right in $logonRights) {
        if (-not $pr.Contains($right)) { continue }
        $entries = @("$($pr[$right])" -split ',' | Where-Object { $_ })
        $keep = @($entries | Where-Object { $_ -notin @('*S-1-1-0', '*S-1-5-32-546', '*S-1-5-7') })
        if ($keep.Count -ne $entries.Count) {
            $wanted[$right] = ($keep -join ',')
            $notes += "$right : remove Everyone/Guests/Anonymous"
        }
    }
    foreach ($right in $denyRights) {
        $entries = @()
        if ($pr.Contains($right)) { $entries = @("$($pr[$right])" -split ',' | Where-Object { $_ }) }
        # A planted "deny" for Administrators/Users/Everyone would lock real users out
        $keep = @($entries | Where-Object { $_ -notin @('*S-1-5-32-544', '*S-1-5-32-545', '*S-1-1-0', '*S-1-5-11') })
        if ($keep -notcontains '*S-1-5-32-546') { $keep += '*S-1-5-32-546' }
        if (($keep -join ',') -ne ($entries -join ',')) {
            $wanted[$right] = ($keep -join ',')
            $removedDeny = @($entries | Where-Object { $keep -notcontains $_ } | ForEach-Object { Resolve-SidName $_ })
            $notes += "$right : make sure Guests are denied$(if ($removedDeny) { '; take ' + ($removedDeny -join ', ') + ' OFF the deny list' })"
        }
    }
    if ($wanted.Count -gt 0) { Add-ReportDetail $notes; foreach ($n in $notes) { Write-Host "          $n" -ForegroundColor DarkGray } }
    if ($wanted.Count -eq 0) { Add-Result 'OK' 'User rights look normal'; return }
    Set-SecPolicy 'Privilege Rights' $wanted 'USER_RIGHTS' 'User rights assignment' | Out-Null
}

# ===========================================================================
# SECTION: Audit policy and event logs
# ===========================================================================
function Invoke-AuditPolicy {
    Write-Info 'Audit policy (what Windows writes to the Security event log)'
    Write-Why 'Without auditing there is no record of logins, account changes or policy changes.'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1 'DWord' 'Use the detailed (advanced) audit policy'
    $legacy = [ordered]@{ AuditSystemEvents = 3; AuditLogonEvents = 3; AuditObjectAccess = 3; AuditPrivilegeUse = 3; AuditPolicyChange = 3
                          AuditAccountManage = 3; AuditProcessTracking = 3; AuditDSAccess = 3; AuditAccountLogon = 3 }
    Set-SecPolicy 'Event Audit' $legacy 'SECURITYPOLICY' 'Basic audit policy: success and failure for every category' | Out-Null
    $rows = @()
    try { $rows = @(& auditpol.exe /get /category:* /r | Where-Object { $_.Trim() } | ConvertFrom-Csv | Where-Object { $_.Subcategory }) } catch { Write-HardenLog "skipped: $($_.Exception.Message)" }
    $weak = @($rows | Where-Object { $_.'Inclusion Setting' -ne 'Success and Failure' })
    if ($rows.Count -eq 0) { Add-Result 'FAILED' 'Could not read the audit policy (auditpol)' }
    elseif ($weak.Count -eq 0) { Add-Result 'OK' 'Every audit subcategory records success and failure' }
    else {
        Invoke-Fix "Audit success and failure for all $($rows.Count) subcategories ($($weak.Count) were not)" {
            & auditpol.exe /set /category:* /success:enable /failure:enable | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "auditpol exit code $LASTEXITCODE" }
        } | Out-Null
    }

    Write-Info 'Event log sizes'
    Write-Why "Small logs fill up and overwrite the evidence of an attack."
    $sizes = [ordered]@{ 'Security' = 196608KB; 'Application' = 32768KB; 'System' = 32768KB; 'Windows PowerShell' = 32768KB; 'Microsoft-Windows-PowerShell/Operational' = 65536KB }
    foreach ($log in $sizes.Keys) {
        $info = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
        if (-not $info) { continue }
        if ($info.MaximumSizeInBytes -ge $sizes[$log]) { Add-Result 'OK' ("{0} log is {1} MB" -f $log, [int]($info.MaximumSizeInBytes / 1MB)); continue }
        $l = $log; $bytes = $sizes[$log]
        Invoke-Fix ("{0} log size -> {1} MB (was {2} MB)" -f $l, [int]($bytes / 1MB), [int]($info.MaximumSizeInBytes / 1MB)) { & wevtutil.exe sl $l "/ms:$bytes"; if ($LASTEXITCODE -ne 0) { throw "wevtutil exit $LASTEXITCODE" } } | Out-Null
    }
    $svc = Get-Service -Name EventLog -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { Add-Result 'OK' 'Windows Event Log service is running' }
    else { Invoke-Fix 'Start the Windows Event Log service' { Set-Service EventLog -StartupType Automatic; Start-Service EventLog -ErrorAction Stop } | Out-Null }

    Write-Info 'PowerShell and command-line logging'
    Write-Why 'Records the commands attackers run, which helps with forensics questions too.'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 'DWord' 'PowerShell script block logging'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging' 1 'DWord' 'PowerShell module logging'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' '*' '*' 'String' 'PowerShell module logging for all modules'
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1 'DWord' 'Include the command line in process-creation events'
}

# ===========================================================================
# SECTION: Microsoft Defender
# ===========================================================================
function Invoke-Defender {
    Write-Info 'Microsoft Defender antivirus'
    Write-Why 'Defender finds and removes malware. Attackers turn it off or add "exclusions" so it ignores their files.'
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    Remove-RegValue $pol 'DisableAntiSpyware' 'No policy turning Defender off (DisableAntiSpyware)'
    Remove-RegValue $pol 'DisableAntiVirus' 'No policy turning Defender off (DisableAntiVirus)'
    foreach ($v in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection', 'DisableScanOnRealtimeEnable', 'DisableIOAVProtection')) {
        Remove-RegValue "$pol\Real-Time Protection" $v "No policy disabling real-time protection ($v)"
    }
    if (Test-Path "$pol\Exclusions") {
        $exKeys = @(Get-ChildItem "$pol\Exclusions" -ErrorAction SilentlyContinue | Where-Object { $_.ValueCount -gt 0 })
        if ($exKeys.Count -gt 0) {
            Add-Result 'REVIEW' 'Group Policy adds Defender exclusions (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions)'
            if (Confirm-Step 'Delete the policy exclusions?' 'y') {
                Backup-RegKey "$pol\Exclusions"
                Invoke-Fix 'Deleted Defender policy exclusions' { Remove-Item "$pol\Exclusions" -Recurse -Force -ErrorAction Stop } | Out-Null
            }
        }
    }
    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if (-not $svc) {
        Add-Result 'REVIEW' 'Microsoft Defender is not installed on this computer'
        if ($script:IsServer -and (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
            if (Confirm-Step 'Install the Windows Defender feature? (needs a reboot)' 'y') {
                Invoke-Fix 'Installed Windows Defender (reboot needed)' { Install-WindowsFeature -Name Windows-Defender -ErrorAction Stop | Out-Null } | Out-Null
            }
        }
        return
    }
    if ($svc.Status -ne 'Running') { Invoke-Fix 'Start the Defender service' { Start-Service WinDefend -ErrorAction Stop } | Out-Null }
    $mp = $null
    try { $mp = Get-MpPreference -ErrorAction Stop } catch { Add-Result 'FAILED' "Cannot read Defender settings - $($_.Exception.Message)"; return }
    $want = [ordered]@{
        DisableRealtimeMonitoring = $false; DisableBehaviorMonitoring = $false; DisableIOAVProtection = $false
        DisableScriptScanning = $false; DisableBlockAtFirstSeen = $false; DisableArchiveScanning = $false
        DisableRemovableDriveScanning = $false; DisableEmailScanning = $false; PUAProtection = 1; MAPSReporting = 2; SubmitSamplesConsent = 1
    }
    foreach ($k in $want.Keys) {
        $cur = $mp.$k
        if ($null -eq $cur) { continue }
        $match = if ($want[$k] -is [bool]) { [bool]$cur -eq $want[$k] } else { [int]$cur -eq $want[$k] }
        if ($match) { Add-Result 'OK' "Defender $k = $($want[$k])"; continue }
        $key = $k; $val = $want[$k]
        Invoke-Fix "Defender $key = $val (was $cur)" { $p = @{ $key = $val; ErrorAction = 'Stop' }; Set-MpPreference @p } | Out-Null
    }
    try {
        if ($mp.EnableNetworkProtection -ne 1) { Invoke-Fix 'Defender network protection on (blocks dangerous websites)' { Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop } | Out-Null }
        else { Add-Result 'OK' 'Defender network protection is on' }
    } catch { Write-HardenLog "skipped: $($_.Exception.Message)" }

    Write-Info 'Defender exclusions (folders, files and programs Defender is told to ignore)'
    $exclusions = @()
    foreach ($e in @($mp.ExclusionPath)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Path'; Value = $e } } }
    foreach ($e in @($mp.ExclusionExtension)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Extension'; Value = $e } } }
    foreach ($e in @($mp.ExclusionProcess)) { if ($e) { $exclusions += [pscustomobject]@{ Type = 'Process'; Value = $e } } }
    if ($exclusions.Count -eq 0) { Add-Result 'OK' 'No Defender exclusions' }
    foreach ($ex in $exclusions) {
        Add-Result 'REVIEW' "Defender ignores $($ex.Type): $($ex.Value)"
        if (Confirm-Step "Remove this exclusion?" 'y') {
            $t = $ex.Type; $v = $ex.Value
            Invoke-Fix "Removed Defender exclusion $t $v" {
                switch ($t) { 'Path' { Remove-MpPreference -ExclusionPath $v -ErrorAction Stop } 'Extension' { Remove-MpPreference -ExclusionExtension $v -ErrorAction Stop } 'Process' { Remove-MpPreference -ExclusionProcess $v -ErrorAction Stop } }
            } | Out-Null
        }
    }
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        if ($st.IsTamperProtected -eq $false) { Add-Result 'REVIEW' 'Tamper Protection is OFF - turn it on in Windows Security > Virus & threat protection > Manage settings (scripts cannot)' }
        if ($st.AntivirusSignatureAge -gt 1) {
            Invoke-Fix "Update Defender virus definitions (they are $($st.AntivirusSignatureAge) days old)" { Update-MpSignature -ErrorAction Stop } | Out-Null
        } else { Add-Result 'OK' 'Virus definitions are up to date' }
        Add-Result 'REVIEW' 'Run a Quick Scan when you have time: Windows Security > Virus & threat protection > Quick scan'
    } catch { Write-HardenLog "skipped: $($_.Exception.Message)" }
}

# ===========================================================================
# SECTION: Windows Firewall
# ===========================================================================
$FirewallGroupsForCritical = @(
    @{ Keys = @('rdp', 'remotedesktop', 'remote-desktop', 'termservice'); Group = 'Remote Desktop' }
    @{ Keys = @('iis', 'web', 'http', 'https', 'w3svc', 'webserver'); Group = 'World Wide Web Services (HTTP)' }
    @{ Keys = @('iis', 'web', 'https', 'webserver'); Group = 'Secure World Wide Web Services (HTTPS)' }
    @{ Keys = @('ftp', 'ftpsvc'); Group = 'FTP Server' }
    @{ Keys = @('smb', 'fileshare', 'file-sharing', 'filesharing', 'print', 'spooler'); Group = 'File and Printer Sharing' }
    @{ Keys = @('dns'); Group = 'DNS Service' }
    @{ Keys = @('dhcp'); Group = 'DHCP Server' }
    @{ Keys = @('ad', 'activedirectory', 'ad-ds', 'adds', 'ldap', 'domain'); Group = 'Active Directory Domain Services' }
    @{ Keys = @('winrm', 'remoting', 'powershell-remoting'); Group = 'Windows Remote Management' }
)

function Invoke-Firewall {
    Write-Info 'Firewall on for every network type'
    Write-Why 'The firewall blocks network connections you did not ask for.'
    $polBase = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
    foreach ($p in @('DomainProfile', 'StandardProfile', 'PublicProfile')) {
        if ((Get-RegValue "$polBase\$p" 'EnableFirewall') -eq 0) { Set-Reg "$polBase\$p" 'EnableFirewall' 1 'DWord' "Group Policy no longer turns the $p firewall off" }
        # Firewall defaults are never changed automatically (that could cut off the scoring report or a README service).
        if ((Get-RegValue "$polBase\$p" 'DefaultOutboundAction') -eq 1) {
            Add-Result 'REVIEW' "Group Policy makes the $p firewall block ALL outgoing connections (updates and the scoring report can stop working). Unless the README wants this, run: Remove-ItemProperty -Path '$polBase\$p' -Name DefaultOutboundAction"
        }
        if ((Get-RegValue "$polBase\$p" 'DefaultInboundAction') -eq 0) {
            Add-Result 'REVIEW' "Group Policy makes the $p firewall ALLOW all incoming connections. Fix: Set-ItemProperty -Path '$polBase\$p' -Name DefaultInboundAction -Value 1"
        }
    }
    foreach ($prof in @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        $n = $prof.Name
        if ($prof.Enabled -eq 'True' -or $prof.Enabled -eq $true) { Add-Result 'OK' "$n firewall is on" }
        else { Invoke-Fix "Turn on the $n firewall" { Set-NetFirewallProfile -Name $n -Enabled True -ErrorAction Stop } | Out-Null }
        if ("$($prof.DefaultInboundAction)" -eq 'Block') { Add-Result 'OK' "$n firewall blocks incoming connections by default" }
        else { Invoke-Fix "$n firewall: block incoming connections by default" { Set-NetFirewallProfile -Name $n -DefaultInboundAction Block -ErrorAction Stop } | Out-Null }
        if ("$($prof.DefaultOutboundAction)" -ne 'Block') { Add-Result 'OK' "$n firewall allows outgoing connections (needed for updates)" }
        else { Add-Result 'REVIEW' "$n firewall blocks ALL outgoing connections by default (updates and the scoring report can stop working). Unless the README wants this, run: Set-NetFirewallProfile -Name $n -DefaultOutboundAction Allow" }
        if ("$($prof.LogBlocked)" -ne 'True') {
            Invoke-Fix "$n firewall: log blocked connections" { Set-NetFirewallProfile -Name $n -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction Stop } | Out-Null
        }
        if ("$($prof.NotifyOnListen)" -ne 'True') {
            Invoke-Fix "$n firewall: tell the user when a program is blocked" { Set-NetFirewallProfile -Name $n -NotifyOnListen True -ErrorAction Stop } | Out-Null
        }
    }

    Write-Info 'Firewall rules for critical services'
    foreach ($entry in $FirewallGroupsForCritical) {
        if (-not (Test-Critical $entry.Keys)) { continue }
        $grp = $entry.Group
        $rules = @(Get-NetFirewallRule -DisplayGroup $grp -Direction Inbound -ErrorAction SilentlyContinue)
        if ($rules.Count -eq 0) { continue }
        if (@($rules | Where-Object { "$($_.Enabled)" -eq 'True' }).Count -gt 0) { Add-Result 'OK' "Inbound rules for '$grp' are enabled (critical service)" }
        else { Invoke-Fix "Enable firewall rules for '$grp' (critical service)" { Enable-NetFirewallRule -DisplayGroup $grp -ErrorAction Stop } | Out-Null }
    }

    Write-Info 'Custom inbound "allow" rules (an attacker may have opened a port)'
    $custom = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Where-Object { -not $_.DisplayGroup -and $_.DisplayName -notmatch $CpProtectRegex })
    if ($custom.Count -eq 0) { Add-Result 'OK' 'No custom inbound allow rules' }
    foreach ($r in $custom) {
        $app = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
        $port = ($r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
        $desc = "'$($r.DisplayName)' program=$app port=$($port.LocalPort)/$($port.Protocol)"
        $suspicious = ($app -match '\\(Users|Temp|ProgramData|PerfLogs)\\|\\(nc|ncat|netcat|nc64)\.exe$') -or ("$($port.LocalPort)" -match '^(4444|1337|31337|6666|6667|12345|5554|9999)$') -or ("$($port.LocalPort)" -eq 'Any' -and $app -eq 'Any')
        if ($suspicious) {
            Add-Result 'REVIEW' "SUSPICIOUS firewall rule: $desc"
            if (Confirm-Step "Disable firewall rule '$($r.DisplayName)'?" 'y') { $nm = $r.Name; Invoke-Fix "Disabled firewall rule $($r.DisplayName)" { Disable-NetFirewallRule -Name $nm -ErrorAction Stop } | Out-Null }
        } else {
            Add-Result 'REVIEW' "Custom firewall rule (keep only if the README needs it): $desc"
        }
    }
}

# ===========================================================================
# SECTION: Services
#   Kind: bad = insecure, disable unless critical
#         situational = fine if the README needs it, otherwise disable
#         careful = ask, never automatic
# ===========================================================================
$ServiceCatalog = @(
    @{ Name = 'TlntSvr';        Keys = @('telnet');                         Kind = 'bad';         Label = 'Telnet server' }
    @{ Name = 'RemoteRegistry'; Keys = @('remoteregistry');                 Kind = 'bad';         Label = 'Remote Registry' }
    @{ Name = 'SNMP';           Keys = @('snmp');                           Kind = 'bad';         Label = 'SNMP' }
    @{ Name = 'SNMPTRAP';       Keys = @('snmp');                           Kind = 'bad';         Label = 'SNMP Trap' }
    @{ Name = 'simptcp';        Keys = @('simptcp');                        Kind = 'bad';         Label = 'Simple TCP/IP services' }
    @{ Name = 'Fax';            Keys = @('fax');                            Kind = 'bad';         Label = 'Fax' }
    @{ Name = 'SSDPSRV';        Keys = @('ssdp', 'upnp');                   Kind = 'situational'; Label = 'SSDP Discovery' }
    @{ Name = 'upnphost';       Keys = @('upnp');                           Kind = 'situational'; Label = 'UPnP Device Host' }
    @{ Name = 'SharedAccess';   Keys = @('ics', 'internet-connection-sharing'); Kind = 'situational'; Label = 'Internet Connection Sharing' }
    @{ Name = 'RemoteAccess';   Keys = @('rras', 'routing', 'vpn');         Kind = 'situational'; Label = 'Routing and Remote Access' }
    @{ Name = 'W3SVC';          Keys = @('iis', 'web', 'http', 'https', 'w3svc', 'webserver'); Kind = 'situational'; Label = 'IIS web server' }
    @{ Name = 'WAS';            Keys = @('iis', 'web', 'http', 'https', 'w3svc', 'webserver', 'ftp'); Kind = 'situational'; Label = 'IIS process activation' }
    @{ Name = 'FTPSVC';         Keys = @('ftp', 'ftpsvc');                  Kind = 'situational'; Label = 'IIS FTP server' }
    @{ Name = 'Spooler';        Keys = @('print', 'printing', 'printer', 'spooler'); Kind = 'situational'; Label = 'Print Spooler' }
    @{ Name = 'WebClient';      Keys = @('webdav', 'webclient');            Kind = 'situational'; Label = 'WebClient (WebDAV)' }
    @{ Name = 'WMPNetworkSvc';  Keys = @('mediasharing');                   Kind = 'situational'; Label = 'Windows Media Player sharing' }
    @{ Name = 'icssvc';         Keys = @('hotspot');                        Kind = 'situational'; Label = 'Mobile hotspot' }
    @{ Name = 'p2psvc';         Keys = @('p2p');                            Kind = 'situational'; Label = 'Peer networking' }
    @{ Name = 'PNRPsvc';        Keys = @('p2p');                            Kind = 'situational'; Label = 'Peer name resolution' }
    @{ Name = 'XblAuthManager'; Keys = @('xbox', 'games');                  Kind = 'situational'; Label = 'Xbox Live Auth Manager' }
    @{ Name = 'XblGameSave';    Keys = @('xbox', 'games');                  Kind = 'situational'; Label = 'Xbox Live Game Save' }
    @{ Name = 'XboxNetApiSvc';  Keys = @('xbox', 'games');                  Kind = 'situational'; Label = 'Xbox Live Networking' }
    @{ Name = 'XboxGipSvc';     Keys = @('xbox', 'games');                  Kind = 'situational'; Label = 'Xbox Accessory Management' }
    @{ Name = 'MSSQLSERVER';    Keys = @('sql', 'mssql', 'sqlserver', 'database'); Kind = 'situational'; Label = 'SQL Server' }
    @{ Name = 'MySQL';          Keys = @('mysql', 'database');              Kind = 'situational'; Label = 'MySQL' }
    @{ Name = 'MySQL80';        Keys = @('mysql', 'database');              Kind = 'situational'; Label = 'MySQL 8' }
    @{ Name = 'Apache2.4';      Keys = @('apache', 'web', 'http');          Kind = 'situational'; Label = 'Apache web server' }
    @{ Name = 'nginx';          Keys = @('nginx', 'web', 'http');           Kind = 'situational'; Label = 'nginx web server' }
    @{ Name = 'FileZilla Server'; Keys = @('ftp', 'filezilla');             Kind = 'situational'; Label = 'FileZilla FTP server' }
    @{ Name = 'TermService';    Keys = @('rdp', 'remotedesktop', 'remote-desktop', 'termservice'); Kind = 'careful'; Label = 'Remote Desktop Services' }
    @{ Name = 'sshd';           Keys = @('ssh', 'openssh', 'sshd');         Kind = 'careful';     Label = 'OpenSSH server' }
    @{ Name = 'WinRM';          Keys = @('winrm', 'remoting', 'powershell-remoting'); Kind = 'careful'; Label = 'Windows Remote Management (WinRM)' }
    @{ Name = 'TeamViewer';     Keys = @('teamviewer');                     Kind = 'bad';         Label = 'TeamViewer' }
    @{ Name = 'AnyDesk';        Keys = @('anydesk');                        Kind = 'bad';         Label = 'AnyDesk' }
    @{ Name = 'tvnserver';      Keys = @('vnc');                            Kind = 'bad';         Label = 'TightVNC server' }
    @{ Name = 'uvnc_service';   Keys = @('vnc');                            Kind = 'bad';         Label = 'UltraVNC server' }
    @{ Name = 'vncserver';      Keys = @('vnc');                            Kind = 'bad';         Label = 'RealVNC server' }
)
$CoreServices = @(
    @{ Name = 'EventLog';  Label = 'Windows Event Log';      Start = 'Automatic' }
    @{ Name = 'mpssvc';    Label = 'Windows Firewall';       Start = 'Automatic' }
    @{ Name = 'WinDefend'; Label = 'Microsoft Defender';     Start = 'Automatic' }
    @{ Name = 'wuauserv';  Label = 'Windows Update';         Start = 'Manual' }
    @{ Name = 'BITS';      Label = 'Background Intelligent Transfer (used by updates)'; Start = 'Manual' }
    @{ Name = 'wscsvc';    Label = 'Security Center';        Start = 'Automatic' }
    @{ Name = 'CryptSvc';  Label = 'Cryptographic Services'; Start = 'Automatic' }
)

function Disable-ServiceNow([string]$Name) {
    Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
    Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
}

function Invoke-Services {
    Write-Info 'Checking services against the README'
    Write-Why 'Every running service is something an attacker can try to break into. Keep only what the README needs.'
    foreach ($entry in $ServiceCatalog) {
        $svc = Get-Service -Name $entry.Name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ($script:IsDC -and $DcProtectedServices -contains $svc.Name) { continue }
        $label = "$($entry.Label) ($($svc.Name))"
        if (Test-Critical $entry.Keys) {
            if ($svc.StartType -eq 'Disabled' -or $svc.Status -ne 'Running') {
                $n = $svc.Name
                Invoke-Fix "Start critical service $label (README says it must run)" { Set-Service -Name $n -StartupType Automatic -ErrorAction Stop; Start-Service -Name $n -ErrorAction Stop } | Out-Null
            } else { Add-Result 'OK' "Critical service $label is running (keeping it)" }
            continue
        }
        if ($svc.StartType -eq 'Disabled' -and $svc.Status -ne 'Running') { Add-Result 'OK' "$label is disabled"; continue }
        $n = $svc.Name
        switch ($entry.Kind) {
            'bad' {
                Add-Result 'REVIEW' "$label is enabled - it is insecure and the README doesn't list it"
                if (Confirm-Step "Stop and disable $label?" 'y') { Invoke-Fix "Stopped and disabled $label" { Disable-ServiceNow $n } | Out-Null }
            }
            'situational' {
                Add-Result 'REVIEW' "$label is enabled but the README doesn't list it as critical"
                if (Confirm-Step "Stop and disable $label?" 'y') { Invoke-Fix "Stopped and disabled $label" { Disable-ServiceNow $n } | Out-Null }
            }
            'careful' {
                Add-Result 'REVIEW' "$label is enabled but not listed as critical in the README"
                if (Confirm-Step "Stop and disable $label? (say NO if anyone needs to connect remotely)" 'n' -Strict) { Invoke-Fix "Stopped and disabled $label" { Disable-ServiceNow $n } | Out-Null }
            }
        }
    }

    Write-Info 'Security services that must be running'
    foreach ($c in $CoreServices) {
        $svc = Get-Service -Name $c.Name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $n = $c.Name; $start = $c.Start
        if ($svc.StartType -eq 'Disabled') {
            Invoke-Fix "Re-enable $($c.Label) (it was disabled)" { Set-Service -Name $n -StartupType $start -ErrorAction Stop; if ($start -eq 'Automatic') { Start-Service -Name $n -ErrorAction SilentlyContinue } } | Out-Null
        } elseif ($start -eq 'Automatic' -and $svc.Status -ne 'Running') {
            Invoke-Fix "Start $($c.Label)" { Start-Service -Name $n -ErrorAction Stop } | Out-Null
        } else { Add-Result 'OK' "$($c.Label) is enabled" }
    }
}

# ===========================================================================
# SECTION: Windows features
# ===========================================================================
function Invoke-Features {
    Write-Info 'Old and risky Windows features'
    Write-Why 'SMBv1 was used by WannaCry; Telnet/TFTP send passwords in plain text; PowerShell 2 skips modern logging.'
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smb.EnableSMB1Protocol) { Invoke-Fix 'SMBv1 server protocol off' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop } | Out-Null }
        else { Add-Result 'OK' 'SMBv1 server protocol is off' }
        if (-not $smb.RequireSecuritySignature) { Invoke-Fix 'SMB server requires signing' { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop } | Out-Null }
    } catch { Write-HardenLog "skipped: $($_.Exception.Message)" }

    if ($script:IsServer -and (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
        $features = @{ 'FS-SMB1' = 'SMBv1'; 'Telnet-Client' = 'Telnet client'; 'TFTP-Client' = 'TFTP client'; 'PowerShell-V2' = 'PowerShell 2.0'; 'Simple-TCPIP' = 'Simple TCP/IP services'; 'SNMP-Service' = 'SNMP' }
        if (-not (Test-Critical @('ftp', 'ftpsvc'))) { $features['Web-Ftp-Server'] = 'IIS FTP server' }
        foreach ($f in $features.Keys) {
            $feat = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
            if (-not $feat) { continue }
            if (-not $feat.Installed) { Add-Result 'OK' "$($features[$f]) is not installed"; continue }
            Add-Result 'REVIEW' "$($features[$f]) feature is installed"
            if (Confirm-Step "Remove the $($features[$f]) feature?" 'y') { $fn = $f; Invoke-Fix "Removed $($features[$fn]) feature" { Uninstall-WindowsFeature -Name $fn -ErrorAction Stop | Out-Null } | Out-Null }
        }
        if (-not (Test-Critical @('iis', 'web', 'http', 'https', 'w3svc', 'webserver', 'ftp'))) {
            $iis = Get-WindowsFeature -Name 'Web-Server' -ErrorAction SilentlyContinue
            if ($iis -and $iis.Installed) {
                Add-Result 'REVIEW' 'The IIS web server role is installed but the README does not list a web server'
                if (Confirm-Step 'Remove the IIS web server role?' 'n' -Strict) { Invoke-Fix 'Removed the IIS role' { Uninstall-WindowsFeature -Name Web-Server -IncludeManagementTools -ErrorAction Stop | Out-Null } | Out-Null }
            }
        }
        return
    }

    $opt = @{}
    try { foreach ($f in @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)) { $opt[$f.FeatureName] = "$($f.State)" } } catch { Add-Result 'FAILED' "Cannot list Windows features - $($_.Exception.Message)"; return }
    $remove = [ordered]@{
        'SMB1Protocol' = 'SMBv1'; 'SMB1Protocol-Client' = 'SMBv1 client'; 'SMB1Protocol-Server' = 'SMBv1 server'
        'TelnetClient' = 'Telnet client'; 'TFTP' = 'TFTP client'; 'TelnetServer' = 'Telnet server'; 'SimpleTCP' = 'Simple TCP/IP services'
        'MicrosoftWindowsPowerShellV2Root' = 'PowerShell 2.0'; 'MicrosoftWindowsPowerShellV2' = 'PowerShell 2.0 engine'
        'Internet-Explorer-Optional-amd64' = 'Internet Explorer 11'
    }
    if (-not (Test-Critical @('iis', 'web', 'http', 'https', 'w3svc', 'webserver'))) { $remove['IIS-WebServerRole'] = 'IIS web server' }
    if (-not (Test-Critical @('ftp', 'ftpsvc'))) { $remove['IIS-FTPServer'] = 'IIS FTP server' }
    foreach ($name in $remove.Keys) {
        if (-not $opt.ContainsKey($name)) { continue }
        if ($opt[$name] -ne 'Enabled') { Add-Result 'OK' "$($remove[$name]) is off"; continue }
        $fn = $name; $lbl = $remove[$name]
        $default = if ($fn -like 'IIS-*') { 'n' } else { 'y' }
        Add-Result 'REVIEW' "$lbl is turned on"
        if (Confirm-Step "Turn off $lbl?" $default) { Invoke-Fix "Turned off $lbl (may need a reboot)" { Disable-WindowsOptionalFeature -Online -FeatureName $fn -NoRestart -ErrorAction Stop | Out-Null } | Out-Null }
    }
    if ($opt['Microsoft-Windows-Subsystem-Linux'] -eq 'Enabled') { Add-Result 'REVIEW' 'Windows Subsystem for Linux is turned on - turn it off if the README does not need it' }
    try {
        $sshCap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop | Where-Object { $_.State -eq 'Installed' }
        if ($sshCap -and -not (Test-Critical @('ssh', 'openssh', 'sshd'))) { Add-Result 'REVIEW' 'The OpenSSH server is installed but the README does not list SSH (Settings > Apps > Optional features)' }
    } catch { Write-HardenLog "skipped: $($_.Exception.Message)" }
}

# ===========================================================================
# SECTION: Remote access
# ===========================================================================
function Invoke-RemoteAccess {
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpTcp = "$ts\WinStations\RDP-Tcp"
    # A Group Policy value here wins over the normal settings below (reported only: Remote Desktop can lock people out).
    $tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $polDeny = Get-RegValue $tsPol 'fDenyTSConnections'
    $polNla = Get-RegValue $tsPol 'UserAuthentication'
    Write-Info 'Remote Desktop'
    if (Test-Critical @('rdp', 'remotedesktop', 'remote-desktop', 'termservice')) {
        if ($polDeny -eq 1) { Add-Result 'REVIEW' "Group Policy turns Remote Desktop OFF, but the README needs it. Fix: Remove-ItemProperty -Path '$tsPol' -Name fDenyTSConnections" }
        if ($null -ne $polNla -and $polNla -eq 0) { Add-Result 'REVIEW' "Group Policy turns off Network Level Authentication for Remote Desktop. Fix: Set-ItemProperty -Path '$tsPol' -Name UserAuthentication -Value 1" }
        Write-Why 'The README needs Remote Desktop, so keep it on but make it safer (Network Level Authentication, strong encryption).'
        Set-Reg $ts 'fDenyTSConnections' 0 'DWord' 'Remote Desktop stays ON (critical service)'
        Set-Reg $rdpTcp 'UserAuthentication' 1 'DWord' 'Remote Desktop requires Network Level Authentication'
        Set-Reg $rdpTcp 'SecurityLayer' 2 'DWord' 'Remote Desktop uses TLS'
        Set-Reg $rdpTcp 'MinEncryptionLevel' 3 'DWord' 'Remote Desktop uses high encryption'
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fPromptForPassword' 1 'DWord' 'Remote Desktop always asks for a password'
        Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fDisableCdm' 1 'DWord' "Remote Desktop can't map the remote user's drives"
    } else {
        Write-Why 'Remote Desktop lets people log in over the network. The README does not need it.'
        if ($polDeny -eq 0) { Add-Result 'REVIEW' "Group Policy turns Remote Desktop ON, which beats the normal setting. If the README doesn't need it: Remove-ItemProperty -Path '$tsPol' -Name fDenyTSConnections" }
        if ((Get-RegValue $ts 'fDenyTSConnections') -ne 1) {
            Add-Result 'REVIEW' 'Remote Desktop is ON but the README does not list it'
            if (Confirm-Step 'Turn off Remote Desktop?' 'y') {
                Set-Reg $ts 'fDenyTSConnections' 1 'DWord' 'Remote Desktop is OFF'
                Invoke-Fix 'Disable the Remote Desktop firewall rules' { Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop } | Out-Null
            }
        } else { Add-Result 'OK' 'Remote Desktop is off' }
    }
    Write-Info 'Remote Assistance'
    Write-Why 'Remote Assistance lets someone take control of the screen when invited.'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp' 0 'DWord' 'Remote Assistance is off'
    Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowFullControl' 0 'DWord' 'Remote Assistance cannot take full control'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited' 0 'DWord' 'No unsolicited Remote Assistance offers'
    Write-Info 'Windows Remote Management (WinRM) security'
    $wrm = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM'
    Set-Reg "$wrm\Service" 'AllowBasic' 0 'DWord' 'WinRM service: no Basic (plain-text) authentication'
    Set-Reg "$wrm\Service" 'AllowUnencryptedTraffic' 0 'DWord' 'WinRM service: no unencrypted traffic'
    Set-Reg "$wrm\Service" 'DisableRunAs' 1 'DWord' 'WinRM service: no stored RunAs credentials'
    Set-Reg "$wrm\Client" 'AllowBasic' 0 'DWord' 'WinRM client: no Basic authentication'
    Set-Reg "$wrm\Client" 'AllowUnencryptedTraffic' 0 'DWord' 'WinRM client: no unencrypted traffic'
}

# ===========================================================================
# SECTION: File shares
# ===========================================================================
function Invoke-Shares {
    Write-Info 'Shared folders'
    Write-Why 'A share lets other computers read (or change) files over the network.'
    $fileShareCritical = Test-Critical @('smb', 'fileshare', 'file-sharing', 'filesharing')
    $defaults = @('ADMIN$', 'IPC$', 'print$')
    if ($script:IsDC) { $defaults += @('NETLOGON', 'SYSVOL') }
    $shares = @()
    try { $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $defaults -notcontains $_.Name -and $_.Name -notmatch '^[A-Z]\$$' }) } catch { Add-Result 'FAILED' 'Cannot list shares'; return }
    if ($shares.Count -eq 0) { Add-Result 'OK' 'Only the built-in shares exist' }
    foreach ($s in $shares) {
        $access = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ', '
        Add-Result 'REVIEW' "Share '$($s.Name)' -> $($s.Path)  [$access]"
        $sn = $s.Name
        if (-not $fileShareCritical) {
            if (Confirm-Step "Remove share '$sn'? (the folder and files stay, only the sharing stops)" 'y') {
                Invoke-Fix "Stopped sharing '$sn'" { Remove-SmbShare -Name $sn -Force -ErrorAction Stop } | Out-Null
            }
        } elseif ($access -match 'Everyone:(Full|Change)') {
            if (Confirm-Step "Share '$sn' lets Everyone write. Remove Everyone's access?" 'y') {
                Invoke-Fix "Removed Everyone from share '$sn'" { Revoke-SmbShareAccess -Name $sn -AccountName 'Everyone' -Force -ErrorAction Stop | Out-Null } | Out-Null
            }
        }
    }
}

# ===========================================================================
# SECTION: Prohibited software
# ===========================================================================
$SoftwarePatterns = [ordered]@{
    'hacking tool'       = 'wireshark|\bnmap\b|zenmap|npcap|winpcap|cain\b|abel\b|john the ripper|hashcat|\bhydra\b|metasploit|burp ?suite|ophcrack|aircrack|netcat|\bncat\b|angry ip|advanced ip scanner|nirsoft|mimikatz|l0phtcrack|lophtcrack|nessus|openvas|nikto|sqlmap|ettercap|maltego|cheat engine|keylog|ardamax|spyrix|refog|revealer|wifi password|password recovery|brutus|\bthc-|lazagne|responder|bloodhound'
    'game'               = '\bsteam\b|epic games|minecraft|roblox|\borigin\b|\bea app\b|battle\.net|ubisoft|uplay|gog galaxy|league of legends|riot client|fortnite|valorant|counter-strike|solitaire|candy crush|chess titans|pinball|world of warcraft|blizzard|\bosu!'
    'file-sharing (P2P)' = 'utorrent|bittorrent|qbittorrent|vuze|azureus|frostwire|limewire|kazaa|\bemule\b|shareaza|deluge|transmission|tixati|bitcomet|ares galaxy|soulseek'
    'remote-access tool' = 'teamviewer|anydesk|tightvnc|realvnc|ultravnc|tigervnc|vnc server|logmein|splashtop|ammyy|radmin|rustdesk|chrome remote desktop|remote utilities|supremo|dameware|netsupport|screenconnect|connectwise control'
}
$SoftwareReviewPattern = 'ccleaner|itunes|spotify|discord|skype|tor browser|free download manager|babylon|toolbar|conduit|mywebsearch|driver booster|pc optimizer|pc cleaner|reimage|webadvisor|ask\.com|bonzi|wallpaper engine'
$AppxPattern = 'MicrosoftSolitaireCollection|CandyCrush|BubbleWitch|MarchofEmpires|Minecraft|Roblox|king\.com|HiddenCity|FarmHeroes|Asphalt|DragonManiaLegends|MicrosoftMahjong|MicrosoftSudoku|MicrosoftMinesweeper|MicrosoftJigsaw|Disney|Spotify'

function Get-InstalledPrograms {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($h in @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $paths += "Registry::HKEY_USERS\$($h.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    return @(Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 } |
             Sort-Object DisplayName -Unique)
}

function Uninstall-Program($Program) {
    $cmd = $Program.QuietUninstallString
    if (-not $cmd -and $Program.UninstallString -match '\{[0-9A-Fa-f\-]{36}\}' -and $Program.UninstallString -match '(?i)msiexec') {
        $cmd = "msiexec.exe /x $($Matches[0]) /qn /norestart"
    }
    if (-not $cmd) { throw "it has no silent uninstaller" }
    Write-HardenLog "UNINSTALL $($Program.DisplayName): $cmd"
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$cmd`"" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -notin @(0, 1605, 3010)) { throw "uninstaller exit code $($p.ExitCode)" }
}

function Invoke-Software {
    Write-Info 'Looking for hacking tools, games, file-sharing and remote-access programs'
    Write-Why 'These are "prohibited software" on almost every image.'
    $programs = Get-InstalledPrograms
    $found = 0
    foreach ($category in $SoftwarePatterns.Keys) {
        foreach ($p in @($programs | Where-Object { $_.DisplayName -match "(?i)$($SoftwarePatterns[$category])" })) {
            $name = $p.DisplayName
            if (Test-Critical @(($name -split '\s')[0])) { Add-Result 'OK' "Keeping $name (listed in the README)"; continue }
            $found++
            Add-Result 'REVIEW' "Found $category`: $name $($p.DisplayVersion)"
            if (-not (Confirm-Step "Uninstall '$name'?" 'y')) { continue }
            $prog = $p
            if ($prog.QuietUninstallString -or ($prog.UninstallString -match '(?i)msiexec')) {
                Invoke-Fix "Uninstalled $name" { Uninstall-Program $prog } | Out-Null
            } elseif (-not $script:AssumeYes -and $prog.UninstallString) {
                Write-Warn "This program has no silent uninstaller. Its own uninstaller will open - click through it."
                Invoke-Fix "Ran the uninstaller for $name (check it finished)" { Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$($prog.UninstallString)`"" -Wait } | Out-Null
            } else {
                Add-Result 'REVIEW' "Remove '$name' by hand: Settings > Apps > Installed apps"
            }
        }
    }
    if ($found -eq 0) { Add-Result 'OK' 'No prohibited programs found in the installed programs list' }
    $maybe = @($programs | Where-Object { $_.DisplayName -match "(?i)$SoftwareReviewPattern" } | ForEach-Object { $_.DisplayName })
    if ($maybe.Count -gt 0) { Add-Result 'REVIEW' "Programs that are sometimes prohibited (check the README): $($maybe -join ', ')" }

    Write-Info 'Store apps (games and similar)'
    try {
        $appx = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.Name -match $AppxPattern })
        if ($appx.Count -eq 0) { Add-Result 'OK' 'No game Store apps found' }
        foreach ($a in $appx) {
            Add-Result 'REVIEW' "Store app: $($a.Name)"
            if (Confirm-Step "Remove Store app '$($a.Name)'?" 'y') {
                $full = $a.PackageFullName; $an = $a.Name
                Invoke-Fix "Removed Store app $an" {
                    Remove-AppxPackage -Package $full -AllUsers -ErrorAction Stop
                    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $an } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
                } | Out-Null
            }
        }
    } catch { Write-HardenLog "Appx check skipped: $($_.Exception.Message)" }
    Add-Result 'REVIEW' 'Also look through Settings > Apps > Installed apps yourself - not every program can be recognized by name'
}

# ===========================================================================
# SECTION: Prohibited files
# ===========================================================================
function Get-SearchRoots {
    $skip = @('Windows', 'Program Files', 'Program Files (x86)', 'ProgramData', 'Users', '$Recycle.Bin', 'System Volume Information', 'Recovery',
              'PerfLogs', 'Config.Msi', 'Documents and Settings', 'harden-toolkit', '$WinREAgent', '$SysReset', '$Windows.~BT', '$Windows.~WS', 'OneDriveTemp', 'MSOCache', 'Boot')
    $roots = @("$env:SystemDrive\Users")
    $roots += @(Get-ChildItem "$env:SystemDrive\" -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $skip -notcontains $_.Name -and $_.Name -notmatch $CpProtectRegex } | ForEach-Object { $_.FullName })
    return $roots
}

# Deletes each path literally: names like "song [remix].mp3" are not wildcards
function Remove-FileList([string[]]$Paths) {
    foreach ($p in $Paths) { Remove-Item -LiteralPath $p -Force -ErrorAction Stop }
}

function Invoke-Files {
    Write-Info 'Looking for media files (music, videos) and other files that break policy'
    Write-Why 'Company policy on CyberPatriot images usually bans personal media and hacking tools. Each one removed is often worth points.'
    Write-Warn 'Answer the FORENSICS QUESTIONS first - they sometimes ask about these files!'
    $media = @('.mp3', '.mp4', '.m4a', '.m4v', '.wav', '.wma', '.wmv', '.flac', '.aac', '.ogg', '.avi', '.mkv', '.mov', '.flv', '.mpg', '.mpeg', '.webm', '.3gp', '.aiff', '.mid', '.torrent')
    $skipPath = '(?i)\\AppData\\Local\\(Microsoft|Packages)\\|\\AppData\\Roaming\\Microsoft\\(Windows\\Recent|Teams)|cyberpatriot|\\harden-toolkit\\'
    $toolRegex = '(?i)^(nc|nc64|ncat|netcat|nmap|zenmap|mimikatz.*|pwdump.*|fgdump.*|wce|procdump(64)?|psexec(64)?|lazagne.*|rubeus.*|sharphound.*|bloodhound.*|john.*|hashcat.*|hydra.*|cain.*|keylog.*|.*backdoor.*|.*rootkit.*|xmrig.*|.*miner.*)\.(exe|ps1|bat|py|zip|7z)$'
    $dataRegex = '(?i)(\.pcapng?$|\.cap$|password|passwd|creditcard|credit_card|\bssn\b|\.kdbx$|rockyou|wordlist|hashes)'
    $mediaFiles = @(); $tools = @(); $data = @()
    foreach ($root in Get-SearchRoots) {
        foreach ($f in @(Get-ChildItem -Path $root -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.FullName -match $skipPath) { continue }
            if ($media -contains $f.Extension.ToLower()) { $mediaFiles += $f.FullName }
            elseif ($f.Name -match $toolRegex) { $tools += $f.FullName }
            elseif ($f.Name -match $dataRegex -and $f.Extension -match '(?i)^\.(txt|csv|xlsx?|docx?|pcapng|pcap|cap|kdbx|lst)$') { $data += $f.FullName }
        }
    }
    foreach ($f in @(Get-ChildItem "$env:SystemDrive\" -File -Force -ErrorAction SilentlyContinue)) {
        if ($media -contains $f.Extension.ToLower()) { $mediaFiles += $f.FullName }
    }
    foreach ($f in @(Get-ChildItem "$env:SystemRoot\Temp" -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -match $toolRegex) { $tools += $f.FullName }
    }
    if ($mediaFiles.Count -eq 0) { Add-Result 'OK' 'No media files found' }
    else {
        Add-Result 'REVIEW' "Found $($mediaFiles.Count) media/torrent file(s)"
        Show-List $mediaFiles 20
        if (Confirm-Step "Delete ALL $($mediaFiles.Count) media/torrent files listed above?" 'y') {
            $list = $mediaFiles
            Invoke-Fix "Deleted $($list.Count) media/torrent files" { Remove-FileList $list } | Out-Null
        }
    }
    if ($tools.Count -eq 0) { Add-Result 'OK' 'No hacking tool files found' }
    else {
        Add-Result 'REVIEW' "Found $($tools.Count) hacking tool / malware file(s)"
        Show-List $tools 20
        if (Confirm-Step "Delete these $($tools.Count) file(s)?" 'y') {
            $list = $tools
            Invoke-Fix "Deleted $($list.Count) hacking tool files" { Remove-FileList $list } | Out-Null
        }
    }
    if ($data.Count -eq 0) { Add-Result 'OK' 'No password lists or packet captures found' }
    else {
        Add-Result 'REVIEW' "Found $($data.Count) file(s) that may hold passwords or stolen data - open and check each one"
        Show-List $data 20
        if (Confirm-Step "Delete these $($data.Count) file(s)? (only if you have checked them)" 'n' -Strict) {
            $list = $data
            Invoke-Fix "Deleted $($list.Count) data files" { Remove-FileList $list } | Out-Null
        }
    }
    Add-Result 'REVIEW' "Empty the Recycle Bin when you are done with forensics (files there still count)"
}

# ===========================================================================
# SECTION: Backdoors and persistence
# ===========================================================================
$SuspiciousCmdRegex = '(?i)(powershell|pwsh).*(-enc|-e\s|-w(indowstyle)?\s+h|downloadstring|downloadfile|iex|invoke-expression|frombase64|bypass)|\\(nc|ncat|netcat|nc64)\.exe|\bnc(64)?\s+-|mshta|rundll32.*(javascript|http)|regsvr32.*(/i:|scrobj)|certutil.*(-urlcache|-decode)|bitsadmin|\\Temp\\|\\Users\\Public\\|\\PerfLogs\\|\.(bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf|scr)(\s|"|$)'

function Get-UserHives {
    return @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)" })
}

function Invoke-Backdoors {
    Write-Info 'Programs that start automatically (Run keys)'
    Write-Why 'Malware adds itself here so it starts every time someone logs in.'
    $runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
                 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    foreach ($h in Get-UserHives) { $runKeys += @("$h\Software\Microsoft\Windows\CurrentVersion\Run", "$h\Software\Microsoft\Windows\CurrentVersion\RunOnce") }
    $count = 0
    foreach ($key in $runKeys) {
        $item = Get-Item -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        foreach ($name in $item.GetValueNames()) {
            if (-not $name) { continue }
            $data = "$($item.GetValue($name))"
            if ($data -match $CpProtectRegex) { continue }
            $count++
            if ($data -match $SuspiciousCmdRegex) {
                Add-Result 'REVIEW' "SUSPICIOUS startup entry '$name': $data"
                if (Confirm-Step "Delete startup entry '$name'?" 'y') {
                    $k = $key; $n = $name
                    Backup-RegKey $k
                    Invoke-Fix "Deleted startup entry $n" { Remove-ItemProperty -LiteralPath $k -Name $n -ErrorAction Stop } | Out-Null
                }
            } else {
                Add-Result 'REVIEW' "Startup entry '$name': $data"
            }
        }
    }
    if ($count -eq 0) { Add-Result 'OK' 'No programs in the Run keys' }

    Write-Info 'Startup folders'
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $dirs += @(Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' })
    $shell = New-Object -ComObject WScript.Shell
    foreach ($d in $dirs) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $target = $f.FullName
            if ($f.Extension -eq '.lnk') { try { $lnk = $shell.CreateShortcut($f.FullName); $target = "$($lnk.TargetPath) $($lnk.Arguments)" } catch { Write-HardenLog "shortcut unreadable: $($f.FullName)" } }
            if ($f.Extension -match '(?i)^\.(bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf|scr|exe)$' -or $target -match $SuspiciousCmdRegex) {
                Add-Result 'REVIEW' "SUSPICIOUS startup item: $($f.FullName) -> $target"
                if (Confirm-Step "Delete $($f.Name)?" 'y') {
                    $path = $f.FullName
                    Copy-Item -LiteralPath $path -Destination $BackupDir -Force -ErrorAction SilentlyContinue
                    Invoke-Fix "Deleted startup item $path" { Remove-Item -LiteralPath $path -Force -ErrorAction Stop } | Out-Null
                }
            } else { Add-Result 'REVIEW' "Startup item: $($f.FullName) -> $target" }
        }
    }

    Write-Info 'Scheduled tasks'
    Write-Why 'A scheduled task can re-start a backdoor every few minutes, even after you delete it.'
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { "$($_.TaskPath)$($_.TaskName)" -notmatch $CpProtectRegex })
    $nonMs = 0
    foreach ($t in $tasks) {
        $actions = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; '
        $isMs = $t.TaskPath -like '\Microsoft\*'
        if ($actions -match $SuspiciousCmdRegex) {
            Add-Result 'REVIEW' "SUSPICIOUS scheduled task $($t.TaskPath)$($t.TaskName): $actions"
            if (Confirm-Step "Delete scheduled task '$($t.TaskName)'?" 'y') {
                $tn = $t.TaskName; $tp = $t.TaskPath
                try { Export-ScheduledTask -TaskName $tn -TaskPath $tp | Out-File (Join-Path $BackupDir ("task-" + ($tn -replace '[\\/:*?"<>|]', '_') + '.xml')) } catch { Write-HardenLog "skipped: $($_.Exception.Message)" }
                Invoke-Fix "Deleted scheduled task $tp$tn" { Unregister-ScheduledTask -TaskName $tn -TaskPath $tp -Confirm:$false -ErrorAction Stop } | Out-Null
            }
        } elseif (-not $isMs) {
            $nonMs++
            Add-Result 'REVIEW' "Non-Microsoft scheduled task $($t.TaskPath)$($t.TaskName): $actions"
        }
    }
    if ($nonMs -eq 0) { Add-Result 'OK' 'No unusual scheduled tasks' }

    Write-Info 'Services running from unusual folders'
    foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
        $path = "$($s.PathName)"
        if (-not $path -or $path -match $CpProtectRegex -or $s.Name -match $CpProtectRegex) { continue }
        if ($path -match '(?i)^"?[A-Z]:\\Windows\\' -or $path -match '(?i)^"?[A-Z]:\\Program Files') {
            if ($path -notmatch '^"' -and $path -match '(?i)^[A-Z]:\\[^"]* [^"]*\.exe') {
                Add-Result 'REVIEW' "Service '$($s.Name)' has an UNQUOTED path with spaces (privilege-escalation risk): $path"
                if (Confirm-Step "Add quotes around the path of '$($s.Name)'?" 'y') {
                    $exe = [regex]::Match($path, '(?i)^.*?\.exe').Value
                    $rest = $path.Substring($exe.Length)
                    Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" 'ImagePath' "`"$exe`"$rest" 'ExpandString' "Quoted the path of service $($s.Name)"
                }
            }
            continue
        }
        if ($path -match $SuspiciousCmdRegex -or $path -match '(?i)\\(Users|ProgramData|Temp)\\') {
            Add-Result 'REVIEW' "SUSPICIOUS service '$($s.Name)' ($($s.DisplayName)): $path"
            if (Confirm-Step "Stop and disable service '$($s.Name)'?" 'y') { $n = $s.Name; Invoke-Fix "Stopped and disabled service $n" { Disable-ServiceNow $n } | Out-Null }
        } else {
            Add-Result 'REVIEW' "Service '$($s.Name)' runs from an unusual folder: $path"
        }
    }

    Write-Info 'Hijacked accessibility tools (sticky keys backdoor)'
    Write-Why 'Replacing sethc.exe (Sticky Keys) or utilman.exe with cmd.exe gives anyone a SYSTEM command prompt at the logon screen.'
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $hij = 0
    foreach ($k in @(Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
        $dbg = $k.GetValue('Debugger')
        if (-not $dbg) { continue }
        $hij++
        Add-Result 'REVIEW' "$($k.PSChildName) is hijacked: whenever it runs, '$dbg' runs instead"
        if (Confirm-Step "Remove the hijack from $($k.PSChildName)?" 'y') {
            $kp = $k.PSPath
            Remove-RegValue $kp 'Debugger' "Removed the Debugger hijack from $($k.PSChildName)"
        }
    }
    foreach ($exe in @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe')) {
        $p = Join-Path $env:SystemRoot "System32\$exe"
        if (-not (Test-Path $p)) { continue }
        $orig = ((Get-Item $p).VersionInfo.OriginalFilename -replace '(?i)\.mui$', '').ToLower()
        if ($orig -match '^(cmd|powershell|pwsh|explorer|taskmgr|regedit|mmc|conhost|wscript|cscript|mshta|rundll32)\.exe$') {
            $hij++
            Add-Result 'REVIEW' "$exe has been REPLACED by another program ($orig)"
            if (Confirm-Step "Restore the real $exe with System File Checker?" 'y') {
                $target = $p
                Invoke-Fix "Restored $exe (sfc /scanfile)" { & sfc.exe "/scanfile=$target" | Out-Null } | Out-Null
            }
        }
    }
    if ($hij -eq 0) { Add-Result 'OK' 'Accessibility tools are not hijacked' }

    Write-Info 'Logon programs, AppInit DLLs and LSA packages'
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $userinit = "$(Get-RegValue $wl 'Userinit')"
    if ($userinit -and $userinit.TrimEnd(',').Trim() -notmatch '(?i)^[A-Z]:\\Windows\\system32\\userinit\.exe$') {
        Add-Result 'REVIEW' "Winlogon Userinit runs extra programs at logon: $userinit"
        if (Confirm-Step 'Reset Userinit to the default?' 'y') { Set-Reg $wl 'Userinit' "$env:SystemRoot\system32\userinit.exe," 'String' 'Winlogon Userinit is the default' }
    } else { Add-Result 'OK' 'Winlogon Userinit is normal' }
    $shellVal = "$(Get-RegValue $wl 'Shell')"
    if ($shellVal -and $shellVal -ne 'explorer.exe') {
        Add-Result 'REVIEW' "Winlogon Shell is not just explorer.exe: $shellVal"
        if ($shellVal -match '(?i)explorer\.exe.+' -and (Confirm-Step 'Reset Shell to explorer.exe?' 'y')) { Set-Reg $wl 'Shell' 'explorer.exe' 'String' 'Winlogon Shell is explorer.exe' }
    }
    foreach ($w in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $dlls = "$(Get-RegValue $w 'AppInit_DLLs')"
        if ($dlls.Trim()) {
            Add-Result 'REVIEW' "AppInit_DLLs loads '$dlls' into every program"
            if (Confirm-Step 'Clear AppInit_DLLs?' 'y') {
                Set-Reg $w 'AppInit_DLLs' '' 'String' 'AppInit_DLLs cleared'
                Set-Reg $w 'LoadAppInit_DLLs' 0 'DWord' 'AppInit_DLLs loading off'
            }
        }
    }
    $lsaItem = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $knownPkgs = @('msv1_0', 'scecli', 'rassfm', 'kerberos', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', '""', '')
    foreach ($v in @('Authentication Packages', 'Notification Packages', 'Security Packages')) {
        $odd = @(@($lsaItem.GetValue($v)) | Where-Object { $knownPkgs -notcontains "$_".ToLower() })
        if ($odd.Count -gt 0) { Add-Result 'REVIEW' "Unusual LSA '$v': $($odd -join ', ') (could be a password stealer like mimilib)" }
    }

    Write-Info 'WMI event subscriptions (a hidden way to run programs)'
    try {
        $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction Stop) +
                     @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
        $consumers = @($consumers | Where-Object { $_ -and "$($_.Name)" -notmatch $CpProtectRegex })
        if ($consumers.Count -eq 0) { Add-Result 'OK' 'No WMI command/script subscriptions' }
        foreach ($c in $consumers) {
            Add-Result 'REVIEW' "WMI subscription '$($c.Name)': $($c.CommandLineTemplate)$($c.ScriptText)"
            if (Confirm-Step "Remove WMI subscription '$($c.Name)'?" 'y') {
                $cons = $c
                Invoke-Fix "Removed WMI subscription $($c.Name)" {
                    $binds = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Where-Object { "$($_.Consumer)" -match [regex]::Escape($cons.Name) })
                    foreach ($b in $binds) {
                        $filterName = [regex]::Match("$($b.Filter)", 'Name = "([^"]+)"').Groups[1].Value
                        $b | Remove-CimInstance -ErrorAction Stop
                        if ($filterName) { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Where-Object { $_.Name -eq $filterName } | Remove-CimInstance -ErrorAction SilentlyContinue }
                    }
                    $cons | Remove-CimInstance -ErrorAction Stop
                } | Out-Null
            }
        }
    } catch { Write-HardenLog "WMI check skipped: $($_.Exception.Message)" }

    Write-Info 'Checking the hosts file for fake website addresses'
    Write-Why 'An attacker can point a real website (a bank, Windows Update) to their own computer.'
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $lines = @(Get-Content $hosts -ErrorAction SilentlyContinue)
    $bad = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i].Trim()
        if (-not $l -or $l.StartsWith('#')) { continue }
        if ($l -match '^(127\.0\.0\.1|::1)\s+localhost\s*$') { continue }
        $bad += $i
    }
    if ($bad.Count -eq 0) { Add-Result 'OK' 'The hosts file has no extra entries' }
    else {
        Add-Result 'REVIEW' "$($bad.Count) unusual line(s) in the hosts file"
        Show-List ($bad | ForEach-Object { $lines[$_] }) 10
        if (Confirm-Step 'Comment out these lines in the hosts file?' 'y') {
            $newLines = $lines; $badIdx = $bad
            Invoke-Fix 'Disabled unusual hosts file entries' {
                Copy-Item $hosts (Join-Path $BackupDir 'hosts') -Force
                for ($j = 0; $j -lt $newLines.Count; $j++) { if ($badIdx -contains $j) { $newLines[$j] = "# disabled by harden.ps1: $($newLines[$j])" } }
                Set-Content -Path $hosts -Value $newLines -Encoding ASCII -ErrorAction Stop
            } | Out-Null
        }
    }

    Write-Info 'Programs listening for network connections'
    Write-Why 'A backdoor is often netcat or a script waiting for the attacker to connect.'
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort -Unique)
    $rows = @()
    foreach ($c in $listen) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $pname = if ($proc) { $proc.ProcessName } else { '?' }
        $rows += ("{0,-6} {1,-22} {2} (PID {3})" -f $c.LocalPort, $c.LocalAddress, $pname, $c.OwningProcess)
        if ($pname -match '(?i)^(nc|nc64|ncat|netcat|powershell|pwsh|cmd|python\d*|perl|ruby|wscript|cscript|mshta|rundll32|socat)$') {
            Add-Result 'REVIEW' "POSSIBLE BACKDOOR: '$pname' (PID $($c.OwningProcess)) is listening on port $($c.LocalPort)"
            if (Confirm-Step "Stop process $($c.OwningProcess)? (also find what starts it: tasks, services, Run keys)" 'y') {
                $procId = $c.OwningProcess
                Invoke-Fix "Stopped process $procId ($pname)" { Stop-Process -Id $procId -Force -ErrorAction Stop } | Out-Null
            }
        }
    }
    Add-Result 'REVIEW' "$($listen.Count) listening port(s) - compare with the README's critical services"
    Show-List $rows 25

    Write-Info 'PowerShell profiles (run every time PowerShell starts)'
    $profiles = @("$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1")
    $profiles += @(Get-ChildItem "$env:SystemDrive\Users\*\Documents\*PowerShell\*profile.ps1" -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $pcount = 0
    foreach ($p in $profiles) { if (Test-Path $p) { $pcount++; Add-Result 'REVIEW' "PowerShell profile exists: $p - check what it runs" } }
    if ($pcount -eq 0) { Add-Result 'OK' 'No PowerShell profiles' }
}

# ===========================================================================
# SECTION: Other hardening
# ===========================================================================
function Invoke-Misc {
    Write-Info 'AutoPlay and AutoRun'
    Write-Why 'AutoRun can start a virus as soon as a USB stick or CD is inserted.'
    $exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Set-Reg $exp 'NoDriveTypeAutoRun' 255 'DWord' 'AutoRun off for all drives'
    Set-Reg $exp 'NoAutorun' 1 'DWord' 'AutoRun commands are ignored'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'NoAutoplayfornonVolume' 1 'DWord' 'AutoPlay off for phones and cameras'

    Write-Info 'SmartScreen and download protection'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1 'DWord' 'Windows SmartScreen on (warns about unknown downloads)'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Warn' 'String' 'SmartScreen warns before running unknown programs'

    Write-Info 'Name-resolution tricks (LLMNR, NetBIOS, WPAD)'
    Write-Why 'Attackers answer these broadcast name lookups to steal password hashes (tools like Responder).'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 'DWord' 'LLMNR off'
    Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad' 1 'DWord' 'Web proxy auto-discovery (WPAD) off'
    Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0 'DWord' 'SMB client: no insecure guest logons'
    if (-not $script:IsDC -or (Confirm-Step 'This is a Domain Controller. Turn off NetBIOS anyway? (old clients may need it)' 'n' -Strict)) {
        foreach ($i in @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)) {
            Set-Reg $i.PSPath 'NetbiosOptions' 2 'DWord' "NetBIOS over TCP/IP off ($($i.PSChildName))"
        }
    }

    Write-Info 'Screen saver lock'
    Write-Why 'An unlocked, unattended screen lets anyone walk up and use the account.'
    $hives = @('HKCU:') + (Get-UserHives) + @('Registry::HKEY_USERS\.DEFAULT')
    foreach ($h in ($hives | Select-Object -Unique)) {
        $k = "$h\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        Set-Reg $k 'ScreenSaveActive' '1' 'String' "Screen saver on ($h)"
        Set-Reg $k 'ScreenSaverIsSecure' '1' 'String' "Screen saver asks for the password ($h)"
        Set-Reg $k 'ScreenSaveTimeOut' '600' 'String' "Screen saver after 10 minutes ($h)"
    }
    Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt' 0 'DWord' 'Show file extensions (helps spot fake "report.pdf.exe" files)'

    Write-Info 'PowerShell script policy'
    $ep = Get-ExecutionPolicy -Scope LocalMachine
    if ("$ep" -in @('Unrestricted', 'Bypass')) {
        Invoke-Fix "PowerShell execution policy RemoteSigned (was $ep)" { Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop } | Out-Null
    } else { Add-Result 'OK' "PowerShell execution policy is $ep" }

    Write-Info 'Data Execution Prevention (DEP)'
    $bcd = (& bcdedit.exe /enum '{current}' 2>$null) -join "`n"
    if ($bcd -match '(?im)^nx\s+AlwaysOff') { Invoke-Fix 'DEP turned back on (OptIn) - takes effect after a reboot' { & bcdedit.exe /set '{current}' nx OptIn | Out-Null } | Out-Null }
    elseif ($bcd) { Add-Result 'OK' 'DEP is on' }
}

# ===========================================================================
# SECTION: Web browsers
# ===========================================================================
# Firefox reads "Preferences" as ONE REG_MULTI_SZ value holding JSON
# (https://mozilla.github.io/policy-templates/#preferences). Version 2.0.0 of this script wrote a
# "Preferences" SUBKEY with JSON strings, which Firefox does not understand and which hides the value.
function Set-FirefoxSafeBrowsing([string]$Ff) {
    $json = '{"browser.safebrowsing.malware.enabled": {"Value": true, "Status": "locked"}, "browser.safebrowsing.phishing.enabled": {"Value": true, "Status": "locked"}}'
    $oldJson = '{"Value": true, "Status": "locked"}'
    foreach ($n in @('browser.safebrowsing.malware.enabled', 'browser.safebrowsing.phishing.enabled')) {
        if ((Get-RegValue "$Ff\Preferences" $n) -eq $oldJson) { Remove-RegValue "$Ff\Preferences" $n "Firefox: removed an old-format preference ($n)" }
    }
    if ($script:Mode -ne 'Audit' -and (Test-Path "$Ff\Preferences") -and (Get-Item -LiteralPath "$Ff\Preferences").ValueCount -eq 0 -and (Get-Item -LiteralPath "$Ff\Preferences").SubKeyCount -eq 0) {
        Remove-Item -LiteralPath "$Ff\Preferences" -Force -ErrorAction SilentlyContinue
    }
    $cur = Get-RegValue $Ff 'Preferences'
    if ($null -eq $cur -or "$cur" -eq $json) {
        Set-Reg $Ff 'Preferences' ([string[]]@($json)) 'MultiString' 'Firefox: block dangerous downloads, malware and phishing sites'
    } else {
        Add-Result 'REVIEW' "Firefox already has a Preferences policy - check that it keeps browser.safebrowsing.malware.enabled and browser.safebrowsing.phishing.enabled on: $cur"
    }
    if (Test-Path "$Ff\Preferences") { Add-Result 'REVIEW' "Old-style Firefox preference policies found in $Ff\Preferences - check them (a value of 0 turns a protection off)" }
}

function Invoke-Browsers {
    Write-Info 'Microsoft Edge'
    Write-Why 'SmartScreen blocks known phishing and malware sites; pop-up blocking stops scam windows.'
    $edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    Set-Reg $edge 'SmartScreenEnabled' 1 'DWord' 'Edge: SmartScreen on'
    Set-Reg $edge 'SmartScreenPuaEnabled' 1 'DWord' 'Edge: block potentially unwanted apps'
    Set-Reg $edge 'DefaultPopupsSetting' 2 'DWord' 'Edge: block pop-ups'
    Set-Reg $edge 'DownloadRestrictions' 1 'DWord' 'Edge: block dangerous downloads'
    Set-Reg $edge 'PasswordManagerEnabled' 0 'DWord' "Edge: doesn't offer to save passwords"

    $chromeExe = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($chromeExe) {
        Write-Info 'Google Chrome'
        $ch = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        Set-Reg $ch 'SafeBrowsingProtectionLevel' 1 'DWord' 'Chrome: Safe Browsing on'
        Set-Reg $ch 'DefaultPopupsSetting' 2 'DWord' 'Chrome: block pop-ups'
        Set-Reg $ch 'DownloadRestrictions' 1 'DWord' 'Chrome: block dangerous downloads'
        Set-Reg $ch 'PasswordManagerEnabled' 0 'DWord' "Chrome: doesn't offer to save passwords"
        Add-Result 'REVIEW' "Update Chrome: open it, then Menu > Help > About Google Chrome (version $((Get-Item $chromeExe).VersionInfo.ProductVersion))"
    }
    $ffExe = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($ffExe) {
        Write-Info 'Mozilla Firefox'
        $ff = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
        Set-Reg "$ff\PopupBlocking" 'Default' 1 'DWord' 'Firefox: block pop-ups'
        Set-Reg "$ff\PopupBlocking" 'Locked' 1 'DWord' "Firefox: users can't turn the pop-up blocker off"
        Set-Reg "$ff\InstallAddonsPermission" 'Default' 0 'DWord' "Firefox: websites can't install add-ons"
        Set-Reg $ff 'HttpsOnlyMode' 'enabled' 'String' 'Firefox: HTTPS-only mode'
        Set-Reg $ff 'PasswordManagerEnabled' 0 'DWord' "Firefox: doesn't save passwords"
        Set-FirefoxSafeBrowsing $ff
        Add-Result 'REVIEW' "Update Firefox: Menu > Help > About Firefox (version $((Get-Item $ffExe).VersionInfo.ProductVersion)). Also check Settings > Privacy & Security by hand."
    }
}

# ===========================================================================
# SECTION: Critical server roles
# ===========================================================================
function Invoke-Roles {
    $did = $false
    if ((Get-Service W3SVC -ErrorAction SilentlyContinue) -and (Test-Critical @('iis', 'web', 'http', 'https', 'w3svc', 'webserver'))) {
        $did = $true
        Write-Info 'IIS web server (critical: hardening it, not removing it)'
        Write-Why 'Turn off folder listings, hide version headers, and keep logging on.'
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $db = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/directoryBrowse' -Name 'enabled'
            if ($db.Value) { Invoke-Fix 'IIS: directory browsing off' { Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -Value $false } | Out-Null }
            else { Add-Result 'OK' 'IIS directory browsing is off (server level)' }
            foreach ($site in @(Get-Website)) {
                $sn = $site.Name
                $sdb = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$sn" -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -ErrorAction SilentlyContinue
                if ($sdb -and $sdb.Value) { Invoke-Fix "IIS site '$sn': directory browsing off" { Set-WebConfigurationProperty -PSPath "IIS:\Sites\$sn" -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -Value $false } | Out-Null }
                if (-not $site.logFile.enabled) { Invoke-Fix "IIS site '$sn': logging on" { Set-ItemProperty "IIS:\Sites\$sn" -Name logFile.enabled -Value $true } | Out-Null }
            }
            try {
                $rsh = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader'
                if (-not $rsh.Value) { Invoke-Fix 'IIS: hide the Server version header' { Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -Value $true } | Out-Null }
            } catch { Write-HardenLog "skipped: $($_.Exception.Message)" }
            $xpb = Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol/customHeaders/add[@name='X-Powered-By']"
            if ($xpb) { Invoke-Fix 'IIS: remove the X-Powered-By header' { Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -AtElement @{ name = 'X-Powered-By' } } | Out-Null }
            foreach ($pool in @(Get-ChildItem IIS:\AppPools)) {
                if ($pool.processModel.identityType -eq 'LocalSystem') {
                    $pn = $pool.Name
                    Add-Result 'REVIEW' "IIS app pool '$pn' runs as LocalSystem (a hacked site would own the server)"
                    if (Confirm-Step "Run app pool '$pn' as ApplicationPoolIdentity instead?" 'y') { Invoke-Fix "IIS app pool '$pn' runs as ApplicationPoolIdentity" { Set-ItemProperty "IIS:\AppPools\$pn" -Name processModel.identityType -Value 4 } | Out-Null }
                }
            }
            # Get-WindowsFeature only exists on Windows Server (on Windows 10/11 this line used to end the IIS block with FAILED)
            if ((Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) -and (Get-WindowsFeature -Name Web-DAV-Publishing -ErrorAction SilentlyContinue).Installed) { Add-Result 'REVIEW' 'WebDAV publishing is installed in IIS - remove it if the README does not need it' }
        } catch { Add-Result 'FAILED' "IIS hardening - $($_.Exception.Message)" }
    }
    if ((Get-Service FTPSVC -ErrorAction SilentlyContinue) -and (Test-Critical @('ftp', 'ftpsvc'))) {
        $did = $true
        Write-Info 'IIS FTP server (critical: hardening it, not removing it)'
        try {
            Import-Module WebAdministration -ErrorAction Stop
            foreach ($site in @(Get-Website | Where-Object { $_.Bindings.Collection.protocol -contains 'ftp' })) {
                $sn = $site.Name
                $anon = Get-ItemProperty "IIS:\Sites\$sn" -Name ftpServer.security.authentication.anonymousAuthentication.enabled
                if ($anon.Value -or $anon -eq $true) {
                    Add-Result 'REVIEW' "FTP site '$sn' allows anonymous logins"
                    if (Confirm-Step "Turn off anonymous FTP on '$sn'?" 'y') { Invoke-Fix "FTP site '$sn': anonymous logins off" { Set-ItemProperty "IIS:\Sites\$sn" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false } | Out-Null }
                } else { Add-Result 'OK' "FTP site '$sn' does not allow anonymous logins" }
                $ssl = (Get-ItemProperty "IIS:\Sites\$sn" -Name ftpServer.security.ssl.controlChannelPolicy).ToString()
                if ($ssl -match 'SslAllow') { Add-Result 'REVIEW' "FTP site '$sn' does not require encryption (SSL policy: Allow). Require SSL if the site has a certificate." }
            }
        } catch { Add-Result 'FAILED' "FTP hardening - $($_.Exception.Message)" }
    }
    if ((Get-Service DNS -ErrorAction SilentlyContinue) -and (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) -and ($script:IsDC -or (Test-Critical @('dns')))) {
        $did = $true
        Write-Info 'DNS server'
        Write-Why 'Zone transfers hand out the list of every computer in the network; insecure dynamic updates let anyone change records.'
        foreach ($z in @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })) {
            $zn = $z.ZoneName
            if ($z.SecureSecondaries -eq 'TransferAnyServer') {
                Add-Result 'REVIEW' "DNS zone '$zn' gives zone transfers to ANY server"
                if (Confirm-Step "Block zone transfers for '$zn'? (say NO if the README mentions a secondary DNS server)" 'y') {
                    Invoke-Fix "DNS zone '$zn': zone transfers off" { Set-DnsServerPrimaryZone -Name $zn -SecureSecondaries NoTransfer -ErrorAction Stop } | Out-Null
                }
            } else { Add-Result 'OK' "DNS zone '$zn' does not transfer to any server" }
            if ($z.DynamicUpdate -eq 'NonsecureAndSecure') {
                if ($z.IsDsIntegrated) { Invoke-Fix "DNS zone '$zn': only secure dynamic updates" { Set-DnsServerPrimaryZone -Name $zn -DynamicUpdate Secure -ErrorAction Stop } | Out-Null }
                else { Add-Result 'REVIEW' "DNS zone '$zn' accepts insecure dynamic updates (it is not AD-integrated, so set it to None if updates are not needed)" }
            }
        }
    }
    if ($script:IsDC -and $script:HasAD) {
        $did = $true
        Write-Info 'Active Directory'
        try {
            $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
            if (-not $rb.EnabledScopes) {
                Add-Result 'REVIEW' 'The AD Recycle Bin is off (deleted accounts cannot be restored)'
                if (Confirm-Step 'Turn on the AD Recycle Bin? (cannot be turned off again)' 'y') {
                    $forest = (Get-ADForest).Name
                    Invoke-Fix 'AD Recycle Bin on' { Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $forest -Confirm:$false -ErrorAction Stop } | Out-Null
                }
            } else { Add-Result 'OK' 'AD Recycle Bin is on' }
            $deleg = @(Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation, PrimaryGroupID | Where-Object { $_.PrimaryGroupID -ne 516 })
            foreach ($c in $deleg) { Add-Result 'REVIEW' "Computer '$($c.Name)' has unconstrained delegation (can impersonate any user)" }
            if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
                $gpos = @(Get-GPO -All | Sort-Object ModificationTime -Descending | ForEach-Object { "$($_.DisplayName)  (changed $($_.ModificationTime))" })
                Add-Result 'REVIEW' "Check these Group Policy Objects for planted settings (newest first)"
                Show-List $gpos 10
            }
        } catch { Add-Result 'FAILED' "Active Directory checks - $($_.Exception.Message)" }
    }
    if (-not $did) { Add-Result 'SKIPPED' 'No critical IIS, FTP, DNS or Active Directory role on this computer' }
}

# ===========================================================================
# SECTION: Windows Update
# ===========================================================================
function Invoke-Updates {
    Write-Info 'Windows Update settings'
    Write-Why 'Security fixes come out every month. Attackers disable updates so old holes stay open.'
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    Set-Reg "$wu\AU" 'NoAutoUpdate' 0 'DWord' 'Automatic updates are not turned off by policy'
    Set-Reg "$wu\AU" 'AUOptions' 4 'DWord' 'Updates download and install automatically'
    Remove-RegValue $wu 'DisableWindowsUpdateAccess' 'Users are not blocked from Windows Update'
    Remove-RegValue $wu 'SetDisableUXWUAccess' 'The Windows Update settings page is not hidden'
    Remove-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoWindowsUpdate' 'Windows Update is not blocked'
    $server = Get-RegValue $wu 'WUServer'
    if ($server) {
        Add-Result 'REVIEW' "Updates are set to come from '$server' instead of Microsoft"
        if (Confirm-Step 'Use Microsoft Update instead? (say NO if the README mentions a WSUS server)' 'y') {
            Remove-RegValue $wu 'WUServer' 'Update server reset to Microsoft'
            Remove-RegValue $wu 'WUStatusServer' 'Update status server reset'
            Set-Reg "$wu\AU" 'UseWUServer' 0 'DWord' 'Do not use a custom update server'
        }
    }
    $ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    foreach ($v in @('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime')) {
        if (Get-RegValue $ux $v) { Remove-RegValue $ux $v "Updates are no longer paused ($v)" }
    }
    $svc = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -eq 'Disabled') { Invoke-Fix 'Re-enable the Windows Update service' { Set-Service wuauserv -StartupType Manual -ErrorAction Stop } | Out-Null }

    Write-Info 'Installing updates'
    if ($script:Mode -eq 'Audit') { Add-Result 'REVIEW' 'Check for updates: Settings > Windows Update > Check for updates (Apply mode can install them)'; return }
    $go = switch ($script:InstallUpdates) { 'yes' { $true } 'no' { $false } default { Confirm-Step 'Search for and install ALL Windows updates now? (can take 10-60 minutes)' 'y' } }
    if (-not $go) { Add-Result 'SKIPPED' 'Windows updates not installed (your choice) - use Settings > Windows Update'; return }
    try {
        Write-Host '      Searching for updates (this can take several minutes)...' -ForegroundColor DarkGray
        $session = New-Object -ComObject Microsoft.Update.Session
        $found = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
        if ($found.Count -eq 0) { Add-Result 'OK' 'Windows is up to date'; return }
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $found) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$coll.Add($u); Write-Host "        - $($u.Title)" -ForegroundColor DarkGray }
        Write-Host "      Downloading $($coll.Count) update(s)..." -ForegroundColor DarkGray
        $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
        Write-Host '      Installing...' -ForegroundColor DarkGray
        $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll; $res = $inst.Install()
        if ($res.ResultCode -in @(2, 3)) { Add-Result 'CHANGED' "Installed $($coll.Count) Windows update(s)" }
        else { Add-Result 'FAILED' "Windows Update finished with result code $($res.ResultCode) - try Settings > Windows Update" }
        if ($res.RebootRequired) { Add-Result 'REVIEW' 'A reboot is needed to finish the updates. Reboot ONCE near the end, after saving your work.' }
    } catch {
        Add-Result 'FAILED' "Windows Update - $($_.Exception.Message). Use Settings > Windows Update instead."
    }
}

# ===========================================================================
# Menu, summary and main
# ===========================================================================
function Show-Summary {
    Write-Header 'Summary'
    $counts = @{}
    foreach ($s in @('OK', 'CHANGED', 'WOULD', 'SKIPPED', 'REVIEW', 'FAILED')) { $counts[$s] = @($script:Results | Where-Object { $_.Status -eq $s }).Count }
    Write-Host ("  OK {0}    CHANGED {1}    WOULD CHANGE {2}    SKIPPED {3}    REVIEW {4}    FAILED {5}" -f $counts.OK, $counts.CHANGED, $counts.WOULD, $counts.SKIPPED, $counts.REVIEW, $counts.FAILED)
    if ($counts.FAILED -gt 0) {
        Write-Host ''; Write-Host '  Failed:' -ForegroundColor Red
        foreach ($r in @($script:Results | Where-Object { $_.Status -eq 'FAILED' })) { Write-Host "    - $($r.Text)" -ForegroundColor Red }
    }
    Write-Host ''
    Write-Host "  Your to-do list (REVIEW items): $ReportFile"
    Write-Host "  Full log:                       $LogFile"
    Write-Host "  Backups of changed settings:    $BackupDir"
    Write-Host ''
    Write-Host '  NEXT: open the Scoring Report on the desktop, then work through the REVIEW items'
    Write-Host '  and the checklist for this OS (docs\checklists\).'
}

function Invoke-Section([string]$Id) {
    $s = $Sections | Where-Object { $_.Id -eq $Id } | Select-Object -First 1
    if (-not $s) { Write-Warn "Unknown section '$Id' (use -List)"; return }
    $script:CurrentSection = $s.Id
    Write-Header ("{0}   [{1}]" -f $s.Title, $script:Mode.ToUpper())
    Add-Content -Path $ReportFile -Value "`r`n## $($s.Title)`r`n"
    try { & $s.Fn } catch { Add-Result 'FAILED' "Section stopped early - $($_.Exception.Message)" }
    $script:CurrentSection = 'setup'
}

function Confirm-Apply {
    if ($script:Mode -ne 'Apply' -or $script:ApplyConfirmed) { return $true }
    Write-Host ''
    Write-Warn 'APPLY mode changes this computer. Before you continue:'
    Write-Host '     1. Have you answered the FORENSICS QUESTIONS? Deleting users and files can destroy the answers.'
    Write-Host "     2. Did you enter the README's authorized users and critical services correctly?"
    Write-Host '     3. Is there a snapshot of this VM you can go back to?'
    if ($script:AssumeYes -or (Confirm-Step 'Ready to make changes?' 'n')) { $script:ApplyConfirmed = $true; return $true }
    return $false
}

function Show-Menu {
    while ($true) {
        Write-Header ("Main menu   (mode: {0})" -f $script:Mode.ToUpper())
        for ($i = 0; $i -lt $Sections.Count; $i++) { Write-Host ('  {0,2}) {1}' -f ($i + 1), $Sections[$i].Title) }
        Write-Host '   a) Run ALL sections'
        if ($script:Mode -eq 'Audit') { Write-Host '   m) Switch to APPLY mode (make changes)' } else { Write-Host '   m) Switch to AUDIT mode (report only)' }
        Write-Host '   r) Re-enter the README information'
        Write-Host '   s) Show the summary so far'
        Write-Host '   q) Quit'
        $choice = (Read-Host '  Choose (examples: 1   or   1 3 5   or   a)').Trim().ToLower()
        switch -Regex ($choice) {
            '^(q|quit|exit)$' { return }
            '^(a|all)$' { if (Confirm-Apply) { foreach ($s in $Sections) { Invoke-Section $s.Id } } }
            '^m$' { $script:Mode = if ($script:Mode -eq 'Audit') { 'Apply' } else { 'Audit' } }
            '^r$' { Read-ReadmeInfo; Complete-ReadmeInfo }
            '^s$' { Show-Summary }
            '^$' { }
            default {
                $ids = @()
                foreach ($n in ($choice -split '[\s,]+' | Where-Object { $_ })) {
                    if ($n -match '^\d+$' -and [int]$n -ge 1 -and [int]$n -le $Sections.Count) { $ids += $Sections[[int]$n - 1].Id }
                    else { Write-Warn "Not a menu choice: $n" }
                }
                if ($ids.Count -gt 0 -and (Confirm-Apply)) { foreach ($id in $ids) { Invoke-Section $id } }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Set-Content -Path $ReportFile -Value ("# Findings report - {0}`r`n# REVIEW items need a human decision. WOULD = audit mode found something to fix." -f (Get-Date))
Write-Host ''
Write-Host " CyberPatriot Toolkit - Windows hardening v$ScriptVersion" -ForegroundColor Cyan
$role = if ($script:IsDC) { 'Domain Controller' } elseif ($script:IsServer) { 'Server' } else { 'Workstation' }
Write-Host "  System: $($script:OsName)   Role: $role   PowerShell: $($PSVersionTable.PSVersion)"
Write-HardenLog "System: $($script:OsName) ($role)"

if ($Config) { Import-ReadmeConfig $Config }
elseif (-not $script:AssumeYes) { Read-ReadmeInfo }
Complete-ReadmeInfo

if (-not $script:Mode) {
    $script:Mode = 'Audit'
    Write-Host ''
    Write-Host '  Starting in AUDIT mode: nothing is changed. Press m in the menu to switch to APPLY.'
    Show-Menu
} elseif (Confirm-Apply) {
    $ids = if ($Only) { @($Only -join ',' -split '[\s,]+' | Where-Object { $_ }) } else { @($Sections | ForEach-Object { $_.Id }) }
    foreach ($id in $ids) { Invoke-Section $id }
}
Show-Summary
