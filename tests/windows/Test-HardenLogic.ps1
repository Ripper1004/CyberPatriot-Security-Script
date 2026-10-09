<#
  Logic tests for scripts/windows/Harden.ps1 that run anywhere PowerShell 7 runs
  (including Linux): the script's functions are loaded without running it, and
  Windows-only programs (secedit.exe, auditpol.exe ...) are replaced by fakes.

      pwsh tests/windows/Test-HardenLogic.ps1

  This does NOT replace a real test on a Windows practice image (Audit mode first!).
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptPath = Join-Path $root 'scripts/windows/Harden.ps1'
if ($env:HARDEN_PS1) { $scriptPath = $env:HARDEN_PS1 }   # e.g. an older copy, to see a test fail

# --- Load every function from Harden.ps1 without running its main code -------
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
# Top-level tables the functions use ($Sections, $ServiceCatalog, regexes ...)
foreach ($st in $ast.EndBlock.Statements) {
    if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and $st.Left.Extent.Text -match '^\$(Sections|ServiceCatalog|CoreServices|SoftwarePatterns|SoftwareReviewPattern|AppxPattern|SuspiciousCmdRegex|CpProtectRegex|DcProtectedServices|FirewallGroupsForCritical)$') {
        . ([scriptblock]::Create($st.Extent.Text))
    }
}

# --- Test environment ----------------------------------------------------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) "harden-test-$PID"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$RunId = 'test'; $BackupDir = Join-Path $tmp 'backup'; $LogFile = Join-Path $tmp 'log.txt'; $ReportFile = Join-Path $tmp 'report.txt'
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
if (-not $env:TEMP) { $env:TEMP = $tmp }
$script:Results = New-Object System.Collections.Generic.List[object]
$script:CurrentSection = 'test'; $script:BackedUpKeys = @{}; $script:Me = 'alice'
function Write-Host { }   # keep the test output readable

$pass = 0; $fail = 0
function Assert([string]$Name, [scriptblock]$Test) {
    try { $ok = & $Test } catch { $ok = $false; $Name += " (threw: $($_.Exception.Message))" }
    if ($ok) { $script:pass++; [Console]::WriteLine("PASS  $Name") } else { $script:fail++; [Console]::WriteLine("FAIL  $Name") }
}
function Reset-Results { $script:Results.Clear() }
function Last-Status { $script:Results[$script:Results.Count - 1].Status }

# --- Fake secedit.exe: keeps a policy "database" in a file ----------------------
$script:FakePolicy = @{ 'System Access' = [ordered]@{ MinimumPasswordLength = '0'; PasswordComplexity = '0'; LockoutBadCount = '0' }
                        'Privilege Rights' = [ordered]@{ SeDebugPrivilege = '*S-1-1-0,*S-1-5-32-544'; SeNetworkLogonRight = '*S-1-1-0,*S-1-5-32-544,*S-1-5-32-545';
                                                         SeDenyInteractiveLogonRight = '*S-1-5-32-545'; SeTcbPrivilege = '*S-1-1-0' } }
function secedit.exe {
    $all = $args
    $cfg = $all[[array]::IndexOf($all, '/cfg') + 1]
    if ($all -contains '/export') {
        $out = @('[Unicode]', 'Unicode=yes')
        # Like the real secedit, a right that nobody holds is left out of the export
        foreach ($sec in $script:FakePolicy.Keys) { $out += "[$sec]"; foreach ($k in $script:FakePolicy[$sec].Keys) { if ("$($script:FakePolicy[$sec][$k])" -ne '') { $out += "$k = $($script:FakePolicy[$sec][$k])" } } }
        $out | Set-Content -Path $cfg
    } elseif ($all -contains '/configure') {
        $section = ''
        foreach ($line in (Get-Content $cfg)) {
            if ($line -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
            if ($line -match '^(\S+) = (.*)$' -and $section -notin @('Unicode', 'Version')) {
                if (-not $script:FakePolicy.ContainsKey($section)) { $script:FakePolicy[$section] = [ordered]@{} }
                $script:FakePolicy[$section][$Matches[1]] = $Matches[2]
            }
        }
    }
}

# ===========================================================================
# Tests
# ===========================================================================
Assert 'Split-Names handles commas, semicolons and spaces' { (Split-Names 'alice, bob;carol   dave').Count -eq 4 }
Assert 'Split-Names handles arrays' { (Split-Names @('alice', 'bob carol')).Count -eq 3 }
Assert 'Strong password accepted' { Test-StrongPassword 'Cyb3r!Patr1ot#2026' }
Assert 'Weak password rejected (no symbol)' { -not (Test-StrongPassword 'Password12345') }
Assert 'Short password rejected' { -not (Test-StrongPassword 'Ab1!') }

$cfgFile = Join-Path $root 'scripts/windows/config.example.psd1'
Import-ReadmeConfig $cfgFile
Assert 'Example config: admins loaded' { $script:AuthAdmins -contains 'alice' }
Assert 'Example config: users loaded' { $script:AuthUsers -contains 'carol' }
Assert 'Example config: critical services lower-cased' { $script:Critical -contains 'rdp' }
Assert 'Test-Critical finds a listed service' { Test-Critical @('remotedesktop', 'rdp') }
Assert 'Test-Critical ignores unlisted services' { -not (Test-Critical @('ftp')) }
Assert 'Test-Authorized' { (Test-Authorized 'carol') -and -not (Test-Authorized 'mallory') }

$script:Mode = 'Audit'; $script:AssumeYes = $false
Assert 'Audit mode never says yes' { -not (Confirm-Step 'x' 'y') }
$script:Mode = 'Apply'; $script:AssumeYes = $true
Assert '-Yes answers yes' { Confirm-Step 'x' 'n' }
Assert '-Yes with -Strict uses the default' { -not (Confirm-Step 'x' 'n' -Strict) }

$script:Mode = 'Audit'; Reset-Results
Invoke-Fix 'do something' { throw 'must not run in audit mode' } | Out-Null
Assert 'Invoke-Fix in Audit mode reports WOULD and runs nothing' { (Last-Status) -eq 'WOULD' }
$script:Mode = 'Apply'; Reset-Results
Invoke-Fix 'works' { 1 } | Out-Null
Assert 'Invoke-Fix success -> CHANGED' { (Last-Status) -eq 'CHANGED' }
Invoke-Fix 'breaks' { throw 'boom' } | Out-Null
Assert 'Invoke-Fix error -> FAILED' { (Last-Status) -eq 'FAILED' }

Assert 'reg.exe path conversion (HKLM:)' { (ConvertTo-RegExePath 'HKLM:\SOFTWARE\X') -eq 'HKLM\SOFTWARE\X' }
Assert 'reg.exe path conversion (provider path)' { (ConvertTo-RegExePath 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\X') -eq 'HKEY_LOCAL_MACHINE\SOFTWARE\X' }

# Password policy through the fake secedit
$script:Mode = 'Audit'; Reset-Results; $script:EnableLockout = 'yes'
Invoke-Passwords
Assert 'Audit: weak password policy reported as WOULD' { @($script:Results | Where-Object Status -eq 'WOULD').Count -eq 1 }
Assert 'Audit: policy untouched' { $script:FakePolicy['System Access']['MinimumPasswordLength'] -eq '0' }
$script:Mode = 'Apply'; Reset-Results
Invoke-Passwords
Assert 'Apply: password policy CHANGED' { (Last-Status) -eq 'CHANGED' }
Assert 'Apply: length 12, complexity on, lockout 5' {
    $sa = $script:FakePolicy['System Access']; $sa['MinimumPasswordLength'] -eq '12' -and $sa['PasswordComplexity'] -eq '1' -and $sa['LockoutBadCount'] -eq '5' }
Reset-Results
Invoke-Passwords
Assert 'Second run: password policy already OK (idempotent)' { (Last-Status) -eq 'OK' }

# User rights
$script:Mode = 'Apply'; Reset-Results
Invoke-UserRights
$pr = $script:FakePolicy['Privilege Rights']
Assert 'Everyone removed from Debug programs' { $pr['SeDebugPrivilege'] -eq '*S-1-5-32-544' }
Assert 'Everyone removed from network logon, Users kept' { $pr['SeNetworkLogonRight'] -eq '*S-1-5-32-544,*S-1-5-32-545' }
Assert 'Users taken off "deny local logon", Guests added' { $pr['SeDenyInteractiveLogonRight'] -eq '*S-1-5-32-546' }
Assert 'Guests denied network logon' { $pr['SeDenyNetworkLogonRight'] -eq '*S-1-5-32-546' }
Assert 'Everyone removed from "Act as part of the OS" (now No One)' { "$($pr['SeTcbPrivilege'])" -eq '' }
Assert 'Emptying a right is reported CHANGED, not a false FAILED' { (Last-Status) -eq 'CHANGED' -and -not @($script:Results | Where-Object Status -eq 'FAILED').Count }
Reset-Results
Invoke-UserRights
Assert 'Second run: user rights OK (idempotent)' { (Last-Status) -eq 'OK' }

# Suspicious command detection
Assert 'Encoded PowerShell is suspicious' { 'powershell.exe -w hidden -enc SQBFAFgA' -match $SuspiciousCmdRegex }
Assert 'netcat is suspicious' { 'C:\Users\Public\nc.exe -lvp 4444 -e cmd.exe' -match $SuspiciousCmdRegex }
Assert 'OneDrive is not suspicious' { -not ('"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' -match $SuspiciousCmdRegex) }
Assert 'Security Health is not suspicious' { -not ('%windir%\system32\SecurityHealthSystray.exe' -match $SuspiciousCmdRegex) }
Assert 'CyberPatriot scoring is protected' { 'C:\CyberPatriot\CCSClient.exe' -match $CpProtectRegex }

# Software patterns
Assert 'Wireshark is a hacking tool' { 'Wireshark 4.2.0 64-bit' -match "(?i)$($SoftwarePatterns['hacking tool'])" }
Assert 'uTorrent is P2P' { 'uTorrent' -match "(?i)$($SoftwarePatterns['file-sharing (P2P)'])" }
Assert 'Notepad++ is not flagged' { -not (@($SoftwarePatterns.Values | Where-Object { 'Notepad++ (64-bit x64)' -match "(?i)$_" }).Count) }
Assert 'Microsoft Edge is not flagged' { -not (@($SoftwarePatterns.Values | Where-Object { 'Microsoft Edge' -match "(?i)$_" }).Count) }

# --- Fake registry: HK* paths live in a hashtable, everything else goes to the real cmdlets ---
$script:FakeReg = @{}
function Reset-Reg { $script:FakeReg = @{} }
function Set-FakeReg([string]$Path, [string]$Name, $Value) {
    if (-not $script:FakeReg.ContainsKey($Path)) { $script:FakeReg[$Path] = [ordered]@{} }
    $script:FakeReg[$Path][$Name] = $Value
}
function reg.exe { }
function Test-Path {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -match '^HK') { return $script:FakeReg.ContainsKey($p) }
    if ($LiteralPath) { return Microsoft.PowerShell.Management\Test-Path -LiteralPath $p }
    return Microsoft.PowerShell.Management\Test-Path -Path $p
}
function Get-Item {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$LiteralPath)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -notmatch '^HK') { return Microsoft.PowerShell.Management\Get-Item @PSBoundParameters }
    if (-not $script:FakeReg.ContainsKey($p)) { throw "Cannot find path '$p'" }
    $o = [pscustomobject]@{ Vals = $script:FakeReg[$p]; ValueCount = $script:FakeReg[$p].Count
                            SubKeyCount = @($script:FakeReg.Keys | Where-Object { $_ -like "$p\*" }).Count }
    # like RegistryKey.GetValue: a REG_MULTI_SZ comes back as one string[] (even an empty one)
    $o | Add-Member ScriptMethod GetValue { param($n, $d) if (-not $this.Vals.Contains($n)) { return $d }; $v = $this.Vals[$n]; if ($v -is [array]) { return ,$v }; return $v }
    $o | Add-Member ScriptMethod GetValueNames { @($this.Vals.Keys) }
    return $o
}
function New-Item {
    [CmdletBinding()] param([Parameter(Position = 0)][string]$Path, [string]$ItemType, [switch]$Force)
    if ($Path -match '^HK') { if (-not $script:FakeReg.ContainsKey($Path)) { $script:FakeReg[$Path] = [ordered]@{} }; return }
    Microsoft.PowerShell.Management\New-Item @PSBoundParameters
}
function New-ItemProperty {
    [CmdletBinding()] param([string]$Path, [string]$Name, $Value, [string]$PropertyType, [switch]$Force)
    if (-not $script:FakeReg.ContainsKey($Path)) { throw "Cannot find path '$Path'" }
    if ($PropertyType -eq 'MultiString') { $v = [string[]]@($Value) } elseif ($PropertyType -eq 'DWord') { $v = [int64]$Value } else { $v = "$Value" }
    $script:FakeReg[$Path][$Name] = $v
}
function Remove-ItemProperty {
    [CmdletBinding()] param([string]$Path, [string]$LiteralPath, [string]$Name)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if (-not ($script:FakeReg.ContainsKey($p) -and $script:FakeReg[$p].Contains($Name))) { throw "No value $Name" }
    $script:FakeReg[$p].Remove($Name)
}
function Remove-Item {
    [CmdletBinding()] param([Parameter(Position = 0, ValueFromPipeline = $true)][string[]]$Path, [string[]]$LiteralPath, [switch]$Force, [switch]$Recurse)
    process {
        foreach ($p in @($LiteralPath | Where-Object { $_ })) {
            if ($p -match '^HK') { $script:FakeReg.Remove($p) } else { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $p -Force:$Force -Recurse:$Recurse -ErrorAction $ErrorActionPreference }
        }
        foreach ($p in @($Path | Where-Object { $_ })) {
            if ($p -match '^HK') { $script:FakeReg.Remove($p) } else { Microsoft.PowerShell.Management\Remove-Item -Path $p -Force:$Force -Recurse:$Recurse -ErrorAction $ErrorActionPreference }
        }
    }
}
function Get-Status([string]$Like) { @($script:Results | Where-Object { $_.Text -like $Like } | ForEach-Object { $_.Status }) }

Assert 'Fake registry: Set-Reg writes, second run is OK' {
    Reset-Reg; Reset-Results; $script:Mode = 'Apply'
    Set-Reg 'HKLM:\SOFTWARE\Test' 'X' 1 'DWord' 'test value'
    Set-Reg 'HKLM:\SOFTWARE\Test' 'X' 1 'DWord' 'test value'
    ((Get-Status 'test value*') -join ',') -eq 'CHANGED,OK' -and $script:FakeReg['HKLM:\SOFTWARE\Test']['X'] -eq 1 }

# Known bug: a planted "DefaultOutboundAction Block" was never reported
$fwPol = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
$script:FwSetCalls = @()
function Get-NetFirewallProfile {
    @([pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'NotConfigured'; LogBlocked = 'True'; NotifyOnListen = 'True' },
      [pscustomobject]@{ Name = 'Public'; Enabled = 'True'; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Block'; LogBlocked = 'True'; NotifyOnListen = 'True' })
}
function Set-NetFirewallProfile { $script:FwSetCalls += ,@($args) + @($PSBoundParameters.Keys) }
function Get-NetFirewallRule { @() }
function Enable-NetFirewallRule { }
function Disable-NetFirewallRule { }
Reset-Reg; Reset-Results; $script:Mode = 'Apply'; $script:AssumeYes = $true
Set-FakeReg "$fwPol\PublicProfile" 'DefaultOutboundAction' 1
Invoke-Firewall
Assert 'Firewall: outbound Block is a REVIEW with the fix command' {
    @($script:Results | Where-Object { $_.Status -eq 'REVIEW' -and $_.Text -like '*Set-NetFirewallProfile -Name Public -DefaultOutboundAction Allow*' }).Count -eq 1 }
Assert 'Firewall: outbound Block set by Group Policy is a REVIEW with the fix command' {
    @($script:Results | Where-Object { $_.Status -eq 'REVIEW' -and $_.Text -like "*Remove-ItemProperty -Path '$fwPol\PublicProfile' -Name DefaultOutboundAction*" }).Count -eq 1 }
Assert 'Firewall: outbound default is never changed by the script' {
    -not @($script:FwSetCalls | Where-Object { "$_" -match 'DefaultOutboundAction' }).Count -and $script:FakeReg["$fwPol\PublicProfile"]['DefaultOutboundAction'] -eq 1 }
Assert 'Firewall: a profile that allows outgoing traffic is OK' { (Get-Status 'Domain firewall allows outgoing*') -contains 'OK' }

# Remote Desktop: a Group Policy value beats the normal setting
$tsPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
Reset-Reg; Reset-Results; $script:Critical = @('rdp')
Set-FakeReg $tsPol 'fDenyTSConnections' 1
Invoke-RemoteAccess
Assert 'RDP critical but turned off by policy -> REVIEW with the fix, policy untouched' {
    @($script:Results | Where-Object { $_.Status -eq 'REVIEW' -and $_.Text -like "*Remove-ItemProperty -Path '$tsPol' -Name fDenyTSConnections*" }).Count -eq 1 -and $script:FakeReg[$tsPol]['fDenyTSConnections'] -eq 1 }
Reset-Reg; Reset-Results; $script:Critical = @()
Set-FakeReg $tsPol 'fDenyTSConnections' 0
Invoke-RemoteAccess
Assert 'RDP not needed but turned on by policy -> REVIEW (the normal setting alone does not turn it off)' {
    @($script:Results | Where-Object { $_.Status -eq 'REVIEW' -and $_.Text -like '*Group Policy turns Remote Desktop ON*' }).Count -eq 1 }

# Security options added in v2: NTLM session security, PrintNightmare, Zerologon (DC only)
Reset-Reg; Reset-Results; $script:Mode = 'Apply'; $script:IsDC = $false; $script:IsServer = $false
Invoke-SecurityOptions
$msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
$ppk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
Assert 'NTLM minimum session security = 537395200 (client and server)' { $script:FakeReg[$msv]['NTLMMinClientSec'] -eq 537395200 -and $script:FakeReg[$msv]['NTLMMinServerSec'] -eq 537395200 }
Assert 'Point and Print: admins only, warnings on' {
    $script:FakeReg[$ppk]['RestrictDriverInstallationToAdministrators'] -eq 1 -and $script:FakeReg[$ppk]['NoWarningNoElevationOnInstall'] -eq 0 -and $script:FakeReg[$ppk]['UpdatePromptSettings'] -eq 0 }
Assert 'Zerologon key not written on a non-DC' { -not $script:FakeReg['HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'].Contains('FullSecureChannelProtection') }
Set-FakeReg $ppk 'NoWarningNoElevationOnInstall' 1
Reset-Results; Invoke-SecurityOptions
Assert 'Planted NoWarningNoElevationOnInstall=1 is fixed; everything else already OK' {
    (Get-Status 'Point and Print: warn and ask for elevation when installing*') -contains 'CHANGED' -and
    -not @($script:Results | Where-Object { $_.Status -in 'CHANGED', 'FAILED' -and $_.Text -notlike 'Point and Print*' }).Count }
Assert 'An empty REG_MULTI_SZ (NullSessionPipes) counts as set: OK on the second run, not rewritten every time' {
    (Get-Status 'SMB server: no pipes open to anonymous users*') -contains 'OK' }
$script:IsDC = $true; Reset-Results; Invoke-SecurityOptions
Assert 'Domain Controller: FullSecureChannelProtection = 1' { $script:FakeReg['HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters']['FullSecureChannelProtection'] -eq 1 }
$script:IsDC = $false

# Browsers: password managers off; Firefox Preferences in the documented REG_MULTI_SZ format
$ffk = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
Reset-Reg; Reset-Results
Invoke-Browsers
Assert 'Edge: PasswordManagerEnabled = 0' { $script:FakeReg['HKLM:\SOFTWARE\Policies\Microsoft\Edge']['PasswordManagerEnabled'] -eq 0 }
Set-FakeReg "$ffk\Preferences" 'browser.safebrowsing.malware.enabled' '{"Value": true, "Status": "locked"}'
Set-FakeReg "$ffk\Preferences" 'browser.safebrowsing.phishing.enabled' '{"Value": true, "Status": "locked"}'
Reset-Results; Set-FirefoxSafeBrowsing $ffk
Assert 'Firefox: Preferences is one REG_MULTI_SZ JSON value with both safe-browsing prefs locked' {
    $v = $script:FakeReg[$ffk]['Preferences']; $j = ("$v" | ConvertFrom-Json)
    $v -is [array] -and $j.'browser.safebrowsing.malware.enabled'.Value -eq $true -and $j.'browser.safebrowsing.phishing.enabled'.Status -eq 'locked' }
Assert 'Firefox: the old-format Preferences subkey from v2.0.0 is removed' { -not $script:FakeReg.ContainsKey("$ffk\Preferences") }
Reset-Results; Set-FirefoxSafeBrowsing $ffk
Assert 'Firefox: second run is OK' { ((Get-Status 'Firefox:*') -join ',') -eq 'OK' }
Reset-Reg; Set-FakeReg $ffk 'Preferences' ([string[]]@('{"browser.startup.homepage": {"Value": "https://example.org"}}'))
Reset-Results; Set-FirefoxSafeBrowsing $ffk
Assert 'Firefox: an existing Preferences policy is not overwritten (REVIEW)' { (Last-Status) -eq 'REVIEW' -and "$($script:FakeReg[$ffk]['Preferences'])" -like '*homepage*' }
# Pretend Chrome and Firefox are installed (empty files under a fake Program Files)
$savedPF = $env:ProgramFiles; $env:ProgramFiles = Join-Path $tmp 'pf'
foreach ($exe in 'Google/Chrome/Application/chrome.exe', 'Mozilla Firefox/firefox.exe') {
    $full = Join-Path $env:ProgramFiles $exe
    Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path (Split-Path $full) -Force | Out-Null
    [IO.File]::WriteAllText($full, '')
}
Reset-Reg; Reset-Results; Invoke-Browsers
$env:ProgramFiles = $savedPF
Assert 'Chrome: PasswordManagerEnabled = 0' { $script:FakeReg['HKLM:\SOFTWARE\Policies\Google\Chrome']['PasswordManagerEnabled'] -eq 0 }
Assert 'Firefox: PasswordManagerEnabled = 0 and safe browsing set through Invoke-Browsers' {
    $script:FakeReg[$ffk]['PasswordManagerEnabled'] -eq 0 -and "$($script:FakeReg[$ffk]['Preferences'])" -like '*browser.safebrowsing.phishing.enabled*' }
Assert 'Browsers: nothing FAILED' { -not @($script:Results | Where-Object Status -eq 'FAILED').Count }

# Never take the person running the script out of Administrators
$script:LocalUsers = @(
    [pscustomobject]@{ Name = 'Administrator'; Enabled = $false; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-500' }; PasswordNeverExpires = $false; UserMayChangePassword = $true; PasswordRequired = $true },
    [pscustomobject]@{ Name = 'alice'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1001' }; PasswordNeverExpires = $false; UserMayChangePassword = $true; PasswordRequired = $true },
    [pscustomobject]@{ Name = 'carol'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1002' }; PasswordNeverExpires = $false; UserMayChangePassword = $true; PasswordRequired = $true },
    [pscustomobject]@{ Name = 'mallory'; Enabled = $true; SID = [pscustomobject]@{ Value = 'S-1-5-21-1-2-3-1003' }; PasswordNeverExpires = $false; UserMayChangePassword = $true; PasswordRequired = $true })
function Get-LocalUser { param([string]$Name) if ($Name) { $script:LocalUsers | Where-Object Name -eq $Name } else { $script:LocalUsers } }
function Get-LocalGroup { }
function Remove-LocalUser { }
function Get-GroupMembers([string]$Group) {
    if ($Group -ne 'Administrators') { return @() }
    foreach ($n in 'alice', 'carol', 'mallory') { [pscustomobject]@{ Short = $n; Full = "PC\$n"; IsLocal = $true; Class = 'User' } }
}
$script:Removed = @()
function Remove-GroupMember([string]$Group, [string]$Member) { $script:Removed += "$Group/$Member" }
$script:AuthAdmins = @('alice'); $script:AuthUsers = @('carol'); $script:Me = 'carol'; $script:NewPassword = 'skip'
$script:Mode = 'Apply'; $script:AssumeYes = $true; Reset-Results
Invoke-Users
Assert 'Users: an unauthorized admin is removed' { $script:Removed -contains 'Administrators/PC\mallory' }
Assert 'Users: the person running the script is never removed from Administrators' {
    $script:Removed -notcontains 'Administrators/PC\carol' -and @($script:Results | Where-Object { $_.Status -eq 'REVIEW' -and $_.Text -like 'You (PC\carol)*' }).Count -eq 1 }
$script:Me = 'alice'

# Deleting files whose names contain [ ] (common in torrent and media names)
$fdir = Join-Path $tmp 'files'
Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $fdir -Force | Out-Null
$f1 = Join-Path $fdir 'song [remix].mp3'; $f2 = Join-Path $fdir 'plain.mp3'
[IO.File]::WriteAllText($f1, 'x'); [IO.File]::WriteAllText($f2, 'x')
Remove-FileList @($f1, $f2)
Assert 'Remove-FileList deletes "song [remix].mp3" (not treated as a wildcard)' {
    -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $f1) -and -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $f2) }

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
[Console]::WriteLine('')
[Console]::WriteLine("Windows logic tests: $pass passed, $fail failed")
if ($fail -gt 0) { exit 1 }
