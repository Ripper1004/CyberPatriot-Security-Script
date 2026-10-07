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
                                                         SeDenyInteractiveLogonRight = '*S-1-5-32-545' } }
function secedit.exe {
    $all = $args
    $cfg = $all[[array]::IndexOf($all, '/cfg') + 1]
    if ($all -contains '/export') {
        $out = @('[Unicode]', 'Unicode=yes')
        foreach ($sec in $script:FakePolicy.Keys) { $out += "[$sec]"; foreach ($k in $script:FakePolicy[$sec].Keys) { $out += "$k = $($script:FakePolicy[$sec][$k])" } }
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

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
[Console]::WriteLine('')
[Console]::WriteLine("Windows logic tests: $pass passed, $fail failed")
if ($fail -gt 0) { exit 1 }
