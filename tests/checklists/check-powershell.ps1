# Syntax-checks every PowerShell block in the Windows checklists with the real
# PowerShell parser, and flags <placeholders> a beginner would paste as-is.
# This does NOT run the commands (that needs a Windows image).
#   pwsh -NoProfile -File tests/checklists/check-powershell.ps1
$repo = Resolve-Path (Join-Path $PSScriptRoot '..' '..')
$bad = 0; $n = 0
foreach ($f in 'windows-10-11', 'windows-server') {
  $json = python3 (Join-Path $PSScriptRoot 'extract.py') (Join-Path $repo "docs/checklists/$f.md")
  foreach ($line in $json) {
    $b = $line | ConvertFrom-Json
    if ($b.lang -notin 'powershell', 'ps1') { continue }
    $n++
    $errs = $null; $tok = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($b.code, [ref]$tok, [ref]$errs)
    foreach ($e in $errs) { $bad++; "SYNTAX  $f.md:$($b.line) [$($b.step)] $($e.Message)" }
    if ($b.code -match '(?m)^[^#\r\n]*<[A-Za-z][A-Za-z _-]*>') { $bad++; "PLACEHOLDER  $f.md:$($b.line) [$($b.step)] has a <placeholder>: use a real example value and say what to change in a comment" }
  }
}
"checked $n PowerShell blocks: $bad problem(s)"
exit ($bad -gt 0 ? 1 : 0)
