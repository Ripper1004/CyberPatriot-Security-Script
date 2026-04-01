# Windows Server 2022 Security Hardening Script
# Run as Administrator

# Function to write logs
function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $logMessage
    Add-Content -Path ".\security_hardening.log" -Value $logMessage
}

Write-Log "Starting Windows Server 2022 Security Hardening Script"

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "Error: Script must be run as Administrator"
    exit 1
}

# 1. Password Policy
Write-Log "Configuring Password Policy"
net accounts /MINPWLEN:14 /MAXPWAGE:30 /MINPWAGE:1 /UNIQUEPW:24
secedit /export /cfg c:\secpol.cfg
(gc C:\secpol.cfg).replace("PasswordComplexity = 0", "PasswordComplexity = 1") | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
Remove-Item -force c:\secpol.cfg -confirm:$false

# 2. Account Lockout Policy
Write-Log "Configuring Account Lockout Policy"
net accounts /lockoutduration:30 /lockoutthreshold:5 /lockoutwindow:30

# 3. Disable Guest and Administrator accounts
Write-Log "Disabling Guest and Administrator accounts"
Net User Guest /Active:No
Net User Administrator /Active:No

# 4. Enable Windows Defender
Write-Log "Configuring Windows Defender"
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableIntrusionPreventionSystem $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -SubmitSamplesConsent 2

# 5. Configure Windows Firewall
Write-Log "Configuring Windows Firewall"
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

# 6. Enable and Configure Auditing
Write-Log "Configuring Audit Policies"
auditpol /set /category:* /success:enable /failure:enable

# 7. Disable unnecessary services
Write-Log "Disabling unnecessary services"
$servicesToDisable = @(
    "XblAuthManager",
    "XblGameSave",
    "XboxGipSvc",
    "XboxNetApiSvc",
    "RemoteRegistry",
    "TelemetryService"
)

foreach ($service in $servicesToDisable) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
}

# 8. Registry Hardening
Write-Log "Applying Registry Hardening"
# Disable Remote Desktop
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1

# Enable SMB Signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" RequireSecuritySignature -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" EnableSecuritySignature -Value 1

# Disable LLMNR
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord

# 9. Advanced Security Settings
Write-Log "Applying advanced security hardening"
# Enable LSA Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
# Disable WDigest (clear-text passwords in memory)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
# Set NTLMv2 only
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null
# Restrict anonymous access
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f | Out-Null
# Enable process creation command-line logging
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
# Enable PowerShell script block and module logging
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
# Disable AutoRun and AutoPlay
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutoPlay /t REG_DWORD /d 1 /f | Out-Null
# Disable Remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f | Out-Null

# 10. Disable PowerShell v2 (prevents downgrade attacks)
Write-Log "Disabling PowerShell v2"
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction SilentlyContinue | Out-Null

# 11. Disable USB Storage
Write-Log "Disabling USB storage"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f | Out-Null

# 12. Configure Windows Defender Hardening
Write-Log "Hardening Windows Defender"
Set-MpPreference -PUAProtection Enabled -ErrorAction SilentlyContinue
Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue

# 13. File System Security
Write-Log "Configuring File System Security"
# Set default NTFS permissions
icacls C:\Windows /reset /T /C
icacls C:\Windows\System32 /reset /T /C

# 10. Enable BitLocker
Write-Log "Configuring BitLocker"
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -RecoveryPasswordProtector

# 11. Configure Windows Update
Write-Log "Configuring Windows Update"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value 3

# 12. Remove unnecessary features
Write-Log "Removing unnecessary Windows features"
$featuresToRemove = @(
    "Internet-Explorer-Optional-amd64",
    "TFTP",
    "TelnetClient",
    "SimpleTCP"
)

foreach ($feature in $featuresToRemove) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}

# 13. Disable legacy network protocol services
Write-Log "Disabling legacy network protocol services"
$legacyServices = @(
    "TlntSvr",  # Telnet
    "FTPSVC",   # FTP
    "Tftpd",    # TFTP
    "W3SVC",    # HTTP Web Server
    "SNMP",     # SNMP v1/v2
    "RshSvc",   # RSH
    "Rlogon",   # Rlogin
    "Rexsvc",   # Rexec
    "POP3Svc",  # POP3
    "IMAP4Svc", # IMAP
    "NTDS",     # LDAP
    "SMTPSVC",  # SMTP
    "simptcp",  # Finger, Daytime, Echo, Chargen
    "NfsClnt",  # NFS Client
    "NfsServer" # NFS Server
)
foreach ($service in $legacyServices) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
}

# Disable SMBv1
Write-Log "Disabling SMBv1"
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null

# Disable NetBIOS over TCP/IP
Write-Log "Disabling NetBIOS over TCP/IP"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object { $_.SetTcpipNetbios(2) } | Out-Null

# 14. Configure Event Log Sizes
Write-Log "Configuring Event Logs"
Limit-EventLog -LogName Application -MaximumSize 32768KB
Limit-EventLog -LogName Security -MaximumSize 81920KB
Limit-EventLog -LogName System -MaximumSize 32768KB

# Final Status
Write-Log "Security Hardening Complete - System requires restart"
Write-Log "Please review security_hardening.log for details"

# Prompt for restart
$restart = Read-Host "Do you want to restart the computer now? (y/n)"
if ($restart -eq 'y') {
    Restart-Computer -Force
}
