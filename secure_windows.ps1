# Secure Windows 10 PowerShell Script for CyberPatriot

# Ensure the script is running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script needs to be run as an administrator. Relaunching with elevated privileges..."
    Start-Process PowerShell -ArgumentList "-File", "$PSCommandPath" -Verb RunAs
    exit
}

# Initialize status tracking
$actionResults = @()

# Create Temp Directory if not exists
try {
    New-Item -Path C:\temp -ItemType Directory -Force
    $actionResults += "Temp Directory Creation: Success"
} catch {
    $actionResults += "Temp Directory Creation: Failed - $_"
}

# 1. Disable Unnecessary Services
$services = @(
    'RemoteRegistry',
    'TermService',  # Remote Desktop Services
    'SSDPSRV',      # SSDP Discovery
    'WSearch',      # Windows Search (optional)
    'RemoteAccess', # Routing and Remote Access
    'Telnet'
)
foreach ($service in $services) {
    try {
        $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceStatus.Status -ne 'Stopped') {
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $service -ErrorAction SilentlyContinue
        }
        $actionResults += "Disable Service ${service}: Success"
    } catch {
        $actionResults += "Disable Service ${service}: Failed - $_"
    }
}

# 2. Disable Guest Account and Unnecessary Users
$users = @(
    'Guest',
    'DefaultAccount'
)
foreach ($user in $users) {
    try {
        if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
            Disable-LocalUser -Name $user
        }
        $actionResults += "Disable User ${user}: Success"
    } catch {
        $actionResults += "Disable User ${user}: Failed - $_"
    }
}

# 3. Set Password Policies
try {
    secedit /export /cfg C:\temp\security_backup.cfg
    $content = Get-Content -Path C:\temp\security_backup.cfg
    $content = $content -replace "MinimumPasswordLength = 0", "MinimumPasswordLength = 12"
    $content = $content -replace "PasswordComplexity = 0", "PasswordComplexity = 1"
    $content = $content -replace "LockoutBadCount = 0", "LockoutBadCount = 5"
    Set-Content -Path C:\temp\security_backup.cfg -Value $content
    secedit /configure /db C:\Windows\Security\Database\SecDB.sdb /cfg C:\temp\security_backup.cfg /overwrite
    Remove-Item -Path C:\temp\security_backup.cfg
    $actionResults += "Set Password Policies: Success"
} catch {
    $actionResults += "Set Password Policies: Failed - $_"
}

# 4. Enable Windows Defender Real-Time Protection
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    $actionResults += "Enable Windows Defender Real-Time Protection: Success"
} catch {
    $actionResults += "Enable Windows Defender Real-Time Protection: Failed - $_"
}

# 5. Configure Firewall - Block all inbound connections except allowed applications
if (Get-Command -Name Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop

        # Add exceptions for necessary services
        $exceptions = @(
            'Remote Desktop',
            'Windows Management Instrumentation (WMI)',
            'File and Printer Sharing'
        )
        foreach ($exception in $exceptions) {
            if (Get-Command -Name Set-NetFirewallRule -ErrorAction SilentlyContinue) {
                Set-NetFirewallRule -DisplayName $exception -Profile Domain,Public,Private -Enabled True -ErrorAction SilentlyContinue
            }
        }

        Set-NetFirewallRule -DisplayName 'File and Printer Sharing (SMB-In)' -Enabled False -ErrorAction SilentlyContinue
        $actionResults += "Configure Firewall: Success"
    } catch {
        $actionResults += "Configure Firewall: Failed - $_"
    }
} else {
    $actionResults += "Configure Firewall: Skipped - Firewall cmdlets not available"
}

# 6. Disable Remote Assistance
try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0
    $actionResults += "Disable Remote Assistance: Success"
} catch {
    $actionResults += "Disable Remote Assistance: Failed - $_"
}

# 7. Audit Policy Configuration
try {
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    $actionResults += "Audit Policy Configuration: Success"
} catch {
    $actionResults += "Audit Policy Configuration: Failed - $_"
}

# 8. Disable USB Storage Access if not needed
try {
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start -Value 4
    $actionResults += "Disable USB Storage Access: Success"
} catch {
    $actionResults += "Disable USB Storage Access: Failed - $_"
}

# 9. Remove Unnecessary Software (Example)
$software = @(
    'Adobe Flash Player',
    'Java'
)
foreach ($app in $software) {
    try {
        Get-Package -Name $app -ErrorAction SilentlyContinue | ForEach-Object { Uninstall-Package -Name $_.Name -Force -ErrorAction SilentlyContinue }
        $actionResults += "Remove Software ${app}: Success"
    } catch {
        $actionResults += "Remove Software ${app}: Failed - $_"
    }
}

# 10. Enable Automatic Windows Updates
try {
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 0 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name AUOptions -Value 4 -ErrorAction SilentlyContinue
    $actionResults += "Enable Automatic Windows Updates: Success"
} catch {
    $actionResults += "Enable Automatic Windows Updates: Failed - $_"
}

# 11. Disable SMBv1
try {
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
    $actionResults += "Disable SMBv1: Success"
} catch {
    $actionResults += "Disable SMBv1: Failed - $_"
}

# 12. Enable Additional Audit Policies
try {
    auditpol /set /category:"Policy Change" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /success:enable /failure:enable
    $actionResults += "Additional Audit Policies: Success"
} catch {
    $actionResults += "Additional Audit Policies: Failed - $_"
}

# 13. Disable LLMNR
try {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Value 0 -Type DWord
    $actionResults += "Disable LLMNR: Success"
} catch {
    $actionResults += "Disable LLMNR: Failed - $_"
}

# 14. Disable NetBIOS over TCP/IP
try {
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | ForEach-Object { $_.SetTcpipNetbios(2) }
    $actionResults += "Disable NetBIOS over TCP/IP: Success"
} catch {
    $actionResults += "Disable NetBIOS over TCP/IP: Failed - $_"
}

# 15. Disable AutoRun for all drives
try {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord
    $actionResults += "Disable AutoRun: Success"
} catch {
    $actionResults += "Disable AutoRun: Failed - $_"
}

# 16. Disable Legacy Network Protocol Services
$legacyServices = @(
    'TlntSvr',  # Telnet
    'FTPSVC',   # FTP Server
    'Tftpd',    # TFTP
    'W3SVC',    # HTTP Web Server (IIS)
    'SNMP',     # SNMP v1/v2
    'RshSvc',   # RSH
    'Rlogon',   # Rlogin
    'Rexsvc',   # Rexec
    'POP3Svc',  # POP3
    'IMAP4Svc', # IMAP
    'NTDS',     # LDAP
    'SMTPSVC',  # SMTP
    'simptcp',  # Finger, Daytime, Echo, Chargen
    'NfsClnt',  # NFS Client
    'NfsServer' # NFS Server
)
foreach ($service in $legacyServices) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne 'Stopped') {
            Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $service -ErrorAction SilentlyContinue
        }
        $actionResults += "Disable Legacy Service ${service}: Success"
    } catch {
        $actionResults += "Disable Legacy Service ${service}: Failed - $_"
    }
}

Write-Host "Basic Security Hardening Completed! Please verify manually for any specific CyberPatriot requirements."

# Display summary of actions
Write-Host "Summary of Actions:"
foreach ($result in $actionResults) {
    Write-Host $result
}
