# CyberPatriot Security Scripts & Checklists

This repository is a hub for CyberPatriot teams — it contains **automated hardening scripts** and **detailed competition checklists** for Windows 10, Windows Server 2022, Ubuntu, and Linux Mint.

## What's Included

### Scripts
| Script | OS | Description |
|--------|----|-------------|
| `secure_windows.ps1` | Windows 10 | PowerShell hardening (services, firewall, Defender, audit policies, registry) |
| `Windows_Server_22.ps1` | Windows Server 2022 | Server-focused hardening (AD-ready, BitLocker, event logs, roles) |
| `secure_ubuntu.sh` | Ubuntu | Bash hardening (UFW, SSH, sysctl, PAM, auditd, AppArmor) |
| `secure_linux_mint.sh` | Linux Mint | Mint-specific hardening (LightDM, Cinnamon/MATE/Xfce, screensaver lock, plus full Ubuntu hardening) |

### Competition Checklists
| Checklist | Description |
|-----------|-------------|
| [`checklists/ubuntu_checklist.md`](checklists/ubuntu_checklist.md) | Step-by-step Ubuntu competition walkthrough |
| [`checklists/windows10_checklist.md`](checklists/windows10_checklist.md) | Step-by-step Windows 10 competition walkthrough |
| [`checklists/windows_server_2022_checklist.md`](checklists/windows_server_2022_checklist.md) | Step-by-step Windows Server 2022 walkthrough (includes AD, DNS, DHCP, IIS) |
| [`checklists/linux_mint_checklist.md`](checklists/linux_mint_checklist.md) | Step-by-step Linux Mint walkthrough (Mint-specific + Ubuntu base) |

Each checklist covers: forensic questions, user/group management, password policies, service hardening, firewall, backdoor hunting, application-specific hardening (Apache, MySQL, PHP, DNS, etc.), and final verification.

## Ubuntu Hardening Overview
The `secure_ubuntu.sh` script performs the following actions to harden an Ubuntu workstation or server:

1. **Package Maintenance**: Updates all installed packages, removes unused dependencies, and enables unattended security updates.
2. **Firewall & Intrusion Prevention**: Configures UFW with a deny-by-default policy and deploys Fail2ban to automatically block repeated authentication failures.
3. **SSH Hardening**: Enforces modern ciphers and MACs, disables root and password-based logins, and applies strict session controls.
4. **Kernel & Filesystem Protections**: Applies sysctl tuning, hardens shared memory, and disables uncommon filesystems to limit privilege escalation paths.
5. **Authentication Policies**: Sets password aging requirements, enforces PAM password complexity and account lockout, and deploys security banners.
6. **Auditing & Monitoring**: Installs auditd with curated rules, deploys antivirus/rootkit scanners, and ensures AppArmor, ClamAV, and other security services start automatically.
7. **Service Hygiene**: Purges legacy network services, restricts cron/at usage, and configures unattended upgrades for ongoing remediation.

> **Important:** The Ubuntu script is intentionally strict. Review the SSH configuration changes (password logins are disabled) and adjust allow-list rules in UFW/Fail2ban before running it on production systems.

## Overview
The Windows script performs the following actions to harden a Windows 10 machine:

1. **Disable Unnecessary Services**: Disables services that are not required to reduce the attack surface.
2. **Disable Guest Account and Unnecessary Users**: Disables default accounts like `Guest` and `DefaultAccount` to prevent unauthorized access.
3. **Set Password Policies**: Configures secure password policies such as minimum password length, password complexity, and account lockout settings.
4. **Enable Windows Defender Real-Time Protection**: Ensures that Windows Defender is actively monitoring for threats.
5. **Configure Firewall Settings**: Blocks all inbound connections by default while adding exceptions for essential services.
6. **Disable Remote Assistance**: Disables Remote Assistance to prevent unauthorized remote access.
7. **Audit Policy Configuration**: Enables auditing for account logon, account management, and logon/logoff activities.
8. **Disable USB Storage Access**: Restricts access to USB storage to prevent unauthorized data access or malware introduction.
9. **Remove Unnecessary Software**: Uninstalls outdated or potentially vulnerable software like `Adobe Flash Player` and `Java`.
10. **Enable Automatic Windows Updates**: Ensures Windows Update is configured to automatically download and install updates.
11. **Disable SMBv1**: Turns off the legacy and insecure SMBv1 protocol.
12. **Enable Additional Audit Policies**: Adds auditing for policy change and object access events.
13. **Disable LLMNR**: Turns off Link-Local Multicast Name Resolution to reduce spoofing risks.
14. **Disable NetBIOS over TCP/IP**: Disables legacy NetBIOS services on all network adapters.
15. **Disable AutoRun**: Prevents automatic execution of media to mitigate autorun-based attacks.

## Running the Windows Script
### Prerequisites
- **Administrative Privileges**: The script must be run as an administrator to make the necessary system changes.
- **PowerShell**: Make sure you have PowerShell installed and the appropriate permissions to execute scripts.

### Installation Options
#### Option 1: Install Git and Clone the Repository (Recommended)
To use Git to clone this repository and run the script, follow these steps:

1. **Install Chocolatey and Git**:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
   choco install git -y
   ```

2. **Clone the Repository**:
   ```sh
   git clone https://github.com/Ripper1004/CyberPatriot-Security-Script.git
   cd CyberPatriot-Security-Script
   ```

3. **Run the Script**:
   - Open PowerShell **as an Administrator**.
   - Bypass the execution policy for this script only and run it:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\secure_windows.ps1
   ```

#### Option 2: Manual Installation of Git (Alternative)
If you prefer to manually install Git without using Chocolatey, you can follow these steps:

1. **Download and Install Git**:
   ```powershell
   $gitInstaller = "https://github.com/git-for-windows/git/releases/download/v2.42.0.windows.1/Git-2.42.0-64-bit.exe"
   $destination = "$env:TEMP\Git-Installer.exe"
   Invoke-WebRequest -Uri $gitInstaller -OutFile $destination
   Start-Process -FilePath $destination -ArgumentList "/SILENT" -Wait
   ```

2. **Clone the Repository**:
   ```sh
   git clone https://github.com/Ripper1004/CyberPatriot-Security-Script.git
   cd CyberPatriot-Security-Script
   ```

3. **Run the Script**:
   - Open PowerShell **as an Administrator**.
   - Bypass the execution policy for this script only and run it:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\secure_windows.ps1
   ```

#### Option 3: Manual Download of the Script
If you cannot use Chocolatey or Git, you can manually download and run the script as follows:

1. **Download the Script Manually**:
   - Navigate to the GitHub repository (e.g., `https://github.com/Ripper1004/CyberPatriot-Security-Script`).
   - Click on the **"Code"** button, then click **"Download ZIP"**.
   - Extract the ZIP file to a location on your computer.

2. **Run the Script**:
   - Open PowerShell **as an Administrator**.
   - Bypass the execution policy for this script only and run it:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\secure_windows.ps1
   ```

### Important Notes for Windows
- **Execution Policy**: To run this script without permanently changing the system's execution policy, use the `-ExecutionPolicy Bypass` option when executing the script as shown above. This ensures only this instance of the script is exempt from the policy.

- **Administrator Rights**: The script checks if it is running with administrative privileges. If not, it will relaunch itself with elevated permissions.
- **Manual Verification**: While the script automates basic security hardening, manual verification is recommended to ensure all CyberPatriot-specific requirements are met.
- **Firewall and Defender Issues**: In certain environments (e.g., virtual machines or restricted environments), some commands, such as configuring the firewall or enabling Windows Defender, may fail. Consider manually reviewing these settings if necessary.

## Script Summary
After running, the script provides a summary of each action performed, indicating whether it was successful or failed. This helps in identifying areas that need manual intervention.

### Example Summary Output
```
Summary of Actions:
Temp Directory Creation: Success
Disable Service RemoteRegistry: Success
Disable User Guest: Success
Set Password Policies: Success
Enable Windows Defender Real-Time Protection: Failed - Provider load failure
Configure Firewall: Failed - Invalid class
...
```

## Contribution
Contributions to enhance the script are welcome! Feel free to submit a pull request if you have any improvements or additional security measures to suggest.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Disclaimer
This script is provided "as is" without warranty of any kind. Use at your own risk, and always test in a non-production environment first.

## Running the Linux Mint Script

### Prerequisites
- **Root Access**: Execute as `root` or via `sudo`.
- **Internet Connectivity**: Required for downloading updates and packages.
- **Backup**: Take a VM snapshot before running — many config files are modified.

### Usage
1. Clone or download this repository onto the Linux Mint host.
2. Make the script executable: `chmod +x secure_linux_mint.sh`.
3. Run as root:
   ```bash
   sudo ./secure_linux_mint.sh
   ```
4. Review output for warnings and verify required services remain running.

### What It Covers Beyond Ubuntu
- **LightDM hardening**: Disables guest sessions, hides user list, disables autologin.
- **Desktop environment locks**: Enables screensaver locking for Cinnamon, MATE, and Xfce.
- **Mint Welcome/update**: Disables Mint Welcome autostart, configures mintUpdate.
- **Nemo file sharing**: Disables built-in file sharing.
- **User/group auditing**: Lists all human accounts, checks empty passwords, reviews sudoers.
- **Prohibited software scan**: Searches for hacking tools, games, and unauthorized software.
- **Cron job audit**: Reviews all user and system cron jobs.
- **SUID/SGID audit**: Finds and logs all SUID/SGID binaries for review.
- **Listening port audit**: Shows all open ports for manual review.
- **Account lockout**: Configures PAM faillock for brute-force protection.

### Post-Run Checklist
- Confirm SSH key-based access works (password auth is disabled).
- Validate firewall: `sudo ufw status verbose`.
- Review the SUID/SGID lists in `/tmp/suid_files.txt` and `/tmp/sgid_files.txt`.
- Run `sudo lynis audit system` for a comprehensive audit.
- See [`checklists/linux_mint_checklist.md`](checklists/linux_mint_checklist.md) for the full competition walkthrough.

## Running the Ubuntu Script

### Prerequisites
- **Root Access**: Execute the script as `root` or via `sudo` to ensure every hardening step succeeds.
- **Internet Connectivity**: Required for downloading updates and security packages such as Fail2ban, ClamAV, and auditd.
- **Backup**: Many system configuration files are modified (backups are created with timestamps). Ensure you have snapshots or backups before running.

### Usage
1. Clone or download this repository onto the Ubuntu host.
2. Make the script executable: `chmod +x secure_ubuntu.sh`.
3. Run the hardening steps as root:
   ```bash
   sudo ./secure_ubuntu.sh
   ```
4. Review the console output for any warnings (some tools such as `freshclam` and `rkhunter` might require additional network access) and verify that essential services like SSH remain reachable.

### Post-Run Checklist
- Confirm that user accounts have SSH key-based access since password authentication is disabled.
- Validate firewall rules with `sudo ufw status verbose` and add allowances for additional services as needed.
- Examine `/etc/ssh/sshd_config.bak.*` and other `.bak` files if you need to revert any changes.
- Run `sudo lynis audit system` for an extra security audit after the initial hardening completes.
- See [`checklists/ubuntu_checklist.md`](checklists/ubuntu_checklist.md) for the full competition walkthrough.

