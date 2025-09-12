# Windows 10 Security Hardening Script for CyberPatriot

This repository contains a PowerShell script designed to secure a Windows 10 system, primarily aimed at use in CyberPatriot competitions. The script includes a series of steps to disable unnecessary services, configure firewall settings, enhance password policies, and more to meet basic security standards.

## Overview
The script performs the following actions to harden a Windows 10 machine:

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

The companion `Windows_Server_22.ps1` script applies similar safeguards for Windows Server 2022, including automatic updates,
SMBv1 removal, and disabling LLMNR, NetBIOS, and AutoRun.

## Running the Script
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

### Important Notes
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

