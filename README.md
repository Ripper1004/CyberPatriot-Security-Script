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

## Running the Script
### Prerequisites
- **Administrative Privileges**: The script must be run as an administrator to make the necessary system changes.
- **PowerShell**: Make sure you have PowerShell installed and the appropriate permissions to execute scripts.

### How to Run
1. **Clone the Repository**:
   ```sh
   git clone https://github.com/your_username/Windows10-Security-Script.git
   cd Windows10-Security-Script
   ```

2. **Run the Script**:
   - Open PowerShell **as an Administrator**.
   - Run the script:
   ```sh
   .\secure_windows.ps1
   ```

### Important Notes
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

