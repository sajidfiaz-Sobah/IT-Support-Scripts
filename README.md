# Azure VM Monitoring & Automation Scripts

This repository contains PowerShell scripts for automating Azure VM monitoring, scheduled restarts, and module installation. These scripts are designed for use with Azure VMs, Sendgrid SMTP and leverage Azure Key Vault for secure credential management.

## Contents
### 1. `Install-PowerShell-AZ-Module.ps1`
**Purpose:**  
Installs the latest Az PowerShell module and dependencies.  
**Features:**  
- Upgrades PowerShellGet and NuGet provider.
- Installs/updates the Az module for all users.
- Designed for use with Azure Custom Script Extension.
- 
### 2. `pre-reboot-script.ps1`
**Purpose:**  
Initiates a scheduled VM restart.  
**Features:**  
- Creates a flag file to signal a scheduled reboot.
- Sends a pre-reboot notification email using SendGrid credentials from Azure Key Vault.
- Logs actions for auditing.

### 3. `post-reboot-script.ps1`
**Purpose:**  
Executes post-reboot actions after a scheduled VM restart.  
**Features:**  
- Checks for the flag file to confirm a scheduled reboot.
- Waits for services to start, verifies and starts a target service if needed.
- Sends a post-reboot notification email.
- Cleans up logs and removes the flag file.




## Usage

> **Note:**  
> These scripts require appropriate permissions on the Azure VM and access to Azure Key Vault secrets.

1. **Pre-reboot:**  
   Run `pre-reboot-script.ps1` to initiate a scheduled restart.

2. **Post-reboot:**  
   Configure `post-reboot-script.ps1` to run at startup (e.g., via Task Scheduler).

3. **Module Installation:**  
   Use `Install-PowerShell-AZ-Module.ps1` to ensure the Az module is available.



## Configuration

- set azure vm idently
- assign vm identity to access key vault. with managed identity there will be no need to store vault access credentials in the scripts
- Update Key Vault and secret names in the scripts as needed.
- 
- Set the target service name in the post-reboot script. it helpes the verification of vm rebooted successfully
- Adjust log paths and retention periods as required.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Author

Sajid  
August 2025
