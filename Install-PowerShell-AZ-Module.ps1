<#
.SYNOPSIS
    This script installs the Az PowerShell module and its dependencies.
.DESCRIPTION
    This script performs the following actions:
    1. Upgrades the PowerShellGet module to ensure the latest version.
    2. Installs the Az PowerShell module from the PowerShell Gallery.
    3. The -Force parameter ensures that any existing versions are updated or overwritten.
    4. The -AllowClobber parameter handles any cmdlet name conflicts.
.NOTES
    This script is designed to be run as an Azure Custom Script Extension.
    Author: Sajid
    Date: August 21, 2025
#>

#>

# Set the execution policy to allow scripts to run.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Check if the NuGet provider is installed and install it if not.
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

# Ensure the latest version of PowerShellGet is installed.
Install-Module -Name PowerShellGet -Force -AllowClobber

# Install the Az module.
# Using -Force and -AllowClobber to ensure it works in all scenarios.
Install-Module -Name Az -Force -AllowClobber -Scope AllUsers

