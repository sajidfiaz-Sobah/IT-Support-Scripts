# =========================================================================
# Powershell Script for Scheduled VM Restart - PART 2 (Post-Reboot)
# =========================================================================

<#
.SYNOPSIS
    This is the second part of a two-part script to automate a VM restart.
    It is designed to run on system startup. Its logic is to check for a
    flag file created by the first script. If the file is present, it will
    perform post-reboot actions and clean up the flag file. If the file is
    not found, it will do nothing.

.DESCRIPTION
    The script checks for the existence of a specific flag file. If found,
    it waits for services to start, checks the status of a specific service,
    attempts to start the service if it's not running, sends a final
    email report, and then deletes the flag file to prevent future executions
    on manual reboots.

.NOTES
    Author: Sajid
    Date: August 21, 2025
#>

# =========================================================================
# Functions (MUST be defined before they are called)
# =========================================================================

function Convert-SecureStringToString {
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.SecureString]$SecureString
    )
    if ($SecureString -and $SecureString.Length -gt 0) {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        try {
            return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
        }
    }
    return $null
}

function Send-EmailNotification {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Subject,
        [Parameter(Mandatory=$true)]
        [string]$Body
    )

$keyVaultName = "YourKeyVaultName"
$sendGridSecretName = "SendGrid-ApiKey"
$senderEmailSecretName = "SenderEmail-noreply"
$recipientEmailSecretName = "RecipientEmail"
$sendGridSmtpServer = "smtp.sendgrid.net"
$sendGridSmtpPort = 587
    
    try {
        Write-Host "Connecting to Azure with Managed Identity..."
        Connect-AzAccount -Identity -ErrorAction Stop

        try {
            Write-Host "Retrieving SendGrid API Key from Azure Key Vault..."
            $sendGridApiKeySecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $sendGridSecretName -ErrorAction Stop
            $sendGridApiKey = Convert-SecureStringToString -SecureString $sendGridApiKeySecret.SecretValue
        } catch {
            Write-Error "Failed to retrieve the SendGrid API Key secret. Please verify the Key Vault name, secret name ($sendGridSecretName), and 'Get' permissions."
            return
        }

        try {
            Write-Host "Retrieving sender email from Azure Key Vault..."
            $sendGridSenderSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $senderEmailSecretName -ErrorAction Stop
            $sendGridSender = Convert-SecureStringToString -SecureString $sendGridSenderSecret.SecretValue
        } catch {
            Write-Error "Failed to retrieve the sender email secret. Please verify the Key Vault name, secret name ($senderEmailSecretName), and 'Get' permissions."
            return
        }

        try {
            Write-Host "Retrieving recipient email from Azure Key Vault..."
            $emailToSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $recipientEmailSecretName -ErrorAction Stop
            $emailTo = Convert-SecureStringToString -SecureString $emailToSecret.SecretValue
        } catch {
            Write-Error "Failed to retrieve the recipient email secret. Please verify the Key Vault name, secret name ($recipientEmailSecretName), and 'Get' permissions."
            return
        }
        
        $message = New-Object System.Net.Mail.MailMessage
        $message.From = $sendGridSender
        $message.To.Add($emailTo)
        $message.Subject = $Subject
        $message.Body = $Body
        $message.IsBodyHtml = $false

        $smtp = New-Object System.Net.Mail.SmtpClient($sendGridSmtpServer, $sendGridSmtpPort)
        $smtp.EnableSsl = $true
        $smtp.DeliveryMethod = "Network"
        $smtp.UseDefaultCredentials = $false
        $smtp.Credentials = New-Object System.Net.NetworkCredential("apikey", $sendGridApiKey)
        $smtp.Send($message)

        Write-Host "Email sent successfully: '$Subject'"

    }
    catch {
        Write-Error "Failed to send email. A general error occurred: $_"
    }
}

function Remove-OldLogs {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [int]$RetentionDays
    )
    Write-Host "Checking for logs older than $RetentionDays days in $Path..."
    try {
        Get-ChildItem -Path $Path -File | Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$RetentionDays) } | Remove-Item -Force -ErrorAction Stop
        Write-Host "Old logs removed successfully."
    }
    catch {
        Write-Warning "Failed to remove old logs. Error: $_"
    }
}

# =========================================================================
# User-Configurable Variables
# =========================================================================
$serviceName = "BrokerInfrastructure"    #Service to Monitor after restart
$restartFlagFile = "C:\Windows\Temp\RestartFlag.txt"
$logPath = "C:\IT-Scripts-1Deg\logs"
$logFile = Join-Path -Path $logPath -ChildPath "Restart_post_$(Get-Date -Format "yyyy-MM-dd").log"
$logRetentionDays = 15

# =========================================================================
# Main Script Logic
# =========================================================================

# Ensure the log directory exists.
if (-not (Test-Path $logPath)) {
    Write-Host "Creating log directory: $logPath"
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

# Check for the restart flag. If not found, exit the script.
if (-not (Test-Path $restartFlagFile)) {
    Write-Host "No flag file found. This was a manual or unscheduled restart. Exiting post-reboot script."
    return
}

Start-Transcript -Path $logFile -Append

try {
    Write-Host "Flag file found. Performing post-restart actions."
    Remove-OldLogs -Path $logPath -RetentionDays $logRetentionDays
    
    Write-Host "Waiting 5 minutes for services to start..."
    Start-Sleep -Seconds (5 * 60)

    $vmName = (Get-CimInstance Win32_ComputerSystem).Name
    $vmIP = (Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null -and $_.IPAddress[0] -match '^\d{1,3}(\.\d{1,3}){3}$' }).IPAddress[0]

    $serviceStatus = "Not Found"
    $serviceActionTaken = "None"
    
    $serviceCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($serviceCheck) {
        $serviceStatus = $serviceCheck.Status
        if ($serviceStatus -ne "Running") {
            Write-Host "Service '$serviceName' is not running. Attempting to start it..."
            try {
                Start-Service -Name $serviceName -ErrorAction Stop
                $serviceStatus = "Running"
                $serviceActionTaken = "Script started the service."
            } catch {
                Write-Error "Failed to start service '$serviceName'. Error: $_"
                $serviceActionTaken = "Script failed to start the service."
            }
        } else {
            $serviceActionTaken = "Service was already running."
        }
    } else {
        $serviceActionTaken = "Service was not found on the system."
    }

    $body = @"
    VM Restart Complete!

    The VM has been successfully restarted.

    VM Name: $vmName
    VM IP: $vmIP

    Service Status:
    - Service Name: $serviceName
    - Final Status: $serviceStatus
    - Action Taken: $serviceActionTaken
"@
    Send-EmailNotification -Subject "VM Restarted - $vmName" -Body $body

    Remove-Item $restartFlagFile -ErrorAction SilentlyContinue
    Write-Host "Removed flag file: $restartFlagFile"

}
catch {
    Write-Error "An unhandled error occurred in the post-reboot script. Error: $_"
}
finally {
    Remove-OldLogs -Path $logPath -RetentionDays $logRetentionDays
    Write-Host "Script execution completed at $(Get-Date)."
    Stop-Transcript
}
