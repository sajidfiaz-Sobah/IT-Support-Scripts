# =========================================================================
# Powershell Script for Scheduled VM Restart - PART 1 (Pre-Reboot)
# =========================================================================

<#
.SYNOPSIS
    This is the first part of a two-part script to automate a VM restart.
    It is designed to run on a daily schedule. Its sole purpose is to
    send a pre-reboot email notification, create a flag file to signal
    the second script, and then initiate a VM restart.

.DESCRIPTION
    The script retrieves the VM's hostname and IP, fetches email credentials
    from Azure Key Vault, sends a notification, creates a flag file
    at a specific path, and then triggers a restart. it sends email using sendgrid SMTP. 

.NOTES
    Author: Sajid
    Date: August 21, 2025
#>

# =========================================================================
# Functions (MUST be defined before they are called)
# =========================================================================

# A robust function to convert a SecureString to a plain text string.
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

# Function to send an email using SendGrid via SMTP.
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

        # --- Retrieve Key Vault Secrets with specific error handling ---
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
        
        # Create the email message.
        $message = New-Object System.Net.Mail.MailMessage
        $message.From = New-Object System.Net.Mail.MailAddress($sendGridSender) # FIXED
        $message.To.Add($emailTo)
        $message.Subject = $Subject
        $message.Body = $Body
        $message.IsBodyHtml = $false

        # Create the SMTP client and send the email.
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

# Function to remove old log files.
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
$restartFlagFile = "C:\Windows\Temp\RestartFlag.txt"
$logPath = "C:\IT-Scripts-1Deg\logs"
$logFile = Join-Path -Path $logPath -ChildPath "Restart_pre_$(Get-Date -Format "yyyy-MM-dd").log"
$logRetentionDays = 15

# =========================================================================
# Main Script Logic
# =========================================================================

# Ensure the log directory exists.
if (-not (Test-Path $logPath)) {
    Write-Host "Creating log directory: $logPath"
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

$transcriptStarted = $false
try {
    Start-Transcript -Path $logFile -Append
    $transcriptStarted = $true
} catch {
    Write-Warning "Could not start transcript: $_"
}

try {
    Write-Host "Starting pre-reboot script."
    Remove-OldLogs -Path $logPath -RetentionDays $logRetentionDays

    # Get VM details for the email.
    $vmName = (Get-CimInstance Win32_ComputerSystem).Name
    $vmIP = (Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }).IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1 # FIXED

    # Build the pre-restart email body.
    $body = @"
    VM Restart Imminent

    This is an automated notification. The VM will restart in 15 minutes.
    
    VM Name: $vmName
    VM IP: $vmIP
    
    Please save any open work and prepare for the restart.
"@
    # Send the first email notification.
    Send-EmailNotification -Subject "VM Restart Scheduled" -Body $body

    # Create the restart flag file.
    New-Item -Path $restartFlagFile -ItemType File -Force | Out-Null
    Write-Host "Created flag file: $restartFlagFile"

    # Wait for 15 minutes before restarting.
    Write-Host "Waiting 15 minutes before restarting..."
    Start-Sleep -Seconds (15 * 60)

    # Restart the computer.
    Write-Host "Restarting VM now..."
    Restart-Computer -Force

}
catch {
    Write-Error "An unhandled error occurred in the pre-reboot script. Error: $_"
}
finally {
    Remove-OldLogs -Path $logPath -RetentionDays 30
    Write-Host "Script execution completed at $(Get-Date)."
    if ($transcriptStarted) {
        Stop-Transcript
    }
}
