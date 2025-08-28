<#
.SYNOPSIS
    This is the second part of a two-part script to automate a VM restart.
    It is designed to run on system startup. Its logic is to check for a
    flag file created by the first script. If the file is present, it will
    perform post-reboot actions and clean up the flag file. If the file is
    not found, it will do nothing and assume the reboot was unscheduled.

.DESCRIPTION
    The script checks for the existence of a specific flag file. If found,
    it waits for services to start, checks the status of a specific service,
    attempts to start the service if it's not running, sends a final
    email report, and then deletes the flag file to prevent future executions
    on manual reboots.

    If the flag file is NOT found, it treats the event as an unscheduled reboot
    and immediately sends an alert email with key VM and service status information.

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
        if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
            Write-Host "Az.KeyVault module not found. Installing..."
            Install-Module -Name Az.KeyVault -Force -Scope AllUsers
        }
        
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
$serviceName = "BrokerInfrastructure"    #Background Tasks Infrastructure Service
$RebootFlagFile = "C:\Windows\Temp\RestartFlag.txt"
$logPath = "C:\IT-Scripts-1Deg\logs"
$logFile = Join-Path -Path $logPath -ChildPath "Restart_Monitor_$(Get-Date -Format "yyyy-MM-dd").log"
$RebootThresholdMinutes = 15 # Time in minutes after reboot to check for flag.

# =========================================================================
# Main Script Logic
# =========================================================================

if (-not (Test-Path $logPath)) {
    Write-Host "Creating log directory: $logPath"
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

Start-Transcript -Path $logFile -Append

try {
    $vmName = (Get-CimInstance Win32_ComputerSystem).Name
    $vmIP = (Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }).IPAddress[0]
    $LastBootUpTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $UptimeMinutes = (New-TimeSpan -Start $LastBootUpTime -End (Get-Date)).TotalMinutes
    Write-Host "Current system uptime is $UptimeMinutes minutes."

    if ($UptimeMinutes -lt $RebootThresholdMinutes) {
        Write-Host "A recent reboot has been detected."
        $FlagExists = Test-Path -Path $RebootFlagFile
        
        if ($FlagExists) {
            Write-Host "Scheduled reboot flag found. This was a planned reboot."

            # Get the status of the specified service.
            $serviceStatus = "Not Found"
            $serviceCheck = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($serviceCheck) {
                $serviceStatus = $serviceCheck.Status
            }

            $Body = "The VM $vmName has successfully completed its scheduled reboot.
VM Name: $vmName
VM IP: $vmIP
Service Monitored: $serviceName
Service Status: $serviceStatus
"
            Send-EmailNotification -Subject "VM scheduled reboot Successfully - $vmName" -Body $Body

            # Clean up the flag file after scheduled reboot
            Remove-Item -Path $RebootFlagFile -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "Scheduled reboot flag NOT found. This was an unscheduled reboot."

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

            $Subject = "ALERT: Unscheduled Reboot Detected on VM $($vmName)"
            $Body = "The VM $vmName has rebooted without the scheduled reboot flag file being present. This indicates a user-initiated or unexpected reboot.
Please investigate this event.

Server Uptime: $($UptimeMinutes) minutes
Detected at: $(Get-Date)
VM Name: $vmName
VM IP: $vmIP
Service Name: $serviceName
Service Status: $serviceStatus
Action Taken: $serviceActionTaken"

            Send-EmailNotification -Subject $Subject -Body $Body
            Write-Host "Alert email sent. Script finished."
        }
    }
    else {
        Write-Host "No recent reboot detected. Exiting script."
    }
}
catch {
    Write-Error "An error occurred during script execution: $_"
    Write-Host "Script failed with error: $_"
}
finally {
    Remove-OldLogs -Path $logPath -RetentionDays 30
    Write-Host "Script execution completed at $(Get-Date)."
    Stop-Transcript
}
