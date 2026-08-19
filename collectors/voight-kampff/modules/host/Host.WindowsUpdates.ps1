<#
.SYNOPSIS
    Module: Windows Updates

.DESCRIPTION
    Enumerates Windows Update status using the native COM object:
    - Last update check timestamp
    - Pending updates (title, KB, severity, download/install status)
    - Recently installed updates (title, KB, date, result)
    - Reboot pending status (Component Based Servicing, Windows Update, pending file rename)

    Does not maintain or require an external KB reference database.
    All intelligence comes from the Windows Update client itself.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKHostWindowsUpdates {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating Windows Update status" -Type "PROCESSING"

    $updateData = [ordered]@{}


    # --------------------------------------------------------
    #  Reboot Pending
    # --------------------------------------------------------
    # Check multiple indicators - any one means a reboot is needed.
    # These are registry-based and work without admin.
    # --------------------------------------------------------

    try {
        $rebootRequired = $false
        $rebootReasons = @()

        # Component Based Servicing
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $rebootRequired = $true
            $rebootReasons += "Component Based Servicing"
        }

        # Windows Update
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $rebootRequired = $true
            $rebootReasons += "Windows Update"
        }

        # Pending file rename operations
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($pendingFileRename.PendingFileRenameOperations) {
            $rebootRequired = $true
            $rebootReasons += "Pending File Rename"
        }

        $updateData["reboot_pending"] = $rebootRequired
        $updateData["reboot_reasons"] = $rebootReasons
    }
    catch {
        Write-LogMessage -Section "Host.WindowsUpdates" -Message "Error checking reboot status: $($_.Exception.Message)" -Level "ERROR"
        $updateData["reboot_pending"] = $null
        $updateData["reboot_reasons"] = @()
    }


    # --------------------------------------------------------
    #  Windows Update Session (COM Object)
    # --------------------------------------------------------

    $updateSession = $null

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
    }
    catch {
        Write-LogMessage -Section "Host.WindowsUpdates" -Message "Unable to create Windows Update session: $($_.Exception.Message)" -Level "ERROR"
        $Data["windows_updates"] = $updateData
        Write-VKStatus -Message "Windows Update enumeration failed - COM object unavailable." -Type "ERROR"
        return
    }


    # --------------------------------------------------------
    #  Last Update Check
    # --------------------------------------------------------

    try {
        $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
        $lastCheckTime = $autoUpdate.Results.LastSearchSuccessDate
        $lastInstallTime = $autoUpdate.Results.LastInstallationSuccessDate

        $updateData["last_check"] = if ($lastCheckTime -and $lastCheckTime -ne [datetime]::MinValue) {
            $lastCheckTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        } else { $null }

        $updateData["last_install"] = if ($lastInstallTime -and $lastInstallTime -ne [datetime]::MinValue) {
            $lastInstallTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        } else { $null }

        # Days since last check for easy backend evaluation
        $updateData["days_since_last_check"] = if ($lastCheckTime -and $lastCheckTime -ne [datetime]::MinValue) {
            ((Get-Date) - $lastCheckTime).Days
        } else { $null }
    }
    catch {
        Write-LogMessage -Section "Host.WindowsUpdates" -Message "Error retrieving last update check time: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  Pending Updates
    # --------------------------------------------------------

    Write-VKStatus -Message "Checking for pending updates" -Type "PROCESSING"

    try {
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0")

        $pendingUpdates = @()

        foreach ($update in $searchResult.Updates) {
            # Map Microsoft severity rating
            $severity = switch ($update.MsrcSeverity) {
                "Critical"  { "Critical" }
                "Important" { "Important" }
                "Moderate"  { "Moderate" }
                "Low"       { "Low" }
                default     { if ($update.MsrcSeverity) { $update.MsrcSeverity } else { "Unspecified" } }
            }

            # Extract KB numbers from the update
            $kbNumbers = @()
            foreach ($kb in $update.KBArticleIDs) {
                $kbNumbers += "KB$kb"
            }

            $pendingUpdates += [ordered]@{
                "title"        = $update.Title
                "kb_numbers"   = $kbNumbers
                "severity"     = $severity
                "is_downloaded"= $update.IsDownloaded
                "is_mandatory" = $update.IsMandatory
                "categories"   = @($update.Categories | ForEach-Object { $_.Name })
            }
        }

        $updateData["pending_count"] = $pendingUpdates.Count
        $updateData["pending_updates"] = $pendingUpdates
    }
    catch {
        Write-LogMessage -Section "Host.WindowsUpdates" -Message "Error searching for pending updates: $($_.Exception.Message)" -Level "ERROR"
        $updateData["pending_count"] = $null
        $updateData["pending_updates"] = @()
    }


    # --------------------------------------------------------
    #  Recently Installed Updates (last 50)
    # --------------------------------------------------------

    Write-VKStatus -Message "Retrieving update history" -Type "PROCESSING"

    try {
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        $maxHistory = [math]::Min($historyCount, 50)

        $history = $updateSearcher.QueryHistory(0, $maxHistory)

        $installedUpdates = @()

        foreach ($entry in $history) {
            # Skip entries with no title (noise)
            if (-not $entry.Title) { continue }

            $resultCode = switch ([int]$entry.ResultCode) {
                0 { "Not Started" }
                1 { "In Progress" }
                2 { "Succeeded" }
                3 { "Succeeded With Errors" }
                4 { "Failed" }
                5 { "Aborted" }
                default { "Unknown" }
            }

            # Extract KB from title if present
            $kbMatch = if ($entry.Title -match 'KB(\d+)') { "KB$($matches[1])" } else { $null }

            $installedUpdates += [ordered]@{
                "title"        = $entry.Title
                "kb_number"    = $kbMatch
                "date"         = if ($entry.Date) { $entry.Date.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
                "result"       = $resultCode
                "operation"    = switch ([int]$entry.Operation) {
                    1 { "Installation" }
                    2 { "Uninstallation" }
                    default { "Unknown" }
                }
            }
        }

        $updateData["installed_recent"] = $installedUpdates
    }
    catch {
        Write-LogMessage -Section "Host.WindowsUpdates" -Message "Error retrieving update history: $($_.Exception.Message)" -Level "ERROR"
        $updateData["installed_recent"] = @()
    }

    $Data["windows_updates"] = $updateData

    Write-VKStatus -Message "Windows Update enumeration complete" -Type "SUCCESS"
}