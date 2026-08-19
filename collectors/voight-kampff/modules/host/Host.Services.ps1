<#
.SYNOPSIS
    Module: Windows Services

.DESCRIPTION
    Enumerates installed Windows services:
    - Service name, display name, description
    - Current state (Running, Stopped, etc.)
    - Start type (Automatic, Manual, Disabled, etc.)
    - Logon account (LocalSystem, NetworkService, specific user, etc.)
    - Binary path (useful for unquoted path and permissions analysis)
    - PID for running services

    Binary path detail is critical for future vulnerability modules:
    - Vul.Services.UnquotedPaths
    - Vul.Services.WeakPermissions
    - Vul.Services.BinaryPermissions

    SCHEMA 1.1 ACQUISITION
    One collection unit:

        host.services.inventory   ->   host.services

    FAIL-CLOSED NOTES
    - The query is terminating and its result is null-guarded. Previously
      the assignment sat inside the try, so a failure left the key absent
      with no record of why.
    - The console summary no longer reports a zero-service count after a
      failure; "(0 services)" read as an observed inventory.
    - An empty array is emitted ONLY when the provider genuinely returned
      zero records.

    ANALYTICAL SCOPE
    All existing service fields are preserved in the raw evidence.
    Downstream analytical admission remains limited to the mapped
    component/service fields in the frozen Table A2.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKHostServices {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating Windows services" -Type "PROCESSING"

    $unitId   = "host.services.inventory"
    $provider = "root\CIMV2:Win32_Service"

    $Data["services"] = $null

    Start-VKAcquisition -UnitId $unitId -Provider $provider -DataPaths @(
        "host.services"
    )

    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

        if ($null -eq $services) {
            throw [System.InvalidOperationException]::new("Win32_Service returned no result object.")
        }

        $serviceList = @()

        foreach ($svc in @($services)) {
            if ($null -eq $svc.Name) {
                throw [System.InvalidOperationException]::new("A service record returned no Name value.")
            }

            # Determine if the binary path contains spaces and is unquoted.
            # This is raw data - the backend or vuln module decides if it is
            # exploitable.
            $pathToExe = $svc.PathName
            $hasSpacesUnquoted = $false

            if ($pathToExe) {
                $trimmedPath = $pathToExe.Trim()
                if ($trimmedPath -and $trimmedPath[0] -ne '"' -and $trimmedPath[0] -ne "'") {
                    $exePortion = ($trimmedPath -split '\s+-|\s+/')[0].Trim()
                    if ($exePortion -match '\s' -and $exePortion -notmatch '\\system32\\' -and $exePortion -notmatch '\\SysWOW64\\') {
                        $hasSpacesUnquoted = $true
                    }
                }
            }

            $serviceList += [ordered]@{
                "name"               = $svc.Name
                "display_name"       = $svc.DisplayName
                "description"        = $svc.Description
                "state"              = $svc.State
                "start_type"         = $svc.StartMode
                "logon_account"      = $svc.StartName
                "binary_path"        = $pathToExe
                "has_spaces_unquoted"= $hasSpacesUnquoted
                "pid"                = if ($svc.ProcessId -and $svc.ProcessId -ne 0) { $svc.ProcessId } else { $null }
            }
        }

        # Genuine zero result only reaches here if the provider answered
        # and returned no records.
        $Data["services"] = $serviceList
        Complete-VKAcquisition -UnitId $unitId

        Write-VKStatus -Message "Service enumeration complete ($($serviceList.Count) services)" -Type "SUCCESS"
    }
    catch {
        # $null, not @(): an empty array would read as "this host runs no
        # services", which was never established.
        $Data["services"] = $null

        Write-LogMessage -Section "Host.Services" -Message "Unable to enumerate services: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $unitId -Provider $provider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $unitId -ErrorRecord $_ -Provider $provider
        }

        # No count is reported: there is no observed inventory to count.
        Write-VKStatus -Message "Service enumeration did not complete." -Type "ERROR"
    }
}
