<#
.SYNOPSIS
    Module: Running Processes

.DESCRIPTION
    Enumerates currently running processes:
    - Process name, PID, parent PID
    - Executable path and command line
    - Owner (user account running the process)
    - Session ID
    - Memory usage (working set)
    - Start time

    Owner and command line details require admin for full visibility.
    Without admin, some processes will have null values for these fields.

    SCHEMA 1.1 ACQUISITION
    One collection unit:

        host.processes.inventory   ->   host.processes

    FAIL-CLOSED NOTES
    - The primary Win32_Process query is terminating and null-guarded.
      A failure yields $null, not an absent key and not an apparent
      zero-process inventory.
    - The console summary no longer reports "(0 processes)" after a
      failure, which read as an observed inventory.
    - Per-process OWNER lookup is optional enrichment: a failure there
      leaves owner null without invalidating the primary inventory.

    ANALYTICAL SCOPE
    owner, executable and especially command_line remain OUTSIDE the
    dissertation analytical allow-list unless a later frozen rule
    explicitly admits them. command_line is unbounded free text and can
    embed usernames, profile paths and credentials; it requires scrubbing,
    not merely pseudonymisation. They are preserved unchanged in the
    secured raw evidence.

    SCOPE NOTE - not session evidence
    owner and session_id must NOT be read as direct C5 interactive-use
    evidence. They describe processes, not sessions, and are not
    aggregated into session-level observations. C5 depends on the separate
    session extension.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKHostProcesses {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating running processes" -Type "PROCESSING"

    $unitId   = "host.processes.inventory"
    $provider = "root\CIMV2:Win32_Process"

    $Data["processes"] = $null

    Start-VKAcquisition -UnitId $unitId -Provider $provider -DataPaths @(
        "host.processes"
    )

    try {
        $cimProcesses = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop

        if ($null -eq $cimProcesses) {
            throw [System.InvalidOperationException]::new("Win32_Process returned no result object.")
        }

        $processList = @()

        foreach ($proc in @($cimProcesses)) {
            if ($null -eq $proc.ProcessId) {
                throw [System.InvalidOperationException]::new("A process record returned no ProcessId value.")
            }

            # OPTIONAL ENRICHMENT: owner resolution is expected to fail for
            # protected processes without admin. It never fails the unit.
            $owner = $null
            try {
                $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($ownerInfo -and $ownerInfo.ReturnValue -eq 0) {
                    $owner = if ($ownerInfo.Domain) {
                        "$($ownerInfo.Domain)\$($ownerInfo.User)"
                    }
                    else {
                        $ownerInfo.User
                    }
                }
            }
            catch {
                $owner = $null
            }

            $memoryMb = if ($proc.WorkingSetSize) {
                [math]::Round($proc.WorkingSetSize / 1MB, 2)
            }
            else { $null }

            $startTime = if ($proc.CreationDate) {
                $proc.CreationDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            else { $null }

            $processList += [ordered]@{
                "name"           = $proc.Name
                "pid"            = $proc.ProcessId
                "parent_pid"     = $proc.ParentProcessId
                "owner"          = $owner
                "executable"     = $proc.ExecutablePath
                "command_line"   = $proc.CommandLine
                "session_id"     = $proc.SessionId
                "memory_mb"      = $memoryMb
                "start_time"     = $startTime
            }
        }

        $Data["processes"] = $processList
        Complete-VKAcquisition -UnitId $unitId

        Write-VKStatus -Message "Process enumeration complete ($($processList.Count) processes)" -Type "SUCCESS"
    }
    catch {
        # $null, not @(): an empty array would read as "no processes are
        # running", which is never true and was never established.
        $Data["processes"] = $null

        Write-LogMessage -Section "Host.Processes" -Message "Unable to enumerate processes: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $unitId -Provider $provider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $unitId -ErrorRecord $_ -Provider $provider
        }

        Write-VKStatus -Message "Process enumeration did not complete." -Type "ERROR"
    }
}
