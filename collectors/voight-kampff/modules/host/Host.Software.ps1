<#
.SYNOPSIS
    Module: Installed Software Inventory

.DESCRIPTION
    Enumerates installed applications from the registry:
    - Application name, version, publisher
    - Install date and estimated size
    - Covers both 64-bit and 32-bit (WOW6432Node) registry hives

    SCHEMA 1.1 ACQUISITION
    Two collection units, one per machine-scope hive:

        host.software.hklm_native     ->  host.installed_software
        host.software.hklm_wow6432    ->  host.installed_software

    SHARED-PATH RULE
    Both units deliberately govern the SAME combined path. The combined
    list is a single analytical object that is complete only when every
    APPLICABLE machine-scope hive succeeded, so:

      - both applicable hives succeed  -> combined list emitted, both units success
      - any applicable hive fails      -> combined list withheld as $null

    A consumer must therefore check BOTH units before reading
    host.installed_software. A partial list would understate installed
    software while appearing complete, which is precisely the failure mode
    the acquisition contract exists to prevent.

    WOW6432Node APPLICABILITY
    The 32-bit hive exists only on 64-bit Windows. Applicability is
    determined from the OS architecture, NOT from a failed path check:
    assuming non-applicability from a failed check would convert a denied
    read into "nothing installed there". On 32-bit Windows the unit is
    recorded unavailable / provider_not_applicable and is excluded from
    the completeness rule above.

    SCOPE LIMITATION - machine scope only
    Only the two HKLM uninstall hives are read. Per-user software under
    HKCU and HKU\<SID> is NOT collected and is explicitly out of scope.
    Consequently a SUCCESSFUL and complete machine-scope collection can
    never establish absence of a per-user installation: under the coverage
    axis of Rule 2 the result simply does not span that question.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Get-VKSoftwareHiveEntries {
    <#
    .SYNOPSIS
        Reads one uninstall hive and returns its records.

    .DESCRIPTION
        Throws on any provider failure, including a failure to read a
        single entry. A per-entry failure makes the HIVE incomplete: it
        must not silently shorten the result, which would understate the
        installed software while appearing complete.

    .PARAMETER RegistryPath
        The uninstall hive to enumerate.

    .PARAMETER RegistryScope
        Scope marker stamped onto each record for reconstruction.

    .OUTPUTS
        Array of ordered records. An empty array means the hive was read
        successfully and contained no named applications.
    #>
    param(
        [Parameter(Mandatory)][string]$RegistryPath,
        [Parameter(Mandatory)][string]$RegistryScope
    )

    if (-not (Test-Path -Path $RegistryPath -ErrorAction Stop)) {
        throw [System.InvalidOperationException]::new(
            "The uninstall hive '$RegistryPath' is not present.")
    }

    $apps = @(Get-ChildItem -Path $RegistryPath -ErrorAction Stop)

    $entries = @()

    foreach ($app in $apps) {
        # -ErrorAction Stop: a single unreadable entry makes the hive
        # incomplete rather than quietly dropping one application.
        $details = Get-ItemProperty -Path $app.PSPath -ErrorAction Stop

        if ($null -eq $details) {
            throw [System.InvalidOperationException]::new(
                "Reading '$($app.PSPath)' returned no properties.")
        }

        $name = $details.DisplayName -as [string]

        # Entries with no display name are system components and update
        # stubs. Skipping them is a documented filter, not a failure.
        if (-not $name) { continue }

        $installDate = $null
        if ($details.InstallDate) {
            $rawDate = $details.InstallDate.ToString()
            if ($rawDate -match "^\d{8}$") {
                try {
                    $installDate = ([datetime]::ParseExact($rawDate, "yyyyMMdd", $null)).ToString("yyyy-MM-dd")
                }
                catch { $installDate = $rawDate }
            }
            else {
                $installDate = $rawDate
            }
        }

        $sizeMb = if ($details.EstimatedSize) {
            [math]::Round($details.EstimatedSize / 1024, 2)
        }
        else { $null }

        $entries += [ordered]@{
            "name"           = $name
            "version"        = $details.DisplayVersion -as [string]
            "publisher"      = $details.Publisher -as [string]
            "install_date"   = $installDate
            "size_mb"        = $sizeMb
            "registry_scope" = $RegistryScope
        }
    }

    return $entries
}


function Invoke-VKHostSoftware {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating installed software" -Type "PROCESSING"

    $nativeUnit = "host.software.hklm_native"
    $wowUnit    = "host.software.hklm_wow6432"

    $nativePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    $wowPath    = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

    $Data["installed_software"] = $null

    Start-VKAcquisition -UnitId $nativeUnit -Provider $nativePath -DataPaths @(
        "host.installed_software"
    )
    Start-VKAcquisition -UnitId $wowUnit -Provider $wowPath -DataPaths @(
        "host.installed_software"
    )

    $nativeEntries   = $null
    $nativeSucceeded = $false
    $wowEntries      = $null
    $wowSucceeded    = $false

    # Applicability is decided by architecture, never by a failed check.
    $wowApplicable = [Environment]::Is64BitOperatingSystem


    # --------------------------------------------------------
    #  Native HKLM hive
    # --------------------------------------------------------

    try {
        $nativeEntries   = @(Get-VKSoftwareHiveEntries -RegistryPath $nativePath -RegistryScope "hklm_native")
        $nativeSucceeded = $true
        Complete-VKAcquisition -UnitId $nativeUnit
    }
    catch {
        $nativeEntries = $null

        Write-LogMessage -Section "Host.Software" -Message "Failed to enumerate apps from ${nativePath}: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $nativeUnit -Provider $nativePath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $nativeUnit -ErrorRecord $_ -Provider $nativePath
        }
    }


    # --------------------------------------------------------
    #  WOW6432Node HKLM hive
    # --------------------------------------------------------

    if (-not $wowApplicable) {
        $reason = "The WOW6432Node uninstall hive does not exist on a 32-bit operating system."

        Write-LogMessage -Section "Host.Software" -Message $reason -Level "INFO"
        Set-VKAcquisitionUnavailable -UnitId $wowUnit -Provider $wowPath `
            -Category "provider_not_applicable" -Message $reason
    }
    else {
        try {
            $wowEntries   = @(Get-VKSoftwareHiveEntries -RegistryPath $wowPath -RegistryScope "hklm_wow6432")
            $wowSucceeded = $true
            Complete-VKAcquisition -UnitId $wowUnit
        }
        catch {
            $wowEntries = $null

            Write-LogMessage -Section "Host.Software" -Message "Failed to enumerate apps from ${wowPath}: $($_.Exception.Message)" -Level "ERROR"

            if ($_.Exception -is [System.InvalidOperationException]) {
                Set-VKAcquisitionUnavailable -UnitId $wowUnit -Provider $wowPath `
                    -Category "provider_value_missing" -Message $_.Exception.Message
            }
            else {
                Set-VKAcquisitionFailure -UnitId $wowUnit -ErrorRecord $_ -Provider $wowPath
            }
        }
    }


    # --------------------------------------------------------
    #  Combined list (shared-path rule)
    # --------------------------------------------------------

    $allApplicableSucceeded = $nativeSucceeded -and ((-not $wowApplicable) -or $wowSucceeded)

    if ($allApplicableSucceeded) {
        $combined = @()
        if ($null -ne $nativeEntries) { $combined += $nativeEntries }
        if ($null -ne $wowEntries)    { $combined += $wowEntries }

        # Sort-Object collapses an empty pipeline to $null, which would be
        # indistinguishable from a withheld collection. Re-wrap to keep a
        # successful empty result as @().
        $Data["installed_software"] = @($combined | Sort-Object { $_["name"] })
    }
    else {
        # At least one applicable hive did not succeed, so the combined
        # list would be incomplete while appearing complete.
        $Data["installed_software"] = $null
    }

    Write-VKStatus -Message "Software enumeration complete" -Type "SUCCESS"
}
