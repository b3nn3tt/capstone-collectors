<#
.SYNOPSIS
    Module: Full Disk Encryption (BitLocker)

.DESCRIPTION
    Evaluates BitLocker encryption configuration:
    - OS drive: volume status, protection status, key protectors, encryption method
    - Additional volumes: same checks per volume, plus auto-unlock status
    - All data captured raw for backend compliance evaluation

    Requires administrative privileges for BitLocker enumeration.

    SCHEMA 1.1 ACQUISITION
    Two independent collection units:

        security.fde.os_drive
        security.fde.additional_volumes

    STUDY RELEVANCE
    Disk-encryption state does not contribute to C1-C7 scoring. It is
    collected because controlled Case 9 deliberately varies it as
    irrelevant telemetry, so its acquisition outcome must be as
    trustworthy as any scored evidence.

    FAIL-CLOSED NOTES
    - Both units are registered even when the scan is not elevated, so a
      non-elevated run yields restricted / insufficient_privilege rather
      than a silently missing section. The previous module returned early
      and emitted nothing at all.
    - Invoke-IfAdmin has been replaced. It swallowed the error and returned
      $null, which made "not elevated", "cmdlet missing" and "query threw"
      indistinguishable and prevented acquisition classification.
    - A volume missing VolumeStatus, ProtectionStatus or EncryptionMethod
      is treated as malformed and throws. It is never rendered as
      "Not Fully Encrypted", "Protection Off" or "Unknown or Not Encrypted",
      which would assert an unfavourable state the host never reported.
    - One malformed volume withholds the whole additional-volumes
      collection: a partial list would appear complete.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Get-VKFDEVolumeDetails {
    <#
    .SYNOPSIS
        Converts a BitLocker volume object into structured evidence.

    .DESCRIPTION
        Throws if a required property is absent. The caller withholds the
        governing unit rather than emitting a partially-observed volume.

    .PARAMETER Volume
        A volume object returned by Get-BitLockerVolume.

    .PARAMETER IncludeAutoUnlock
        Emits auto_unlock_enabled, which is only meaningful for non-OS
        volumes.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Volume,

        [switch]$IncludeAutoUnlock
    )

    if ($null -eq $Volume) {
        throw [System.InvalidOperationException]::new("Get-BitLockerVolume returned no volume object.")
    }

    $mountPoint = $Volume.MountPoint
    if (-not $mountPoint) {
        throw [System.InvalidOperationException]::new("BitLocker volume returned no MountPoint.")
    }

    # Required properties. Absence means the provider did not report the
    # state, which is not the same as reporting an unfavourable state.
    foreach ($required in @('VolumeStatus', 'ProtectionStatus', 'EncryptionMethod')) {
        if ($null -eq $Volume.$required) {
            throw [System.InvalidOperationException]::new(
                "BitLocker volume '$mountPoint' returned no $required value.")
        }
    }

    $details = [ordered]@{
        "mount_point" = $mountPoint
    }

    # Volume status: 1 = FullyEncrypted. Any other reported status is a
    # genuine observation of "not fully encrypted".
    $details["volume_status"] = if ([int]$Volume.VolumeStatus -eq 1) {
        "Fully Encrypted"
    }
    else {
        "Not Fully Encrypted"
    }

    $details["protection_status"] = switch ([int]$Volume.ProtectionStatus) {
        1       { "Protection On" }
        0       { "Protection Off" }
        default { "Unknown" }
    }

    $rawMethod = $Volume.EncryptionMethod -as [string]
    $details["encryption_method"] = Resolve-LookupValue -Value $rawMethod -LookupTable $script:VKEncryptionMethods -Default "Unknown or Not Encrypted"

    # Key protectors. An empty set here is a genuine observation - the
    # property was present and listed nothing.
    $primaryProtectors  = @()
    $recoveryProtectors = @()

    if ($Volume.KeyProtector) {
        $keyProtectors = $Volume.KeyProtector -split ';'
        foreach ($protector in $keyProtectors) {
            $protector = $protector.Trim()
            if (-not $protector) { continue }

            $resolved = Resolve-LookupValue -Value $protector -LookupTable $script:VKKeyProtectorTypes -Default $protector

            if ($protector -in @("RecoveryPassword", "NumericalPassword")) {
                $recoveryProtectors += $resolved
            }
            else {
                $primaryProtectors += $resolved
            }
        }
    }

    $details["primary_key_protectors"]  = $primaryProtectors
    $details["recovery_key_protectors"] = $recoveryProtectors

    if ($IncludeAutoUnlock) {
        $details["auto_unlock_enabled"] = if ($null -ne $Volume.AutoUnlockEnabled) {
            $Volume.AutoUnlockEnabled
        }
        else { $null }
    }

    return $details
}


function Invoke-VKSecurityFDE {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating FDE configuration" -Type "PROCESSING"

    $osDriveUnit     = "security.fde.os_drive"
    $volumesUnit     = "security.fde.additional_volumes"
    $bitLockerProv   = "Get-BitLockerVolume"
    $osProvider      = "root\CIMV2:Win32_OperatingSystem"

    # Governed paths initialised to $null, never to a substantive default.
    $Data["fde_os_drive"]           = $null
    $Data["fde_additional_volumes"] = $null

    Start-VKAcquisition -UnitId $osDriveUnit -Provider $bitLockerProv -DataPaths @(
        "security.fde_os_drive"
    )
    Start-VKAcquisition -UnitId $volumesUnit -Provider $bitLockerProv -DataPaths @(
        "security.fde_additional_volumes"
    )

    # --------------------------------------------------------
    #  Elevation precondition
    # --------------------------------------------------------

    if (-not $IsAdmin) {
        # Registered and classified, not silently skipped. Re-collecting
        # elevated is the remedy, which is exactly what 'restricted' means.
        $reason = "BitLocker enumeration requires administrative privileges."

        Write-VKStatus -Message "Skipping FDE enumeration - requires admin privileges." -Type "BYPASS"
        Write-LogMessage -Section "Security.FDE" -Message $reason -Level "WARNING"

        foreach ($unit in @($osDriveUnit, $volumesUnit)) {
            Set-VKAcquisitionFailure -UnitId $unit -Provider $bitLockerProv `
                -Outcome "restricted" -Category "insufficient_privilege" -Message $reason
        }
        return
    }

    # --------------------------------------------------------
    #  OS drive letter (precondition for both units)
    # --------------------------------------------------------

    $osDrive      = $null
    $osDriveError = $null

    try {
        $osInstance = @(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop) |
            Select-Object -First 1

        if ($null -eq $osInstance -or -not $osInstance.SystemDrive) {
            throw [System.InvalidOperationException]::new(
                "Win32_OperatingSystem returned no SystemDrive value.")
        }

        $osDrive = $osInstance.SystemDrive
    }
    catch {
        $osDriveError = $_
    }

    if ($osDriveError) {
        # Without the OS drive letter neither unit can be evaluated: the OS
        # volume cannot be targeted and additional volumes cannot be
        # distinguished from it.
        $message = "Unable to determine the OS drive: $($osDriveError.Exception.Message)"
        Write-LogMessage -Section "Security.FDE" -Message $message -Level "ERROR"

        foreach ($unit in @($osDriveUnit, $volumesUnit)) {
            Set-VKAcquisitionFailure -UnitId $unit -ErrorRecord $osDriveError -Provider $osProvider -Message $message
        }
        return
    }

    # --------------------------------------------------------
    #  OS Drive
    # --------------------------------------------------------

    Write-VKStatus -Message "Checking FDE for OS drive ($osDrive)" -Type "PROCESSING"

    try {
        $osVolume = @(Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop) | Select-Object -First 1

        if ($null -eq $osVolume) {
            throw [System.InvalidOperationException]::new(
                "Get-BitLockerVolume returned no volume for the OS drive '$osDrive'.")
        }

        $Data["fde_os_drive"] = Get-VKFDEVolumeDetails -Volume $osVolume
        Complete-VKAcquisition -UnitId $osDriveUnit
    }
    catch {
        $Data["fde_os_drive"] = $null

        Write-LogMessage -Section "Security.FDE" -Message "Unable to retrieve BitLocker details for the OS drive: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $osDriveUnit -ErrorRecord $_ -Provider $bitLockerProv
    }

    # --------------------------------------------------------
    #  Additional Volumes
    # --------------------------------------------------------

    Write-VKStatus -Message "Checking FDE for additional volumes" -Type "PROCESSING"

    try {
        $allVolumes = @(Get-BitLockerVolume -ErrorAction Stop)

        if ($allVolumes.Count -eq 0) {
            # BitLocker enumerates at least the OS volume on a working
            # provider. Nothing at all means the provider did not answer,
            # which is distinct from "no ADDITIONAL volumes exist".
            throw [System.InvalidOperationException]::new(
                "Get-BitLockerVolume returned no volumes at all.")
        }

        $additional  = @($allVolumes | Where-Object { $_.MountPoint -ne $osDrive })
        $volumesList = @()

        # A malformed volume throws out of this loop, withholding the whole
        # collection. A partial list would read as complete.
        foreach ($volume in $additional) {
            $volumesList += Get-VKFDEVolumeDetails -Volume $volume -IncludeAutoUnlock
        }

        # Genuine zero-result: the provider answered and there are no
        # additional volumes. An empty array is correct here.
        $Data["fde_additional_volumes"] = $volumesList
        Complete-VKAcquisition -UnitId $volumesUnit
    }
    catch {
        # $null, not @(): an empty array would read as "no additional
        # volumes exist", which was never established.
        $Data["fde_additional_volumes"] = $null

        Write-LogMessage -Section "Security.FDE" -Message "Unable to enumerate additional BitLocker volumes: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $volumesUnit -ErrorRecord $_ -Provider $bitLockerProv
    }

    Write-VKStatus -Message "FDE enumeration complete" -Type "SUCCESS"
}
