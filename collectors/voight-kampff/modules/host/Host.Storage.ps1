<#
.SYNOPSIS
    Module: Logical Storage

.DESCRIPTION
    Enumerates logical partition information:
    - Drive letters, volume labels, file systems
    - Total size, free space, and usage percentage
    - Drive type (Local, Removable, Network, etc.)
    - SMART status correlation with physical drives
    - Volume serial numbers

    Relies on $script:VKSmartStatusMap populated by Host.Hardware module.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKHostStorage {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating logical partitions" -Type "PROCESSING"

    $partitionsInfo = @()

    try {
        # Mappings between physical drives, partitions, and logical disks
        $diskToPartition    = Get-CimInstance -ClassName Win32_DiskDriveToDiskPartition
        $logicalToPartition = Get-CimInstance -ClassName Win32_LogicalDiskToPartition
        $physicalDrives     = Get-CimInstance -ClassName Win32_DiskDrive
        $logicalDisks       = Get-CimInstance -ClassName Win32_LogicalDisk

        foreach ($diskMapping in $diskToPartition) {
            $physicalDrive = $physicalDrives | Where-Object { $_.DeviceID -eq $diskMapping.Antecedent.DeviceID }
            $partitionNumber = $diskMapping.Dependent.DeviceID -replace ".*Partition #", ""

            # Find logical disks mapped to this partition
            $logicalMappings = $logicalToPartition | Where-Object {
                $_.Antecedent.DeviceID -eq $diskMapping.Dependent.DeviceID
            }

            foreach ($logicalMapping in $logicalMappings) {
                $logicalDisk = $logicalDisks | Where-Object {
                    $_.DeviceID -eq $logicalMapping.Dependent.DeviceID
                }

                # Clean physical drive ID and retrieve SMART status
                $cleanDriveID = $physicalDrive.DeviceID -replace "^\\\\\.\\", ""
                $smartStatus = if ($script:VKSmartStatusMap.ContainsKey($cleanDriveID)) {
                    $script:VKSmartStatusMap[$cleanDriveID]
                }
                else {
                    "Unknown"
                }

                # Calculate disk usage percentage
                $usagePercent = if ($logicalDisk.Size -and $logicalDisk.Size -gt 0) {
                    [math]::Round(100 - (($logicalDisk.FreeSpace / $logicalDisk.Size) * 100), 2)
                }
                else {
                    $null
                }

                $partitionsInfo += [ordered]@{
                    "physical_drive"      = $physicalDrive.Model
                    "physical_drive_id"   = $cleanDriveID
                    "partition"           = [int]$partitionNumber
                    "drive_letter"        = $logicalDisk.DeviceID
                    "volume_label"        = if ($logicalDisk.VolumeName) { $logicalDisk.VolumeName } else { $null }
                    "file_system"         = $logicalDisk.FileSystem
                    "drive_type"          = Resolve-LookupValue -Value ([int]$logicalDisk.DriveType) -LookupTable $script:VKDriveTypes
                    "total_size_gb"       = if ($logicalDisk.Size) { [math]::Round($logicalDisk.Size / 1GB, 2) } else { $null }
                    "free_space_gb"       = if ($logicalDisk.FreeSpace) { [math]::Round($logicalDisk.FreeSpace / 1GB, 2) } else { $null }
                    "usage_percent"       = $usagePercent
                    "smart_status"        = $smartStatus
                    "volume_serial"       = $logicalDisk.VolumeSerialNumber
                }
            }
        }

        $Data["storage"] = $partitionsInfo
    }
    catch {
        Write-LogMessage -Section "Host.Storage" -Message "Unable to enumerate logical partitions: $($_.Exception.Message)" -Level "ERROR"
    }

    Write-VKStatus -Message "Storage enumeration complete" -Type "SUCCESS"
}