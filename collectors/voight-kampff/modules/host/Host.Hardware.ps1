<#
.SYNOPSIS
    Module: Hardware Enumeration

.DESCRIPTION
    Enumerates physical hardware details:
    - CPU (model, cores, threads)
    - RAM (total, used, free, module details including type and speed)
    - Disk drives (model, serial, size, media type, interface, SMART status)
    - BIOS (manufacturer, version, release date)
    - TPM (presence, version, manufacturer - requires admin)

    Also exposes a SMART status map for use by the Host.Storage module.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKHostHardware {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    # --------------------------------------------------------
    #  CPU
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating CPU" -Type "PROCESSING"

    try {
        $cpuInfo = Get-CimInstance -ClassName Win32_Processor |
            Select-Object -Property Name, NumberOfCores, NumberOfLogicalProcessors

        $Data["cpu"] = [ordered]@{
            "model"   = $cpuInfo.Name.Trim()
            "cores"   = $cpuInfo.NumberOfCores
            "threads" = $cpuInfo.NumberOfLogicalProcessors
        }
    }
    catch {
        Write-LogMessage -Section "Host.Hardware" -Message "Unable to retrieve CPU details: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  RAM
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating RAM" -Type "PROCESSING"

    try {
        $memory = Get-CimInstance -ClassName Win32_OperatingSystem
        $totalMemory = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
        $freeMemory  = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
        $usedMemory  = [math]::Round($totalMemory - $freeMemory, 2)

        $ramModules = @()
        $moduleIndex = 1

        Get-CimInstance -ClassName Win32_PhysicalMemory | ForEach-Object {
            $typeCode = [int]$_.SMBIOSMemoryType
            $typeName = Resolve-LookupValue -Value $typeCode -LookupTable $script:VKMemoryTypes

            $ramModules += [ordered]@{
                "name"  = "Module $moduleIndex"
                "type"  = $typeName
                "size_gb"  = [math]::Round($_.Capacity / 1GB, 2)
                "speed_mhz" = $_.Speed
                "slot"  = $_.DeviceLocator
            }
            $moduleIndex++
        }

        $Data["ram"] = [ordered]@{
            "total_gb" = $totalMemory
            "used_gb"  = $usedMemory
            "free_gb"  = $freeMemory
            "modules"  = $ramModules
        }
    }
    catch {
        Write-LogMessage -Section "Host.Hardware" -Message "Unable to retrieve RAM details: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  Disk Drives
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating disk drives" -Type "PROCESSING"

    # SMART status map is stored at script scope so Host.Storage can use it
    $script:VKSmartStatusMap = @{}

    try {
        $diskDrives = Get-CimInstance -ClassName Win32_DiskDrive
        $diskDriveDetails = @()

        # Get-PhysicalDisk reports the actual bus type (NVMe, SATA, USB etc.)
        # whereas Win32_DiskDrive reports "SCSI" for all NVMe drives.
        # We build a lookup by disk number to enrich each drive.
        $physicalDisks = @{}
        try {
            Get-PhysicalDisk | ForEach-Object {
                $physicalDisks[[int]$_.DeviceId] = $_
            }
        }
        catch {
            Write-LogMessage -Section "Host.Hardware" -Message "Unable to retrieve PhysicalDisk details for bus type enrichment: $($_.Exception.Message)" -Level "WARNING"
        }

        foreach ($drive in $diskDrives) {
            $cleanDeviceID = $drive.DeviceID -replace "^\\\\\.\\", ""
            $script:VKSmartStatusMap[$cleanDeviceID] = $drive.Status

            # Extract disk number to match against Get-PhysicalDisk
            $diskNumber = [int]($cleanDeviceID -replace "PHYSICALDRIVE", "")
            $physDisk = $physicalDisks[$diskNumber]

            $busType = if ($physDisk) { $physDisk.BusType } else { $null }
            $physicalMediaType = if ($physDisk) { $physDisk.MediaType } else { $null }

            $capabilities = if ($drive.CapabilityDescriptions) {
                $drive.CapabilityDescriptions
            }
            else {
                @("Unknown")
            }

            $diskDriveDetails += [ordered]@{
                "device_id"        = $cleanDeviceID
                "model"            = $drive.Model
                "serial_number"    = $drive.SerialNumber
                "size_gb"          = if ($drive.Size) { [math]::Round($drive.Size / 1GB, 2) } else { $null }
                "media_type"       = $physicalMediaType   # SSD, HDD, Unspecified (from PhysicalDisk)
                "bus_type"         = $busType              # NVMe, SATA, USB, etc. (actual bus)
                "interface_type"   = $drive.InterfaceType  # WMI-reported (often "SCSI" for NVMe)
                "scsi_port"        = $drive.SCSIPort
                "partitions"       = $drive.Partitions
                "firmware_version" = $drive.FirmwareRevision
                "capabilities"     = $capabilities
                "smart_status"     = $drive.Status
            }
        }

        $Data["disk_drives"] = $diskDriveDetails
    }
    catch {
        Write-LogMessage -Section "Host.Hardware" -Message "Unable to retrieve disk drive details: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  BIOS
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating BIOS" -Type "PROCESSING"

    try {
        $biosInfo = Get-CimInstance -ClassName Win32_BIOS |
            Select-Object -Property Manufacturer, SMBIOSBIOSVersion, ReleaseDate

        $releaseDate = if ($biosInfo.ReleaseDate -is [datetime]) {
            $biosInfo.ReleaseDate.ToString("yyyy-MM-dd")
        }
        elseif ($biosInfo.ReleaseDate -and $biosInfo.ReleaseDate.Length -ge 8) {
            try {
                ([datetime]::ParseExact($biosInfo.ReleaseDate.Substring(0, 8), "yyyyMMdd", $null)).ToString("yyyy-MM-dd")
            }
            catch { "Unknown" }
        }
        else {
            "Unknown"
        }

        $Data["bios"] = [ordered]@{
            "manufacturer" = $biosInfo.Manufacturer
            "version"      = $biosInfo.SMBIOSBIOSVersion
            "release_date" = $releaseDate
        }
    }
    catch {
        Write-LogMessage -Section "Host.Hardware" -Message "Unable to retrieve BIOS details: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  TPM (requires admin)
    # --------------------------------------------------------

    if ($IsAdmin) {
        Write-VKStatus -Message "Enumerating TPM" -Type "PROCESSING"

        $tpmData = Invoke-IfAdmin -SectionName "Host.Hardware.TPM" -ScriptBlock {
            $tpmDetails = [ordered]@{}

            $tpmInfo = Get-Tpm -ErrorAction Stop
            $tpmDetails["present"]  = $tpmInfo.TpmPresent
            $tpmDetails["enabled"]  = $tpmInfo.TpmEnabled

            # Manufacturer
            $manufacturerID = [int]$tpmInfo.ManufacturerID
            $tpmDetails["manufacturer_id"]   = $manufacturerID
            $tpmDetails["manufacturer_name"] = Resolve-LookupValue -Value $manufacturerID -LookupTable $script:VKTpmManufacturers -Default "Unknown Manufacturer"

            # Manufacturer version (clean null bytes)
            $tpmDetails["manufacturer_version"] = ($tpmInfo.ManufacturerVersion -replace '\0', '').Trim()

            # Spec version
            $tpmSpec = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm
            $tpmDetails["spec_version"] = if ($tpmSpec.SpecVersion -like "2.0*") { "2.0" }
                elseif ($tpmSpec.SpecVersion -like "1.2*") { "1.2" }
                else { "Unknown" }

            $tpmDetails["spec_version_raw"] = $tpmSpec.SpecVersion

            return $tpmDetails
        }

        if ($null -ne $tpmData) {
            $Data["tpm"] = $tpmData
        }
        else {
            Write-VKStatus -Message "TPM data is unavailable due to an error." -Type "ERROR"
        }
    }
    else {
        Write-VKStatus -Message "Skipping TPM enumeration - requires admin privileges." -Type "BYPASS"
    }

    Write-VKStatus -Message "Hardware enumeration complete" -Type "SUCCESS"
}