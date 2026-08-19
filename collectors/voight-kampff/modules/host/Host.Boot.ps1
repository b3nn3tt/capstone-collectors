<#
.SYNOPSIS
    Module: Boot Configuration

.DESCRIPTION
    Enumerates boot and startup configuration:
    - Boot device
    - BIOS mode (UEFI/Legacy) derived from OS drive partition style
    - Secure Boot state and configuration (requires admin for full detail)
    - Startup programs from registry Run keys (HKLM and HKCU)

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKHostBoot {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    $Data["boot"] = [ordered]@{}

    # --------------------------------------------------------
    #  Boot Device and BIOS Mode
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating boot configuration" -Type "PROCESSING"

    try {
        # Boot device
        $bootDevice = (Get-CimInstance -ClassName Win32_OperatingSystem).BootDevice
        $Data["boot"]["boot_device"] = if ($bootDevice) { $bootDevice } else { "Unknown" }

        # Determine OS drive and its partition style to infer BIOS mode
        $osDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
        $osDriveLetter = $osDrive.TrimEnd(":")
        $osDiskNumber = (Get-Partition | Where-Object { $_.DriveLetter -eq $osDriveLetter }).DiskNumber

        $biosMode = "Unknown"
        if ($null -ne $osDiskNumber) {
            $partitionStyle = (Get-Disk | Where-Object { $_.Number -eq $osDiskNumber }).PartitionStyle
            $biosMode = switch ($partitionStyle) {
                "GPT"   { "UEFI" }
                "MBR"   { "Legacy" }
                default { "Unknown" }
            }
        }
        $Data["boot"]["bios_mode"] = $biosMode
    }
    catch {
        Write-LogMessage -Section "Host.Boot" -Message "Unable to determine boot configuration: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  Secure Boot
    # --------------------------------------------------------

    if ($biosMode -eq "UEFI") {
        if ($IsAdmin) {
            Write-VKStatus -Message "Enumerating Secure Boot status" -Type "PROCESSING"

            try {
                $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                $Data["boot"]["secure_boot_enabled"] = if ($secureBootEnabled) { $true } else { $false }
            }
            catch {
                $Data["boot"]["secure_boot_enabled"] = "Unknown"
                Write-LogMessage -Section "Host.Boot" -Message "Unable to determine Secure Boot state: $($_.Exception.Message)" -Level "ERROR"
            }
        }
        else {
            $Data["boot"]["secure_boot_enabled"] = "Unknown - requires admin"
            Write-VKStatus -Message "Skipping Secure Boot enumeration - requires admin privileges." -Type "BYPASS"
        }
    }
    else {
        $Data["boot"]["secure_boot_enabled"] = "Not Applicable (Legacy BIOS)"
    }


    # --------------------------------------------------------
    #  Startup Programs
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating startup programs" -Type "PROCESSING"

    $startupPrograms = @()

    $registryPaths = @(
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"; Scope = "Machine" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"; Scope = "User" }
    )

    # Properties to exclude (PowerShell metadata, not actual startup entries)
    $excludeProperties = @("PSChildName", "PSDrive", "PSParentPath", "PSPath", "PSProvider")

    foreach ($entry in $registryPaths) {
        $regPath = $entry.Path
        $scope   = $entry.Scope

        if (Test-Path $regPath) {
            try {
                $regValues = Get-ItemProperty -Path $regPath
                $properties = ($regValues | Get-Member -MemberType NoteProperty).Name

                foreach ($prop in $properties) {
                    if ($prop -notin $excludeProperties) {
                        $startupPrograms += [ordered]@{
                            "name"    = $prop
                            "command" = $regValues.$prop
                            "scope"   = $scope
                            "source"  = $regPath
                        }
                    }
                }
            }
            catch {
                Write-LogMessage -Section "Host.Boot" -Message "Unable to read startup entries from ${regPath}: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }

    $Data["boot"]["startup_programs"] = $startupPrograms

    Write-VKStatus -Message "Boot configuration enumeration complete" -Type "SUCCESS"
}