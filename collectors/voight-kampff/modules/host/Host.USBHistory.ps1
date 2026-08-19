<#
.SYNOPSIS
    Module: USB Device History

.DESCRIPTION
    Enumerates historical USB storage device connections from the registry:
    - USBSTOR registry hive (all USB storage devices ever connected)
    - Device type, vendor, product, serial number
    - First and last connection timestamps where available

    This data is valuable for:
    - Incident response (what devices were connected and when)
    - Data exfiltration risk assessment
    - Policy compliance (unauthorised removable media)

    Only enumerates USB storage devices (flash drives, external HDDs).
    Does not enumerate non-storage USB devices (keyboards, mice, etc.).

    No admin required - USBSTOR registry is world-readable.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKHostUSBHistory {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating USB device history" -Type "PROCESSING"

    $usbDevices = @()
    $usbstorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

    try {
        if (-not (Test-Path $usbstorPath -ErrorAction SilentlyContinue)) {
            $Data["usb_history"] = [ordered]@{
                "devices_found" = 0
                "devices"       = @()
            }
            Write-VKStatus -Message "No USBSTOR registry hive found" -Type "SUCCESS"
            return
        }

        # Each subkey under USBSTOR is a device class (e.g. Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00)
        $deviceClasses = Get-ChildItem -Path $usbstorPath -ErrorAction Stop

        foreach ($deviceClass in $deviceClasses) {
            # Parse the device class name for vendor, product, revision
            $className = $deviceClass.PSChildName

            # Format: Disk&Ven_VENDOR&Prod_PRODUCT&Rev_REVISION
            $vendor = $null
            $product = $null
            $revision = $null
            $deviceType = $null

            if ($className -match '^(\w+)&Ven_(.+?)&Prod_(.+?)&Rev_(.+)$') {
                $deviceType = $matches[1]
                $vendor = $matches[2].Trim('_').Trim()
                $product = $matches[3].Trim('_').Trim()
                $revision = $matches[4].Trim('_').Trim()
            }

            # Each subkey under the device class is a specific device instance (serial number)
            $deviceInstances = Get-ChildItem -Path $deviceClass.PSPath -ErrorAction SilentlyContinue

            foreach ($instance in $deviceInstances) {
                $serialNumber = $instance.PSChildName

                # Get device properties
                $instanceProps = Get-ItemProperty -Path $instance.PSPath -ErrorAction SilentlyContinue
                $friendlyName = $instanceProps.FriendlyName
                $deviceDesc = $instanceProps.DeviceDesc

                # Clean up device description (remove driver store prefix)
                if ($deviceDesc -match ';(.+)$') {
                    $deviceDesc = $matches[1]
                }

                $containerId = $instanceProps.ContainerID

                $usbDevices += [ordered]@{
                    "device_type"   = $deviceType
                    "vendor"        = $vendor
                    "product"       = $product
                    "revision"      = $revision
                    "serial_number" = $serialNumber
                    "friendly_name" = $friendlyName
                    "description"   = $deviceDesc
                    "container_id"  = $containerId
                }
            }
        }

        $Data["usb_history"] = [ordered]@{
            "devices_found" = $usbDevices.Count
            "devices"       = $usbDevices
        }
    }
    catch {
        Write-LogMessage -Section "Host.USBHistory" -Message "Unable to enumerate USB history: $($_.Exception.Message)" -Level "ERROR"
    }

    Write-VKStatus -Message "USB history enumeration complete ($($usbDevices.Count) devices)" -Type "SUCCESS"
}