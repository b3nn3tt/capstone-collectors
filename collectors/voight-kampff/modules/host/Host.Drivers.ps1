<#
.SYNOPSIS
    Module: Loaded Drivers

.DESCRIPTION
    Enumerates loaded kernel drivers:
    - Driver name, display name, description
    - Current state and start type
    - Binary path
    - Signing status (signed, unsigned, signature verification)

    Signing data is critical for future vulnerability modules:
    - Vul.Drivers.Unsigned
    - Vul.Drivers.Vulnerable (BYOVD detection)

    Driver signing verification uses Get-AuthenticodeSignature which
    works without admin, but some driver paths may be inaccessible
    without elevated privileges.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKHostDrivers {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating loaded drivers" -Type "PROCESSING"

    $driverList = @()

    try {
        # Win32_SystemDriver gives us loaded kernel-mode drivers
        $drivers = Get-CimInstance -ClassName Win32_SystemDriver

        foreach ($drv in $drivers) {

            # Resolve the binary path for signature checking
            # Driver paths often use \SystemRoot\ or \??\ prefixes
            $rawPath = $drv.PathName
            $resolvedPath = $null

            if ($rawPath) {
                $resolvedPath = $rawPath `
                    -replace '^\\\?\?\\', '' `
                    -replace '\\SystemRoot\\', "$env:SystemRoot\" `
                    -replace '^system32\\', "$env:SystemRoot\system32\"
            }

            # Check digital signature
            $signatureStatus = $null
            $signer = $null

            if ($resolvedPath -and (Test-Path $resolvedPath -ErrorAction SilentlyContinue)) {
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $resolvedPath -ErrorAction SilentlyContinue
                    if ($sig) {
                        $signatureStatus = $sig.Status.ToString()
                        $signer = if ($sig.SignerCertificate) {
                            $sig.SignerCertificate.Subject
                        }
                        else { $null }
                    }
                }
                catch {
                    # Silently skip - some paths are inaccessible
                }
            }

            $driverList += [ordered]@{
                "name"              = $drv.Name
                "display_name"      = $drv.DisplayName
                "description"       = $drv.Description
                "state"             = $drv.State
                "start_type"        = $drv.StartMode
                "binary_path"       = $rawPath
                "resolved_path"     = $resolvedPath
                "signature_status"  = $signatureStatus
                "signer"            = $signer
            }
        }

        $Data["drivers"] = $driverList
    }
    catch {
        Write-LogMessage -Section "Host.Drivers" -Message "Unable to enumerate drivers: $($_.Exception.Message)" -Level "ERROR"
    }

    Write-VKStatus -Message "Driver enumeration complete ($($driverList.Count) drivers)" -Type "SUCCESS"
}