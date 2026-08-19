<#
.SYNOPSIS
    Module: Host Identification

.DESCRIPTION
    Enumerates basic host identity information:
    - Hostname
    - Operating system (name, architecture, version, build, platform role)
    - Domain/workgroup status
    - Manufacturer details (make, model, serial)

    SCHEMA 1.1 ACQUISITION
    Three study collection units:

        host.identification.hostname
        host.identification.operating_system
        host.identification.computer_system

    SCOPE NOTE - platform_role
    platform_role is a DECLARED machine/chassis role taken from
    Win32_ComputerSystem.PCSystemType. It is not, and must never be read
    as, evidence of interactive use: a desktop chassis running unattended
    still reports "Desktop". C5 depends on the separate session extension.

    LEGACY RAW INVENTORY
    Manufacturer and BIOS details are retained as raw inventory only. They
    sit OUTSIDE the study acquisition register and outside the analytical
    allow-list, and a failure there cannot change the outcome of the three
    study units above.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKHostIdentification {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    $hostnameUnit = "host.identification.hostname"
    $osUnit       = "host.identification.operating_system"
    $csUnit       = "host.identification.computer_system"

    $osProvider = "root\CIMV2:Win32_OperatingSystem"
    $csProvider = "root\CIMV2:Win32_ComputerSystem"

    # Governed paths initialised to $null.
    $Data["hostname"]      = $null
    $Data["os"]            = [ordered]@{
        "name"          = $null
        "architecture"  = $null
        "version"       = $null
        "build"         = $null
        "platform_role" = $null
    }
    $Data["domain_status"] = [ordered]@{
        "status"         = $null
        "domain_name"    = $null
        "workgroup_name" = $null
    }

    Start-VKAcquisition -UnitId $hostnameUnit -Provider "env:COMPUTERNAME" -DataPaths @(
        "host.hostname"
    )
    Start-VKAcquisition -UnitId $osUnit -Provider $osProvider -DataPaths @(
        "host.os.name"
        "host.os.architecture"
        "host.os.version"
        "host.os.build"
    )
    Start-VKAcquisition -UnitId $csUnit -Provider $csProvider -DataPaths @(
        "host.os.platform_role"
        "host.domain_status.status"
        "host.domain_status.domain_name"
        "host.domain_status.workgroup_name"
    )


    # --------------------------------------------------------
    #  Hostname
    # --------------------------------------------------------

    try {
        $computerName = $env:COMPUTERNAME

        if ([string]::IsNullOrWhiteSpace($computerName)) {
            throw [System.InvalidOperationException]::new("The COMPUTERNAME environment variable is not set.")
        }

        $Data["hostname"] = $computerName
        Complete-VKAcquisition -UnitId $hostnameUnit
    }
    catch {
        $Data["hostname"] = $null

        Write-LogMessage -Section "Host.Identification" -Message "Unable to determine the hostname: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionUnavailable -UnitId $hostnameUnit -Provider "env:COMPUTERNAME" `
            -Category "provider_value_missing" -Message $_.Exception.Message
    }


    # --------------------------------------------------------
    #  Operating System
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating Operating System" -Type "PROCESSING"

    try {
        $osInfo = @(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop) |
            Select-Object -First 1

        if ($null -eq $osInfo) {
            throw [System.InvalidOperationException]::new("Win32_OperatingSystem returned no instance.")
        }

        foreach ($required in @('Caption', 'OSArchitecture', 'Version', 'BuildNumber')) {
            if ($null -eq $osInfo.$required) {
                throw [System.InvalidOperationException]::new(
                    "Win32_OperatingSystem returned no $required value.")
            }
        }

        $Data["os"]["name"]         = $osInfo.Caption
        $Data["os"]["architecture"] = $osInfo.OSArchitecture
        $Data["os"]["version"]      = $osInfo.Version
        # Guarded above: [int]$null would silently become build 0.
        $Data["os"]["build"]        = [int]$osInfo.BuildNumber

        Complete-VKAcquisition -UnitId $osUnit
    }
    catch {
        $Data["os"]["name"]         = $null
        $Data["os"]["architecture"] = $null
        $Data["os"]["version"]      = $null
        $Data["os"]["build"]        = $null

        Write-LogMessage -Section "Host.Identification" -Message "Unable to retrieve OS details: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $osUnit -Provider $osProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $osUnit -ErrorRecord $_ -Provider $osProvider
        }
    }


    # --------------------------------------------------------
    #  Computer System: platform role and domain membership
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating domain status" -Type "PROCESSING"

    $computerSystem = $null

    try {
        $computerSystem = @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop) |
            Select-Object -First 1

        if ($null -eq $computerSystem) {
            throw [System.InvalidOperationException]::new("Win32_ComputerSystem returned no instance.")
        }

        if ($null -eq $computerSystem.PCSystemType) {
            throw [System.InvalidOperationException]::new("Win32_ComputerSystem returned no PCSystemType value.")
        }

        if ($null -eq $computerSystem.PartOfDomain) {
            throw [System.InvalidOperationException]::new("Win32_ComputerSystem returned no PartOfDomain value.")
        }

        # A declared chassis role only. See the scope note in the header.
        $Data["os"]["platform_role"] = Resolve-LookupValue -Value $computerSystem.PCSystemType -LookupTable $script:VKPlatformRoles

        if ($computerSystem.PartOfDomain) {
            $Data["domain_status"]["status"]      = "Domain-Joined"
            $Data["domain_status"]["domain_name"] = $computerSystem.Domain
        }
        else {
            $Data["domain_status"]["status"]         = "Standalone"
            $Data["domain_status"]["workgroup_name"] = $computerSystem.Workgroup
        }

        Complete-VKAcquisition -UnitId $csUnit
    }
    catch {
        $Data["os"]["platform_role"]              = $null
        $Data["domain_status"]["status"]          = $null
        $Data["domain_status"]["domain_name"]     = $null
        $Data["domain_status"]["workgroup_name"]  = $null

        Write-LogMessage -Section "Host.Identification" -Message "Unable to determine computer system details: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $csUnit -Provider $csProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $csUnit -ErrorRecord $_ -Provider $csProvider
        }
    }


    # --------------------------------------------------------
    #  Manufacturer Details - LEGACY RAW INVENTORY, NOT INSTRUMENTED
    # --------------------------------------------------------
    # Deliberately uninstrumented and excluded from the analytical
    # allow-list. Wrapped so that a failure here cannot affect the three
    # study units above.

    Write-VKStatus -Message "Enumerating system hardware" -Type "PROCESSING"

    $Data["manufacturer"] = [ordered]@{}

    try {
        $systemInfo = if ($null -ne $computerSystem) {
            $computerSystem
        }
        else {
            @(Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop) | Select-Object -First 1
        }

        $biosInfo = @(Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop) | Select-Object -First 1

        $mfr    = $systemInfo.Manufacturer
        $model  = $systemInfo.Model
        $serial = $biosInfo.SerialNumber
        $family = $systemInfo.SystemFamily
        $sku    = $systemInfo.SystemSKUNumber

        # Common placeholder strings returned by motherboard vendors on custom builds
        $oemPlaceholders = @(
            "To Be Filled By OEM",
            "To be filled by O.E.M.",
            "System Manufacturer",
            "System Product Name",
            "System Serial Number",
            "Default String",
            "Default string",
            "SKU",
            "Not Applicable",
            "None",
            ""
        )

        if ($mfr    -in $oemPlaceholders) { $mfr    = "Custom Build" }
        if ($model  -in $oemPlaceholders) { $model   = "Custom Build" }
        if ($serial -in $oemPlaceholders) { $serial  = "Not Available" }
        if ($family -in $oemPlaceholders) { $family  = "Not Available" }
        if ($sku    -in $oemPlaceholders) { $sku     = "Not Available" }

        $Data["manufacturer"]["manufacturer"]  = $mfr
        $Data["manufacturer"]["model"]         = $model
        $Data["manufacturer"]["serial_number"] = $serial
        $Data["manufacturer"]["system_family"] = $family
        $Data["manufacturer"]["system_sku"]    = $sku
    }
    catch {
        Write-LogMessage -Section "Host.Identification" -Message "Unable to retrieve manufacturer details: $($_.Exception.Message)" -Level "ERROR"
    }

    Write-VKStatus -Message "Host identification complete" -Type "SUCCESS"
}
