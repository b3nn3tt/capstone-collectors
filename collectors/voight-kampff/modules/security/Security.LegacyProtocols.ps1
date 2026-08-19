<#
.SYNOPSIS
    Module: Legacy Protocols

.DESCRIPTION
    Enumerates legacy and insecure protocol configuration:
    - LLMNR (Link-Local Multicast Name Resolution) - poisoning risk
    - NetBIOS over TCP/IP - poisoning and enumeration risk
    - WPAD (Web Proxy Auto-Discovery) - relay risk
    - mDNS (Multicast DNS) - poisoning risk
    - TLS/SSL protocol versions enabled (1.0, 1.1, 1.2, 1.3)
    - SSL 2.0 and 3.0 status

    These protocols are commonly exploited during internal assessments
    for credential capture and relay attacks (Responder, mitm6, etc.).

    No admin required - all registry reads.

    SCHEMA 1.1 ACQUISITION
    Instrumented with six independent collection units so that one
    successful query cannot conceal another's failure:

        security.legacy_protocols.llmnr
        security.legacy_protocols.mdns
        security.legacy_protocols.netbios
        security.legacy_protocols.wpad_service
        security.legacy_protocols.wpad_auto_detect
        security.legacy_protocols.tls_protocols

    VALUE PROVENANCE
    LLMNR and mDNS are enabled by default when their policy value is
    absent. That inference is only sound if the read SUCCEEDED. The
    module therefore distinguishes three states:

        read succeeded, value present  -> effective value, value_source = "explicit"
        read succeeded, value absent   -> effective value, value_source = "default_inferred"
        read did not succeed           -> $null,           value_source = $null

    A failed, restricted or unavailable read NEVER produces an inferred
    effective value. This corrects the schema 1.0 defect where a read
    failure set the value to $true.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityLegacyProtocols {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating legacy protocol configuration" -Type "PROCESSING"

    $protocolData = [ordered]@{}


    # --------------------------------------------------------
    #  LLMNR
    # --------------------------------------------------------
    # HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
    # EnableMulticast: 0 = disabled, 1 or absent = enabled
    #
    # The policy key is frequently absent on an unmanaged host. Absence is
    # a legitimate, successfully observed state - not a failure - and the
    # documented Windows default then applies. It is recorded with a
    # provenance marker so that an inferred value is never mistaken for an
    # observed one.

    $llmnrUnit    = "security.legacy_protocols.llmnr"
    $llmnrRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

    Start-VKAcquisition -UnitId $llmnrUnit -Provider $llmnrRegPath -DataPaths @(
        "security.legacy_protocols.llmnr_enabled"
        "security.legacy_protocols.llmnr_value_source"
    )

    try {
        $llmnrExplicit = $null

        # -ErrorAction Stop on the existence test itself, not only on the
        # read. Without it a provider error makes Test-Path emit a
        # non-terminating error and return $false, which is indistinguishable
        # from "the key is genuinely absent" and would wrongly license the
        # documented default below.
        if (Test-Path -Path $llmnrRegPath -ErrorAction Stop) {
            $llmnrKey = Get-ItemProperty -Path $llmnrRegPath -ErrorAction Stop
            if ($null -ne $llmnrKey.EnableMulticast) {
                $llmnrExplicit = [int]$llmnrKey.EnableMulticast
            }
        }

        if ($null -ne $llmnrExplicit) {
            $protocolData["llmnr_enabled"]      = ($llmnrExplicit -ne 0)
            $protocolData["llmnr_value_source"] = "explicit"
        }
        else {
            # Read succeeded; the policy value is genuinely absent.
            $protocolData["llmnr_enabled"]      = $true
            $protocolData["llmnr_value_source"] = "default_inferred"
        }

        Complete-VKAcquisition -UnitId $llmnrUnit
    }
    catch {
        # Read did not succeed - assert nothing. Previously this branch set
        # llmnr_enabled to $true, fabricating an observation.
        $protocolData["llmnr_enabled"]      = $null
        $protocolData["llmnr_value_source"] = $null

        Write-LogMessage -Section "Security.LegacyProtocols" -Message "Unable to determine LLMNR status: $($_.Exception.Message)" -Level "WARNING"
        Set-VKAcquisitionFailure -UnitId $llmnrUnit -ErrorRecord $_ -Provider $llmnrRegPath
    }


    # --------------------------------------------------------
    #  NetBIOS over TCP/IP
    # --------------------------------------------------------
    # Per-adapter setting via Win32_NetworkAdapterConfiguration
    # TcpipNetbiosOptions: 0 = Default (DHCP), 1 = Enabled, 2 = Disabled
    $netbiosMap = @{
        0 = "Default (via DHCP)"
        1 = "Enabled"
        2 = "Disabled"
    }

    $netbiosUnit     = "security.legacy_protocols.netbios"
    $netbiosProvider = "root\CIMV2:Win32_NetworkAdapterConfiguration"

    Start-VKAcquisition -UnitId $netbiosUnit -Provider $netbiosProvider -DataPaths @(
        "security.legacy_protocols.netbios_adapters"
        "security.legacy_protocols.netbios_any_enabled"
    )

    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        $netbiosSettings = @()

        foreach ($adapter in $adapters) {
            $netbiosSettings += [ordered]@{
                "description" = $adapter.Description
                "setting"     = Resolve-LookupValue -Value ([int]$adapter.TcpipNetbiosOptions) -LookupTable $netbiosMap
                "raw_value"   = $adapter.TcpipNetbiosOptions
            }
        }

        $protocolData["netbios_adapters"] = $netbiosSettings

        # Summary flag - true if any adapter has NetBIOS enabled or defaulting
        $protocolData["netbios_any_enabled"] = ($netbiosSettings | Where-Object { $_["raw_value"] -ne 2 }).Count -gt 0

        Complete-VKAcquisition -UnitId $netbiosUnit
    }
    catch {
        # $null, not an empty array: an empty array would read as
        # "no adapters have NetBIOS enabled", which was never observed.
        $protocolData["netbios_adapters"]    = $null
        $protocolData["netbios_any_enabled"] = $null

        Write-LogMessage -Section "Security.LegacyProtocols" -Message "Unable to determine NetBIOS status: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $netbiosUnit -ErrorRecord $_ -Provider $netbiosProvider
    }


    # --------------------------------------------------------
    #  WPAD (Web Proxy Auto-Discovery)
    # --------------------------------------------------------
    # WinHttpAutoProxySvc service: if running, WPAD is active
    # Also check: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings
    # AutoDetect: 1 = enabled
    # Two independent providers - a CIM service query and a registry read.
    # Separate units, so a failure of one does not imply anything about
    # the other.

    $wpadServiceUnit     = "security.legacy_protocols.wpad_service"
    $wpadServiceProvider = "root\CIMV2:Win32_Service(WinHttpAutoProxySvc)"

    Start-VKAcquisition -UnitId $wpadServiceUnit -Provider $wpadServiceProvider -DataPaths @(
        "security.legacy_protocols.wpad_service_state"
        "security.legacy_protocols.wpad_service_start_type"
    )

    try {
        $wpadService = Get-CimInstance -ClassName Win32_Service -Filter "Name='WinHttpAutoProxySvc'" -ErrorAction Stop

        # A successful query returning no service is a valid zero result.
        $protocolData["wpad_service_state"]      = if ($wpadService) { $wpadService.State }     else { "Not Found" }
        $protocolData["wpad_service_start_type"] = if ($wpadService) { $wpadService.StartMode } else { "Not Found" }

        Complete-VKAcquisition -UnitId $wpadServiceUnit
    }
    catch {
        # "Not Found" is reserved for a successful zero result and must
        # never stand in for a failed query.
        $protocolData["wpad_service_state"]      = $null
        $protocolData["wpad_service_start_type"] = $null

        Write-LogMessage -Section "Security.LegacyProtocols" -Message "Unable to determine WPAD service status: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $wpadServiceUnit -ErrorRecord $_ -Provider $wpadServiceProvider
    }

    $wpadDetectUnit    = "security.legacy_protocols.wpad_auto_detect"
    $wpadDetectRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"

    Start-VKAcquisition -UnitId $wpadDetectUnit -Provider $wpadDetectRegPath -DataPaths @(
        "security.legacy_protocols.wpad_auto_detect"
    )

    try {
        $wpadExplicit = $null

        # -ErrorAction Stop: an undeterminable key must reach the catch and
        # yield no value, rather than silently resolving to $null as though
        # the setting had been successfully observed as unconfigured.
        if (Test-Path -Path $wpadDetectRegPath -ErrorAction Stop) {
            $inetSettings = Get-ItemProperty -Path $wpadDetectRegPath -ErrorAction Stop
            if ($null -ne $inetSettings.AutoDetect) {
                $wpadExplicit = [int]$inetSettings.AutoDetect
            }
        }

        # No documented default is asserted here: absence stays $null.
        $protocolData["wpad_auto_detect"] = if ($null -ne $wpadExplicit) { ($wpadExplicit -eq 1) } else { $null }

        Complete-VKAcquisition -UnitId $wpadDetectUnit
    }
    catch {
        $protocolData["wpad_auto_detect"] = $null

        Write-LogMessage -Section "Security.LegacyProtocols" -Message "Unable to determine WPAD auto-detect status: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $wpadDetectUnit -ErrorRecord $_ -Provider $wpadDetectRegPath
    }


    # --------------------------------------------------------
    #  mDNS (Multicast DNS)
    # --------------------------------------------------------
    # HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
    # EnableMDNS: 0 = disabled, 1 or absent = enabled
    $mdnsUnit    = "security.legacy_protocols.mdns"
    $mdnsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"

    Start-VKAcquisition -UnitId $mdnsUnit -Provider $mdnsRegPath -DataPaths @(
        "security.legacy_protocols.mdns_enabled"
        "security.legacy_protocols.mdns_value_source"
    )

    try {
        $mdnsExplicit = $null

        # -ErrorAction Stop: see the LLMNR unit above. An undeterminable key
        # must not be reported as an absent key.
        if (Test-Path -Path $mdnsRegPath -ErrorAction Stop) {
            $mdnsKey = Get-ItemProperty -Path $mdnsRegPath -ErrorAction Stop
            if ($null -ne $mdnsKey.EnableMDNS) {
                $mdnsExplicit = [int]$mdnsKey.EnableMDNS
            }
        }

        if ($null -ne $mdnsExplicit) {
            $protocolData["mdns_enabled"]      = ($mdnsExplicit -ne 0)
            $protocolData["mdns_value_source"] = "explicit"
        }
        else {
            # Read succeeded; the value is genuinely absent.
            $protocolData["mdns_enabled"]      = $true
            $protocolData["mdns_value_source"] = "default_inferred"
        }

        Complete-VKAcquisition -UnitId $mdnsUnit
    }
    catch {
        # Previously this branch set mdns_enabled to $true.
        $protocolData["mdns_enabled"]      = $null
        $protocolData["mdns_value_source"] = $null

        Write-LogMessage -Section "Security.LegacyProtocols" -Message "Unable to determine mDNS status: $($_.Exception.Message)" -Level "WARNING"
        Set-VKAcquisitionFailure -UnitId $mdnsUnit -ErrorRecord $_ -Provider $mdnsRegPath
    }


    # --------------------------------------------------------
    #  TLS/SSL Protocol Versions
    # --------------------------------------------------------
    # HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
    # Each protocol has a Client and Server subkey with Enabled and DisabledByDefault values

    $tlsProtocols = @(
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1",
        "TLS 1.2",
        "TLS 1.3"
    )

    $schannelBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    $tlsUnit = "security.legacy_protocols.tls_protocols"

    Start-VKAcquisition -UnitId $tlsUnit -Provider $schannelBase -DataPaths @(
        "security.legacy_protocols.tls_protocols"
    )

    try {
        $tlsSettings = @()

        foreach ($protocol in $tlsProtocols) {
            $entry = [ordered]@{
                "protocol" = $protocol
            }

            foreach ($role in @("Client", "Server")) {
                $regPath = Join-Path $schannelBase "$protocol\$role"

                $enabled = $null
                $disabledByDefault = $null

                # An absent subkey means SCHANNEL holds no explicit value
                # for this protocol and role. That is a successful read of
                # "nothing configured", left as $null rather than being
                # resolved to an effective protocol state, which SCHANNEL
                # does not expose here.
                #
                # -ErrorAction Stop keeps that reading honest: only a
                # SUCCESSFUL negative existence test may be treated as
                # "nothing configured". A provider error propagates to the
                # unit's catch and withholds the whole protocol collection.
                if (Test-Path -Path $regPath -ErrorAction Stop) {
                    $values = Get-ItemProperty -Path $regPath -ErrorAction Stop
                    if ($null -ne $values.Enabled) { $enabled = ($values.Enabled -eq 1) }
                    if ($null -ne $values.DisabledByDefault) { $disabledByDefault = ($values.DisabledByDefault -eq 1) }
                }

                $entry["${role}_enabled".ToLower()] = $enabled
                $entry["${role}_disabled_by_default".ToLower()] = $disabledByDefault
            }

            $tlsSettings += $entry
        }

        $protocolData["tls_protocols"] = $tlsSettings

        Complete-VKAcquisition -UnitId $tlsUnit
    }
    catch {
        # A partial protocol list would understate configured protocols,
        # so the whole collection is withheld.
        $protocolData["tls_protocols"] = $null

        Write-LogMessage -Section "Security.LegacyProtocols" -Message "Unable to enumerate SCHANNEL protocol configuration: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $tlsUnit -ErrorRecord $_ -Provider $schannelBase
    }

    $Data["legacy_protocols"] = $protocolData

    Write-VKStatus -Message "Legacy protocol enumeration complete" -Type "SUCCESS"
}