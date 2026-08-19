<#
.SYNOPSIS
    Module: Windows Remote Management (WinRM)

.DESCRIPTION
    Enumerates WinRM configuration:
    - WinRM service state and start type
    - HTTP and HTTPS listener configuration
    - Authentication methods enabled (Basic, Kerberos, Negotiate, CredSSP, Certificate)
    - Trusted hosts configuration
    - AllowUnencrypted traffic setting
    - Client settings (authentication and trusted hosts)

    Registry and service based - no admin required.

    SCHEMA 1.1 ACQUISITION
    Five independent collection units:

        security.winrm.service
        security.winrm.server_registry
        security.winrm.client_registry
        security.winrm.trusted_hosts
        security.winrm.listeners

    VALUE PROVENANCE
    The WSMAN authentication values have documented Windows defaults that
    apply when the value is absent. Those defaults are retained, with
    provenance exposed additively:

        server_value_sources  { <field> = "explicit" | "default_inferred" }
        client_value_sources  { <field> = "explicit" | "default_inferred" }

    FAIL-CLOSED NOTES
    - service_state and service_start_type no longer fall back to the
      string "Unknown" on a failed query. "Unknown" is a value, and it
      appeared in the payload as though it had been observed. They are now
      $null with a non-success outcome on the service unit.
    - Test-Path and the listener enumeration are terminating. A failure
      part-way through listener enumeration withholds the whole collection
      rather than emitting a shorter list that reads as complete.
    - A successful absence of listeners is still an empty array.

    NOT IN THIS TRANCHE
    No new runtime-state collection is added. The module still reads the
    configured state rather than probing the effective listener state.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityWinRM {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating WinRM configuration" -Type "PROCESSING"

    $serverRegPath   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
    $clientRegPath   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Client"
    $listenerBase    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener"
    $serviceProvider = "root\CIMV2:Win32_Service(WinRM)"

    $serviceUnit   = "security.winrm.service"
    $serverRegUnit = "security.winrm.server_registry"
    $clientRegUnit = "security.winrm.client_registry"
    $trustedUnit   = "security.winrm.trusted_hosts"
    $listenersUnit = "security.winrm.listeners"

    # Every governed path pre-initialised to $null.
    $winrmData = [ordered]@{
        "service_state"            = $null
        "service_start_type"       = $null
        "allow_unencrypted"        = $null
        "server_auth"              = $null
        "server_value_sources"     = $null
        "client_auth"              = $null
        "client_allow_unencrypted" = $null
        "client_value_sources"     = $null
        "trusted_hosts"            = $null
        "listeners"                = $null
    }

    Start-VKAcquisition -UnitId $serviceUnit -Provider $serviceProvider -DataPaths @(
        "security.winrm.service_state"
        "security.winrm.service_start_type"
    )

    Start-VKAcquisition -UnitId $serverRegUnit -Provider $serverRegPath -DataPaths @(
        "security.winrm.allow_unencrypted"
        "security.winrm.server_auth"
        "security.winrm.server_value_sources"
    )

    Start-VKAcquisition -UnitId $clientRegUnit -Provider $clientRegPath -DataPaths @(
        "security.winrm.client_auth"
        "security.winrm.client_allow_unencrypted"
        "security.winrm.client_value_sources"
    )

    Start-VKAcquisition -UnitId $trustedUnit -Provider "$clientRegPath\TrustedHosts" -DataPaths @(
        "security.winrm.trusted_hosts"
    )

    Start-VKAcquisition -UnitId $listenersUnit -Provider $listenerBase -DataPaths @(
        "security.winrm.listeners"
    )


    # --------------------------------------------------------
    #  WinRM Service Status
    # --------------------------------------------------------

    try {
        $winrmService = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop) |
            Select-Object -First 1

        if ($null -eq $winrmService) {
            throw [System.InvalidOperationException]::new(
                "Win32_Service returned no WinRM service instance.")
        }

        foreach ($required in @('State', 'StartMode')) {
            if ($null -eq $winrmService.$required) {
                throw [System.InvalidOperationException]::new(
                    "The WinRM service returned no $required value.")
            }
        }

        $winrmData["service_state"]      = $winrmService.State
        $winrmData["service_start_type"] = $winrmService.StartMode

        Complete-VKAcquisition -UnitId $serviceUnit
    }
    catch {
        # $null, not the string "Unknown", which read as an observed value.
        $winrmData["service_state"]      = $null
        $winrmData["service_start_type"] = $null

        Write-LogMessage -Section "Security.WinRM" -Message "Unable to query WinRM service: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $serviceUnit -Provider $serviceProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $serviceUnit -ErrorRecord $_ -Provider $serviceProvider
        }
    }


    # --------------------------------------------------------
    #  WinRM Server Settings (registry)
    # --------------------------------------------------------

    try {
        if (-not (Test-Path -Path $serverRegPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new("The WSMAN Service key is not present.")
        }

        $serverSettings = Get-ItemProperty -Path $serverRegPath -ErrorAction Stop

        if ($null -eq $serverSettings) {
            throw [System.InvalidOperationException]::new("Reading the WSMAN Service key returned no properties.")
        }

        $serverSources = [ordered]@{}

        # AllowUnencrypted: documented default is disabled.
        if ($null -ne $serverSettings.AllowUnencrypted) {
            $winrmData["allow_unencrypted"]      = ([int]$serverSettings.AllowUnencrypted -eq 1)
            $serverSources["allow_unencrypted"]  = "explicit"
        }
        else {
            $winrmData["allow_unencrypted"]      = $false
            $serverSources["allow_unencrypted"]  = "default_inferred"
        }

        $serverAuthFields = @(
            @{ Path = "basic";       Name = "AllowBasic";       Default = $false }
            @{ Path = "kerberos";    Name = "AllowKerberos";    Default = $true  }
            @{ Path = "negotiate";   Name = "AllowNegotiate";   Default = $true  }
            @{ Path = "credssp";     Name = "AllowCredSSP";     Default = $false }
            @{ Path = "certificate"; Name = "AllowCertificate"; Default = $false }
        )

        $serverAuth = [ordered]@{}

        foreach ($field in $serverAuthFields) {
            $raw = $serverSettings.($field.Name)

            if ($null -ne $raw) {
                $serverAuth[$field.Path]                     = ([int]$raw -eq 1)
                $serverSources["server_auth.$($field.Path)"] = "explicit"
            }
            else {
                $serverAuth[$field.Path]                     = $field.Default
                $serverSources["server_auth.$($field.Path)"] = "default_inferred"
            }
        }

        $winrmData["server_auth"]          = $serverAuth
        $winrmData["server_value_sources"] = $serverSources

        Complete-VKAcquisition -UnitId $serverRegUnit
    }
    catch {
        foreach ($path in @("allow_unencrypted", "server_auth", "server_value_sources")) {
            $winrmData[$path] = $null
        }

        # Access denied is expected without admin - the outcome records it.
        Write-LogMessage -Section "Security.WinRM" -Message "Unable to read WinRM server settings: $($_.Exception.Message)" -Level "INFO"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $serverRegUnit -Provider $serverRegPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $serverRegUnit -ErrorRecord $_ -Provider $serverRegPath
        }
    }


    # --------------------------------------------------------
    #  WinRM Client Settings (registry)
    # --------------------------------------------------------

    try {
        if (-not (Test-Path -Path $clientRegPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new("The WSMAN Client key is not present.")
        }

        $clientSettings = Get-ItemProperty -Path $clientRegPath -ErrorAction Stop

        if ($null -eq $clientSettings) {
            throw [System.InvalidOperationException]::new("Reading the WSMAN Client key returned no properties.")
        }

        $clientSources = [ordered]@{}

        $clientAuthFields = @(
            @{ Path = "basic";     Name = "AllowBasic";     Default = $false }
            @{ Path = "kerberos";  Name = "AllowKerberos";  Default = $true  }
            @{ Path = "negotiate"; Name = "AllowNegotiate"; Default = $true  }
            @{ Path = "credssp";   Name = "AllowCredSSP";   Default = $false }
        )

        $clientAuth = [ordered]@{}

        foreach ($field in $clientAuthFields) {
            $raw = $clientSettings.($field.Name)

            if ($null -ne $raw) {
                $clientAuth[$field.Path]                     = ([int]$raw -eq 1)
                $clientSources["client_auth.$($field.Path)"] = "explicit"
            }
            else {
                $clientAuth[$field.Path]                     = $field.Default
                $clientSources["client_auth.$($field.Path)"] = "default_inferred"
            }
        }

        if ($null -ne $clientSettings.AllowUnencrypted) {
            $winrmData["client_allow_unencrypted"]     = ([int]$clientSettings.AllowUnencrypted -eq 1)
            $clientSources["client_allow_unencrypted"] = "explicit"
        }
        else {
            $winrmData["client_allow_unencrypted"]     = $false
            $clientSources["client_allow_unencrypted"] = "default_inferred"
        }

        $winrmData["client_auth"]          = $clientAuth
        $winrmData["client_value_sources"] = $clientSources

        Complete-VKAcquisition -UnitId $clientRegUnit
    }
    catch {
        foreach ($path in @("client_auth", "client_allow_unencrypted", "client_value_sources")) {
            $winrmData[$path] = $null
        }

        Write-LogMessage -Section "Security.WinRM" -Message "Unable to read WinRM client settings: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $clientRegUnit -Provider $clientRegPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $clientRegUnit -ErrorRecord $_ -Provider $clientRegPath
        }
    }


    # --------------------------------------------------------
    #  Trusted Hosts
    # --------------------------------------------------------

    try {
        if (-not (Test-Path -Path $clientRegPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new("The WSMAN Client key is not present.")
        }

        $clientKey = Get-ItemProperty -Path $clientRegPath -ErrorAction Stop

        if ($null -eq $clientKey) {
            throw [System.InvalidOperationException]::new("Reading the WSMAN Client key returned no properties.")
        }

        # An absent TrustedHosts value is a genuine observation: no trusted
        # hosts are configured. $null is the correct representation.
        $winrmData["trusted_hosts"] = if ($clientKey.TrustedHosts) { $clientKey.TrustedHosts } else { $null }

        Complete-VKAcquisition -UnitId $trustedUnit
    }
    catch {
        $winrmData["trusted_hosts"] = $null

        Write-LogMessage -Section "Security.WinRM" -Message "Unable to read WinRM trusted hosts: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $trustedUnit -Provider "$clientRegPath\TrustedHosts" `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $trustedUnit -ErrorRecord $_ -Provider "$clientRegPath\TrustedHosts"
        }
    }


    # --------------------------------------------------------
    #  Listeners (registry enumeration)
    # --------------------------------------------------------

    try {
        $listeners = @()

        # An absent Listener key means no listener has ever been configured.
        # That is a genuine zero result, not a failure.
        if (Test-Path -Path $listenerBase -ErrorAction Stop) {
            $listenerKeys = @(Get-ChildItem -Path $listenerBase -ErrorAction Stop)

            foreach ($key in $listenerKeys) {
                # A failure reading one listener withholds the whole
                # collection: a shorter list would read as complete.
                $props = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop

                if ($null -eq $props) {
                    throw [System.InvalidOperationException]::new(
                        "Listener '$($key.PSChildName)' returned no properties.")
                }

                $listeners += [ordered]@{
                    "address"                = $props.Address
                    "transport"              = $props.Transport
                    "port"                   = if ($null -ne $props.Port) { [int]$props.Port } else { $null }
                    "hostname"               = $props.hostname
                    "enabled"                = if ($null -ne $props.Enabled) { ([int]$props.Enabled -eq 1) } else { $null }
                    "certificate_thumbprint" = if ($props.CertificateThumbprint) { $props.CertificateThumbprint } else { $null }
                }
            }
        }

        $winrmData["listeners"] = $listeners
        Complete-VKAcquisition -UnitId $listenersUnit
    }
    catch {
        # $null, not @(): an empty array would read as "no listeners are
        # configured", which was never established.
        $winrmData["listeners"] = $null

        Write-LogMessage -Section "Security.WinRM" -Message "Unable to enumerate WinRM listeners: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $listenersUnit -Provider $listenerBase `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $listenersUnit -ErrorRecord $_ -Provider $listenerBase
        }
    }

    $Data["winrm"] = $winrmData

    Write-VKStatus -Message "WinRM enumeration complete" -Type "SUCCESS"
}
