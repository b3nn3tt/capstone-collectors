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

    PRESENT BUT VALUE-EMPTY KEYS (2.1.1)
    A WSMAN key may exist and hold no registry values at all, which is the
    default state of a host that has never had WinRM explicitly configured.
    Reading it succeeds - the provider raises no error and simply emits no
    object - so Get-ItemProperty returns $null with nothing having failed.

    That is a PRESENT, VALUE-EMPTY key and a genuine observation:

      - server / client authentication and AllowUnencrypted take the
        documented Windows defaults, every field marked default_inferred,
        and the applicable unit completes successfully;
      - TrustedHosts is recorded as $null with a SUCCESSFUL outcome,
        because an absent value means no trusted hosts are configured. No
        configured value is ever manufactured.

    These remain fail-closed and non-success:

      - a MISSING key (the terminating Test-Path returns false);
      - a THROWN read or access error, which never reaches the value-empty
        path at all.

    Property access goes through Get-VKWinRMRegistryValue so a $null
    property object and an absent value are handled identically and without
    relying on permissive missing-property behaviour under Set-StrictMode.

    NOT IN THIS TRANCHE
    No new runtime-state collection is added. The module still reads the
    configured state rather than probing the effective listener state.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.1
#>

function Get-VKWinRMRegistryValue {
    <#
    .SYNOPSIS
        Reads one named value from a registry property object, safely.

    .DESCRIPTION
        Returns $null in both of the cases that mean "this value is not
        configured":

          - the property object itself is $null, which is how a present but
            VALUE-EMPTY key reaches this function, because Get-ItemProperty
            emits no object for a key that holds no values;
          - the object exists but carries no property of that name.

        Windows PowerShell 5.1 compatible, and deliberately does NOT rely on
        permissive missing-property access: under Set-StrictMode -Version 2
        a direct $object.Missing reference raises PropertyNotFoundException.
        The PSObject property table is consulted explicitly instead, which
        is defined behaviour under every strict mode.

        This function reports absence only. It never supplies a default and
        never converts a value; the caller decides what an absent value
        means and records the provenance.

    .PARAMETER PropertyObject
        The object returned by Get-ItemProperty, or $null.

    .PARAMETER Name
        The registry value name to read.

    .OUTPUTS
        The stored value, or $null when it is not present.
    #>
    param(
        $PropertyObject,

        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $PropertyObject) { return $null }

    $property = $PropertyObject.PSObject.Properties[$Name]

    if ($null -eq $property) { return $null }

    return $property.Value
}


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

        # A THROWN read or access error is handled by the catch below and
        # fails the unit closed. A key that exists and is read SUCCESSFULLY
        # but holds no values makes Get-ItemProperty emit no object, so
        # $serverSettings is $null with nothing having failed. That is a
        # present, value-empty key: the documented Windows defaults apply,
        # every field below is marked default_inferred, and the unit
        # completes successfully.
        $serverSettings = Get-ItemProperty -Path $serverRegPath -ErrorAction Stop

        $serverSources = [ordered]@{}

        # AllowUnencrypted: documented default is disabled.
        $rawAllowUnencrypted = Get-VKWinRMRegistryValue -PropertyObject $serverSettings -Name "AllowUnencrypted"

        if ($null -ne $rawAllowUnencrypted) {
            $winrmData["allow_unencrypted"]      = ([int]$rawAllowUnencrypted -eq 1)
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
            $raw = Get-VKWinRMRegistryValue -PropertyObject $serverSettings -Name $field.Name

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

        # As for the server key above: a thrown error fails the unit closed,
        # while a successfully read, value-empty key yields $null here and
        # licenses the documented client defaults as default_inferred.
        $clientSettings = Get-ItemProperty -Path $clientRegPath -ErrorAction Stop

        $clientSources = [ordered]@{}

        $clientAuthFields = @(
            @{ Path = "basic";     Name = "AllowBasic";     Default = $false }
            @{ Path = "kerberos";  Name = "AllowKerberos";  Default = $true  }
            @{ Path = "negotiate"; Name = "AllowNegotiate"; Default = $true  }
            @{ Path = "credssp";   Name = "AllowCredSSP";   Default = $false }
        )

        $clientAuth = [ordered]@{}

        foreach ($field in $clientAuthFields) {
            $raw = Get-VKWinRMRegistryValue -PropertyObject $clientSettings -Name $field.Name

            if ($null -ne $raw) {
                $clientAuth[$field.Path]                     = ([int]$raw -eq 1)
                $clientSources["client_auth.$($field.Path)"] = "explicit"
            }
            else {
                $clientAuth[$field.Path]                     = $field.Default
                $clientSources["client_auth.$($field.Path)"] = "default_inferred"
            }
        }

        $rawClientAllowUnencrypted = Get-VKWinRMRegistryValue -PropertyObject $clientSettings -Name "AllowUnencrypted"

        if ($null -ne $rawClientAllowUnencrypted) {
            $winrmData["client_allow_unencrypted"]     = ([int]$rawClientAllowUnencrypted -eq 1)
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

        # A thrown error fails the unit closed. A successfully read,
        # value-empty Client key yields $null here - the key is present and
        # simply holds no values - which is handled identically to a key
        # that holds other values but no TrustedHosts.
        $clientKey = Get-ItemProperty -Path $clientRegPath -ErrorAction Stop

        # An absent TrustedHosts value is a genuine observation: no trusted
        # hosts are configured. $null is the correct representation and the
        # unit completes SUCCESSFULLY. No configured value is manufactured.
        $rawTrustedHosts = Get-VKWinRMRegistryValue -PropertyObject $clientKey -Name "TrustedHosts"

        $winrmData["trusted_hosts"] = if ($rawTrustedHosts) { $rawTrustedHosts } else { $null }

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
