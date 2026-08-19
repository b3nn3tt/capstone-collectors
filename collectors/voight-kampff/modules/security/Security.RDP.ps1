<#
.SYNOPSIS
    Module: Remote Desktop Protocol (RDP)

.DESCRIPTION
    Enumerates RDP configuration from the registry:
    - RDP enabled/disabled
    - Network Level Authentication (NLA) requirement
    - Listening port
    - Security layer (RDP Security, Negotiate, SSL/TLS)
    - Encryption level
    - Session timeout settings
    - RDP allowed users (via Remote Desktop Users group)

    Registry sources:
    - HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server
    - HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp

    No admin required - these registry keys are world-readable.

    SCHEMA 1.1 ACQUISITION
    Three independent collection units:

        security.rdp.terminal_server
        security.rdp.rdp_tcp
        security.rdp.allowed_users

    The two registry keys are separate providers. Previously a single try
    block covered both, so a failure reading the Terminal Server key
    silently discarded every RDP-Tcp value as well, and vice versa.

    VALUE PROVENANCE
    An absent PortNumber means RDP listens on the documented default of
    3389. That default is retained, with provenance exposed additively:

        port_value_source   "explicit" | "default_inferred"

    FAIL-CLOSED NOTES
    - Every property is guarded before boolean comparison or integer
      conversion. $null -eq 0 is false and [int]$null is 0, so an absent
      value previously produced a confident "disabled"/"not required"
      reading or a mapped security level the host never reported.
    - Get-LocalGroupMember now uses terminating error handling. A failed
      group enumeration yields $null, not an empty user list, which would
      read as "nobody is permitted RDP access".

    NOT IN THIS TRANCHE
    Principal treatment is unchanged: allowed_users still carries the
    observed account names. Domain-aware session evidence and
    pseudonymisation belong to later tranches and to the ingestion layer.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityRDP {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating RDP configuration" -Type "PROCESSING"

    $tsPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $rdpTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

    $tsUnit    = "security.rdp.terminal_server"
    $tcpUnit   = "security.rdp.rdp_tcp"
    $usersUnit = "security.rdp.allowed_users"

    $rdpGroup = "Remote Desktop Users"

    # Every governed path pre-initialised to $null.
    $rdpData = [ordered]@{
        "rdp_enabled"              = $null
        "restricted_admin_enabled" = $null
        "port"                     = $null
        "port_value_source"        = $null
        "nla_required"             = $null
        "security_layer"           = $null
        "encryption_level"         = $null
        "idle_timeout_ms"          = $null
        "disconnect_timeout_ms"    = $null
        "session_limit_ms"         = $null
        "allowed_users"            = $null
    }

    Start-VKAcquisition -UnitId $tsUnit -Provider $tsPath -DataPaths @(
        "security.rdp.rdp_enabled"
        "security.rdp.restricted_admin_enabled"
    )

    Start-VKAcquisition -UnitId $tcpUnit -Provider $rdpTcpPath -DataPaths @(
        "security.rdp.port"
        "security.rdp.port_value_source"
        "security.rdp.nla_required"
        "security.rdp.security_layer"
        "security.rdp.encryption_level"
        "security.rdp.idle_timeout_ms"
        "security.rdp.disconnect_timeout_ms"
        "security.rdp.session_limit_ms"
    )

    Start-VKAcquisition -UnitId $usersUnit -Provider "Get-LocalGroupMember($rdpGroup)" -DataPaths @(
        "security.rdp.allowed_users"
    )


    # --------------------------------------------------------
    #  Terminal Server key
    # --------------------------------------------------------

    try {
        if (-not (Test-Path -Path $tsPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new("The Terminal Server key is not present.")
        }

        $tsSettings = Get-ItemProperty -Path $tsPath -ErrorAction Stop

        if ($null -eq $tsSettings) {
            throw [System.InvalidOperationException]::new("Reading the Terminal Server key returned no properties.")
        }

        # fDenyTSConnections: 0 = RDP enabled, 1 = RDP disabled.
        # Absent means the state was not reported; $null -eq 0 is false,
        # which would have read as "RDP is disabled".
        if ($null -eq $tsSettings.fDenyTSConnections) {
            throw [System.InvalidOperationException]::new(
                "The Terminal Server key returned no fDenyTSConnections value.")
        }

        $rdpData["rdp_enabled"] = ([int]$tsSettings.fDenyTSConnections -eq 0)

        # DisableRestrictedAdmin is genuinely optional. Absent stays $null:
        # no documented default is asserted for it.
        $rdpData["restricted_admin_enabled"] = if ($null -ne $tsSettings.DisableRestrictedAdmin) {
            ([int]$tsSettings.DisableRestrictedAdmin -eq 0)
        }
        else { $null }

        Complete-VKAcquisition -UnitId $tsUnit
    }
    catch {
        $rdpData["rdp_enabled"]              = $null
        $rdpData["restricted_admin_enabled"] = $null

        Write-LogMessage -Section "Security.RDP" -Message "Unable to read the Terminal Server key: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $tsUnit -Provider $tsPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $tsUnit -ErrorRecord $_ -Provider $tsPath
        }
    }


    # --------------------------------------------------------
    #  RDP-Tcp key
    # --------------------------------------------------------

    try {
        if (-not (Test-Path -Path $rdpTcpPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new("The RDP-Tcp key is not present.")
        }

        $rdpTcpSettings = Get-ItemProperty -Path $rdpTcpPath -ErrorAction Stop

        if ($null -eq $rdpTcpSettings) {
            throw [System.InvalidOperationException]::new("Reading the RDP-Tcp key returned no properties.")
        }

        # Port: an absent value means the documented default of 3389.
        if ($null -ne $rdpTcpSettings.PortNumber) {
            $rdpData["port"]              = [int]$rdpTcpSettings.PortNumber
            $rdpData["port_value_source"] = "explicit"
        }
        else {
            $rdpData["port"]              = 3389
            $rdpData["port_value_source"] = "default_inferred"
        }

        # UserAuthentication: 1 = NLA required. No defensible default, so
        # an absent value withholds the whole RDP-Tcp collection rather
        # than reading as "NLA is not required".
        if ($null -eq $rdpTcpSettings.UserAuthentication) {
            throw [System.InvalidOperationException]::new(
                "The RDP-Tcp key returned no UserAuthentication value.")
        }
        $rdpData["nla_required"] = ([int]$rdpTcpSettings.UserAuthentication -eq 1)

        $securityLayerMap = @{
            0 = "RDP Security Layer"
            1 = "Negotiate"
            2 = "SSL/TLS"
        }

        $encryptionLevelMap = @{
            1 = "Low"
            2 = "Client Compatible"
            3 = "High"
            4 = "FIPS Compliant"
        }

        # [int]$null is 0, which maps to the LEAST secure security layer.
        if ($null -eq $rdpTcpSettings.SecurityLayer) {
            throw [System.InvalidOperationException]::new(
                "The RDP-Tcp key returned no SecurityLayer value.")
        }
        $rdpData["security_layer"] = Resolve-LookupValue -Value ([int]$rdpTcpSettings.SecurityLayer) -LookupTable $securityLayerMap

        if ($null -eq $rdpTcpSettings.MinEncryptionLevel) {
            throw [System.InvalidOperationException]::new(
                "The RDP-Tcp key returned no MinEncryptionLevel value.")
        }
        $rdpData["encryption_level"] = Resolve-LookupValue -Value ([int]$rdpTcpSettings.MinEncryptionLevel) -LookupTable $encryptionLevelMap

        # Timeouts are optional; absent stays $null rather than becoming 0,
        # which means "no limit" and is a substantive claim.
        $rdpData["idle_timeout_ms"]       = if ($null -ne $rdpTcpSettings.MaxIdleTime)          { [int]$rdpTcpSettings.MaxIdleTime }          else { $null }
        $rdpData["disconnect_timeout_ms"] = if ($null -ne $rdpTcpSettings.MaxDisconnectionTime) { [int]$rdpTcpSettings.MaxDisconnectionTime } else { $null }
        $rdpData["session_limit_ms"]      = if ($null -ne $rdpTcpSettings.MaxConnectionTime)    { [int]$rdpTcpSettings.MaxConnectionTime }    else { $null }

        Complete-VKAcquisition -UnitId $tcpUnit
    }
    catch {
        foreach ($path in @(
            "port", "port_value_source", "nla_required", "security_layer",
            "encryption_level", "idle_timeout_ms", "disconnect_timeout_ms", "session_limit_ms"
        )) {
            $rdpData[$path] = $null
        }

        Write-LogMessage -Section "Security.RDP" -Message "Unable to read the RDP-Tcp key: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $tcpUnit -Provider $rdpTcpPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $tcpUnit -ErrorRecord $_ -Provider $rdpTcpPath
        }
    }


    # --------------------------------------------------------
    #  Remote Desktop Users Group
    # --------------------------------------------------------

    try {
        # -ErrorAction Stop, not SilentlyContinue: a failed enumeration
        # previously yielded an empty list, indistinguishable from a group
        # with no members.
        $members = @(Get-LocalGroupMember -Group $rdpGroup -ErrorAction Stop)

        $rdpUsers = @()
        foreach ($member in $members) {
            if ($null -eq $member.Name) {
                throw [System.InvalidOperationException]::new(
                    "A member of '$rdpGroup' returned no Name value.")
            }
            $rdpUsers += ($member.Name -split '\\' | Select-Object -Last 1)
        }

        # Genuine zero result: the group exists and has no members.
        $rdpData["allowed_users"] = $rdpUsers
        Complete-VKAcquisition -UnitId $usersUnit
    }
    catch {
        # $null, not @(): an empty array would read as "nobody is permitted
        # RDP access", which was never established.
        $rdpData["allowed_users"] = $null

        Write-LogMessage -Section "Security.RDP" -Message "Unable to enumerate the '$rdpGroup' group: $($_.Exception.Message)" -Level "WARNING"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $usersUnit -Provider "Get-LocalGroupMember($rdpGroup)" `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $usersUnit -ErrorRecord $_ -Provider "Get-LocalGroupMember($rdpGroup)"
        }
    }

    $Data["rdp"] = $rdpData

    Write-VKStatus -Message "RDP enumeration complete" -Type "SUCCESS"
}
