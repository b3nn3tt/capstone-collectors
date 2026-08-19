<#
.SYNOPSIS
    Module: SMB Protocol Configuration

.DESCRIPTION
    Enumerates SMB protocol configuration:
    - SMBv1 enabled/disabled (critical - should be disabled)
    - SMB signing (required, enabled, or disabled) for server and client
    - Guest authentication (insecure guest logons)
    - Encryption settings
    - Null session / anonymous access indicators

    Registry sources:
    - HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
    - HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
    - SMB server configuration via Get-SmbServerConfiguration

    SCHEMA 1.1 ACQUISITION
    Four independent collection units:

        security.smb.smbv1
        security.smb.server_registry
        security.smb.client_registry
        security.smb.server_configuration

    VALUE PROVENANCE
    Several SMB settings have a documented Windows default that applies
    when the registry value is absent. Retaining those defaults is
    defensible, but only where the read SUCCEEDED. Provenance is exposed
    through additive source maps:

        server_value_sources  { <field> = "explicit" | "default_inferred" }
        client_value_sources  { <field> = "explicit" | "default_inferred" }
        smbv1_value_source    "explicit" | "feature_observed" | $null

    SMBv1 additionally distinguishes a registry-explicit state from an
    optional-feature-observed state, because they are different providers
    answering a related but not identical question.

    FAIL-CLOSED NOTES
    - The previous module probed SMBv1 with -ErrorAction SilentlyContinue,
      so a failed or denied registry read was indistinguishable from an
      absent value before the feature fallback even ran.
    - Failed registry reads no longer license any documented default: the
      governed fields stay $null with no provenance entry.
    - Get-SmbServerConfiguration without admin is now recorded as
      restricted / insufficient_privilege rather than being silently
      omitted from the payload.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecuritySMB {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating SMB configuration" -Type "PROCESSING"

    $serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

    $smbv1Unit     = "security.smb.smbv1"
    $serverRegUnit = "security.smb.server_registry"
    $clientRegUnit = "security.smb.client_registry"
    $serverCfgUnit = "security.smb.server_configuration"

    # Every governed path pre-initialised to $null.
    $smbData = [ordered]@{
        "smbv1_enabled"                = $null
        "smbv1_value_source"           = $null
        "server_signing_required"      = $null
        "server_signing_enabled"       = $null
        "server_encrypt_data"          = $null
        "server_reject_unencrypted"    = $null
        "null_session_pipes"           = $null
        "null_session_shares"          = $null
        "restrict_null_session_access" = $null
        "server_value_sources"         = $null
        "client_signing_required"      = $null
        "client_signing_enabled"       = $null
        "client_insecure_guest_auth"   = $null
        "client_value_sources"         = $null
        "smb2_enabled"                 = $null
        "server_multichannel"          = $null
        "server_leasing"               = $null
        "max_channel_per_session"      = $null
    }

    Start-VKAcquisition -UnitId $smbv1Unit -Provider "$serverRegPath\SMB1 / Get-WindowsOptionalFeature(SMB1Protocol)" -DataPaths @(
        "security.smb.smbv1_enabled"
        "security.smb.smbv1_value_source"
    )

    Start-VKAcquisition -UnitId $serverRegUnit -Provider $serverRegPath -DataPaths @(
        "security.smb.server_signing_required"
        "security.smb.server_signing_enabled"
        "security.smb.server_encrypt_data"
        "security.smb.server_reject_unencrypted"
        "security.smb.null_session_pipes"
        "security.smb.null_session_shares"
        "security.smb.restrict_null_session_access"
        "security.smb.server_value_sources"
    )

    Start-VKAcquisition -UnitId $clientRegUnit -Provider $clientRegPath -DataPaths @(
        "security.smb.client_signing_required"
        "security.smb.client_signing_enabled"
        "security.smb.client_insecure_guest_auth"
        "security.smb.client_value_sources"
    )

    Start-VKAcquisition -UnitId $serverCfgUnit -Provider "Get-SmbServerConfiguration" -DataPaths @(
        "security.smb.smb2_enabled"
        "security.smb.server_multichannel"
        "security.smb.server_leasing"
        "security.smb.max_channel_per_session"
    )


    # --------------------------------------------------------
    #  SMBv1 Status
    # --------------------------------------------------------
    # SMBv1 is a critical finding if enabled - EternalBlue, WannaCry, etc.

    try {
        $smbv1Explicit = $null

        if (Test-Path -Path $serverRegPath -ErrorAction Stop) {
            $serverKey = Get-ItemProperty -Path $serverRegPath -ErrorAction Stop
            if ($null -ne $serverKey.SMB1) {
                $smbv1Explicit = [int]$serverKey.SMB1
            }
        }

        if ($null -ne $smbv1Explicit) {
            # Registry-explicit state.
            $smbData["smbv1_enabled"]      = ($smbv1Explicit -eq 1)
            $smbData["smbv1_value_source"] = "explicit"
            Complete-VKAcquisition -UnitId $smbv1Unit
        }
        else {
            # No registry value. Fall back to the optional-feature state,
            # which is a DIFFERENT provider answering a related question:
            # whether the SMB1 feature is installed and enabled.
            $smbv1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop

            if ($null -eq $smbv1Feature -or $null -eq $smbv1Feature.State) {
                throw [System.InvalidOperationException]::new(
                    "Get-WindowsOptionalFeature returned no state for SMB1Protocol.")
            }

            $smbData["smbv1_enabled"]      = ($smbv1Feature.State -eq "Enabled")
            $smbData["smbv1_value_source"] = "feature_observed"
            Complete-VKAcquisition -UnitId $smbv1Unit
        }
    }
    catch {
        $smbData["smbv1_enabled"]      = $null
        $smbData["smbv1_value_source"] = $null

        Write-LogMessage -Section "Security.SMB" -Message "Unable to determine SMBv1 status: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $smbv1Unit -Provider $serverRegPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $smbv1Unit -ErrorRecord $_ -Provider $serverRegPath
        }
    }


    # --------------------------------------------------------
    #  SMB Server Settings (registry)
    # --------------------------------------------------------

    try {
        if (-not (Test-Path -Path $serverRegPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new(
                "The LanmanServer parameters key is not present.")
        }

        $serverParams = Get-ItemProperty -Path $serverRegPath -ErrorAction Stop

        if ($null -eq $serverParams) {
            throw [System.InvalidOperationException]::new(
                "Reading the LanmanServer parameters key returned no properties.")
        }

        $serverSources = [ordered]@{}

        # Field, registry value name, and the documented Windows default
        # that applies when the value is genuinely absent.
        $serverFields = @(
            @{ Path = "server_signing_required";      Name = "RequireSecuritySignature"; Default = $false }
            @{ Path = "server_signing_enabled";       Name = "EnableSecuritySignature";  Default = $true  }
            @{ Path = "server_encrypt_data";          Name = "EncryptData";              Default = $false }
            @{ Path = "server_reject_unencrypted";    Name = "RejectUnencryptedAccess";  Default = $true  }
            @{ Path = "restrict_null_session_access"; Name = "RestrictNullSessAccess";   Default = $true  }
        )

        foreach ($field in $serverFields) {
            $raw = $serverParams.($field.Name)

            if ($null -ne $raw) {
                $smbData[$field.Path]      = ([int]$raw -eq 1)
                $serverSources[$field.Path] = "explicit"
            }
            else {
                # Read succeeded; the value is genuinely absent, so the
                # documented default applies - marked as inferred.
                $smbData[$field.Path]      = $field.Default
                $serverSources[$field.Path] = "default_inferred"
            }
        }

        # Multi-string values. An absent value here means no null-session
        # pipes/shares are configured, which is a genuine empty observation.
        foreach ($listField in @(
            @{ Path = "null_session_pipes";  Name = "NullSessionPipes"  }
            @{ Path = "null_session_shares"; Name = "NullSessionShares" }
        )) {
            $rawList = $serverParams.($listField.Name)

            if ($null -ne $rawList) {
                $smbData[$listField.Path]       = @(@($rawList) | Where-Object { $_ -and $_.Trim() })
                $serverSources[$listField.Path] = "explicit"
            }
            else {
                $smbData[$listField.Path]       = @()
                $serverSources[$listField.Path] = "default_inferred"
            }
        }

        $smbData["server_value_sources"] = $serverSources
        Complete-VKAcquisition -UnitId $serverRegUnit
    }
    catch {
        # No default is licensed by a failed read.
        foreach ($path in @(
            "server_signing_required", "server_signing_enabled", "server_encrypt_data",
            "server_reject_unencrypted", "null_session_pipes", "null_session_shares",
            "restrict_null_session_access", "server_value_sources"
        )) {
            $smbData[$path] = $null
        }

        Write-LogMessage -Section "Security.SMB" -Message "Unable to read SMB server registry parameters: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $serverRegUnit -Provider $serverRegPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $serverRegUnit -ErrorRecord $_ -Provider $serverRegPath
        }
    }


    # --------------------------------------------------------
    #  SMB Client Settings (registry)
    # --------------------------------------------------------

    try {
        if (-not (Test-Path -Path $clientRegPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new(
                "The LanmanWorkstation parameters key is not present.")
        }

        $clientParams = Get-ItemProperty -Path $clientRegPath -ErrorAction Stop

        if ($null -eq $clientParams) {
            throw [System.InvalidOperationException]::new(
                "Reading the LanmanWorkstation parameters key returned no properties.")
        }

        $clientSources = [ordered]@{}

        $clientFields = @(
            @{ Path = "client_signing_required";    Name = "RequireSecuritySignature"; Default = $false }
            @{ Path = "client_signing_enabled";     Name = "EnableSecuritySignature";  Default = $true  }
            @{ Path = "client_insecure_guest_auth"; Name = "AllowInsecureGuestAuth";   Default = $false }
        )

        foreach ($field in $clientFields) {
            $raw = $clientParams.($field.Name)

            if ($null -ne $raw) {
                $smbData[$field.Path]       = ([int]$raw -eq 1)
                $clientSources[$field.Path] = "explicit"
            }
            else {
                $smbData[$field.Path]       = $field.Default
                $clientSources[$field.Path] = "default_inferred"
            }
        }

        $smbData["client_value_sources"] = $clientSources
        Complete-VKAcquisition -UnitId $clientRegUnit
    }
    catch {
        foreach ($path in @(
            "client_signing_required", "client_signing_enabled",
            "client_insecure_guest_auth", "client_value_sources"
        )) {
            $smbData[$path] = $null
        }

        Write-LogMessage -Section "Security.SMB" -Message "Unable to read SMB client registry parameters: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $clientRegUnit -Provider $clientRegPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $clientRegUnit -ErrorRecord $_ -Provider $clientRegPath
        }
    }


    # --------------------------------------------------------
    #  SMB Server Configuration (cmdlet - richer data if admin)
    # --------------------------------------------------------

    if (-not $IsAdmin) {
        # Recorded, not silently omitted. Re-collecting elevated is the
        # remedy, which is what 'restricted' signals.
        $reason = "Get-SmbServerConfiguration requires administrative privileges."

        Write-LogMessage -Section "Security.SMB" -Message $reason -Level "WARNING"
        Set-VKAcquisitionFailure -UnitId $serverCfgUnit -Provider "Get-SmbServerConfiguration" `
            -Outcome "restricted" -Category "insufficient_privilege" -Message $reason
    }
    else {
        try {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop

            if ($null -eq $smbConfig) {
                throw [System.InvalidOperationException]::new(
                    "Get-SmbServerConfiguration returned no configuration object.")
            }

            $configFields = @(
                @{ Path = "smb2_enabled";            Name = "EnableSMB2Protocol"   }
                @{ Path = "server_multichannel";     Name = "EnableMultiChannel"   }
                @{ Path = "server_leasing";          Name = "EnableLeasing"        }
                @{ Path = "max_channel_per_session"; Name = "MaxChannelPerSession" }
            )

            foreach ($field in $configFields) {
                $raw = $smbConfig.($field.Name)

                if ($null -eq $raw) {
                    throw [System.InvalidOperationException]::new(
                        "Get-SmbServerConfiguration returned no $($field.Name) value.")
                }

                $smbData[$field.Path] = $raw
            }

            Complete-VKAcquisition -UnitId $serverCfgUnit
        }
        catch {
            foreach ($path in @("smb2_enabled", "server_multichannel", "server_leasing", "max_channel_per_session")) {
                $smbData[$path] = $null
            }

            Write-LogMessage -Section "Security.SMB" -Message "Unable to retrieve SMB server configuration: $($_.Exception.Message)" -Level "WARNING"

            if ($_.Exception -is [System.InvalidOperationException]) {
                Set-VKAcquisitionUnavailable -UnitId $serverCfgUnit -Provider "Get-SmbServerConfiguration" `
                    -Category "provider_value_missing" -Message $_.Exception.Message
            }
            else {
                Set-VKAcquisitionFailure -UnitId $serverCfgUnit -ErrorRecord $_ -Provider "Get-SmbServerConfiguration"
            }
        }
    }

    $Data["smb"] = $smbData

    Write-VKStatus -Message "SMB enumeration complete" -Type "SUCCESS"
}
