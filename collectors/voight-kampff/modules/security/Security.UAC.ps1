<#
.SYNOPSIS
    Module: User Account Control (UAC)

.DESCRIPTION
    Enumerates UAC configuration from the registry:
    - UAC enabled/disabled
    - Consent prompt behaviour for admins and standard users
    - Admin Approval Mode
    - Built-in Administrator elevation behaviour
    - Secure Desktop for elevation prompts
    - Installer detection
    - ValidateAdminCodeSignatures (only elevate signed executables)
    - FilterAdministratorToken (built-in admin gets filtered token)

    All values from: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

    No admin required - these registry keys are world-readable.

    SCHEMA 1.1 ACQUISITION
    One collection unit, because every value comes from a single registry
    key read:

        security.uac.configuration

    FAIL-CLOSED NOTES
    - Every field is pre-initialised to $null and every property is guarded
      before comparison, lookup or integer conversion.
    - The previous module compared absent properties directly, e.g.
      ($uacKeys.EnableLUA -eq 1). $null -eq 1 is false, so an absent value
      silently became a confident "UAC is disabled". The same applied to
      secure_desktop_enabled, detect_installations,
      validate_admin_code_signatures and only_elevate_ui_access.
    - Consent prompt values were cast with [int], and [int]$null is 0,
      which maps to "Elevate without prompting" for administrators and
      "Automatically deny elevation requests" for standard users. Both are
      substantive prompt modes the host never reported.
    - No documented default is asserted for any UAC value. After a
      SUCCESSFUL read, an absent value stays $null: Windows defaults for
      these policies vary by edition and servicing state, so inventing one
      would not be defensible. The unit still completes as success, because
      the read itself succeeded.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityUAC {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating UAC configuration" -Type "PROCESSING"

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacUnit = "security.uac.configuration"

    # Every governed path pre-initialised to $null.
    $uacData = [ordered]@{
        "uac_enabled"                    = $null
        "admin_approval_mode"            = $null
        "consent_prompt_admin"           = $null
        "consent_prompt_admin_text"      = $null
        "consent_prompt_standard"        = $null
        "consent_prompt_standard_text"   = $null
        "secure_desktop_enabled"         = $null
        "detect_installations"           = $null
        "validate_admin_code_signatures" = $null
        "built_in_admin_approval_mode"   = $null
        "only_elevate_signed"            = $null
        "only_elevate_ui_access"         = $null
    }

    Start-VKAcquisition -UnitId $uacUnit -Provider $regPath -DataPaths @(
        "security.uac.uac_enabled"
        "security.uac.admin_approval_mode"
        "security.uac.consent_prompt_admin"
        "security.uac.consent_prompt_admin_text"
        "security.uac.consent_prompt_standard"
        "security.uac.consent_prompt_standard_text"
        "security.uac.secure_desktop_enabled"
        "security.uac.detect_installations"
        "security.uac.validate_admin_code_signatures"
        "security.uac.built_in_admin_approval_mode"
        "security.uac.only_elevate_signed"
        "security.uac.only_elevate_ui_access"
    )

    try {
        if (-not (Test-Path -Path $regPath -ErrorAction Stop)) {
            throw [System.InvalidOperationException]::new("The UAC policy key is not present.")
        }

        $uacKeys = Get-ItemProperty -Path $regPath -ErrorAction Stop

        if ($null -eq $uacKeys) {
            throw [System.InvalidOperationException]::new("Reading the UAC policy key returned no properties.")
        }

        # --- Boolean policy values -----------------------------------
        # Each stays $null when the value is absent from a successful read.
        $booleanFields = @(
            @{ Path = "uac_enabled";                    Name = "EnableLUA" }
            @{ Path = "admin_approval_mode";            Name = "FilterAdministratorToken" }
            @{ Path = "built_in_admin_approval_mode";   Name = "FilterAdministratorToken" }
            @{ Path = "secure_desktop_enabled";         Name = "PromptOnSecureDesktop" }
            @{ Path = "detect_installations";           Name = "EnableInstallerDetection" }
            @{ Path = "validate_admin_code_signatures"; Name = "ValidateAdminCodeSignatures" }
            @{ Path = "only_elevate_signed";            Name = "ValidateAdminCodeSignatures" }
            @{ Path = "only_elevate_ui_access";         Name = "EnableSecureUIAPaths" }
        )

        foreach ($field in $booleanFields) {
            $raw = $uacKeys.($field.Name)
            $uacData[$field.Path] = if ($null -ne $raw) { ([int]$raw -eq 1) } else { $null }
        }

        # --- Consent prompt behaviour --------------------------------
        # 0 is a meaningful mode for both maps, so an absent value must not
        # reach [int] conversion or the lookup.
        $adminConsentMap = @{
            0 = "Elevate without prompting"
            1 = "Prompt for credentials on secure desktop"
            2 = "Prompt for consent on secure desktop"
            3 = "Prompt for credentials"
            4 = "Prompt for consent"
            5 = "Prompt for consent for non-Windows binaries"
        }

        $standardConsentMap = @{
            0 = "Automatically deny elevation requests"
            1 = "Prompt for credentials on secure desktop"
            3 = "Prompt for credentials"
        }

        $consentFields = @(
            @{ ValuePath = "consent_prompt_admin";    TextPath = "consent_prompt_admin_text";    Name = "ConsentPromptBehaviorAdmin"; Map = $adminConsentMap }
            @{ ValuePath = "consent_prompt_standard"; TextPath = "consent_prompt_standard_text"; Name = "ConsentPromptBehaviorUser";  Map = $standardConsentMap }
        )

        foreach ($field in $consentFields) {
            $raw = $uacKeys.($field.Name)

            if ($null -ne $raw) {
                $value = [int]$raw
                $uacData[$field.ValuePath] = $value
                $uacData[$field.TextPath]  = Resolve-LookupValue -Value $value -LookupTable $field.Map
            }
            else {
                $uacData[$field.ValuePath] = $null
                $uacData[$field.TextPath]  = $null
            }
        }

        # The read succeeded. Individual values may legitimately be absent,
        # which is recorded as $null rather than as an invented default.
        Complete-VKAcquisition -UnitId $uacUnit
    }
    catch {
        foreach ($path in @($uacData.Keys)) {
            $uacData[$path] = $null
        }

        Write-LogMessage -Section "Security.UAC" -Message "Unable to retrieve UAC configuration: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $uacUnit -Provider $regPath `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $uacUnit -ErrorRecord $_ -Provider $regPath
        }
    }

    $Data["uac"] = $uacData

    Write-VKStatus -Message "UAC enumeration complete" -Type "SUCCESS"
}
