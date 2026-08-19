<#
.SYNOPSIS
    Module: Defender Advanced Settings

.DESCRIPTION
    Enumerates advanced Windows Defender / Microsoft Defender settings:
    - Attack Surface Reduction (ASR) rules and their actions
    - Network protection status
    - Controlled folder access status
    - PUA (Potentially Unwanted Application) protection
    - Cloud protection level and sample submission
    - Tamper protection status

    Only relevant on endpoints where Defender is the active AV.
    Uses Get-MpPreference, which is available without admin.

    SCHEMA 1.1 ACQUISITION
    Three independent collection units:

        security.defender_advanced.asr_rules
        security.defender_advanced.protection_preferences
        security.defender_advanced.tamper_protection

    PRECONDITION
    This module does NOT repeat the root\SecurityCenter2 product query.
    Security.Antivirus runs first in both maintained execution paths (the
    modular runner and the generated standalone), so its product evidence
    and the outcome of security.antivirus.products are used as the explicit
    precondition. Repeating the query would risk two modules disagreeing
    about which product is active, and would double an already-restricted
    provider call.

    FAIL-CLOSED NOTES
    - The previous module re-queried SecurityCenter2 with
      -ErrorAction SilentlyContinue and returned early on no match, so
      "Defender is not the active AV" and "the probe failed or was denied"
      both left security.defender_advanced entirely absent.
    - A mismatched ASR identifier/action pair no longer defaults the
      missing action to 0 / "Disabled", which asserted that a rule was off
      when its action was simply not reported.
    - A malformed ASR result withholds only the ASR unit. Independently
      valid protection-preference evidence from the same Get-MpPreference
      response is retained, because it does not depend on the ASR arrays.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityDefenderAdvanced {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating Defender advanced settings" -Type "PROCESSING"

    $asrUnit       = "security.defender_advanced.asr_rules"
    $prefsUnit     = "security.defender_advanced.protection_preferences"
    $tamperUnit    = "security.defender_advanced.tamper_protection"
    $prefsProvider = "Get-MpPreference"
    $statusProv    = "Get-MpComputerStatus"

    # Governed paths, all initialised to $null.
    $defenderData = [ordered]@{
        "asr_rules"                = $null
        "asr_rules_count"          = $null
        "asr_rules_blocking"       = $null
        "network_protection"       = $null
        "controlled_folder_access" = $null
        "pua_protection"           = $null
        "cloud_protection"         = $null
        "sample_submission"        = $null
        "tamper_protection"        = $null
    }

    Start-VKAcquisition -UnitId $asrUnit -Provider $prefsProvider -DataPaths @(
        "security.defender_advanced.asr_rules"
        "security.defender_advanced.asr_rules_count"
        "security.defender_advanced.asr_rules_blocking"
    )

    Start-VKAcquisition -UnitId $prefsUnit -Provider $prefsProvider -DataPaths @(
        "security.defender_advanced.network_protection"
        "security.defender_advanced.controlled_folder_access"
        "security.defender_advanced.pua_protection"
        "security.defender_advanced.cloud_protection"
        "security.defender_advanced.sample_submission"
    )

    Start-VKAcquisition -UnitId $tamperUnit -Provider $statusProv -DataPaths @(
        "security.defender_advanced.tamper_protection"
    )

    $allUnits = @($asrUnit, $prefsUnit, $tamperUnit)

    # --------------------------------------------------------
    #  Precondition: the product evidence already collected
    # --------------------------------------------------------

    # Get-VKAcquisitionReport projects the store without mutating it, so it
    # is safe to read mid-scan. A unit still pending would project as
    # 'failed', which is the correct fail-closed reading here.
    $acquisitionSoFar = Get-VKAcquisitionReport

    $productOutcome = $null
    if ($acquisitionSoFar.Contains("security.antivirus.products")) {
        $productOutcome = $acquisitionSoFar["security.antivirus.products"].acquisition_outcome
    }

    $productName = $null
    if ($Data.Contains("antivirus") -and $null -ne $Data["antivirus"]) {
        $productName = $Data["antivirus"]["product_name"]
    }

    if ($productOutcome -ne "success") {
        # The registered product was never established, so whether Defender
        # is active is unknown. Nothing is asserted about it.
        $reason = if ($null -eq $productOutcome) {
            "The antivirus product unit was not recorded, so Defender applicability could not be established."
        }
        else {
            "The antivirus product unit resolved to '$productOutcome', so Defender applicability could not be established."
        }

        Write-VKStatus -Message "Defender applicability unknown - skipping advanced settings." -Type "BYPASS"
        Write-LogMessage -Section "Security.DefenderAdvanced" -Message $reason -Level "WARNING"

        foreach ($unit in $allUnits) {
            Set-VKAcquisitionUnavailable -UnitId $unit -Provider $prefsProvider `
                -Category "precondition_not_met" -Message $reason
        }

        $Data["defender_advanced"] = $defenderData
        return
    }

    if ($productName -notmatch "Windows Defender|Microsoft Defender") {
        # A legitimate, informative capability gap rather than an error.
        $reason = "Microsoft Defender is not the registered antivirus product on this host."

        Write-VKStatus -Message "Defender is not the active AV - skipping advanced settings." -Type "BYPASS"

        foreach ($unit in $allUnits) {
            Set-VKAcquisitionUnavailable -UnitId $unit -Provider $prefsProvider `
                -Category "provider_not_applicable" -Message $reason
        }

        $Data["defender_advanced"] = $defenderData
        return
    }

    # --------------------------------------------------------
    #  Get-MpPreference (queried once, governs two units)
    # --------------------------------------------------------

    $prefs      = $null
    $prefsError = $null

    try {
        $prefs = Get-MpPreference -ErrorAction Stop

        if ($null -eq $prefs) {
            throw [System.InvalidOperationException]::new("Get-MpPreference returned no preference object.")
        }
    }
    catch {
        $prefsError = $_
    }

    if ($prefsError) {
        Write-LogMessage -Section "Security.DefenderAdvanced" -Message "Unable to retrieve Defender preferences: $($prefsError.Exception.Message)" -Level "ERROR"

        foreach ($unit in @($asrUnit, $prefsUnit)) {
            if ($prefsError.Exception -is [System.InvalidOperationException]) {
                Set-VKAcquisitionUnavailable -UnitId $unit -Provider $prefsProvider `
                    -Category "provider_value_missing" -Message $prefsError.Exception.Message
            }
            else {
                Set-VKAcquisitionFailure -UnitId $unit -ErrorRecord $prefsError -Provider $prefsProvider
            }
        }
    }
    else {
        # --- ASR rules ------------------------------------------------
        try {
            $asrActionMap = @{
                0 = "Disabled"
                1 = "Block"
                2 = "Audit"
                6 = "Warn"
            }

            $asrRuleNames = @{
                "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
                "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
                "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from LSASS"
                "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
                "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet criteria"
                "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
                "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded content"
                "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
                "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
                "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
                "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
                "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
                "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode"
                "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
                "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools"
                "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for servers"
                "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
                "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
            }

            $ruleIds     = @($prefs.AttackSurfaceReductionRules_Ids)
            $ruleActions = @($prefs.AttackSurfaceReductionRules_Actions)

            # A rule id with no corresponding action is a malformed result.
            # Defaulting the action to 0 would assert that the rule is
            # Disabled, which the provider never reported.
            if ($ruleIds.Count -ne $ruleActions.Count) {
                throw [System.InvalidOperationException]::new(
                    "Defender returned $($ruleIds.Count) ASR rule identifiers and $($ruleActions.Count) actions; the result is malformed.")
            }

            $asrRules = @()

            for ($i = 0; $i -lt $ruleIds.Count; $i++) {
                $ruleGuid = $ruleIds[$i]
                if ($null -eq $ruleGuid) {
                    throw [System.InvalidOperationException]::new("Defender returned a null ASR rule identifier at index $i.")
                }

                $rawAction = $ruleActions[$i]
                if ($null -eq $rawAction) {
                    throw [System.InvalidOperationException]::new(
                        "Defender returned no action for ASR rule '$ruleGuid'.")
                }

                $ruleGuid = ([string]$ruleGuid).ToLower()
                $action   = [int]$rawAction

                $asrRules += [ordered]@{
                    "guid"        = $ruleGuid
                    "name"        = if ($asrRuleNames.ContainsKey($ruleGuid)) { $asrRuleNames[$ruleGuid] } else { "Unknown Rule" }
                    "action"      = $action
                    "action_text" = Resolve-LookupValue -Value $action -LookupTable $asrActionMap
                }
            }

            # A successful query returning no configured rules is a genuine
            # zero result and an empty array is correct.
            $defenderData["asr_rules"]          = $asrRules
            $defenderData["asr_rules_count"]    = $asrRules.Count
            $defenderData["asr_rules_blocking"] = @($asrRules | Where-Object { $_["action"] -eq 1 }).Count

            Complete-VKAcquisition -UnitId $asrUnit
        }
        catch {
            $defenderData["asr_rules"]          = $null
            $defenderData["asr_rules_count"]    = $null
            $defenderData["asr_rules_blocking"] = $null

            Write-LogMessage -Section "Security.DefenderAdvanced" -Message "Unable to interpret ASR rules: $($_.Exception.Message)" -Level "ERROR"
            Set-VKAcquisitionUnavailable -UnitId $asrUnit -Provider $prefsProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }

        # --- Protection preferences -----------------------------------
        # Independent of the ASR arrays, so a malformed ASR result above
        # does not invalidate this evidence.
        try {
            $protectionModeMap = @{
                0 = "Disabled"
                1 = "Enabled"
                2 = "Audit"
            }

            $cloudLevelMap = @{
                0 = "Disabled"
                1 = "Basic"
                2 = "Advanced"
            }

            $submissionMap = @{
                0 = "Always prompt"
                1 = "Send safe samples automatically"
                2 = "Never send"
                3 = "Send all samples automatically"
            }

            $preferenceFields = @(
                @{ Path = "network_protection";       Property = "EnableNetworkProtection";        Map = $protectionModeMap }
                @{ Path = "controlled_folder_access"; Property = "EnableControlledFolderAccess";   Map = $protectionModeMap }
                @{ Path = "pua_protection";           Property = "PUAProtection";                  Map = $protectionModeMap }
                @{ Path = "cloud_protection";         Property = "MAPSReporting";                  Map = $cloudLevelMap }
                @{ Path = "sample_submission";        Property = "SubmitSamplesConsent";           Map = $submissionMap }
            )

            foreach ($field in $preferenceFields) {
                $raw = $prefs.($field.Property)

                # A missing value must not be cast to 0, which every map
                # above resolves to a substantive "Disabled"-style state.
                if ($null -eq $raw) {
                    throw [System.InvalidOperationException]::new(
                        "Get-MpPreference returned no $($field.Property) value.")
                }

                $defenderData[$field.Path] = Resolve-LookupValue -Value ([int]$raw) -LookupTable $field.Map
            }

            Complete-VKAcquisition -UnitId $prefsUnit
        }
        catch {
            foreach ($path in @("network_protection", "controlled_folder_access", "pua_protection", "cloud_protection", "sample_submission")) {
                $defenderData[$path] = $null
            }

            Write-LogMessage -Section "Security.DefenderAdvanced" -Message "Unable to interpret Defender preferences: $($_.Exception.Message)" -Level "ERROR"
            Set-VKAcquisitionUnavailable -UnitId $prefsUnit -Provider $prefsProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
    }

    # --------------------------------------------------------
    #  Tamper protection (Get-MpComputerStatus, queried once)
    # --------------------------------------------------------

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        if ($null -eq $mpStatus) {
            throw [System.InvalidOperationException]::new("Get-MpComputerStatus returned no status object.")
        }

        if ($null -eq $mpStatus.IsTamperProtected) {
            throw [System.InvalidOperationException]::new("Get-MpComputerStatus returned no IsTamperProtected value.")
        }

        $defenderData["tamper_protection"] = $mpStatus.IsTamperProtected
        Complete-VKAcquisition -UnitId $tamperUnit
    }
    catch {
        $defenderData["tamper_protection"] = $null

        Write-LogMessage -Section "Security.DefenderAdvanced" -Message "Unable to determine tamper protection status: $($_.Exception.Message)" -Level "WARNING"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $tamperUnit -Provider $statusProv `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $tamperUnit -ErrorRecord $_ -Provider $statusProv
        }
    }

    $Data["defender_advanced"] = $defenderData

    Write-VKStatus -Message "Defender advanced enumeration complete" -Type "SUCCESS"
}
