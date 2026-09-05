<#
.SYNOPSIS
    Module: Windows Optional Features

.DESCRIPTION
    Enumerates the COMPLETE Windows optional-feature inventory reported by
    the servicing stack, as raw endpoint evidence:
        - feature_name  the FeatureName exactly as the provider supplied it
        - state         the provider's own state string, unreduced

    RAW EVIDENCE ONLY.

    This module collects facts. It does not select dissertation-specific
    feature identifiers, assess CVE applicability, classify risk, or make
    any compliance judgement. There is deliberately NO project-specific
    feature allowlist here: the full inventory is emitted and any
    research-specific extraction is a downstream concern.

    STATE IS PRESERVED, NOT INTERPRETED.

    Get-WindowsOptionalFeature reports more than two states. Reducing State
    to a Boolean would destroy the distinction between, for example,
    "Disabled" and "DisabledWithPayloadRemoved", and would misrepresent the
    pending states as settled ones. The provider's own string
    representation is therefore retained verbatim, whatever it is:

        Enabled | Disabled | DisabledWithPayloadRemoved
        EnablePending | DisablePending

    ELEVATION.

    Get-WindowsOptionalFeature -Online requires administrative privileges.
    Without elevation the provider is NOT invoked at all - no DISM session
    is opened - and the unit records restricted / insufficient_privilege so
    that re-collecting elevated is the visible remedy. The payload is
    retained as $null, never as an empty inventory.

    INVOCATION AND VALIDATION ARE SEPARATE.

    The single provider query has its own try/catch, and its catch ALWAYS
    passes the original error record to Set-VKAcquisitionFailure, whatever
    the exception type. A query that threw is an acquisition failure, and
    the shared classifier decides the outcome.

    Only once that query has returned does the inventory get validated.
    Those checks inspect records already in hand and never issue a second
    query, so a malformed answer is reported as unavailable /
    provider_value_missing - "the provider answered, but not usefully" -
    which is a different claim from "the query failed".

    Keeping them apart matters: while they shared one handler the outcome
    depended on the exception's TYPE, so a provider raising
    InvalidOperationException was misreported as missing provider data
    rather than as a failed query.

    A ZERO-RECORD RESPONSE IS NOT A GENUINE WINDOWS STATE.

    Every serviceable Windows installation reports optional features, so an
    empty response describes a provider that did not answer usefully rather
    than a host with no optional features. It is recorded as a non-success
    outcome with the payload withheld, not as a successful empty result.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.3.0
#>

function Invoke-VKHostWindowsOptionalFeatures {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating Windows optional features" -Type "PROCESSING"

    $featureUnit     = "host.windows_optional_features.inventory"
    $featureProvider = "Get-WindowsOptionalFeature -Online"

    # A failed, restricted or unusable query is UNKNOWN, never a
    # successful empty inventory.
    $Data["windows_optional_features"] = $null

    # Registered BEFORE the provider is invoked, so the unit fails closed
    # if anything below throws past its own handler.
    Start-VKAcquisition -UnitId $featureUnit -Provider $featureProvider `
        -DataPaths @("host.windows_optional_features")


    # --------------------------------------------------------
    #  Elevation gate
    # --------------------------------------------------------
    # Recorded, not silently omitted. DISM is not touched.
    # --------------------------------------------------------

    if (-not $IsAdmin) {
        $reason = "Get-WindowsOptionalFeature -Online requires administrative privileges."

        Write-LogMessage -Section "Host.WindowsOptionalFeatures" -Message $reason -Level "WARNING"
        Set-VKAcquisitionFailure -UnitId $featureUnit -Provider $featureProvider `
            -Outcome "restricted" -Category "insufficient_privilege" -Message $reason

        Write-VKStatus -Message "Windows optional-feature inventory skipped - insufficient privileges." -Type "BYPASS"
        return
    }


    # --------------------------------------------------------
    #  Provider invocation (exactly one query)
    # --------------------------------------------------------
    # Deliberately separated from validation below.
    #
    # An exception raised BY THE PROVIDER is an acquisition failure and
    # must always reach the shared conservative classifier, whatever type
    # it happens to be. Folding this into the validation handler made the
    # outcome depend on the exception's type: a provider throwing
    # InvalidOperationException was misreported as usable-but-missing
    # provider data rather than as a failed query.
    # --------------------------------------------------------

    $features = $null

    try {
        $features = @(Get-WindowsOptionalFeature -Online -ErrorAction Stop)
    }
    catch {
        # Withheld: the query did not complete, so nothing was observed.
        $Data["windows_optional_features"] = $null

        Write-LogMessage -Section "Host.WindowsOptionalFeatures" `
            -Message "Unable to query Windows optional features: $($_.Exception.Message)" -Level "ERROR"

        # ALWAYS the classifier, never a type-conditional category.
        Set-VKAcquisitionFailure -UnitId $featureUnit -ErrorRecord $_ -Provider $featureProvider

        Write-VKStatus -Message "Windows optional-feature query failed." -Type "ERROR"
        return
    }


    # --------------------------------------------------------
    #  Inventory validation (no second query)
    # --------------------------------------------------------
    # Reached only after the single query above completed. Everything
    # below inspects the records already in hand: the provider answered,
    # so any problem here is a malformed or unusable ANSWER, recorded as
    # unavailable / provider_value_missing.
    # --------------------------------------------------------

    try {
        if ($features.Count -eq 0) {
            throw [System.InvalidOperationException]::new(
                "Get-WindowsOptionalFeature -Online returned no optional-feature records.")
        }

        # Keyed by the feature name as supplied. The comparer is
        # case-insensitive so that two records differing only by case are
        # rejected as malformed provider output rather than silently
        # collapsing into one, or producing an unstable ordering.
        $byName = New-Object 'System.Collections.Generic.Dictionary[string,object]' (
            [System.StringComparer]::OrdinalIgnoreCase)

        foreach ($feature in $features) {
            $nameProperty = $null
            if ($feature) { $nameProperty = $feature.PSObject.Properties['FeatureName'] }

            $featureName = $null
            if ($nameProperty) { $featureName = $nameProperty.Value }

            if ($null -eq $featureName -or [string]::IsNullOrWhiteSpace([string]$featureName)) {
                throw [System.InvalidOperationException]::new(
                    "Get-WindowsOptionalFeature -Online returned a record with no FeatureName.")
            }

            # Preserved exactly as supplied - never normalised or re-cased.
            $featureName = [string]$featureName

            $stateProperty = $feature.PSObject.Properties['State']

            $stateValue = $null
            if ($stateProperty) { $stateValue = $stateProperty.Value }

            if ($null -eq $stateValue) {
                throw [System.InvalidOperationException]::new(
                    "Get-WindowsOptionalFeature -Online returned no State for feature '$featureName'.")
            }

            # The provider's own representation. An enum renders as its
            # member name; a string passes through unchanged. Nothing is
            # mapped, reduced to a Boolean or reinterpreted.
            $stateText = [string]$stateValue

            if ([string]::IsNullOrWhiteSpace($stateText)) {
                throw [System.InvalidOperationException]::new(
                    "Get-WindowsOptionalFeature -Online returned an empty State for feature '$featureName'.")
            }

            if ($byName.ContainsKey($featureName)) {
                throw [System.InvalidOperationException]::new(
                    "Get-WindowsOptionalFeature -Online returned duplicate FeatureName '$featureName'.")
            }

            $byName[$featureName] = [ordered]@{
                "feature_name" = $featureName
                "state"        = $stateText
            }
        }

        # Deterministic ORDINAL ordering. Sort-Object is culture-sensitive,
        # so an artefact collected under a different locale could order the
        # same inventory differently. [Array]::Sort with an ordinal
        # StringComparer is stable across locales and is available on
        # Windows PowerShell 5.1.
        $sortedNames = [string[]]@($byName.Keys)
        [Array]::Sort($sortedNames, [System.StringComparer]::Ordinal)

        $featureRecords = @()
        foreach ($name in $sortedNames) {
            $featureRecords += $byName[$name]
        }

        $Data["windows_optional_features"] = $featureRecords
        Complete-VKAcquisition -UnitId $featureUnit

        Write-VKStatus -Message "Windows optional-feature enumeration complete" -Type "SUCCESS"
    }
    catch {
        # Withheld, never partially emitted: an inventory is complete or it
        # is unknown.
        $Data["windows_optional_features"] = $null

        Write-LogMessage -Section "Host.WindowsOptionalFeatures" `
            -Message "Unusable Windows optional-feature inventory: $($_.Exception.Message)" -Level "ERROR"

        # The provider answered, but not with a usable inventory. No
        # further query is issued.
        Set-VKAcquisitionUnavailable -UnitId $featureUnit -Provider $featureProvider `
            -Category "provider_value_missing" -Message $_.Exception.Message

        Write-VKStatus -Message "Windows optional-feature inventory rejected as malformed." -Type "ERROR"
    }
}
