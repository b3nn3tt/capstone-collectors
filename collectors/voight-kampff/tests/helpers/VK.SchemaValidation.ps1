<#
.SYNOPSIS
    Schema conformance checks for Voight-Kampff evidence artefacts.

.DESCRIPTION
    TEST-ONLY. This file is development assurance and is NEVER included in
    the generated standalone collector. It is not referenced by the build
    template and adds no target-machine dependency.

    Implements the schema 1.1 conformance rules from
    docs/dissertation-agent-evidence-contract.md section 5.5.

    Test-side validation deliberately mirrors what the real ingestion layer
    must do: it REPORTS an artefact as invalid. It never repairs one, and
    it never invents an acquisition outcome for missing metadata.

.NOTES
    Tranche 2A.
#>

$script:VKPermittedOutcomes = @('success', 'failed', 'restricted', 'unavailable')

$script:VKRequiredAcquisitionFields = @(
    'observation_start'
    'observation_end'
    'acquisition_outcome'
    'agent_version'
    'schema_version'
    'data_paths'
    'error'
)

$script:VKRequiredErrorFields = @(
    'category'
    'provider'
    'message'
    'exception_type'
)

$script:VKSchema11Sections = @('scan_metadata', 'acquisition', 'host', 'security', 'vulnerability')
$script:VKSchema10Sections = @('scan_metadata', 'host', 'security', 'vulnerability')

$script:VKRequiredScanMetadata = @(
    'schema_version'
    'agent_version'
    'hostname'
    'running_user'
    'running_user_sid'
    'scan_start'
    'scan_end'
    'scan_duration_seconds'
    'ran_as_admin'
    'modules_executed'
)


function Get-VKMemberNames {
    <#
    .SYNOPSIS
        Returns key/property names for an ordered dictionary or a PSObject.

    .DESCRIPTION
        Fixtures are ordered dictionaries; artefacts parsed back from JSON
        are PSCustomObjects. Both shapes must validate identically.
    #>
    param([Parameter(Mandatory)][AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return @() }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return @($InputObject.Keys)
    }

    return @($InputObject.PSObject.Properties.Name)
}


function Get-VKMemberValue {
    <#
    .SYNOPSIS
        Reads a member from an ordered dictionary or a PSObject.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}


function Test-VKIsUtcTimestamp {
    <#
    .SYNOPSIS
        True when the value is an ISO 8601 UTC timestamp the agent emits.
    #>
    param([AllowNull()]$Value)

    if ($Value -isnot [string]) { return $false }
    if ($Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') { return $false }

    $parsed = [datetime]::MinValue
    return [datetime]::TryParseExact(
        $Value,
        'yyyy-MM-ddTHH:mm:ssZ',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$parsed
    )
}


function Test-VKAcquisitionEntry {
    <#
    .SYNOPSIS
        Validates a single acquisition entry.

    .OUTPUTS
        String[] of violation messages. Empty means conformant.
    #>
    param(
        [Parameter(Mandatory)][string]$UnitId,
        [Parameter(Mandatory)][AllowNull()]$Entry
    )

    $violations = @()

    if ($null -eq $Entry) {
        return @("[$UnitId] acquisition entry is null.")
    }

    $names = Get-VKMemberNames -InputObject $Entry

    foreach ($field in $script:VKRequiredAcquisitionFields) {
        if ($names -notcontains $field) {
            $violations += "[$UnitId] missing required field '$field'."
        }
    }

    # --- Outcome vocabulary ---
    $outcome = Get-VKMemberValue -InputObject $Entry -Name 'acquisition_outcome'
    if ($names -contains 'acquisition_outcome') {
        if ($script:VKPermittedOutcomes -notcontains $outcome) {
            $violations += "[$UnitId] acquisition_outcome '$outcome' is not one of: $($script:VKPermittedOutcomes -join ', ')."
        }
    }

    # --- Timestamps ---
    foreach ($field in @('observation_start', 'observation_end')) {
        if ($names -contains $field) {
            $value = Get-VKMemberValue -InputObject $Entry -Name $field
            if (-not (Test-VKIsUtcTimestamp -Value $value)) {
                $violations += "[$UnitId] $field '$value' is not a valid ISO 8601 UTC timestamp."
            }
        }
    }

    # --- data_paths ---
    if ($names -contains 'data_paths') {
        $paths = @(Get-VKMemberValue -InputObject $Entry -Name 'data_paths')
        if ($paths.Count -eq 0) {
            $violations += "[$UnitId] data_paths is empty; every entry must govern at least one payload path."
        }
        foreach ($path in $paths) {
            if ([string]::IsNullOrWhiteSpace($path)) {
                $violations += "[$UnitId] data_paths contains an empty value."
            }
        }
    }

    # --- error shape ---
    $errorValue = Get-VKMemberValue -InputObject $Entry -Name 'error'

    if ($outcome -eq 'success') {
        if ($null -ne $errorValue) {
            $violations += "[$UnitId] outcome is success but error is not null."
        }
    }
    elseif ($script:VKPermittedOutcomes -contains $outcome) {
        if ($null -eq $errorValue) {
            $violations += "[$UnitId] outcome is '$outcome' but error is null."
        }
        else {
            $errorNames = Get-VKMemberNames -InputObject $errorValue
            foreach ($field in $script:VKRequiredErrorFields) {
                if ($errorNames -notcontains $field) {
                    $violations += "[$UnitId] error is missing required field '$field'."
                }
            }

            $category = Get-VKMemberValue -InputObject $errorValue -Name 'category'
            if ([string]::IsNullOrWhiteSpace($category)) {
                $violations += "[$UnitId] error.category must be a stable machine-readable value."
            }

            $message = Get-VKMemberValue -InputObject $errorValue -Name 'message'
            if ($message -and ($message -match '(?m)^\s*at\s+\S+' -or $message -match 'StackTrace')) {
                $violations += "[$UnitId] error.message appears to contain a stack trace."
            }
        }
    }

    return $violations
}


function Test-VKEvidenceArtefact {
    <#
    .SYNOPSIS
        Validates a whole evidence artefact against its declared schema.

    .DESCRIPTION
        Schema 1.1 requires exactly five top-level sections and a
        conforming acquisition entry for every governed collection unit.

        Schema 1.0 is LEGACY: four sections, no acquisition section. It is
        not invalid - it predates the contract - but callers must not read
        empty or missing values from it as confirmed absence.

    .PARAMETER Artefact
        An ordered dictionary or a PSObject parsed from JSON.

    .PARAMETER RequiredUnitIds
        Collection-unit identifiers that must be present under schema 1.1.

    .OUTPUTS
        PSCustomObject with IsValid, IsLegacy, SchemaVersion and Violations.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Artefact,
        [string[]]$RequiredUnitIds = @()
    )

    $violations = @()

    if ($null -eq $Artefact) {
        return [pscustomobject]@{
            IsValid = $false; IsLegacy = $false; SchemaVersion = $null
            Violations = @('Artefact is null.')
        }
    }

    $metadata      = Get-VKMemberValue -InputObject $Artefact -Name 'scan_metadata'
    $schemaVersion = Get-VKMemberValue -InputObject $metadata -Name 'schema_version'
    $sections      = Get-VKMemberNames -InputObject $Artefact

    $isLegacy = ($schemaVersion -eq '1.0')

    # --- Required scan metadata (both schemas) ---
    $metadataNames = Get-VKMemberNames -InputObject $metadata
    foreach ($field in $script:VKRequiredScanMetadata) {
        if ($metadataNames -notcontains $field) {
            $violations += "scan_metadata is missing required field '$field'."
        }
    }

    if ($isLegacy) {
        if (@(Compare-Object -ReferenceObject $script:VKSchema10Sections -DifferenceObject $sections -SyncWindow 0).Count -ne 0) {
            $violations += "Schema 1.0 artefact must contain exactly: $($script:VKSchema10Sections -join ', ')."
        }
    }
    else {
        if (@(Compare-Object -ReferenceObject $script:VKSchema11Sections -DifferenceObject $sections -SyncWindow 0).Count -ne 0) {
            $violations += "Schema 1.1 artefact must contain exactly: $($script:VKSchema11Sections -join ', ')."
        }

        $acquisition = Get-VKMemberValue -InputObject $Artefact -Name 'acquisition'

        if ($null -eq $acquisition) {
            # Reported, never repaired. Nothing here fabricates an outcome.
            $violations += 'Schema 1.1 artefact has no acquisition section.'
        }
        else {
            $unitIds = Get-VKMemberNames -InputObject $acquisition

            foreach ($required in $RequiredUnitIds) {
                if ($unitIds -notcontains $required) {
                    $violations += "Required collection unit '$required' has no acquisition entry."
                }
            }

            foreach ($unitId in $unitIds) {
                $entry = Get-VKMemberValue -InputObject $acquisition -Name $unitId
                $violations += Test-VKAcquisitionEntry -UnitId $unitId -Entry $entry
            }
        }
    }

    return [pscustomobject]@{
        IsValid       = (@($violations).Count -eq 0)
        IsLegacy      = $isLegacy
        SchemaVersion = $schemaVersion
        Violations    = @($violations)
    }
}


function Test-VKLegacyCanAssertAbsence {
    <#
    .SYNOPSIS
        Always $false for schema 1.0 evidence.

    .DESCRIPTION
        Encodes the legacy reading rule as an executable assertion: under
        schema 1.0 there is no acquisition outcome, so the first stage of
        Rule 2 can never be satisfied and an empty or missing result is
        UNKNOWN rather than absent.

        Kept as a function rather than a constant so the rule is asserted
        by tests rather than merely documented.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Artefact,
        [Parameter(Mandatory)][string]$DataPath
    )

    $metadata      = Get-VKMemberValue -InputObject $Artefact -Name 'scan_metadata'
    $schemaVersion = Get-VKMemberValue -InputObject $metadata -Name 'schema_version'

    if ($schemaVersion -eq '1.0') { return $false }

    # Schema 1.1: absence is only ASSESSABLE where the governing unit
    # succeeded. Even then, confirmed absence additionally requires the
    # condition-specific applicability, coverage, authority and
    # field-semantics rules to permit it - which is a downstream decision
    # this helper deliberately does not make.
    $acquisition = Get-VKMemberValue -InputObject $Artefact -Name 'acquisition'
    if ($null -eq $acquisition) { return $false }

    foreach ($unitId in (Get-VKMemberNames -InputObject $acquisition)) {
        $entry = Get-VKMemberValue -InputObject $acquisition -Name $unitId
        $paths = @(Get-VKMemberValue -InputObject $entry -Name 'data_paths')
        if ($paths -contains $DataPath) {
            return ((Get-VKMemberValue -InputObject $entry -Name 'acquisition_outcome') -eq 'success')
        }
    }

    return $false
}
