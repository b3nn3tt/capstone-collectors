<#
.SYNOPSIS
    Shared utility functions for Voight-Kampff modules.

.DESCRIPTION
    Contains helper functions used across multiple modules.
    These are dot-sourced by the runner before any modules execute.

    Functions here support data collection and enrichment only.
    Compliance evaluation is handled by the backend application.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>


function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes a structured log entry to the error log file.

    .PARAMETER Section
        The module or check section that generated the message.

    .PARAMETER Message
        The log message content.

    .PARAMETER Level
        Severity level: ERROR, WARNING, or INFO. Defaults to ERROR.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Section,

        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("ERROR", "WARNING", "INFO")]
        [string]$Level = "ERROR"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$Section] - $Message"
    Add-Content -Path $script:ErrorLogPath -Value $logEntry
}


function Invoke-IfAdmin {
    <#
    .SYNOPSIS
        Guards execution of a script block behind an admin privilege check.

    .DESCRIPTION
        If the current session has admin privileges, executes the script block
        and returns its output. Otherwise logs a warning and returns $null,
        allowing the caller to handle the absence gracefully.

    .PARAMETER SectionName
        Name of the section, used for logging.

    .PARAMETER ScriptBlock
        The code to execute if admin privileges are available.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$SectionName,

        [Parameter(Mandatory)]
        [ScriptBlock]$ScriptBlock
    )

    if ($script:IsAdmin) {
        try {
            return & $ScriptBlock
        }
        catch {
            Write-LogMessage -Section $SectionName -Message "Error executing section: $($_.Exception.Message)" -Level "ERROR"
            return $null
        }
    }
    else {
        Write-LogMessage -Section $SectionName -Message "Skipped - insufficient privileges." -Level "WARNING"
        return $null
    }
}


# ============================================================
#  ACQUISITION STATUS  (schema 1.1)
# ============================================================
# Records, per collection unit, WHETHER COLLECTION WORKED. Nothing here
# expresses condition applicability, contextual evidence state, confirmed
# presence or absence, or contextual direction or weight. Those are
# downstream determinations and must not be inferred from these values.
#
# FAIL-CLOSED CONTRACT
#   - A unit is registered BEFORE its provider or query is invoked.
#   - Registration records the observation start and an internal
#     'pending' state. 'pending' is an INTERNAL state only and can never
#     appear in emitted JSON.
#   - 'success' is recorded ONLY by an explicit Complete-VKAcquisition call
#     after the provider or query completed correctly. Invocation alone
#     never produces success.
#   - Any unit still unresolved at serialisation becomes 'failed' with
#     category 'incomplete_collection'.
#   - Only these four outcomes are ever emitted:
#         success | failed | restricted | unavailable
#
# HELPER INTERFACE  (Tranche 2B instruments remaining modules with these)
#
#   Initialize-VKAcquisition
#       Resets the store. Called once by the runner before any module runs.
#
#   Start-VKAcquisition -UnitId <string> -DataPaths <string[]> [-Provider <string>]
#       Registers a unit as pending and stamps observation_start.
#       -DataPaths are the exact JSON paths this outcome governs.
#       -Provider is the namespace, registry path, cmdlet or API queried.
#
#   Complete-VKAcquisition -UnitId <string>
#       Marks the unit 'success'. Call ONLY after the query returned
#       correctly - including when it correctly returned zero results.
#
#   Set-VKAcquisitionFailure -UnitId <string> [-ErrorRecord <ErrorRecord>]
#                            [-Provider <string>] [-Outcome <string>]
#                            [-Category <string>] [-Message <string>]
#       Marks a non-success outcome. With -ErrorRecord and no -Outcome the
#       outcome is classified conservatively by Get-VKAcquisitionClassification.
#       -Outcome overrides classification for non-exception cases.
#
#   Set-VKAcquisitionUnavailable -UnitId <string> [-Category] [-Provider] [-Message]
#       Convenience wrapper for a capability that is legitimately absent.
#
#   Complete-VKAcquisitionReport
#       Sweeps unresolved units to failed/incomplete_collection and stamps
#       any missing observation_end. Called by the runner before export.
#
#   Get-VKAcquisitionReport
#       Projects the store into the ordered schema 1.1 acquisition section.
#
# USAGE PATTERN
#
#   $unit = 'security.example.thing'
#   Start-VKAcquisition -UnitId $unit -Provider 'root\CIMV2:Win32_Thing' `
#       -DataPaths @('security.example.thing_state')
#   try {
#       $result = Get-CimInstance -ClassName Win32_Thing -ErrorAction Stop
#       $Data['thing_state'] = $result.State
#       Complete-VKAcquisition -UnitId $unit
#   }
#   catch {
#       $Data['thing_state'] = $null        # never a substantive value
#       Set-VKAcquisitionFailure -UnitId $unit -ErrorRecord $_ `
#           -Provider 'root\CIMV2:Win32_Thing'
#   }
# ============================================================

$script:VKAcquisitionOutcomes     = @("success", "failed", "restricted", "unavailable")
$script:VKAcquisitionPendingState = "pending"
$script:VKAcquisitionFinalState   = "final"
$script:VKAcquisitionMaxMessage   = 400


function Get-VKAcquisitionTimestamp {
    <#
    .SYNOPSIS
        Returns the current time as an ISO 8601 UTC string.
    #>
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}


function ConvertTo-VKBoundedMessage {
    <#
    .SYNOPSIS
        Bounds and sanitises a diagnostic message for inclusion in evidence.

    .DESCRIPTION
        Collapses whitespace, strips anything resembling a stack trace,
        redacts user profile paths and the running account name, and
        truncates to a fixed length.

        Diagnostic messages are for triage only. They must never carry a
        stack trace, and must not introduce avoidable personal information
        into the evidence artefact.
    #>
    param(
        [AllowNull()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $text = $Message

    # Drop stack-trace style continuation lines before collapsing whitespace.
    $text = ($text -split "`r?`n" | Where-Object { $_ -notmatch '^\s*(at\s|\+\s|In\s+Zeile|CategoryInfo|FullyQualifiedErrorId)' }) -join ' '

    # Collapse all remaining whitespace.
    $text = ($text -replace '\s+', ' ').Trim()

    # Redact user profile paths and the running account name.
    $text = $text -replace '(?i)([A-Z]:\\Users\\)[^\\\s"'']+', '$1<redacted>'
    if ($env:USERNAME) {
        $text = $text -replace ('(?i)' + [regex]::Escape($env:USERNAME)), '<redacted>'
    }

    if ($text.Length -gt $script:VKAcquisitionMaxMessage) {
        $text = $text.Substring(0, $script:VKAcquisitionMaxMessage) + '...'
    }

    return $text
}


function Get-VKAcquisitionClassification {
    <#
    .SYNOPSIS
        Conservatively classifies an error into an acquisition outcome.

    .DESCRIPTION
        Returns an ordered hashtable with 'outcome', 'category' and
        'exception_type'.

        Classification prefers strong signals over fragile ones, in order:
          1. exception type (including the inner-exception chain)
          2. FullyQualifiedErrorId
          3. ErrorCategory
          4. HRESULT (WMI/COM)
          5. message text - LAST RESORT only

        Anything unrecognised is classified 'failed', never 'success'.

    .PARAMETER ErrorRecord
        An ErrorRecord or Exception. $null yields failed/unexpected_error.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $ErrorRecord
    )

    $result = [ordered]@{
        "outcome"        = "failed"
        "category"       = "unexpected_error"
        "exception_type" = $null
    }

    if ($null -eq $ErrorRecord) { return $result }

    $exception = $null
    $fqid      = $null
    $category  = $null

    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $exception = $ErrorRecord.Exception
        $fqid      = $ErrorRecord.FullyQualifiedErrorId
        if ($ErrorRecord.CategoryInfo) { $category = $ErrorRecord.CategoryInfo.Category.ToString() }
    }
    elseif ($ErrorRecord -is [System.Exception]) {
        $exception = $ErrorRecord
    }

    if ($exception) { $result["exception_type"] = $exception.GetType().FullName }

    # --- 1. Exception type chain -------------------------------------
    $typeNames = @()
    $walk  = $exception
    $guard = 0
    while ($walk -and $guard -lt 8) {
        $typeNames += $walk.GetType().FullName
        $walk = $walk.InnerException
        $guard++
    }

    $typeRules = @(
        @{ Match = 'UnauthorizedAccessException';   Outcome = 'restricted';  Category = 'access_denied' }
        @{ Match = 'PrivilegeNotHeldException';     Outcome = 'restricted';  Category = 'insufficient_privilege' }
        @{ Match = 'SecurityException';             Outcome = 'restricted';  Category = 'security_policy' }
        @{ Match = 'CommandNotFoundException';      Outcome = 'unavailable'; Category = 'command_not_found' }
        @{ Match = 'DriveNotFoundException';        Outcome = 'unavailable'; Category = 'provider_not_found' }
        @{ Match = 'ItemNotFoundException';         Outcome = 'unavailable'; Category = 'path_not_found' }
        @{ Match = 'NotImplementedException';       Outcome = 'unavailable'; Category = 'capability_not_supported' }
        @{ Match = 'NotSupportedException';         Outcome = 'unavailable'; Category = 'capability_not_supported' }
        @{ Match = 'EntryPointNotFoundException';   Outcome = 'unavailable'; Category = 'capability_not_supported' }
        @{ Match = 'DllNotFoundException';          Outcome = 'unavailable'; Category = 'capability_not_supported' }
        @{ Match = 'TypeLoadException';             Outcome = 'unavailable'; Category = 'capability_not_supported' }
        @{ Match = 'FileNotFoundException';         Outcome = 'unavailable'; Category = 'provider_not_found' }
    )

    foreach ($typeName in $typeNames) {
        foreach ($rule in $typeRules) {
            if ($typeName -like "*$($rule.Match)") {
                $result["outcome"]  = $rule.Outcome
                $result["category"] = $rule.Category
                return $result
            }
        }
    }

    # --- 2. FullyQualifiedErrorId ------------------------------------
    if ($fqid) {
        $idRules = @(
            @{ Match = '*UnauthorizedAccess*';  Outcome = 'restricted';  Category = 'access_denied' }
            @{ Match = '*AccessDenied*';        Outcome = 'restricted';  Category = 'access_denied' }
            @{ Match = '*PermissionDenied*';    Outcome = 'restricted';  Category = 'access_denied' }
            @{ Match = '*SecurityError*';       Outcome = 'restricted';  Category = 'security_policy' }
            @{ Match = '*CommandNotFound*';     Outcome = 'unavailable'; Category = 'command_not_found' }
            @{ Match = '*PathNotFound*';        Outcome = 'unavailable'; Category = 'path_not_found' }
            @{ Match = '*ItemNotFound*';        Outcome = 'unavailable'; Category = 'path_not_found' }
            @{ Match = '*InvalidNamespace*';    Outcome = 'unavailable'; Category = 'namespace_not_found' }
            @{ Match = '*ProviderNotFound*';    Outcome = 'unavailable'; Category = 'provider_not_found' }
            @{ Match = '*NotInstalled*';        Outcome = 'unavailable'; Category = 'capability_not_supported' }
        )
        foreach ($rule in $idRules) {
            if ($fqid -like $rule.Match) {
                $result["outcome"]  = $rule.Outcome
                $result["category"] = $rule.Category
                return $result
            }
        }
    }

    # --- 3. ErrorCategory --------------------------------------------
    if ($category) {
        switch ($category) {
            'PermissionDenied'    { $result["outcome"] = 'restricted';  $result["category"] = 'access_denied';             return $result }
            'SecurityError'       { $result["outcome"] = 'restricted';  $result["category"] = 'security_policy';           return $result }
            'ObjectNotFound'      { $result["outcome"] = 'unavailable'; $result["category"] = 'path_not_found';            return $result }
            'ResourceUnavailable' { $result["outcome"] = 'unavailable'; $result["category"] = 'provider_not_found';        return $result }
            'NotInstalled'        { $result["outcome"] = 'unavailable'; $result["category"] = 'capability_not_supported';  return $result }
            'NotImplemented'      { $result["outcome"] = 'unavailable'; $result["category"] = 'capability_not_supported';  return $result }
            'DeviceError'         { $result["outcome"] = 'unavailable'; $result["category"] = 'provider_not_found';        return $result }
        }
    }

    # --- 4. HRESULT (WMI / COM) --------------------------------------
    if ($exception -and $exception.PSObject.Properties.Name -contains 'HResult') {
        switch ($exception.HResult) {
            -2147217405 { $result["outcome"] = 'restricted';  $result["category"] = 'access_denied';       return $result }  # WBEM_E_ACCESS_DENIED
            -2147024891 { $result["outcome"] = 'restricted';  $result["category"] = 'access_denied';       return $result }  # E_ACCESSDENIED
            -2147217394 { $result["outcome"] = 'unavailable'; $result["category"] = 'namespace_not_found'; return $result }  # WBEM_E_INVALID_NAMESPACE
            -2147217406 { $result["outcome"] = 'unavailable'; $result["category"] = 'provider_not_found';  return $result }  # WBEM_E_NOT_FOUND
            -2147217392 { $result["outcome"] = 'unavailable'; $result["category"] = 'provider_not_found';  return $result }  # WBEM_E_INVALID_CLASS
        }
    }

    # --- 5. Message text (LAST RESORT) -------------------------------
    # Deliberately last. Message text is localised and unstable; it is used
    # only when every structured signal above was absent.
    if ($exception -and $exception.Message) {
        $message = $exception.Message
        if ($message -match '(?i)access is denied|access denied|unauthorized|not allowed|requires elevation|privilege') {
            $result["outcome"]  = 'restricted'
            $result["category"] = 'access_denied'
            return $result
        }
        if ($message -match '(?i)invalid namespace|not recognized as the name|is not installed|not supported|could not be found|cannot find path') {
            $result["outcome"]  = 'unavailable'
            $result["category"] = 'capability_not_supported'
            return $result
        }
    }

    return $result
}


function Initialize-VKAcquisition {
    <#
    .SYNOPSIS
        Resets the acquisition store. Called once by the runner.
    #>
    $script:VKAcquisitionUnits = [ordered]@{}
}


function Get-VKAcquisitionUnitStore {
    <#
    .SYNOPSIS
        Returns the acquisition store, initialising it if required.
    #>
    if ($null -eq $script:VKAcquisitionUnits) { Initialize-VKAcquisition }
    return $script:VKAcquisitionUnits
}


function Start-VKAcquisition {
    <#
    .SYNOPSIS
        Registers a collection unit as pending, before its query runs.

    .PARAMETER UnitId
        Stable dotted collection-unit identifier, e.g.
        'security.antivirus.products'.

    .PARAMETER DataPaths
        The exact JSON paths this unit's outcome governs.

    .PARAMETER Provider
        The namespace, registry path, cmdlet or API being queried.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$UnitId,

        [Parameter(Mandatory)]
        [string[]]$DataPaths,

        [string]$Provider
    )

    $store = Get-VKAcquisitionUnitStore

    $store[$UnitId] = [ordered]@{
        "unit_id"        = $UnitId
        "state"          = $script:VKAcquisitionPendingState
        "outcome"        = $null
        "start"          = Get-VKAcquisitionTimestamp
        "end"            = $null
        "data_paths"     = @($DataPaths)
        "provider"       = $Provider
        "category"       = $null
        "message"        = $null
        "exception_type" = $null
    }
}


function Complete-VKAcquisition {
    <#
    .SYNOPSIS
        Marks a collection unit successful.

    .DESCRIPTION
        Call ONLY after the provider or query completed correctly. A
        correct zero-result collection IS a success - that is precisely
        the case the schema 1.0 agent could not express.

        Completing a unit that was never registered is treated as a
        fail-closed defect: the unit is recorded as failed with category
        'unregistered_unit' rather than being granted success.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$UnitId
    )

    $store = Get-VKAcquisitionUnitStore

    if (-not $store.Contains($UnitId)) {
        $store[$UnitId] = [ordered]@{
            "unit_id"        = $UnitId
            "state"          = $script:VKAcquisitionFinalState
            "outcome"        = "failed"
            "start"          = Get-VKAcquisitionTimestamp
            "end"            = Get-VKAcquisitionTimestamp
            "data_paths"     = @()
            "provider"       = $null
            "category"       = "unregistered_unit"
            "message"        = "Completion was recorded for a collection unit that was never registered."
            "exception_type" = $null
        }
        return
    }

    $unit = $store[$UnitId]
    $unit["state"]          = $script:VKAcquisitionFinalState
    $unit["outcome"]        = "success"
    $unit["end"]            = Get-VKAcquisitionTimestamp
    $unit["category"]       = $null
    $unit["message"]        = $null
    $unit["exception_type"] = $null
}


function Set-VKAcquisitionFailure {
    <#
    .SYNOPSIS
        Records a non-success acquisition outcome for a collection unit.

    .PARAMETER ErrorRecord
        The caught ErrorRecord. Classified conservatively unless -Outcome
        is supplied.

    .PARAMETER Outcome
        Explicit outcome, for non-exception cases such as a capability
        that is legitimately absent. Overrides classification.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$UnitId,

        [AllowNull()]
        $ErrorRecord = $null,

        [string]$Provider,

        [ValidateSet("failed", "restricted", "unavailable")]
        [string]$Outcome,

        [string]$Category,

        [string]$Message
    )

    $store = Get-VKAcquisitionUnitStore

    if (-not $store.Contains($UnitId)) {
        # Fail closed: record the unit rather than losing the signal.
        Start-VKAcquisition -UnitId $UnitId -DataPaths @() -Provider $Provider
    }

    $unit = $store[$UnitId]

    $classification = Get-VKAcquisitionClassification -ErrorRecord $ErrorRecord

    $resolvedOutcome  = if ($Outcome)  { $Outcome }  else { $classification["outcome"] }
    $resolvedCategory = if ($Category) { $Category } else { $classification["category"] }

    $resolvedMessage = $Message
    if (-not $resolvedMessage -and $ErrorRecord) {
        if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.Exception) {
            $resolvedMessage = $ErrorRecord.Exception.Message
        }
        elseif ($ErrorRecord -is [System.Exception]) {
            $resolvedMessage = $ErrorRecord.Message
        }
    }

    $unit["state"]          = $script:VKAcquisitionFinalState
    $unit["outcome"]        = $resolvedOutcome
    $unit["end"]            = Get-VKAcquisitionTimestamp
    $unit["category"]       = $resolvedCategory
    $unit["message"]        = ConvertTo-VKBoundedMessage -Message $resolvedMessage
    $unit["exception_type"] = $classification["exception_type"]

    if ($Provider) { $unit["provider"] = $Provider }
}


function Set-VKAcquisitionUnavailable {
    <#
    .SYNOPSIS
        Records that a required provider, feature or capability was not
        available on the host. Convenience wrapper over
        Set-VKAcquisitionFailure.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$UnitId,

        [string]$Category = "capability_not_supported",

        [string]$Provider,

        [string]$Message
    )

    Set-VKAcquisitionFailure -UnitId $UnitId -Outcome "unavailable" `
        -Category $Category -Provider $Provider -Message $Message
}


function Complete-VKAcquisitionReport {
    <#
    .SYNOPSIS
        Resolves any unit left pending, immediately before serialisation.

    .DESCRIPTION
        This is the fail-closed backstop. A unit that was registered but
        never explicitly completed or failed - because the module threw
        past its own handler, returned early, or was simply never wired up
        - becomes 'failed' with category 'incomplete_collection'.

        It never becomes 'success'.
    #>
    $store = Get-VKAcquisitionUnitStore

    foreach ($unitId in @($store.Keys)) {
        $unit = $store[$unitId]

        if ($unit["state"] -ne $script:VKAcquisitionFinalState -or
            ($script:VKAcquisitionOutcomes -notcontains $unit["outcome"])) {

            $unit["state"]    = $script:VKAcquisitionFinalState
            $unit["outcome"]  = "failed"
            $unit["category"] = "incomplete_collection"
            if (-not $unit["message"]) {
                $unit["message"] = "Collection unit was registered but never resolved to a final outcome."
            }
        }

        if (-not $unit["end"])   { $unit["end"]   = Get-VKAcquisitionTimestamp }
        if (-not $unit["start"]) { $unit["start"] = $unit["end"] }
    }
}


function Get-VKAcquisitionReport {
    <#
    .SYNOPSIS
        Projects the acquisition store into the schema 1.1 section.

    .DESCRIPTION
        Emits only the contract fields, in contract order. Module payload
        data is never duplicated here - each entry points at the payload
        through data_paths.

        Defends the vocabulary a second time: any outcome outside the
        permitted four is emitted as failed/incomplete_collection, so an
        internal state can never leak into evidence.

    .OUTPUTS
        Ordered dictionary keyed by collection-unit identifier.
    #>
    $store  = Get-VKAcquisitionUnitStore
    $report = [ordered]@{}

    foreach ($unitId in @($store.Keys)) {
        $unit = $store[$unitId]

        $outcome  = $unit["outcome"]
        $category = $unit["category"]
        $message  = $unit["message"]

        if ($script:VKAcquisitionOutcomes -notcontains $outcome) {
            $outcome  = "failed"
            $category = "incomplete_collection"
            if (-not $message) {
                $message = "Collection unit did not resolve to a permitted acquisition outcome."
            }
        }

        $entry = [ordered]@{
            "observation_start"   = $unit["start"]
            "observation_end"     = $unit["end"]
            "acquisition_outcome" = $outcome
            "agent_version"       = $script:VKAgentVersion
            "schema_version"      = $script:VKSchemaVersion
            "data_paths"          = @($unit["data_paths"])
            "error"               = $null
        }

        if ($outcome -ne "success") {
            $entry["error"] = [ordered]@{
                "category"       = $category
                "provider"       = $unit["provider"]
                "message"        = $message
                "exception_type" = $unit["exception_type"]
            }
        }

        $report[$unitId] = $entry
    }

    return $report
}


function Get-ProductStateDescription {
    <#
    .SYNOPSIS
        Decodes the productState bitmask from the AntiVirusProduct WMI class.

    .DESCRIPTION
        This is DATA ENRICHMENT, not compliance evaluation.

        The raw productState integer is meaningless without decoding. This
        function translates it into human-readable operational state and
        signature status so the backend receives usable data.

        Bitmask layout:
        - Bits 12-15: Operational state (Off, On, Snoozed, Expired)
        - Bits 4-7:   Signature status (Up to Date, Out of Date)

    .PARAMETER ProductState
        The productState integer from AntiVirusProduct.

    .OUTPUTS
        Ordered hashtable with ProductState, HexadecimalState,
        OperationalState, and SignatureStatus.
    #>
    param(
        [Parameter(Mandatory)]
        [int]$ProductState
    )

    $hexProductState = '{0:X}' -f $ProductState

    $operationalState = ($ProductState -band 0xF000) -shr 12
    $operationalDescription = switch ($operationalState) {
        0 { "Off (Protection Disabled)" }
        1 { "On (Protection Enabled)" }
        2 { "Snoozed (Temporarily Inactive)" }
        3 { "Expired (Subscription Expired)" }
        default { "Unknown Operational State" }
    }

    $signatureState = ($ProductState -band 0xF0) -shr 4
    $signatureDescription = switch ($signatureState) {
        0 { "Up to Date" }
        1 { "Out of Date" }
        default { "Unknown Signature Status" }
    }

    return [ordered]@{
        "ProductState"     = $ProductState
        "HexadecimalState" = "0x$hexProductState"
        "OperationalState" = $operationalDescription
        "SignatureStatus"  = $signatureDescription
    }
}


function Resolve-LookupValue {
    <#
    .SYNOPSIS
        Resolves a raw value against a lookup hashtable, with a fallback.

    .DESCRIPTION
        Generic helper for translating Windows enum codes, IDs, and other
        numeric or string values into human-readable strings using the
        lookup tables defined in VK.Config.ps1.

    .PARAMETER Value
        The raw value to look up.

    .PARAMETER LookupTable
        The hashtable to resolve against.

    .PARAMETER Default
        Fallback value if the lookup fails. Defaults to "Unknown".

    .OUTPUTS
        The resolved string, or the default value.

    .EXAMPLE
        Resolve-LookupValue -Value 1 -LookupTable $script:VKPlatformRoles
        # Returns "Desktop"

    .EXAMPLE
        Resolve-LookupValue -Value 99 -LookupTable $script:VKPlatformRoles -Default "Unrecognised"
        # Returns "Unrecognised"
    #>
    param(
        [Parameter(Mandatory)]
        $Value,

        [Parameter(Mandatory)]
        [hashtable]$LookupTable,

        [string]$Default = "Unknown"
    )

    if ($LookupTable.ContainsKey($Value)) {
        return $LookupTable[$Value]
    }

    # CIM often returns UInt16/UInt32 which won't match Int32 hashtable keys.
    # Try an explicit int cast as a fallback before giving up.
    try {
        $intValue = [int]$Value
        if ($LookupTable.ContainsKey($intValue)) {
            return $LookupTable[$intValue]
        }
    }
    catch {
        # Value isn't numeric, that's fine - fall through to default
    }

    return $Default
}


# ============================================================
#  CONSOLE OUTPUT HELPERS
# ============================================================

function Write-VKBanner {
    <#
    .SYNOPSIS
        Displays the Voight-Kampff ASCII banner.
        Uses only 7-bit ASCII characters for maximum terminal compatibility.
    #>
    Write-Host @"

    +==================================================+
    |          V O I G H T - K A M P F F               |
    |          Endpoint Assessment Agent               |
    |                  Version $($script:VKAgentVersion)                     |
    +==================================================+

"@ -ForegroundColor Cyan
}


function Write-SectionHeader {
    <#
    .SYNOPSIS
        Displays a formatted section header in the console.

    .PARAMETER Title
        The section title to display.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    $border = "-" * ($Title.Length + 4)
    Write-Host "`n$border" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$border`n" -ForegroundColor Cyan
}


function Write-VKStatus {
    <#
    .SYNOPSIS
        Displays a formatted status message during scan execution.

    .PARAMETER Message
        The status message to display.

    .PARAMETER Type
        The message type: PROCESSING, SUCCESS, WARNING, ERROR, or BYPASS.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("PROCESSING", "SUCCESS", "WARNING", "ERROR", "BYPASS")]
        [string]$Type = "PROCESSING"
    )

    switch ($Type) {
        "PROCESSING" { Write-Host "[PROCESSING] $Message`n" -ForegroundColor Yellow }
        "SUCCESS"    { Write-Host "[SUCCESS] $Message`n" -ForegroundColor Green }
        "WARNING"    { Write-Host "[** WARNING **] $Message`n" -ForegroundColor Yellow }
        "ERROR"      { Write-Host "[!! ERROR !!] $Message`n" -ForegroundColor Red }
        "BYPASS"     { Write-Host "[** BYPASS **] $Message`n" -ForegroundColor Red }
    }
}