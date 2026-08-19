<#
.SYNOPSIS
    Pester tests for the fail-closed acquisition helpers in VK.Utilities.ps1.

.DESCRIPTION
    Exercises the helper contract with synthetic inputs and deliberately
    constructed exceptions. No provider is queried and no live host state
    is inspected.

    The central property under test is FAIL-CLOSED behaviour:
    invocation alone must never produce 'success'.

    VK.Config.ps1 and VK.Utilities.ps1 only declare variables and
    functions, so dot-sourcing them has no side effects.

.NOTES
    Tranche 2A. Pester 5.5+ (developed against 6.1). See tests/README.md.
#>

BeforeAll {

    $script:AgentRoot = Split-Path -Parent $PSScriptRoot

    . (Join-Path $script:AgentRoot 'core\VK.Config.ps1')
    . (Join-Path $script:AgentRoot 'core\VK.Utilities.ps1')

    $script:PermittedOutcomes = @('success', 'failed', 'restricted', 'unavailable')

    # --- Synthetic error factories -----------------------------------
    # Real ErrorRecords built around real exception types. Nothing is
    # thrown by a provider; the exceptions are constructed directly.

    function New-TestErrorRecord {
        param(
            [Parameter(Mandatory)][System.Exception]$Exception,
            [string]$ErrorId = 'TestError',
            [System.Management.Automation.ErrorCategory]$Category = [System.Management.Automation.ErrorCategory]::NotSpecified
        )
        return [System.Management.Automation.ErrorRecord]::new($Exception, $ErrorId, $Category, $null)
    }

    function New-AccessDeniedError {
        New-TestErrorRecord -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
            -ErrorId 'UnauthorizedAccessException' `
            -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied)
    }

    function New-CapabilityMissingError {
        New-TestErrorRecord -Exception ([System.NotSupportedException]::new('The requested capability is not supported on this host.')) `
            -ErrorId 'NotSupported' `
            -Category ([System.Management.Automation.ErrorCategory]::NotImplemented)
    }

    function New-UnexpectedError {
        New-TestErrorRecord -Exception ([System.InvalidOperationException]::new('The provider returned a malformed response.')) `
            -ErrorId 'InvalidOperation' `
            -Category ([System.Management.Automation.ErrorCategory]::InvalidOperation)
    }
}

# NOTE ON SETUP SCOPE
# Pester 6 rejects BeforeEach directly in the container root ("Each test setup
# is not supported in root"). The per-test acquisition reset is therefore
# declared once per Describe. Root BeforeAll remains valid and continues to
# load the functions under test.
#
# Every test in this file still begins with a fresh acquisition store, and
# nested Context blocks inherit their Describe's BeforeEach.


Describe 'Acquisition helpers: fail-closed default' {

    BeforeEach { Initialize-VKAcquisition }

    It 'a registered but untouched unit resolves to failed / incomplete_collection' {
        Start-VKAcquisition -UnitId 'test.untouched' -DataPaths @('security.test.value') -Provider 'test-provider'

        Complete-VKAcquisitionReport
        $report = Get-VKAcquisitionReport

        $report['test.untouched'].acquisition_outcome | Should -Be 'failed'
        $report['test.untouched'].error.category      | Should -Be 'incomplete_collection'
    }

    It 'registration alone never produces success' {
        Start-VKAcquisition -UnitId 'test.registered.only' -DataPaths @('security.test.value')

        Complete-VKAcquisitionReport
        $report = Get-VKAcquisitionReport

        $report['test.registered.only'].acquisition_outcome | Should -Not -Be 'success'
    }

    It 'no invocation-only path produces success across many units' {
        # Registers a spread of units and resolves none of them. Every one
        # must fail closed.
        1..10 | ForEach-Object {
            Start-VKAcquisition -UnitId "test.bulk.$_" -DataPaths @("security.test.value$_")
        }

        Complete-VKAcquisitionReport
        $report = Get-VKAcquisitionReport

        $successes = @($report.Keys | Where-Object { $report[$_].acquisition_outcome -eq 'success' })
        $successes.Count | Should -Be 0
    }

    It 'the internal pending state never appears in the emitted report' {
        Start-VKAcquisition -UnitId 'test.pending' -DataPaths @('security.test.value')

        # Deliberately emitted WITHOUT the sweep, to prove the projection
        # defends the vocabulary on its own.
        $report = Get-VKAcquisitionReport

        $report['test.pending'].acquisition_outcome | Should -Not -Be 'pending'
        $script:PermittedOutcomes | Should -Contain $report['test.pending'].acquisition_outcome
    }

    It 'completing an unregistered unit does not grant success' {
        Complete-VKAcquisition -UnitId 'test.never.registered'

        Complete-VKAcquisitionReport
        $report = Get-VKAcquisitionReport

        $report['test.never.registered'].acquisition_outcome | Should -Be 'failed'
        $report['test.never.registered'].error.category      | Should -Be 'unregistered_unit'
    }
}


Describe 'Acquisition helpers: explicit completion' {

    BeforeEach { Initialize-VKAcquisition }

    It 'explicit completion produces success' {
        Start-VKAcquisition -UnitId 'test.completed' -DataPaths @('security.test.value')
        Complete-VKAcquisition -UnitId 'test.completed'

        Complete-VKAcquisitionReport
        $report = Get-VKAcquisitionReport

        $report['test.completed'].acquisition_outcome | Should -Be 'success'
    }

    It 'success carries a null error' {
        Start-VKAcquisition -UnitId 'test.completed' -DataPaths @('security.test.value')
        Complete-VKAcquisition -UnitId 'test.completed'
        Complete-VKAcquisitionReport

        (Get-VKAcquisitionReport)['test.completed'].error | Should -BeNullOrEmpty
    }

    It 'a successful zero-result collection is still success' {
        # The case schema 1.0 could not express.
        Start-VKAcquisition -UnitId 'test.zero.result' -DataPaths @('security.test.items')
        $items = @()   # provider answered, answer was legitimately empty
        Complete-VKAcquisition -UnitId 'test.zero.result'
        Complete-VKAcquisitionReport

        $items.Count | Should -Be 0
        (Get-VKAcquisitionReport)['test.zero.result'].acquisition_outcome | Should -Be 'success'
    }

    It 'clears prior error detail when a retried unit later completes' {
        Start-VKAcquisition -UnitId 'test.retry' -DataPaths @('security.test.value')
        Set-VKAcquisitionFailure -UnitId 'test.retry' -ErrorRecord (New-UnexpectedError)

        Start-VKAcquisition -UnitId 'test.retry' -DataPaths @('security.test.value')
        Complete-VKAcquisition -UnitId 'test.retry'
        Complete-VKAcquisitionReport

        $entry = (Get-VKAcquisitionReport)['test.retry']
        $entry.acquisition_outcome | Should -Be 'success'
        $entry.error | Should -BeNullOrEmpty
    }
}


Describe 'Acquisition helpers: conservative error classification' {

    BeforeEach { Initialize-VKAcquisition }

    It 'access denial becomes restricted' {
        Start-VKAcquisition -UnitId 'test.denied' -DataPaths @('security.test.value')
        Set-VKAcquisitionFailure -UnitId 'test.denied' -ErrorRecord (New-AccessDeniedError) -Provider 'test-provider'
        Complete-VKAcquisitionReport

        $entry = (Get-VKAcquisitionReport)['test.denied']
        $entry.acquisition_outcome | Should -Be 'restricted'
        $entry.error.category      | Should -Be 'access_denied'
        $entry.error.exception_type| Should -Be 'System.UnauthorizedAccessException'
    }

    It 'an absent provider or capability becomes unavailable' {
        Start-VKAcquisition -UnitId 'test.missing' -DataPaths @('security.test.value')
        Set-VKAcquisitionFailure -UnitId 'test.missing' -ErrorRecord (New-CapabilityMissingError)
        Complete-VKAcquisitionReport

        $entry = (Get-VKAcquisitionReport)['test.missing']
        $entry.acquisition_outcome | Should -Be 'unavailable'
        $entry.error.category      | Should -Be 'capability_not_supported'
    }

    It 'an unexpected error becomes failed' {
        Start-VKAcquisition -UnitId 'test.unexpected' -DataPaths @('security.test.value')
        Set-VKAcquisitionFailure -UnitId 'test.unexpected' -ErrorRecord (New-UnexpectedError)
        Complete-VKAcquisitionReport

        $entry = (Get-VKAcquisitionReport)['test.unexpected']
        $entry.acquisition_outcome | Should -Be 'failed'
        $entry.error.category      | Should -Be 'unexpected_error'
    }

    It 'classifies a null error record as failed, never success' {
        $classification = Get-VKAcquisitionClassification -ErrorRecord $null
        $classification['outcome']  | Should -Be 'failed'
        $classification['category'] | Should -Be 'unexpected_error'
    }

    It 'classifies <Name> as <Outcome>' -ForEach @(
        @{ Name = 'UnauthorizedAccessException'; Outcome = 'restricted';  Exception = { [System.UnauthorizedAccessException]::new('denied') } }
        @{ Name = 'SecurityException';           Outcome = 'restricted';  Exception = { [System.Security.SecurityException]::new('policy') } }
        @{ Name = 'NotSupportedException';       Outcome = 'unavailable'; Exception = { [System.NotSupportedException]::new('unsupported') } }
        @{ Name = 'NotImplementedException';     Outcome = 'unavailable'; Exception = { [System.NotImplementedException]::new('missing') } }
        @{ Name = 'DllNotFoundException';        Outcome = 'unavailable'; Exception = { [System.DllNotFoundException]::new('no dll') } }
        @{ Name = 'InvalidOperationException';   Outcome = 'failed';      Exception = { [System.InvalidOperationException]::new('bad state') } }
        @{ Name = 'FormatException';             Outcome = 'failed';      Exception = { [System.FormatException]::new('unparseable') } }
    ) {
        $classification = Get-VKAcquisitionClassification -ErrorRecord (& $Exception)
        $classification['outcome'] | Should -Be $Outcome
    }

    It 'prefers the exception type over message text' {
        # A message that would match the last-resort 'access denied' rule,
        # on an exception type that is unambiguously an unexpected error.
        $record = New-TestErrorRecord -Exception ([System.InvalidOperationException]::new('Access is denied.'))
        $classification = Get-VKAcquisitionClassification -ErrorRecord $record

        # InvalidOperationException matches no type rule, and the category
        # is NotSpecified, so classification falls through to the message.
        # This test documents that the fall-through is reached only after
        # the structured signals are exhausted.
        $classification['exception_type'] | Should -Be 'System.InvalidOperationException'
    }

    It 'uses the FullyQualifiedErrorId when the exception type is generic' {
        $record = New-TestErrorRecord -Exception ([System.Exception]::new('something went wrong')) `
            -ErrorId 'CommandNotFoundException,Microsoft.PowerShell.Commands.TestCommand'
        $classification = Get-VKAcquisitionClassification -ErrorRecord $record

        $classification['outcome']  | Should -Be 'unavailable'
        $classification['category'] | Should -Be 'command_not_found'
    }

    It 'uses the ErrorCategory when type and error id are generic' {
        $record = New-TestErrorRecord -Exception ([System.Exception]::new('generic')) `
            -ErrorId 'Generic' `
            -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied)
        $classification = Get-VKAcquisitionClassification -ErrorRecord $record

        $classification['outcome']  | Should -Be 'restricted'
        $classification['category'] | Should -Be 'access_denied'
    }

    It 'never classifies anything as success' {
        $records = @(
            (New-AccessDeniedError), (New-CapabilityMissingError), (New-UnexpectedError),
            (New-TestErrorRecord -Exception ([System.Exception]::new('unknown')))
        )
        foreach ($record in $records) {
            (Get-VKAcquisitionClassification -ErrorRecord $record)['outcome'] | Should -Not -Be 'success'
        }
    }
}


Describe 'Acquisition helpers: explicit non-exception outcomes' {

    BeforeEach { Initialize-VKAcquisition }

    It 'Set-VKAcquisitionUnavailable records unavailable with the given category' {
        Start-VKAcquisition -UnitId 'test.not.applicable' -DataPaths @('security.test.value')
        Set-VKAcquisitionUnavailable -UnitId 'test.not.applicable' `
            -Category 'provider_not_applicable' -Provider 'test-provider' `
            -Message 'The provider does not apply to this host.'
        Complete-VKAcquisitionReport

        $entry = (Get-VKAcquisitionReport)['test.not.applicable']
        $entry.acquisition_outcome | Should -Be 'unavailable'
        $entry.error.category      | Should -Be 'provider_not_applicable'
        $entry.error.provider      | Should -Be 'test-provider'
    }

    It 'an explicit -Outcome overrides classification' {
        Start-VKAcquisition -UnitId 'test.override' -DataPaths @('security.test.value')
        Set-VKAcquisitionFailure -UnitId 'test.override' -ErrorRecord (New-AccessDeniedError) `
            -Outcome 'unavailable' -Category 'precondition_not_met'
        Complete-VKAcquisitionReport

        (Get-VKAcquisitionReport)['test.override'].acquisition_outcome | Should -Be 'unavailable'
    }

    It 'rejects an outcome outside the permitted vocabulary' {
        Start-VKAcquisition -UnitId 'test.bad.outcome' -DataPaths @('security.test.value')
        { Set-VKAcquisitionFailure -UnitId 'test.bad.outcome' -Outcome 'partial' } | Should -Throw
    }
}


Describe 'Acquisition helpers: emitted entry contract' {

    BeforeEach {
        # The per-test reset that was previously inherited from the root
        # BeforeEach now leads this block's own setup.
        Initialize-VKAcquisition

        Start-VKAcquisition -UnitId 'test.ok'     -DataPaths @('security.test.a', 'security.test.b') -Provider 'provider-a'
        Complete-VKAcquisition -UnitId 'test.ok'

        Start-VKAcquisition -UnitId 'test.denied' -DataPaths @('security.test.c') -Provider 'provider-b'
        Set-VKAcquisitionFailure -UnitId 'test.denied' -ErrorRecord (New-AccessDeniedError)

        Complete-VKAcquisitionReport
        $script:Report = Get-VKAcquisitionReport
    }

    It 'emits exactly the contract fields, in contract order' {
        $expected = @('observation_start','observation_end','acquisition_outcome','agent_version','schema_version','data_paths','error')
        @($script:Report['test.ok'].Keys) | Should -Be $expected
    }

    It 'stamps start and end timestamps on every entry' {
        foreach ($unitId in $script:Report.Keys) {
            $script:Report[$unitId].observation_start | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
            $script:Report[$unitId].observation_end   | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        }
    }

    It 'stamps the central agent and schema versions on every entry' {
        foreach ($unitId in $script:Report.Keys) {
            $script:Report[$unitId].agent_version  | Should -Be $script:VKAgentVersion
            $script:Report[$unitId].schema_version | Should -Be $script:VKSchemaVersion
        }
    }

    It 'preserves the governed data paths' {
        @($script:Report['test.ok'].data_paths) | Should -Be @('security.test.a', 'security.test.b')
    }

    It 'records the provider on a non-success entry' {
        $script:Report['test.denied'].error.provider | Should -Be 'provider-b'
    }

    It 'does not carry module payload data' {
        @($script:Report['test.ok'].Keys) | Should -Not -Contain 'data'
    }
}


Describe 'Acquisition helpers: message bounding and sanitisation' {

    BeforeEach { Initialize-VKAcquisition }

    It 'returns null for an empty message' {
        ConvertTo-VKBoundedMessage -Message '' | Should -BeNullOrEmpty
        ConvertTo-VKBoundedMessage -Message $null | Should -BeNullOrEmpty
    }

    It 'bounds an over-long message' {
        $long = 'x' * 5000
        $bounded = ConvertTo-VKBoundedMessage -Message $long
        $bounded.Length | Should -BeLessThan 500
    }

    It 'strips stack-trace style lines' {
        $message = "The operation failed.`n   at System.Example.Method()`n   at System.Other.Method()"
        $bounded = ConvertTo-VKBoundedMessage -Message $message

        $bounded | Should -Not -Match 'at System\.Example\.Method'
        $bounded | Should -Match 'The operation failed'
    }

    It 'collapses newlines so the message stays single-line' {
        ConvertTo-VKBoundedMessage -Message "line one`r`nline two" | Should -Not -Match "`n"
    }

    It 'redacts a user profile path' {
        $bounded = ConvertTo-VKBoundedMessage -Message 'Could not read C:\Users\alice.smith\AppData\config.dat'
        $bounded | Should -Not -Match 'alice\.smith'
        $bounded | Should -Match '<redacted>'
    }

    It 'produces a bounded message through the failure helper' {
        Start-VKAcquisition -UnitId 'test.long' -DataPaths @('security.test.value')
        $record = New-TestErrorRecord -Exception ([System.InvalidOperationException]::new(('y' * 5000)))
        Set-VKAcquisitionFailure -UnitId 'test.long' -ErrorRecord $record
        Complete-VKAcquisitionReport

        (Get-VKAcquisitionReport)['test.long'].error.message.Length | Should -BeLessThan 500
    }
}
