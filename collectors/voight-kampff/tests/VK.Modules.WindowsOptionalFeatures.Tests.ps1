<#
.SYNOPSIS
    Focused tests for Host.WindowsOptionalFeatures acquisition semantics.

.DESCRIPTION
    The DISM provider is mocked throughout. Nothing here opens a servicing
    session, queries live optional-feature state, or reads host
    configuration of any kind. Results are identical on any machine.

    Get-WindowsOptionalFeature is not guaranteed to be present on the
    machine running the suite, so a stub is declared in BeforeAll and
    mocked. Pester cannot mock a command that does not exist, and a suite
    that silently skipped on an unserviceable host would prove nothing.

    Proves the raw-evidence contract:
      - the COMPLETE inventory is retained, never an allowlist;
      - FeatureName is preserved exactly as supplied;
      - State is preserved as the provider's own string, never reduced to
        a Boolean and never remapped;
      - ordering is deterministic and ordinal;
      - malformed provider output is rejected rather than partially
        emitted;
      - a zero-record response is NOT a successful empty inventory;
      - a non-elevated run records restricted / insufficient_privilege
        without invoking DISM at all.

.NOTES
    Agent 2.3.0, schema 1.2. Pester 5.5+ (developed against 6.1).
#>

BeforeAll {
    $script:AgentRoot = Split-Path -Parent $PSScriptRoot

    . (Join-Path $script:AgentRoot 'core\VK.Config.ps1')
    . (Join-Path $script:AgentRoot 'core\VK.Utilities.ps1')
    . (Join-Path $script:AgentRoot 'modules\host\Host.WindowsOptionalFeatures.ps1')

    $script:FeatureUnitId  = 'host.windows_optional_features.inventory'
    $script:FeatureProvider = 'Get-WindowsOptionalFeature -Online'

    # Stub so the provider is mockable on any host. It throws if it is ever
    # reached unmocked, so an escaping call fails loudly rather than
    # reaching a real servicing session.
    function Get-WindowsOptionalFeature {
        [CmdletBinding()]
        param([switch]$Online)
        throw 'Get-WindowsOptionalFeature stub was invoked without a mock.'
    }

    function New-TestFeature {
        param($FeatureName, $State)

        # Built through Add-Member so a deliberately ABSENT property is
        # distinguishable from a property present with a null value.
        $feature = [pscustomobject]@{}
        if ($PSBoundParameters.ContainsKey('FeatureName')) {
            $feature | Add-Member -MemberType NoteProperty -Name 'FeatureName' -Value $FeatureName
        }
        if ($PSBoundParameters.ContainsKey('State')) {
            $feature | Add-Member -MemberType NoteProperty -Name 'State' -Value $State
        }
        return $feature
    }

    function Invoke-TestFeatureCollection {
        param([bool]$IsAdmin = $true)

        $script:Section = [ordered]@{}

        Invoke-VKHostWindowsOptionalFeatures -Data $script:Section -IsAdmin $IsAdmin
        Complete-VKAcquisitionReport

        $script:Features    = $script:Section['windows_optional_features']
        $script:FeatureEntry = (Get-VKAcquisitionReport)[$script:FeatureUnitId]
    }
}


Describe 'Host.WindowsOptionalFeatures raw-evidence contract' {

    BeforeEach {
        Initialize-VKAcquisition

        Mock Write-VKStatus { }
        Mock Write-LogMessage { }

        $script:ProviderResult = @()
        $script:ProviderError  = $null

        Mock Get-WindowsOptionalFeature {
            if ($script:ProviderError) { throw $script:ProviderError }
            return $script:ProviderResult
        }
    }

    Context 'when the provider returns a mixed Enabled / Disabled inventory' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'IIS-WebServerRole'   -State 'Disabled'
                New-TestFeature -FeatureName 'NetFx4-AdvSrvs'      -State 'Enabled'
                New-TestFeature -FeatureName 'TelnetClient'        -State 'Disabled'
                New-TestFeature -FeatureName 'Windows-Defender-ApplicationGuard' -State 'Enabled'
            )

            Invoke-TestFeatureCollection
        }

        It 'retains every returned feature' {
            @($script:Features).Count | Should -Be 4
        }

        It 'preserves both states unreduced' {
            $iis = @($script:Features | Where-Object { $_['feature_name'] -eq 'IIS-WebServerRole' })
            $net = @($script:Features | Where-Object { $_['feature_name'] -eq 'NetFx4-AdvSrvs' })

            $iis[0]['state'] | Should -Be 'Disabled'
            $net[0]['state'] | Should -Be 'Enabled'
        }

        It 'never reduces state to a Boolean' {
            foreach ($feature in $script:Features) {
                $feature['state'] | Should -BeOfType [string]
                $feature['state'] | Should -Not -BeOfType [bool]
            }
        }

        It 'emits exactly feature_name and state on every record' {
            foreach ($feature in $script:Features) {
                @($feature.Keys) | Should -Be @('feature_name', 'state')
            }
        }

        It 'records the acquisition as success with no error' {
            $script:FeatureEntry.acquisition_outcome | Should -Be 'success'
            $script:FeatureEntry.error | Should -BeNullOrEmpty
        }

        It 'governs exactly the optional-feature payload path' {
            @($script:FeatureEntry.data_paths) | Should -Be @('host.windows_optional_features')
        }

        It 'issues exactly one complete query' {
            Should -Invoke Get-WindowsOptionalFeature -Times 1 -Exactly
        }
    }

    Context 'when the provider reports payload and pending states' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'Containers-DisposableClientVM' -State 'DisabledWithPayloadRemoved'
                New-TestFeature -FeatureName 'MicrosoftWindowsPowerShellV2'  -State 'EnablePending'
                New-TestFeature -FeatureName 'SMB1Protocol'                  -State 'DisablePending'
            )

            Invoke-TestFeatureCollection
        }

        It 'preserves DisabledWithPayloadRemoved exactly' {
            $record = @($script:Features | Where-Object { $_['feature_name'] -eq 'Containers-DisposableClientVM' })
            $record[0]['state'] | Should -BeExactly 'DisabledWithPayloadRemoved'
        }

        It 'preserves <_> exactly' -ForEach @('EnablePending', 'DisablePending') {
            @($script:Features | ForEach-Object { $_['state'] }) | Should -Contain $_
        }

        It 'does not collapse a payload or pending state into Disabled or Enabled' {
            $states = @($script:Features | ForEach-Object { $_['state'] })
            $states | Should -Not -Contain 'Disabled'
            $states | Should -Not -Contain 'Enabled'
            @($states | Sort-Object -Unique).Count | Should -Be 3
        }

        It 'still reports success' {
            $script:FeatureEntry.acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'when the provider returns a non-string state object' {

        BeforeEach {
            # The live provider returns a Microsoft.Dism.Commands.FeatureState
            # enum, not a string. Its own representation must be retained.
            $enumLike = [pscustomobject]@{}
            $enumLike | Add-Member -MemberType ScriptMethod -Name ToString `
                -Value { 'DisabledWithPayloadRemoved' } -Force

            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'Containers-DisposableClientVM' -State $enumLike
            )

            Invoke-TestFeatureCollection
        }

        It "keeps the provider's own representation as a string" {
            @($script:Features).Count | Should -Be 1
            $script:Features[0]['state'] | Should -BeExactly 'DisabledWithPayloadRemoved'
            $script:FeatureEntry.acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'when the inventory contains features of no research interest' {

        BeforeEach {
            # An allowlist would drop most of these. The collector emits
            # facts; selecting study-relevant identifiers is downstream work.
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'Printing-Foundation-Features' -State 'Enabled'
                New-TestFeature -FeatureName 'WorkFolders-Client'           -State 'Enabled'
                New-TestFeature -FeatureName 'MediaPlayback'                -State 'Enabled'
                New-TestFeature -FeatureName 'SearchEngine-Client-Package'  -State 'Enabled'
                New-TestFeature -FeatureName 'SMB1Protocol'                 -State 'Disabled'
                New-TestFeature -FeatureName 'TelnetClient'                 -State 'Disabled'
                New-TestFeature -FeatureName 'Xps-Foundation-Xps-Viewer'    -State 'Disabled'
            )

            Invoke-TestFeatureCollection
        }

        It 'retains the complete inventory rather than a filtered subset' {
            @($script:Features).Count | Should -Be 7

            $emitted = @($script:Features | ForEach-Object { $_['feature_name'] })
            foreach ($expected in @(
                'MediaPlayback', 'Printing-Foundation-Features',
                'SMB1Protocol', 'SearchEngine-Client-Package',
                'TelnetClient', 'WorkFolders-Client',
                'Xps-Foundation-Xps-Viewer'
            )) {
                $emitted | Should -Contain $expected
            }
        }

        It 'attaches no risk, category or compliance interpretation' {
            foreach ($feature in $script:Features) {
                foreach ($forbidden in @('category', 'risk', 'severity', 'applicable', 'compliant', 'display_name')) {
                    @($feature.Keys) | Should -Not -Contain $forbidden
                }
            }
        }
    }

    Context 'when the provider returns records out of order' {

        BeforeEach {
            # Deliberately includes names whose ordinal and culture-aware
            # orderings differ: ordinal puts every upper-case letter and the
            # '-' separator before lower-case letters.
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'telnetclient'    -State 'Disabled'
                New-TestFeature -FeatureName 'IIS-WebServer'   -State 'Disabled'
                New-TestFeature -FeatureName 'IISWebServer'    -State 'Disabled'
                New-TestFeature -FeatureName 'Windows-Defender' -State 'Enabled'
                New-TestFeature -FeatureName 'NetFx3'          -State 'Enabled'
            )

            Invoke-TestFeatureCollection
        }

        It 'orders output ordinally by feature_name' {
            $names = @($script:Features | ForEach-Object { $_['feature_name'] })

            $expected = [string[]]@(
                'IIS-WebServer', 'IISWebServer', 'NetFx3',
                'Windows-Defender', 'telnetclient'
            )

            $names | Should -Be $expected
        }

        It 'produces the same order regardless of the order the provider returned' {
            $first = @($script:Features | ForEach-Object { $_['feature_name'] })

            Initialize-VKAcquisition
            $script:ProviderResult = @($script:ProviderResult[4], $script:ProviderResult[0],
                                       $script:ProviderResult[3], $script:ProviderResult[2],
                                       $script:ProviderResult[1])
            Invoke-TestFeatureCollection

            @($script:Features | ForEach-Object { $_['feature_name'] }) | Should -Be $first
        }
    }

    Context 'when the provider returns a case-insensitive duplicate feature name' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'TelnetClient' -State 'Disabled'
                New-TestFeature -FeatureName 'telnetclient' -State 'Enabled'
            )

            Invoke-TestFeatureCollection
        }

        It 'withholds the whole inventory' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
        }

        It 'records a non-success outcome with provider_value_missing' {
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'success'
            $script:FeatureEntry.error.category | Should -Be 'provider_value_missing'
            $script:FeatureEntry.error.provider | Should -Be $script:FeatureProvider
        }

        It 'does not silently keep one of the two conflicting records' {
            $script:FeatureEntry.error.message | Should -Match 'duplicate'
        }
    }

    Context 'when a record has no feature name' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'TelnetClient' -State 'Disabled'
                New-TestFeature -State 'Enabled'
            )

            Invoke-TestFeatureCollection
        }

        It 'withholds the whole inventory rather than emitting the good record' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
        }

        It 'records a non-success outcome' {
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'success'
            $script:FeatureEntry.error.category | Should -Be 'provider_value_missing'
        }
    }

    Context 'when a record has an empty feature name' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName '   ' -State 'Enabled'
            )

            Invoke-TestFeatureCollection
        }

        It 'rejects it as malformed provider output' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'success'
        }
    }

    Context 'when a record has no state' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'TelnetClient' -State 'Disabled'
                New-TestFeature -FeatureName 'SMB1Protocol' -State $null
            )

            Invoke-TestFeatureCollection
        }

        It 'withholds the whole inventory' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
        }

        It 'never substitutes a default or Boolean state' {
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'success'
            $script:FeatureEntry.error.category | Should -Be 'provider_value_missing'
            $script:FeatureEntry.error.message  | Should -Match 'State'
        }
    }

    Context 'when a record has an empty state' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'TelnetClient' -State ''
            )

            Invoke-TestFeatureCollection
        }

        It 'rejects it as malformed provider output' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'success'
        }
    }

    Context 'when the provider succeeds but returns zero records' {

        BeforeEach {
            $script:ProviderResult = @()
            Invoke-TestFeatureCollection
        }

        It 'does not treat the empty response as a genuine Windows state' {
            # Contrast with a genuinely empty collection elsewhere in the
            # agent: every serviceable Windows installation reports optional
            # features, so zero records describes a provider that did not
            # answer usefully.
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'success'
        }

        It 'retains null rather than an empty inventory' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
        }

        It 'uses category provider_value_missing' {
            $script:FeatureEntry.error.category | Should -Be 'provider_value_missing'
            $script:FeatureEntry.error.provider | Should -Be $script:FeatureProvider
        }
    }

    Context 'when the provider throws' {

        BeforeEach {
            # Distinct from the malformed-output cases: this is an exception
            # raised by the provider itself, classified by the shared helper.
            $script:ProviderError = [System.Runtime.InteropServices.COMException]::new(
                'Synthetic DISM servicing failure.', -2147024891)

            Invoke-TestFeatureCollection
        }

        It 'withholds the governed payload' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
        }

        It 'creates a machine-readable non-success outcome' {
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'success'
            $script:FeatureEntry.error | Should -Not -BeNullOrEmpty
            $script:FeatureEntry.error.category       | Should -Not -BeNullOrEmpty
            $script:FeatureEntry.error.provider       | Should -Be $script:FeatureProvider
            $script:FeatureEntry.error.exception_type | Should -Not -BeNullOrEmpty
        }

        It 'still governs the same data path on failure' {
            @($script:FeatureEntry.data_paths) | Should -Be @('host.windows_optional_features')
        }

        It 'uses the shared error classification rather than a hardcoded outcome' {
            # E_ACCESSDENIED classifies conservatively to restricted.
            $script:FeatureEntry.acquisition_outcome | Should -Be 'restricted'
            $script:FeatureEntry.error.category | Should -Be 'access_denied'
        }
    }

    Context 'when the provider throws System.InvalidOperationException' {

        # REGRESSION GUARD.
        #
        # The module raises InvalidOperationException itself to signal a
        # malformed INVENTORY, which resolves to unavailable /
        # provider_value_missing. While invocation and validation shared
        # one handler, that type test also caught the PROVIDER throwing the
        # same type, and silently reclassified a failed query as
        # usable-but-missing provider data.
        #
        # Provider invocation now has its own try/catch whose handler
        # always passes the error record to the shared classifier, so the
        # outcome no longer depends on which exception type the provider
        # happened to raise.

        BeforeEach {
            $script:ProviderError = [System.InvalidOperationException]::new(
                'Synthetic servicing-stack failure raised by the provider.')

            Invoke-TestFeatureCollection
        }

        It 'withholds the governed payload' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
        }

        It 'follows the shared failure classifier rather than the malformed-inventory path' {
            # Get-VKAcquisitionClassification has no rule for
            # InvalidOperationException, so it classifies conservatively as
            # failed / unexpected_error. The point is that the QUERY-FAILED
            # path ran at all.
            $expected = Get-VKAcquisitionClassification -ErrorRecord $script:ProviderError

            $script:FeatureEntry.acquisition_outcome | Should -Be $expected['outcome']
            $script:FeatureEntry.error.category      | Should -Be $expected['category']
        }

        It 'is not recorded as missing provider data' {
            $script:FeatureEntry.error.category      | Should -Not -Be 'provider_value_missing'
            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'unavailable'
        }

        It 'records it as a failed acquisition' {
            $script:FeatureEntry.acquisition_outcome | Should -Be 'failed'
            $script:FeatureEntry.error.category      | Should -Be 'unexpected_error'
        }

        It 'preserves the original exception type' {
            $script:FeatureEntry.error.exception_type |
                Should -Be 'System.InvalidOperationException'
            $script:FeatureEntry.error.provider | Should -Be $script:FeatureProvider
        }

        It 'is distinguishable from a malformed inventory carrying the same exception type' {
            # CONTRAST, asserted rather than assumed. The same exception
            # type raised by the module's own validation must still yield
            # unavailable / provider_value_missing.
            $queryFailure = $script:FeatureEntry

            Initialize-VKAcquisition
            $script:ProviderError  = $null
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'TelnetClient' -State 'Disabled'
                New-TestFeature -FeatureName 'telnetclient' -State 'Enabled'
            )
            Invoke-TestFeatureCollection

            $script:FeatureEntry.acquisition_outcome | Should -Be 'unavailable'
            $script:FeatureEntry.error.category      | Should -Be 'provider_value_missing'

            $queryFailure.acquisition_outcome |
                Should -Not -Be $script:FeatureEntry.acquisition_outcome
        }

        It 'issues no second provider query' {
            Should -Invoke Get-WindowsOptionalFeature -Times 1 -Exactly
        }
    }

    Context 'when the session is not elevated' {

        BeforeEach {
            $script:ProviderResult = @(
                New-TestFeature -FeatureName 'TelnetClient' -State 'Disabled'
            )

            Invoke-TestFeatureCollection -IsAdmin $false
        }

        It 'does not invoke DISM at all' {
            Should -Invoke Get-WindowsOptionalFeature -Times 0 -Exactly
        }

        It 'retains null rather than an empty inventory' {
            [object]::ReferenceEquals($null, $script:Features) | Should -BeTrue
        }

        It 'records restricted / insufficient_privilege' {
            $script:FeatureEntry.acquisition_outcome | Should -Be 'restricted'
            $script:FeatureEntry.error.category | Should -Be 'insufficient_privilege'
            $script:FeatureEntry.error.provider | Should -Be $script:FeatureProvider
        }

        It 'still governs the optional-feature data path' {
            @($script:FeatureEntry.data_paths) | Should -Be @('host.windows_optional_features')
        }
    }

    Context 'across every outcome the module can produce' {

        It 'never leaves the unit unresolved, pending or outside the vocabulary' -ForEach @(
            @{ Case = 'success';       Admin = $true;  Records = 1; Throws = $false }
            @{ Case = 'zero-record';   Admin = $true;  Records = 0; Throws = $false }
            @{ Case = 'provider-throw';Admin = $true;  Records = 1; Throws = $true  }
            @{ Case = 'not-elevated';  Admin = $false; Records = 1; Throws = $false }
        ) {
            if ($Records -gt 0) {
                $script:ProviderResult = @(
                    New-TestFeature -FeatureName 'TelnetClient' -State 'Disabled'
                )
            }
            if ($Throws) {
                $script:ProviderError = [System.InvalidOperationException]::new('Synthetic failure.')
            }

            Invoke-TestFeatureCollection -IsAdmin $Admin

            @('success', 'failed', 'restricted', 'unavailable') |
                Should -Contain $script:FeatureEntry.acquisition_outcome -Because "case '$Case' must resolve"

            $script:FeatureEntry.acquisition_outcome | Should -Not -Be 'pending'
            $script:FeatureEntry.error.category      | Should -Not -Be 'incomplete_collection'
            $script:FeatureEntry.error.category      | Should -Not -Be 'unregistered_unit'

            @($script:FeatureEntry.data_paths) | Should -Be @('host.windows_optional_features')
        }
    }
}
