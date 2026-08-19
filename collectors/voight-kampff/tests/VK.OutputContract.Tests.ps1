<#
.SYNOPSIS
    Pester tests for the Voight-Kampff schema 1.1 JSON output contract.

.DESCRIPTION
    Verifies the shape of the agent's output envelope, the acquisition
    section, and the fidelity of its JSON serialisation, using the
    synthetic fixtures in tests/fixtures/. No live host configuration is
    read and the collector is never executed.

    Covers:
    - the FIVE required top-level sections (schema 1.1)
    - central agent version, schema version and JSON depth
    - required scan_metadata fields
    - acquisition entry shape, vocabulary, timestamps and data_paths
    - schema 1.1 missing-acquisition examples are identified as INVALID
    - schema 1.0 legacy examples cannot support empty-result absence
    - the representative fixture survives serialisation at depth 10
    - truncation is detected loudly rather than passing silently

    The depth tests are deliberately BEHAVIOURAL: they serialise at
    whatever depth VK.Config.ps1 declares, on whatever PowerShell edition
    is running, and assert on the actual result.

.NOTES
    Tranche 2A. Pester 5.5+ (developed against 6.1). See tests/README.md.
#>

BeforeAll {

    $script:AgentRoot   = Split-Path -Parent $PSScriptRoot
    $script:ConfigPath  = Join-Path $script:AgentRoot 'core\VK.Config.ps1'
    $script:FixturePath = Join-Path $PSScriptRoot 'fixtures\Get-VKRepresentativeStudyEvidence.ps1'
    $script:LegacyPath  = Join-Path $PSScriptRoot 'fixtures\Get-VKLegacySchema10Evidence.ps1'
    $script:InvalidPath = Join-Path $PSScriptRoot 'fixtures\Get-VKInvalidSchema11Evidence.ps1'

    # Test-only validator. Never part of the generated collector.
    . (Join-Path $PSScriptRoot 'helpers\VK.SchemaValidation.ps1')

    # VK.Config.ps1 only declares variables and lookup tables. It performs
    # no collection and has no side effects, so dot-sourcing is safe.
    . $script:ConfigPath
    $script:ConfiguredDepth  = $script:VKJsonDepth
    $script:ConfiguredAgent  = $script:VKAgentVersion
    $script:ConfiguredSchema = $script:VKSchemaVersion

    # Invoke the fixtures rather than dot-sourcing them, so nothing leaks
    # into the test scope.
    $script:Fixture       = & $script:FixturePath
    $script:LegacyFixture = & $script:LegacyPath
    $script:InvalidCases  = & $script:InvalidPath

    $script:Json     = $script:Fixture | ConvertTo-Json -Depth $script:ConfiguredDepth
    $script:Reparsed = $script:Json | ConvertFrom-Json

    # TRUNCATION SCAN SURFACE
    #
    # error.exception_type contractually holds a .NET type name, e.g.
    # "System.Management.Automation.CommandNotFoundException". That is a
    # legitimate observed value, not evidence of truncation, and it occurs
    # in real collections whenever a cmdlet is absent.
    #
    # Its value is therefore blanked before the marker scan. Every other
    # position is scanned unchanged, so the check is scoped, not weakened -
    # a type name appearing anywhere else still fails.
    $script:ScannableJson = $script:Json -replace '"exception_type"\s*:\s*"[^"]*"', '"exception_type": ""'

    # Collection units instrumented so far. Later tranches extend this;
    # the list is intentionally exhaustive rather than a sample, so a unit
    # dropped from a module fails the required-unit assertion.
    $script:Tranche2AUnitIds = @(
        # Tranche 2A
        'security.legacy_protocols.llmnr'
        'security.legacy_protocols.mdns'
        'security.legacy_protocols.netbios'
        'security.legacy_protocols.wpad_service'
        'security.legacy_protocols.wpad_auto_detect'
        'security.legacy_protocols.tls_protocols'
        'security.host_security.kernel_dma_protection'
        'security.host_security.dep_policy'
        'security.host_security.device_guard'
        'security.antivirus.products'
        'security.antivirus.defender_status'
    )

    $script:Tranche2B1UnitIds = @(
        'security.defender_advanced.asr_rules'
        'security.defender_advanced.protection_preferences'
        'security.defender_advanced.tamper_protection'
        'security.firewall.profiles'
        'security.firewall.inbound_rules'
        'security.smb.smbv1'
        'security.smb.server_registry'
        'security.smb.client_registry'
        'security.smb.server_configuration'
        'security.rdp.terminal_server'
        'security.rdp.rdp_tcp'
        'security.rdp.allowed_users'
        'security.winrm.service'
        'security.winrm.server_registry'
        'security.winrm.client_registry'
        'security.winrm.trusted_hosts'
        'security.winrm.listeners'
        'security.uac.configuration'
        'security.fde.os_drive'
        'security.fde.additional_volumes'
    )

    $script:Tranche2B2UnitIds = @(
        'host.identification.hostname'
        'host.identification.operating_system'
        'host.identification.computer_system'
        'host.network_config.tcp_connections'
        'host.network_config.udp_listeners'
        'host.services.inventory'
        'host.processes.inventory'
        'host.software.hklm_native'
        'host.software.hklm_wow6432'
        'host.users.local_accounts'
        'host.users.group_memberships'
        'vulnerability.token_privileges.current_token'
    )

    $script:Tranche2CUnitIds = @(
        'host.sessions.current_sessions'
        'host.sessions.session_principals'
        'host.sessions.user_profiles'
    )

    $script:AllInstrumentedUnitIds = @(
        $script:Tranche2AUnitIds + $script:Tranche2B1UnitIds +
        $script:Tranche2B2UnitIds + $script:Tranche2CUnitIds
    )

    # Governed data paths per unit, asserted exactly. A renamed or dropped
    # path fails here rather than passing unnoticed.
    $script:ExpectedDataPaths = @{
        'host.identification.hostname'        = @('host.hostname')
        'host.identification.operating_system'= @('host.os.name', 'host.os.architecture', 'host.os.version', 'host.os.build')
        'host.identification.computer_system' = @('host.os.platform_role', 'host.domain_status.status', 'host.domain_status.domain_name', 'host.domain_status.workgroup_name')
        'host.network_config.tcp_connections' = @('host.network_config.tcp_connections', 'host.network_config.summary.tcp_connections')
        'host.network_config.udp_listeners'   = @('host.network_config.udp_listeners', 'host.network_config.summary.udp_listeners')
        'host.services.inventory'             = @('host.services')
        'host.processes.inventory'            = @('host.processes')
        'host.software.hklm_native'           = @('host.installed_software')
        'host.software.hklm_wow6432'          = @('host.installed_software')
        'host.users.local_accounts'           = @('host.base_sid', 'host.user_accounts')
        'host.users.group_memberships'        = @('host.group_memberships', 'host.user_accounts[].is_admin')
        'vulnerability.token_privileges.current_token' = @('vulnerability.token_privileges')
        'host.sessions.current_sessions'      = @('host.sessions.current_sessions', 'host.sessions.current_sessions_summary')
        'host.sessions.session_principals'    = @('host.sessions.session_principals', 'host.sessions.session_principals_summary')
        'host.sessions.user_profiles'         = @('host.sessions.observation_window', 'host.sessions.user_profiles', 'host.sessions.user_profiles_summary')
    }

    $script:PermittedOutcomes = @('success', 'failed', 'restricted', 'unavailable')
}


Describe 'Central configuration' {

    It 'declares agent version 2.1.0' {
        $script:ConfiguredAgent | Should -Be '2.1.0'
    }

    It 'declares schema version 1.1' {
        $script:ConfiguredSchema | Should -Be '1.1'
    }

    It 'declares JSON depth 10' {
        $script:ConfiguredDepth | Should -Be 10
    }
}


Describe 'Envelope: required top-level sections (schema 1.1)' {

    It 'declares exactly the five required top-level sections, in order' {
        # Schema 1.1 supersedes the schema 1.0 four-section assertion.
        # This is an EXACT match, deliberately not a subset or containment
        # check: a subset test would stop detecting a missing section.
        $keys = @($script:Fixture.Keys)
        $keys | Should -Be @('scan_metadata', 'acquisition', 'host', 'security', 'vulnerability')
    }

    It 'retains the <_> section after a serialise / parse round trip' -ForEach @(
        'scan_metadata', 'acquisition', 'host', 'security', 'vulnerability'
    ) {
        $script:Reparsed.PSObject.Properties.Name | Should -Contain $_
    }

    It 'has exactly five sections after a round trip' {
        @($script:Reparsed.PSObject.Properties.Name).Count | Should -Be 5
    }
}


Describe 'Envelope: required scan-metadata fields' {

    It 'emits the <_> metadata field' -ForEach @(
        'schema_version', 'agent_version', 'hostname', 'running_user', 'running_user_sid',
        'scan_start', 'scan_end', 'scan_duration_seconds', 'ran_as_admin', 'modules_executed'
    ) {
        $script:Reparsed.scan_metadata.PSObject.Properties.Name | Should -Contain $_
    }

    It 'declares the central schema and agent versions' {
        $script:Reparsed.scan_metadata.schema_version | Should -Be $script:ConfiguredSchema
        $script:Reparsed.scan_metadata.agent_version  | Should -Be $script:ConfiguredAgent
    }

    It 'emits scan_start and scan_end as ISO 8601 UTC' {
        Test-VKIsUtcTimestamp -Value $script:Reparsed.scan_metadata.scan_start | Should -BeTrue
        Test-VKIsUtcTimestamp -Value $script:Reparsed.scan_metadata.scan_end   | Should -BeTrue
    }

    It 'does not list any module more than once in modules_executed' {
        $duplicates = @(
            $script:Reparsed.scan_metadata.modules_executed |
                Group-Object | Where-Object { $_.Count -gt 1 } |
                ForEach-Object { "$($_.Name) x$($_.Count)" }
        )
        $duplicates -join ', ' | Should -BeNullOrEmpty
    }
}


Describe 'Acquisition section (schema 1.1)' {

    It 'contains an entry for each instrumented collection unit' {
        foreach ($unitId in $script:AllInstrumentedUnitIds) {
            $script:Reparsed.acquisition.PSObject.Properties.Name |
                Should -Contain $unitId -Because "unit '$unitId' is instrumented"
        }
    }

    It 'contains no acquisition entry that is not an instrumented unit' {
        # Exact correspondence in both directions: a stray or renamed unit
        # identifier fails here rather than passing unnoticed.
        $emitted = @($script:Reparsed.acquisition.PSObject.Properties.Name)
        $unexpected = @($emitted | Where-Object { $script:AllInstrumentedUnitIds -notcontains $_ })
        $unexpected -join ', ' | Should -BeNullOrEmpty
    }

    It 'emits exactly 46 acquisition entries' {
        @($script:Reparsed.acquisition.PSObject.Properties.Name).Count | Should -Be 46
        @($script:AllInstrumentedUnitIds).Count | Should -Be 46
    }

    It 'governs the documented data paths for <_>' -ForEach @(
        'host.identification.hostname'
        'host.identification.operating_system'
        'host.identification.computer_system'
        'host.network_config.tcp_connections'
        'host.network_config.udp_listeners'
        'host.services.inventory'
        'host.processes.inventory'
        'host.software.hklm_native'
        'host.software.hklm_wow6432'
        'host.users.local_accounts'
        'host.users.group_memberships'
        'vulnerability.token_privileges.current_token'
        'host.sessions.current_sessions'
        'host.sessions.session_principals'
        'host.sessions.user_profiles'
    ) {
        $entry = $script:Reparsed.acquisition.$_
        $entry | Should -Not -BeNullOrEmpty
        @($entry.data_paths) | Should -Be $script:ExpectedDataPaths[$_]
    }

    It 'keeps session state evidence when principal resolution is restricted' {
        # The three session units must not share analytical fate.
        $script:Reparsed.acquisition.'host.sessions.session_principals'.acquisition_outcome | Should -Be 'restricted'
        $script:Reparsed.acquisition.'host.sessions.current_sessions'.acquisition_outcome   | Should -Be 'success'
        $script:Reparsed.acquisition.'host.sessions.user_profiles'.acquisition_outcome      | Should -Be 'success'

        @($script:Reparsed.host.sessions.current_sessions).Count | Should -Be 3
        $script:Reparsed.host.sessions.session_principals         | Should -BeNullOrEmpty
        $script:Reparsed.host.sessions.session_principals_summary | Should -BeNullOrEmpty
    }

    It 'marks every profile record as proxy evidence, never as a logon record' {
        # NB: not $profile - that is a PowerShell automatic variable.
        foreach ($userProfile in $script:Reparsed.host.sessions.user_profiles) {
            $userProfile.evidence_strength | Should -Be 'profile_use_proxy'
        }
    }

    It 'emits a self-describing observation window governed by the profile unit' {
        $window = $script:Reparsed.host.sessions.observation_window
        Test-VKIsUtcTimestamp -Value $window.window_start | Should -BeTrue
        Test-VKIsUtcTimestamp -Value $window.window_end   | Should -BeTrue
        $window.window_duration_hours | Should -Be 24
        $window.window_source         | Should -Be 'configured'

        $script:ExpectedDataPaths['host.sessions.user_profiles'] |
            Should -Contain 'host.sessions.observation_window'
    }

    It 'has both software hives governing the same combined path' {
        # The shared-path rule: the combined list is a single analytical
        # object, complete only when every applicable hive succeeded.
        $native = @($script:Reparsed.acquisition.'host.software.hklm_native'.data_paths)
        $wow    = @($script:Reparsed.acquisition.'host.software.hklm_wow6432'.data_paths)

        $native | Should -Be @('host.installed_software')
        $wow    | Should -Be @('host.installed_software')
    }

    It 'validates cleanly against the schema 1.1 conformance rules' {
        $result = Test-VKEvidenceArtefact -Artefact $script:Reparsed -RequiredUnitIds $script:AllInstrumentedUnitIds
        $result.Violations -join ' | ' | Should -BeNullOrEmpty
        $result.IsValid | Should -BeTrue
    }

    Context 'per-entry contract' {

        BeforeAll {
            $script:Entries = @()
            foreach ($property in $script:Reparsed.acquisition.PSObject.Properties) {
                $script:Entries += [pscustomobject]@{ UnitId = $property.Name; Entry = $property.Value }
            }
        }

        It 'every entry carries all required fields' {
            foreach ($item in $script:Entries) {
                $names = $item.Entry.PSObject.Properties.Name
                foreach ($field in @('observation_start','observation_end','acquisition_outcome','agent_version','schema_version','data_paths','error')) {
                    $names | Should -Contain $field -Because "$($item.UnitId) must carry $field"
                }
            }
        }

        It 'every outcome belongs to the permitted four-value vocabulary' {
            foreach ($item in $script:Entries) {
                $script:PermittedOutcomes |
                    Should -Contain $item.Entry.acquisition_outcome -Because "$($item.UnitId) must use a permitted outcome"
            }
        }

        It 'no entry remains pending or incomplete' {
            foreach ($item in $script:Entries) {
                $item.Entry.acquisition_outcome | Should -Not -Be 'pending'
                $item.Entry.acquisition_outcome | Should -Not -Be 'incomplete'
                $item.Entry.acquisition_outcome | Should -Not -BeNullOrEmpty
            }
        }

        It 'every entry declares the central agent and schema versions' {
            foreach ($item in $script:Entries) {
                $item.Entry.agent_version  | Should -Be $script:ConfiguredAgent
                $item.Entry.schema_version | Should -Be $script:ConfiguredSchema
            }
        }

        It 'every entry has valid UTC start and end timestamps' {
            foreach ($item in $script:Entries) {
                Test-VKIsUtcTimestamp -Value $item.Entry.observation_start |
                    Should -BeTrue -Because "$($item.UnitId) observation_start must be ISO 8601 UTC"
                Test-VKIsUtcTimestamp -Value $item.Entry.observation_end |
                    Should -BeTrue -Because "$($item.UnitId) observation_end must be ISO 8601 UTC"
            }
        }

        It 'every entry populates data_paths' {
            foreach ($item in $script:Entries) {
                @($item.Entry.data_paths).Count |
                    Should -BeGreaterThan 0 -Because "$($item.UnitId) must govern at least one payload path"
            }
        }

        It 'success entries have error = null' {
            $successes = @($script:Entries | Where-Object { $_.Entry.acquisition_outcome -eq 'success' })
            $successes.Count | Should -BeGreaterThan 0
            foreach ($item in $successes) {
                $item.Entry.error | Should -BeNullOrEmpty -Because "$($item.UnitId) succeeded"
            }
        }

        It 'non-success entries carry structured error data' {
            $failures = @($script:Entries | Where-Object { $_.Entry.acquisition_outcome -ne 'success' })
            $failures.Count | Should -BeGreaterThan 0 -Because 'the fixture must exercise non-success outcomes'
            foreach ($item in $failures) {
                $item.Entry.error | Should -Not -BeNullOrEmpty
                foreach ($field in @('category', 'provider', 'message', 'exception_type')) {
                    $item.Entry.error.PSObject.Properties.Name |
                        Should -Contain $field -Because "$($item.UnitId) error must carry $field"
                }
                $item.Entry.error.category | Should -Not -BeNullOrEmpty
            }
        }

        It 'no error message contains a stack trace' {
            foreach ($item in $script:Entries) {
                if ($item.Entry.error -and $item.Entry.error.message) {
                    $item.Entry.error.message | Should -Not -Match 'StackTrace'
                    $item.Entry.error.message | Should -Not -Match '(?m)^\s*at\s+\S+'
                }
            }
        }

        It 'does not duplicate module payload data beneath acquisition' {
            # Entries point at the payload through data_paths; they must not
            # carry a payload of their own.
            foreach ($item in $script:Entries) {
                $item.Entry.PSObject.Properties.Name | Should -Not -Contain 'data'
            }
        }
    }

    It 'exercises more than one distinct outcome' {
        $distinct = @($script:Reparsed.acquisition.PSObject.Properties.Value.acquisition_outcome | Sort-Object -Unique)
        $distinct.Count | Should -BeGreaterThan 1 -Because 'a single-outcome fixture would not exercise the error shape'
    }
}


Describe 'Schema 1.1 validation rejects non-conforming artefacts' {

    It 'identifies the <_> case as invalid' -ForEach @(
        'MissingAcquisitionSection'
        'MissingUnitEntry'
        'MissingRequiredField'
        'InvalidOutcomeValue'
        'PendingLeaked'
        'SuccessWithError'
        'NonSuccessWithoutError'
        'EmptyDataPaths'
    ) {
        $artefact = $script:InvalidCases[$_]
        $artefact | Should -Not -BeNullOrEmpty

        $result = Test-VKEvidenceArtefact -Artefact $artefact -RequiredUnitIds @('security.antivirus.products')

        $result.IsValid | Should -BeFalse -Because "the '$_' fixture violates the schema 1.1 contract"
        @($result.Violations).Count | Should -BeGreaterThan 0
    }

    It 'does not invent an acquisition outcome for missing metadata' {
        # Missing metadata is a SCHEMA-VALIDITY problem, not an acquisition
        # outcome. Validation must report it, never repair it into 'failed'.
        $artefact = $script:InvalidCases['MissingAcquisitionSection']
        $result   = Test-VKEvidenceArtefact -Artefact $artefact -RequiredUnitIds @('security.antivirus.products')

        $result.IsValid | Should -BeFalse

        # The artefact is unchanged: no acquisition section was fabricated.
        @($artefact.Keys) | Should -Not -Contain 'acquisition'
    }

    It 'accepts the representative fixture as valid (positive control)' {
        $result = Test-VKEvidenceArtefact -Artefact $script:Fixture -RequiredUnitIds $script:AllInstrumentedUnitIds
        $result.IsValid | Should -BeTrue -Because 'the validator must not reject conforming input'
    }
}


Describe 'Schema 1.0 legacy evidence' {

    It 'is recognised as legacy rather than invalid' {
        $result = Test-VKEvidenceArtefact -Artefact $script:LegacyFixture
        $result.IsLegacy      | Should -BeTrue
        $result.SchemaVersion | Should -Be '1.0'
    }

    It 'has no acquisition section' {
        @($script:LegacyFixture.Keys) | Should -Not -Contain 'acquisition'
        @($script:LegacyFixture.Keys) | Should -Be @('scan_metadata', 'host', 'security', 'vulnerability')
    }

    It 'cannot support confirmed absence for an empty result' {
        # host.network_shares is empty in the legacy fixture. Under schema
        # 1.0 that is UNKNOWN, never absent, because acquisition success
        # cannot be established.
        Test-VKLegacyCanAssertAbsence -Artefact $script:LegacyFixture -DataPath 'host.network_shares' |
            Should -BeFalse
    }

    It 'cannot support confirmed absence for any path' -ForEach @(
        'host.network_shares'
        'security.legacy_protocols.tls_protocols'
        'vulnerability.token_privileges.privileges'
        'security.antivirus.product_name'
    ) {
        Test-VKLegacyCanAssertAbsence -Artefact $script:LegacyFixture -DataPath $_ | Should -BeFalse
    }

    It 'permits absence to be ASSESSED under schema 1.1 where the unit succeeded (contrast)' {
        # Contrast case: the same question against schema 1.1 evidence whose
        # governing unit succeeded. This makes absence ASSESSABLE only - the
        # condition-specific applicability, coverage, authority and
        # field-semantics rules still decide whether it may be ASSERTED.
        Test-VKLegacyCanAssertAbsence -Artefact $script:Fixture -DataPath 'security.antivirus.product_name' |
            Should -BeTrue
    }

    It 'does not permit assessment where the schema 1.1 unit did not succeed' {
        Test-VKLegacyCanAssertAbsence -Artefact $script:Fixture -DataPath 'security.legacy_protocols.wpad_auto_detect' |
            Should -BeFalse -Because 'that unit failed, so absence may never be claimed'
    }
}


Describe 'Serialisation: round trip fidelity' {

    It 'produces parseable JSON' {
        { $script:Json | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'preserves scalar values across the round trip' {
        $script:Reparsed.scan_metadata.hostname     | Should -Be 'FIXTURE-HOST-01'
        $script:Reparsed.scan_metadata.ran_as_admin | Should -BeTrue
        $script:Reparsed.host.os.build              | Should -Be 26200
        $script:Reparsed.security.antivirus.real_time_protection | Should -BeTrue
    }
}


Describe 'Serialisation: nested values survive the configured JSON depth' {

    It 'uses the depth declared in VK.Config.ps1' {
        $script:ConfiguredDepth | Should -Be 10
    }

    Context 'deepest study-relevant paths' {

        It 'preserves host.windows_updates.pending_updates[].kb_numbers[]' {
            $kb = $script:Reparsed.host.windows_updates.pending_updates[0].kb_numbers
            @($kb).Count | Should -Be 2
            $kb | Should -Contain 'KB5099999'
        }

        It 'preserves host.network_shares[].permissions[].account' {
            $perms = $script:Reparsed.host.network_shares[0].permissions
            @($perms).Count | Should -Be 2
            $perms[1].account | Should -Be 'BUILTIN\Administrators'
        }

        It 'preserves host.network_config.dns_servers[].server_addresses[]' {
            @($script:Reparsed.host.network_config.dns_servers[0].server_addresses).Count | Should -Be 2
        }
    }

    Context 'acquisition nested paths' {

        It 'preserves acquisition[].data_paths[]' {
            $entry = $script:Reparsed.acquisition.'security.host_security.device_guard'
            @($entry.data_paths).Count | Should -Be 3
            $entry.data_paths | Should -Contain 'security.host_security.security_services'
        }

        It 'preserves the complete acquisition[].error object' {
            # POSITIVE CONTROL for the depth negative control below: the
            # configured depth must retain the whole nested error object,
            # not merely one scalar from it.
            $entry = $script:Reparsed.acquisition.'security.host_security.kernel_dma_protection'

            $entry.error | Should -Not -BeNullOrEmpty
            foreach ($field in @('category', 'provider', 'message', 'exception_type')) {
                $entry.error.PSObject.Properties.Name | Should -Contain $field
            }

            $entry.error.category       | Should -Be 'access_denied'
            $entry.error.exception_type | Should -Be 'System.UnauthorizedAccessException'
            $entry.error.provider       | Should -Not -BeNullOrEmpty
            $entry.error.message        | Should -Not -BeNullOrEmpty
        }
    }

    Context 'condition-relevant nested paths' {

        It 'preserves C1 host.network_config.tcp_connections[].local_port' {
            $script:Reparsed.host.network_config.tcp_connections[0].local_port | Should -Be 3389
        }

        It 'preserves C3 security.legacy_protocols.tls_protocols[].client_enabled' {
            $tls12 = $script:Reparsed.security.legacy_protocols.tls_protocols | Where-Object { $_.protocol -eq 'TLS 1.2' }
            $tls12.client_enabled | Should -BeTrue
        }

        It 'preserves C4 security.host_security.security_services[].running' {
            $cg = $script:Reparsed.security.host_security.security_services | Where-Object { $_.service_name -eq 'Credential Guard' }
            $cg.running | Should -BeTrue
        }

        It 'preserves C4 security.defender_advanced.asr_rules[].action_text' {
            $script:Reparsed.security.defender_advanced.asr_rules[0].action_text | Should -Be 'Block'
        }

        It 'preserves C6 security.winrm.server_auth.basic' {
            $script:Reparsed.security.winrm.server_auth.basic | Should -BeFalse
        }

        It 'preserves C6 vulnerability.token_privileges.privileges[].state' {
            $impersonate = $script:Reparsed.vulnerability.token_privileges.privileges |
                Where-Object { $_.privilege -eq 'SeImpersonatePrivilege' }
            $impersonate.state | Should -Be 'Enabled'
        }

        It 'preserves C7 security.antivirus.product_state.OperationalState' {
            $script:Reparsed.security.antivirus.product_state.OperationalState | Should -Be 'On (Protection Enabled)'
        }
    }

    Context 'Tranche 2A provenance and outcome fields' {

        It 'preserves legacy-protocol value provenance markers' {
            $script:Reparsed.security.legacy_protocols.llmnr_value_source | Should -Be 'explicit'
            $script:Reparsed.security.legacy_protocols.mdns_value_source  | Should -Be 'default_inferred'
        }

        It 'preserves the antivirus products_detected count' {
            $script:Reparsed.security.antivirus.products_detected | Should -Be 1
        }
    }
}


Describe 'Serialisation: truncation is detected, not silently accepted' {

    It 'contains no <_> truncation marker' -ForEach @(
        'System.Collections.Specialized.OrderedDictionary'
        'System.Collections.Hashtable'
        'System.Collections.ArrayList'
        'System.Management.Automation'
    ) {
        $script:ScannableJson | Should -Not -BeLike "*$_*" -Because 'a .NET type name outside error.exception_type means PowerShell replaced real content it refused to serialise'
    }

    It 'contains no System.Object[] truncation marker' {
        $script:ScannableJson | Should -Not -Match ([regex]::Escape('System.Object[]'))
    }

    It 'still scans every position other than error.exception_type' {
        # Guards the exclusion above from being over-broad: only the
        # exception_type value is blanked, and nothing else is removed.
        $script:ScannableJson.Length | Should -BeLessThan $script:Json.Length
        $script:ScannableJson | Should -Match '"category"'
        $script:ScannableJson | Should -Match '"provider"'
        $script:ScannableJson | Should -Match '"data_paths"'
    }

    It 'fails loudly when the configured depth is too shallow (negative control)' {
        $shallow = $script:Fixture | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue

        $hasMarker = $false
        foreach ($marker in @('System.Collections', 'System.Object', 'System.Management.Automation')) {
            if ($shallow -like "*$marker*") { $hasMarker = $true; break }
        }

        $hasMarker | Should -BeTrue -Because 'the truncation markers asserted above must be the strings PowerShell actually emits'
    }

    It 'loses the deep kb_numbers content when serialised too shallowly (negative control)' {
        $shallow  = $script:Fixture | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue
        $reparsed = $shallow | ConvertFrom-Json
        $reparsed.host.windows_updates.pending_updates[0].kb_numbers | Should -Not -Contain 'KB5099999'
    }

    It 'does not faithfully retain the acquisition error object at an inadequate depth (negative control)' {
        # DEPTH CHOICE, derived rather than guessed.
        #
        # The error object sits at level 3 below the root:
        #     root(0) -> acquisition(1) -> unit entry(2) -> error(3)
        # and its scalars at level 4.
        #
        # Depth 3 is therefore ADEQUATE to reach the error object, and on
        # Windows PowerShell 5.1 it duly preserved exception_type. The
        # previous form of this control asserted that depth 3 lost that
        # scalar, which was simply wrong, and the test failed correctly.
        #
        # Depth 2 is the shallowest depth that still reaches the unit entry
        # while leaving the error object below the limit, so it is the
        # smallest demonstrably inadequate depth for this structure.
        #
        # The assertion is on FAITHFUL RETENTION of the whole nested object,
        # not on the loss of one particular scalar. That holds regardless of
        # whether an edition truncates by substituting a type-name string or
        # by dropping members, so the control cannot silently stop proving
        # anything on a different runtime.
        $shallow  = $script:Fixture | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue
        $reparsed = $shallow | ConvertFrom-Json

        $entry = $reparsed.acquisition.'security.host_security.kernel_dma_protection'
        $entry | Should -Not -BeNullOrEmpty -Because 'depth 2 still reaches the unit entry itself'

        $requiredErrorFields = @('category', 'provider', 'message', 'exception_type')

        $faithful = $true
        if ($null -eq $entry.error) {
            $faithful = $false
        }
        elseif ($entry.error -isnot [System.Management.Automation.PSCustomObject]) {
            # Truncated to a scalar - typically the .NET type name string.
            $faithful = $false
        }
        else {
            $names = @($entry.error.PSObject.Properties.Name)
            foreach ($field in $requiredErrorFields) {
                if ($names -notcontains $field) { $faithful = $false }
            }
            if ($entry.error.exception_type -ne 'System.UnauthorizedAccessException') { $faithful = $false }
            if ($entry.error.category       -ne 'access_denied')                      { $faithful = $false }
        }

        $faithful | Should -BeFalse -Because 'depth 2 is below the acquisition error object, so it cannot be retained intact - if this ever passes, the depth assertions above have stopped proving anything'
    }

    It 'retains the same error object faithfully at the configured depth (paired control)' {
        # The paired positive half, asserted against the identical predicate
        # so that the two halves cannot drift apart.
        $entry = $script:Reparsed.acquisition.'security.host_security.kernel_dma_protection'

        $requiredErrorFields = @('category', 'provider', 'message', 'exception_type')

        $faithful = $true
        if ($null -eq $entry.error -or $entry.error -isnot [System.Management.Automation.PSCustomObject]) {
            $faithful = $false
        }
        else {
            $names = @($entry.error.PSObject.Properties.Name)
            foreach ($field in $requiredErrorFields) {
                if ($names -notcontains $field) { $faithful = $false }
            }
            if ($entry.error.exception_type -ne 'System.UnauthorizedAccessException') { $faithful = $false }
            if ($entry.error.category       -ne 'access_denied')                      { $faithful = $false }
        }

        $faithful | Should -BeTrue -Because "the configured depth of $($script:ConfiguredDepth) must retain the complete nested error object"
    }
}
