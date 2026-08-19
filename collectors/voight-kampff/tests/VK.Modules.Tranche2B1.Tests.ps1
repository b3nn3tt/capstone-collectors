<#
.SYNOPSIS
    Pester tests for the seven modules instrumented in Tranche 2B.1.

.DESCRIPTION
    Covers Security.DefenderAdvanced, Security.Firewall, Security.SMB,
    Security.RDP, Security.WinRM, Security.UAC and Security.FDE.

    Providers are MOCKED throughout. No live host state is inspected and
    the collector is never executed.

    Every module is tested against the same fail-closed contract:

      - a genuine success records success and retains the evidence;
      - a legitimate zero result records success with an empty array;
      - a failure, denial or absent provider records a non-success outcome
        and withholds the payload rather than emitting a substantive
        default, empty collection, false, zero, "Unknown" or "Not Found";
      - a null provider response or missing required property is guarded;
      - an independent unit that succeeded keeps its evidence when a
        sibling unit fails.

    Contract assertions shared by every unit are parameterised in the final
    Describe rather than repeated per module.

.NOTES
    Tranche 2B.1. Pester 5.5+ (developed against 6.1), Windows PowerShell
    5.1 compatible. See tests/README.md.
#>

BeforeAll {

    $script:AgentRoot  = Split-Path -Parent $PSScriptRoot
    $script:SecModules = Join-Path $script:AgentRoot 'modules\security'

    . (Join-Path $script:AgentRoot 'core\VK.Config.ps1')
    . (Join-Path $script:AgentRoot 'core\VK.Utilities.ps1')

    foreach ($module in @(
        'Security.DefenderAdvanced', 'Security.Firewall', 'Security.SMB',
        'Security.RDP', 'Security.WinRM', 'Security.UAC', 'Security.FDE'
    )) {
        . (Join-Path $script:SecModules "$module.ps1")
    }

    function New-TestErrorRecord {
        param(
            [Parameter(Mandatory)][System.Exception]$Exception,
            [string]$ErrorId = 'TestError',
            [System.Management.Automation.ErrorCategory]$Category = [System.Management.Automation.ErrorCategory]::NotSpecified
        )
        return [System.Management.Automation.ErrorRecord]::new($Exception, $ErrorId, $Category, $null)
    }

    function New-DeniedError {
        New-TestErrorRecord -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
            -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied)
    }

    function New-MissingCommandError {
        New-TestErrorRecord -Exception ([System.NotSupportedException]::new('The cmdlet is not available on this host.')) `
            -Category ([System.Management.Automation.ErrorCategory]::NotImplemented)
    }

    function New-TestSection { return [ordered]@{} }

    # Values that must never appear as a result of a failed collection.
    $script:FabricatedValues = @('Unknown', 'Not Found', 'Disabled', 'Not Fully Encrypted', 'Protection Off')

    # --- Firewall rule enums -----------------------------------------
    # The real Get-NetFirewallRule returns Direction and Action as ENUMS,
    # and Security.Firewall relies on both enum behaviours:
    #
    #     $_.Direction -eq "Inbound"      (enum compares equal to its name)
    #     [int]$rule.Direction            (enum casts to its numeric value)
    #
    # A plain string satisfies the first and THROWS on the second
    # ([int]'Inbound' is not a valid cast), so a display-string mock would
    # misrepresent the provider. These enums model the real type.
    if (-not ([System.Management.Automation.PSTypeName]'VKTestFirewallDirection').Type) {
        Add-Type -TypeDefinition @'
public enum VKTestFirewallDirection { Inbound = 1, Outbound = 2 }
public enum VKTestFirewallAction { Block = 1, Allow = 2 }
'@
    }
}


# ============================================================
#  Security.DefenderAdvanced
# ============================================================

Describe 'Security.DefenderAdvanced: precondition and provider handling' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }

        # DEFINED SO THE ZERO-CALL ASSERTION IS VALID.
        #
        # Should -Invoke can only assert against a command that has a mock
        # in scope. This mock is also deliberately failing: DefenderAdvanced
        # must reuse Security.Antivirus's product evidence rather than
        # re-querying root\SecurityCenter2, so ANY call here is a defect and
        # fails visibly at the point of invocation rather than only in the
        # count assertion.
        Mock Get-CimInstance {
            throw [System.InvalidOperationException]::new(
                'Security.DefenderAdvanced must not query CIM; it reuses the antivirus product evidence.')
        }
    }

    Context 'when the antivirus product unit did not succeed' {

        BeforeEach {
            # Simulate Security.Antivirus having run and failed.
            Start-VKAcquisition -UnitId 'security.antivirus.products' -DataPaths @('security.antivirus.product_name')
            Set-VKAcquisitionFailure -UnitId 'security.antivirus.products' -ErrorRecord (New-DeniedError)

            $script:Section = New-TestSection
            $script:Section['antivirus'] = [ordered]@{ 'product_name' = $null }

            Invoke-VKSecurityDefenderAdvanced -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records <_> as unavailable / precondition_not_met' -ForEach @(
            'security.defender_advanced.asr_rules'
            'security.defender_advanced.protection_preferences'
            'security.defender_advanced.tamper_protection'
        ) {
            $script:Report[$_].acquisition_outcome | Should -Be 'unavailable'
            $script:Report[$_].error.category      | Should -Be 'precondition_not_met'
        }

        It 'emits the section with every governed value null' {
            $script:Section['defender_advanced'] | Should -Not -BeNullOrEmpty
            foreach ($key in $script:Section['defender_advanced'].Keys) {
                $script:Section['defender_advanced'][$key] | Should -BeNullOrEmpty
            }
        }

        It 'does not re-query the SecurityCenter2 product namespace' {
            # The module must reuse Security.Antivirus's evidence.
            Should -Invoke Get-CimInstance -Times 0 -Exactly
        }
    }

    Context 'when Defender is not the registered product' {

        BeforeEach {
            Start-VKAcquisition -UnitId 'security.antivirus.products' -DataPaths @('security.antivirus.product_name')
            Complete-VKAcquisition -UnitId 'security.antivirus.products'

            $script:Section = New-TestSection
            $script:Section['antivirus'] = [ordered]@{ 'product_name' = 'Fixture Endpoint Protection' }

            Invoke-VKSecurityDefenderAdvanced -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records <_> as unavailable / provider_not_applicable' -ForEach @(
            'security.defender_advanced.asr_rules'
            'security.defender_advanced.protection_preferences'
            'security.defender_advanced.tamper_protection'
        ) {
            $script:Report[$_].acquisition_outcome | Should -Be 'unavailable'
            $script:Report[$_].error.category      | Should -Be 'provider_not_applicable'
        }
    }

    Context 'when Defender is active and both providers answer' {

        BeforeEach {
            Start-VKAcquisition -UnitId 'security.antivirus.products' -DataPaths @('security.antivirus.product_name')
            Complete-VKAcquisition -UnitId 'security.antivirus.products'

            Mock Get-MpPreference {
                [pscustomobject]@{
                    AttackSurfaceReductionRules_Ids     = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a')
                    AttackSurfaceReductionRules_Actions = @(1, 2)
                    EnableNetworkProtection             = 1
                    EnableControlledFolderAccess        = 0
                    PUAProtection                       = 1
                    MAPSReporting                       = 2
                    SubmitSamplesConsent                = 1
                }
            }
            Mock Get-MpComputerStatus { [pscustomobject]@{ IsTamperProtected = $true } }

            $script:Section = New-TestSection
            $script:Section['antivirus'] = [ordered]@{ 'product_name' = 'Windows Defender' }

            Invoke-VKSecurityDefenderAdvanced -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records all three units as success' {
            foreach ($unit in @(
                'security.defender_advanced.asr_rules'
                'security.defender_advanced.protection_preferences'
                'security.defender_advanced.tamper_protection'
            )) {
                $script:Report[$unit].acquisition_outcome | Should -Be 'success'
            }
        }

        It 'retains the observed ASR evidence' {
            $script:Section['defender_advanced']['asr_rules_count']    | Should -Be 2
            $script:Section['defender_advanced']['asr_rules_blocking'] | Should -Be 1
            $script:Section['defender_advanced']['asr_rules'][0]['action_text'] | Should -Be 'Block'
        }

        It 'retains the observed protection preferences' {
            $script:Section['defender_advanced']['network_protection']       | Should -Be 'Enabled'
            $script:Section['defender_advanced']['controlled_folder_access'] | Should -Be 'Disabled'
            $script:Section['defender_advanced']['cloud_protection']         | Should -Be 'Advanced'
        }

        It 'queries each provider exactly once' {
            Should -Invoke Get-MpPreference     -Times 1 -Exactly
            Should -Invoke Get-MpComputerStatus -Times 1 -Exactly
        }
    }

    Context 'when the ASR arrays are mismatched' {

        BeforeEach {
            Start-VKAcquisition -UnitId 'security.antivirus.products' -DataPaths @('security.antivirus.product_name')
            Complete-VKAcquisition -UnitId 'security.antivirus.products'

            Mock Get-MpPreference {
                [pscustomobject]@{
                    # Two rule ids, one action: the missing action must not
                    # default to 0 / "Disabled".
                    AttackSurfaceReductionRules_Ids     = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'd4f940ab-401b-4efc-aadc-ad5f3c50688a')
                    AttackSurfaceReductionRules_Actions = @(1)
                    EnableNetworkProtection             = 1
                    EnableControlledFolderAccess        = 0
                    PUAProtection                       = 1
                    MAPSReporting                       = 2
                    SubmitSamplesConsent                = 1
                }
            }
            Mock Get-MpComputerStatus { [pscustomobject]@{ IsTamperProtected = $true } }

            $script:Section = New-TestSection
            $script:Section['antivirus'] = [ordered]@{ 'product_name' = 'Windows Defender' }

            Invoke-VKSecurityDefenderAdvanced -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the ASR result entirely' {
            $script:Section['defender_advanced']['asr_rules']          | Should -BeNullOrEmpty
            $script:Section['defender_advanced']['asr_rules_count']    | Should -BeNullOrEmpty
            $script:Section['defender_advanced']['asr_rules_blocking'] | Should -BeNullOrEmpty
        }

        It 'records the ASR unit as non-success' {
            $script:Report['security.defender_advanced.asr_rules'].acquisition_outcome | Should -Not -Be 'success'
        }

        It 'never defaults a missing ASR action to Disabled' {
            $rules = $script:Section['defender_advanced']['asr_rules']
            if ($rules) {
                foreach ($rule in $rules) { $rule['action_text'] | Should -Not -Be 'Disabled' }
            }
            $rules | Should -BeNullOrEmpty
        }

        It 'does not invalidate the independent protection-preference evidence' {
            $script:Report['security.defender_advanced.protection_preferences'].acquisition_outcome | Should -Be 'success'
            $script:Section['defender_advanced']['network_protection'] | Should -Be 'Enabled'
        }
    }

    Context 'when Get-MpPreference returns null' {

        BeforeEach {
            Start-VKAcquisition -UnitId 'security.antivirus.products' -DataPaths @('security.antivirus.product_name')
            Complete-VKAcquisition -UnitId 'security.antivirus.products'

            Mock Get-MpPreference     { $null }
            Mock Get-MpComputerStatus { [pscustomobject]@{ IsTamperProtected = $false } }

            $script:Section = New-TestSection
            $script:Section['antivirus'] = [ordered]@{ 'product_name' = 'Windows Defender' }

            Invoke-VKSecurityDefenderAdvanced -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records both preference-derived units as provider_value_missing' {
            foreach ($unit in @('security.defender_advanced.asr_rules', 'security.defender_advanced.protection_preferences')) {
                $script:Report[$unit].acquisition_outcome | Should -Be 'unavailable'
                $script:Report[$unit].error.category      | Should -Be 'provider_value_missing'
            }
        }

        It 'still records the independent tamper-protection observation' {
            $script:Report['security.defender_advanced.tamper_protection'].acquisition_outcome | Should -Be 'success'
            $script:Section['defender_advanced']['tamper_protection'] | Should -BeFalse
        }
    }
}


# ============================================================
#  Security.Firewall
# ============================================================

Describe 'Security.Firewall: profiles and inbound rules' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when both providers answer' {

        BeforeEach {
            Mock Get-NetFirewallProfile {
                @(
                    [pscustomobject]@{ Name = 'Domain';  Enabled = 1; DefaultInboundAction = 4; DefaultOutboundAction = 2 }
                    [pscustomobject]@{ Name = 'Private'; Enabled = 1; DefaultInboundAction = 4; DefaultOutboundAction = 2 }
                )
            }
            Mock Get-NetFirewallRule {
                # Direction and Action are enums, as the real cmdlet returns.
                @([pscustomobject]@{
                    DisplayName = 'RDP In'
                    ID          = 'RDP-In'
                    Enabled     = $true
                    Direction   = [VKTestFirewallDirection]::Inbound
                    Action      = [VKTestFirewallAction]::Allow
                })
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityFirewall -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records both units as success' {
            $script:Report['security.firewall.profiles'].acquisition_outcome      | Should -Be 'success'
            $script:Report['security.firewall.inbound_rules'].acquisition_outcome | Should -Be 'success'

            # Proves the enum path: both the string comparison used to filter
            # and the [int] cast used to map resolved correctly.
            $script:Section['firewall_rules'][0]['direction'] | Should -Be 'Inbound'
            $script:Section['firewall_rules'][0]['action']    | Should -Be 'Allow'
        }

        It 'retains the observed profile evidence' {
            @($script:Section['firewall_profiles']).Count | Should -Be 2
            $script:Section['firewall_profiles'][0]['inbound_action'] | Should -Be 'Block'
        }
    }

    Context 'when the rule query succeeds with no enabled inbound rules' {

        BeforeEach {
            Mock Get-NetFirewallProfile {
                @([pscustomobject]@{ Name = 'Domain'; Enabled = 1; DefaultInboundAction = 4; DefaultOutboundAction = 2 })
            }
            Mock Get-NetFirewallRule { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityFirewall -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success with an empty array' {
            $script:Report['security.firewall.inbound_rules'].acquisition_outcome | Should -Be 'success'

            # An empty array emits no pipeline object, so a piped comparison
            # would see $null and could not tell @() from $null - which is
            # exactly the distinction this contract turns on. The identity
            # check is made off-pipeline; the count check then confirms the
            # array is genuinely empty rather than merely non-null.
            [object]::ReferenceEquals($null, $script:Section['firewall_rules']) | Should -BeFalse
            @($script:Section['firewall_rules']).Count | Should -Be 0
        }
    }

    Context 'when the rule query fails' {

        BeforeEach {
            Mock Get-NetFirewallProfile {
                @([pscustomobject]@{ Name = 'Domain'; Enabled = 1; DefaultInboundAction = 4; DefaultOutboundAction = 2 })
            }
            Mock Get-NetFirewallRule { throw (New-DeniedError) }

            $script:Section = New-TestSection
            Invoke-VKSecurityFirewall -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'yields null rather than an empty rule list' {
            $script:Section['firewall_rules'] | Should -BeNullOrEmpty
            $script:Report['security.firewall.inbound_rules'].acquisition_outcome | Should -Be 'restricted'
        }

        It 'preserves the successful profile evidence' {
            $script:Report['security.firewall.profiles'].acquisition_outcome | Should -Be 'success'
            @($script:Section['firewall_profiles']).Count | Should -Be 1
        }
    }

    Context 'when a profile is missing a required property' {

        BeforeEach {
            Mock Get-NetFirewallProfile {
                @([pscustomobject]@{ Name = 'Domain'; Enabled = $null; DefaultInboundAction = 4; DefaultOutboundAction = 2 })
            }
            Mock Get-NetFirewallRule { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityFirewall -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the profile collection rather than mapping null to Disabled' {
            $script:Section['firewall_profiles'] | Should -BeNullOrEmpty
            $script:Report['security.firewall.profiles'].acquisition_outcome | Should -Not -Be 'success'
        }
    }
}


# ============================================================
#  Security.SMB
# ============================================================

Describe 'Security.SMB: provenance and privilege handling' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the registry answers with a mix of explicit and absent values' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                # RequireSecuritySignature explicit; the rest absent, so
                # documented defaults apply and must be marked inferred.
                [pscustomobject]@{ SMB1 = 0; RequireSecuritySignature = 1 }
            }
            Mock Get-SmbServerConfiguration {
                [pscustomobject]@{
                    EnableSMB2Protocol = $true; EnableMultiChannel = $true
                    EnableLeasing = $true; MaxChannelPerSession = 32
                }
            }

            $script:Section = New-TestSection
            Invoke-VKSecuritySMB -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'marks the SMBv1 value as registry-explicit' {
            $script:Section['smb']['smbv1_enabled']      | Should -BeFalse
            $script:Section['smb']['smbv1_value_source'] | Should -Be 'explicit'
        }

        It 'marks an observed registry value as explicit' {
            $script:Section['smb']['server_value_sources']['server_signing_required'] | Should -Be 'explicit'
        }

        It 'marks a retained documented default as default_inferred' {
            $script:Section['smb']['server_signing_enabled'] | Should -BeTrue
            $script:Section['smb']['server_value_sources']['server_signing_enabled'] | Should -Be 'default_inferred'
        }

        It 'records all four units as success' {
            foreach ($unit in @(
                'security.smb.smbv1', 'security.smb.server_registry',
                'security.smb.client_registry', 'security.smb.server_configuration'
            )) {
                $script:Report[$unit].acquisition_outcome | Should -Be 'success'
            }
        }
    }

    Context 'when the SMBv1 registry value is absent and the feature answers' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { [pscustomobject]@{ RequireSecuritySignature = 1 } }
            Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = 'Disabled' } }

            $script:Section = New-TestSection
            Invoke-VKSecuritySMB -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'distinguishes feature-observed state from registry-explicit state' {
            $script:Section['smb']['smbv1_enabled']      | Should -BeFalse
            $script:Section['smb']['smbv1_value_source'] | Should -Be 'feature_observed'
            $script:Report['security.smb.smbv1'].acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'when the server registry read fails' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { throw (New-DeniedError) }
            Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = 'Disabled' } }

            $script:Section = New-TestSection
            Invoke-VKSecuritySMB -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'licenses no documented default' {
            foreach ($path in @(
                'server_signing_required', 'server_signing_enabled', 'server_encrypt_data',
                'server_reject_unencrypted', 'restrict_null_session_access', 'server_value_sources'
            )) {
                $script:Section['smb'][$path] | Should -BeNullOrEmpty
            }
        }

        It 'records the server registry unit as restricted' {
            $script:Report['security.smb.server_registry'].acquisition_outcome | Should -Be 'restricted'
        }
    }

    Context 'when the scan is not elevated' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { [pscustomobject]@{ SMB1 = 0 } }
            Mock Get-SmbServerConfiguration { throw (New-DeniedError) }

            $script:Section = New-TestSection
            Invoke-VKSecuritySMB -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the server configuration unit as restricted / insufficient_privilege' {
            $entry = $script:Report['security.smb.server_configuration']
            $entry.acquisition_outcome | Should -Be 'restricted'
            $entry.error.category      | Should -Be 'insufficient_privilege'
        }

        It 'does not call the elevated cmdlet at all' {
            Should -Invoke Get-SmbServerConfiguration -Times 0 -Exactly
        }

        It 'leaves the cmdlet-sourced fields null' {
            foreach ($path in @('smb2_enabled', 'server_multichannel', 'server_leasing', 'max_channel_per_session')) {
                $script:Section['smb'][$path] | Should -BeNullOrEmpty
            }
        }
    }
}


# ============================================================
#  Security.RDP
# ============================================================

Describe 'Security.RDP: separated providers and guarded properties' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when both registry keys answer' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{
                    fDenyTSConnections = 0
                    DisableRestrictedAdmin = 1
                    UserAuthentication = 1
                    SecurityLayer = 2
                    MinEncryptionLevel = 3
                    MaxIdleTime = 0
                }
            }
            Mock Get-LocalGroupMember { @([pscustomobject]@{ Name = 'FIXTUREDOM\fixture.user' }) }

            $script:Section = New-TestSection
            Invoke-VKSecurityRDP -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records all three units as success' {
            foreach ($unit in @('security.rdp.terminal_server', 'security.rdp.rdp_tcp', 'security.rdp.allowed_users')) {
                $script:Report[$unit].acquisition_outcome | Should -Be 'success'
            }
        }

        It 'marks the inferred default port as default_inferred' {
            $script:Section['rdp']['port']              | Should -Be 3389
            $script:Section['rdp']['port_value_source'] | Should -Be 'default_inferred'
        }

        It 'retains the observed security layer' {
            $script:Section['rdp']['security_layer'] | Should -Be 'SSL/TLS'
        }
    }

    Context 'when an explicit port is configured' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{
                    fDenyTSConnections = 0; UserAuthentication = 1
                    SecurityLayer = 2; MinEncryptionLevel = 3; PortNumber = 33890
                }
            }
            Mock Get-LocalGroupMember { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityRDP -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
        }

        It 'marks the observed port as explicit' {
            $script:Section['rdp']['port']              | Should -Be 33890
            $script:Section['rdp']['port_value_source'] | Should -Be 'explicit'
        }
    }

    Context 'when the RDP-Tcp key is missing required properties' {

        BeforeEach {
            Mock Test-Path { $true }
            # fDenyTSConnections present, UserAuthentication absent.
            Mock Get-ItemProperty { [pscustomobject]@{ fDenyTSConnections = 0 } }
            Mock Get-LocalGroupMember { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityRDP -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not read an absent UserAuthentication as "NLA not required"' {
            $script:Section['rdp']['nla_required'] | Should -BeNullOrEmpty
        }

        It 'does not map an absent SecurityLayer to the least secure layer' {
            $script:Section['rdp']['security_layer'] | Should -Not -Be 'RDP Security Layer'
            $script:Section['rdp']['security_layer'] | Should -BeNullOrEmpty
        }

        It 'preserves the successful Terminal Server evidence' {
            $script:Report['security.rdp.terminal_server'].acquisition_outcome | Should -Be 'success'
            $script:Section['rdp']['rdp_enabled'] | Should -BeTrue
            $script:Report['security.rdp.rdp_tcp'].acquisition_outcome | Should -Not -Be 'success'
        }
    }

    Context 'when group enumeration fails' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{ fDenyTSConnections = 0; UserAuthentication = 1; SecurityLayer = 2; MinEncryptionLevel = 3 }
            }
            Mock Get-LocalGroupMember { throw (New-DeniedError) }

            $script:Section = New-TestSection
            Invoke-VKSecurityRDP -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'yields null rather than an empty allowed-user list' {
            $script:Section['rdp']['allowed_users'] | Should -BeNullOrEmpty
            $script:Report['security.rdp.allowed_users'].acquisition_outcome | Should -Be 'restricted'
        }
    }

    Context 'when the group exists with no members' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{ fDenyTSConnections = 0; UserAuthentication = 1; SecurityLayer = 2; MinEncryptionLevel = 3 }
            }
            Mock Get-LocalGroupMember { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityRDP -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success with an empty array' {
            $script:Report['security.rdp.allowed_users'].acquisition_outcome | Should -Be 'success'

            # Off-pipeline identity check: @() and $null are indistinguishable
            # once piped, and telling them apart is the whole contract here.
            [object]::ReferenceEquals($null, $script:Section['rdp']['allowed_users']) | Should -BeFalse
            @($script:Section['rdp']['allowed_users']).Count | Should -Be 0
        }
    }
}


# ============================================================
#  Security.WinRM
# ============================================================

Describe 'Security.WinRM: service, registry and listeners' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the service query fails' {

        BeforeEach {
            Mock Get-CimInstance  { throw (New-DeniedError) }
            Mock Test-Path        { $false }
            Mock Get-ItemProperty { [pscustomobject]@{} }
            Mock Get-ChildItem    { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityWinRM -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not emit the string "Unknown" as an observed service state' {
            $script:Section['winrm']['service_state']      | Should -Not -Be 'Unknown'
            $script:Section['winrm']['service_start_type'] | Should -Not -Be 'Unknown'
            $script:Section['winrm']['service_state']      | Should -BeNullOrEmpty
        }

        It 'records the service unit as restricted' {
            $script:Report['security.winrm.service'].acquisition_outcome | Should -Be 'restricted'
        }
    }

    Context 'when the registry answers' {

        BeforeEach {
            Mock Get-CimInstance { [pscustomobject]@{ State = 'Running'; StartMode = 'Auto' } }
            Mock Test-Path       { $true }
            Mock Get-ItemProperty { [pscustomobject]@{ AllowBasic = 0; TrustedHosts = 'fixture-host' } }
            Mock Get-ChildItem   { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityWinRM -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'marks an observed value as explicit and a retained default as inferred' {
            $script:Section['winrm']['server_value_sources']['server_auth.basic']    | Should -Be 'explicit'
            $script:Section['winrm']['server_value_sources']['server_auth.kerberos'] | Should -Be 'default_inferred'
        }

        It 'records the trusted hosts observation' {
            $script:Section['winrm']['trusted_hosts'] | Should -Be 'fixture-host'
            $script:Report['security.winrm.trusted_hosts'].acquisition_outcome | Should -Be 'success'
        }

        It 'records success with an empty listener array when none are configured' {
            $script:Report['security.winrm.listeners'].acquisition_outcome | Should -Be 'success'

            # Off-pipeline identity check: @() and $null are indistinguishable
            # once piped, and telling them apart is the whole contract here.
            [object]::ReferenceEquals($null, $script:Section['winrm']['listeners']) | Should -BeFalse
            @($script:Section['winrm']['listeners']).Count | Should -Be 0
        }
    }

    Context 'when listener enumeration fails part-way' {

        BeforeEach {
            Mock Get-CimInstance { [pscustomobject]@{ State = 'Running'; StartMode = 'Auto' } }
            Mock Test-Path       { $true }
            Mock Get-ChildItem   {
                @(
                    [pscustomobject]@{ PSPath = 'HKLM:\listener1'; PSChildName = 'listener1' }
                    [pscustomobject]@{ PSPath = 'HKLM:\listener2'; PSChildName = 'listener2' }
                )
            }
            # The listener read fails; the registry settings read succeeds.
            Mock Get-ItemProperty { throw (New-DeniedError) } -ParameterFilter { $Path -like 'HKLM:\listener*' }
            Mock Get-ItemProperty { [pscustomobject]@{ AllowBasic = 0 } }

            $script:Section = New-TestSection
            Invoke-VKSecurityWinRM -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the whole listener collection rather than emitting a partial list' {
            $script:Section['winrm']['listeners'] | Should -BeNullOrEmpty
            $script:Report['security.winrm.listeners'].acquisition_outcome | Should -Not -Be 'success'
        }

        It 'preserves the independent server registry evidence' {
            $script:Report['security.winrm.server_registry'].acquisition_outcome | Should -Be 'success'
        }
    }
}


# ============================================================
#  Security.UAC
# ============================================================

Describe 'Security.UAC: guarded properties' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the key answers with every value present' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{
                    EnableLUA = 1; FilterAdministratorToken = 0
                    ConsentPromptBehaviorAdmin = 5; ConsentPromptBehaviorUser = 3
                    PromptOnSecureDesktop = 1; EnableInstallerDetection = 0
                    ValidateAdminCodeSignatures = 0; EnableSecureUIAPaths = 1
                }
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityUAC -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the unit as success' {
            $script:Report['security.uac.configuration'].acquisition_outcome | Should -Be 'success'
        }

        It 'retains the observed values' {
            $script:Section['uac']['uac_enabled']               | Should -BeTrue
            $script:Section['uac']['consent_prompt_admin']      | Should -Be 5
            $script:Section['uac']['consent_prompt_admin_text'] | Should -Be 'Prompt for consent for non-Windows binaries'
        }
    }

    Context 'when the read succeeds but values are absent' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { [pscustomobject]@{ EnableLUA = 1 } }

            $script:Section = New-TestSection
            Invoke-VKSecurityUAC -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'still records success, because the read itself succeeded' {
            $script:Report['security.uac.configuration'].acquisition_outcome | Should -Be 'success'
        }

        It 'does not read an absent value as false' {
            # Two distinct claims, asserted separately:
            #   1. the value is absent;
            #   2. it was not converted into a Boolean.
            # -Not -BeFalse cannot carry claim 2, because $null passes
            # through that matcher ambiguously. A type check states it
            # directly, so a future regression to $false fails here.
            $value = $script:Section['uac']['secure_desktop_enabled']

            $value | Should -BeNullOrEmpty
            ($value -is [bool]) | Should -BeFalse
        }

        It 'does not map an absent admin consent value to "Elevate without prompting"' {
            $script:Section['uac']['consent_prompt_admin']      | Should -BeNullOrEmpty
            $script:Section['uac']['consent_prompt_admin_text'] | Should -Not -Be 'Elevate without prompting'
        }

        It 'does not map an absent standard consent value to "Automatically deny elevation requests"' {
            $script:Section['uac']['consent_prompt_standard_text'] | Should -Not -Be 'Automatically deny elevation requests'
        }
    }

    Context 'when the key read fails' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty { throw (New-DeniedError) }

            $script:Section = New-TestSection
            Invoke-VKSecurityUAC -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'nulls every governed field' {
            foreach ($key in $script:Section['uac'].Keys) {
                $script:Section['uac'][$key] | Should -BeNullOrEmpty
            }
        }

        It 'records the unit as restricted' {
            $script:Report['security.uac.configuration'].acquisition_outcome | Should -Be 'restricted'
        }
    }
}


# ============================================================
#  Security.FDE
# ============================================================

Describe 'Security.FDE: elevation, null guards and partial volumes' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the scan is not elevated' {

        BeforeEach {
            $script:Section = New-TestSection
            Invoke-VKSecurityFDE -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'still registers both units' {
            $script:Report.Contains('security.fde.os_drive')           | Should -BeTrue
            $script:Report.Contains('security.fde.additional_volumes') | Should -BeTrue
        }

        It 'records <_> as restricted / insufficient_privilege' -ForEach @(
            'security.fde.os_drive'
            'security.fde.additional_volumes'
        ) {
            $script:Report[$_].acquisition_outcome | Should -Be 'restricted'
            $script:Report[$_].error.category      | Should -Be 'insufficient_privilege'
        }

        It 'presents both governed paths as null' {
            $script:Section['fde_os_drive']           | Should -BeNullOrEmpty
            $script:Section['fde_additional_volumes'] | Should -BeNullOrEmpty
        }
    }

    Context 'when elevated and BitLocker answers' {

        BeforeEach {
            Mock Get-CimInstance { [pscustomobject]@{ SystemDrive = 'C:' } }
            Mock Get-BitLockerVolume {
                @(
                    [pscustomobject]@{
                        MountPoint = 'C:'; VolumeStatus = 1; ProtectionStatus = 1
                        EncryptionMethod = 'XtsAes128'; KeyProtector = 'TPM;RecoveryPassword'
                    }
                )
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityFDE -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the OS drive evidence' {
            $script:Report['security.fde.os_drive'].acquisition_outcome | Should -Be 'success'
            $script:Section['fde_os_drive']['volume_status']     | Should -Be 'Fully Encrypted'
            $script:Section['fde_os_drive']['encryption_method'] | Should -Be 'XTS-AES 128-bit'
        }

        It 'records zero additional volumes as success with an empty array' {
            $script:Report['security.fde.additional_volumes'].acquisition_outcome | Should -Be 'success'

            # Off-pipeline identity check: @() and $null are indistinguishable
            # once piped, and telling them apart is the whole contract here -
            # $null would mean the collection was never established.
            [object]::ReferenceEquals($null, $script:Section['fde_additional_volumes']) | Should -BeFalse
            @($script:Section['fde_additional_volumes']).Count | Should -Be 0
        }
    }

    Context 'when a volume is missing a required property' {

        BeforeEach {
            Mock Get-CimInstance { [pscustomobject]@{ SystemDrive = 'C:' } }
            Mock Get-BitLockerVolume {
                @(
                    [pscustomobject]@{ MountPoint = 'C:'; VolumeStatus = 1; ProtectionStatus = 1; EncryptionMethod = 'XtsAes128' }
                    # D: reports no ProtectionStatus.
                    [pscustomobject]@{ MountPoint = 'D:'; VolumeStatus = 1; ProtectionStatus = $null; EncryptionMethod = 'XtsAes128' }
                )
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityFDE -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the whole additional-volume collection' {
            $script:Section['fde_additional_volumes'] | Should -BeNullOrEmpty
            $script:Report['security.fde.additional_volumes'].acquisition_outcome | Should -Not -Be 'success'
        }

        It 'never renders a missing property as an observed unfavourable state' {
            $emitted = $script:Section['fde_additional_volumes']
            $emitted | Should -BeNullOrEmpty
        }

        It 'preserves the successful OS-drive evidence' {
            $script:Report['security.fde.os_drive'].acquisition_outcome | Should -Be 'success'
            $script:Section['fde_os_drive']['mount_point'] | Should -Be 'C:'
        }
    }

    Context 'when the BitLocker cmdlet is unavailable' {

        BeforeEach {
            Mock Get-CimInstance     { [pscustomobject]@{ SystemDrive = 'C:' } }
            Mock Get-BitLockerVolume { throw (New-MissingCommandError) }

            $script:Section = New-TestSection
            Invoke-VKSecurityFDE -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records both units as unavailable' {
            $script:Report['security.fde.os_drive'].acquisition_outcome           | Should -Be 'unavailable'
            $script:Report['security.fde.additional_volumes'].acquisition_outcome | Should -Be 'unavailable'
        }

        It 'yields null for additional volumes, not an empty array' {
            $script:Section['fde_additional_volumes'] | Should -BeNullOrEmpty
        }
    }

    Context 'when the OS drive cannot be determined' {

        BeforeEach {
            Mock Get-CimInstance     { $null }
            Mock Get-BitLockerVolume { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityFDE -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records both units as non-success' {
            $script:Report['security.fde.os_drive'].acquisition_outcome           | Should -Not -Be 'success'
            $script:Report['security.fde.additional_volumes'].acquisition_outcome | Should -Not -Be 'success'
        }

        It 'does not query BitLocker without an OS drive letter' {
            Should -Invoke Get-BitLockerVolume -Times 0 -Exactly
        }
    }
}


# ============================================================
#  Shared contract across every Tranche 2B.1 unit
# ============================================================

Describe 'Tranche 2B.1 units satisfy the shared acquisition contract' {

    # Parameterised rather than repeated per module: each scenario drives a
    # module into a failure state and the same invariants are asserted.

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }

        # Drive every module into a denied-provider state at once.
        Mock Test-Path                  { throw (New-DeniedError) }
        Mock Get-ItemProperty           { throw (New-DeniedError) }
        Mock Get-CimInstance            { throw (New-DeniedError) }
        Mock Get-ChildItem              { throw (New-DeniedError) }
        Mock Get-LocalGroupMember       { throw (New-DeniedError) }
        Mock Get-NetFirewallProfile     { throw (New-DeniedError) }
        Mock Get-NetFirewallRule        { throw (New-DeniedError) }
        Mock Get-SmbServerConfiguration { throw (New-DeniedError) }
        Mock Get-WindowsOptionalFeature { throw (New-DeniedError) }
        Mock Get-BitLockerVolume        { throw (New-DeniedError) }
        Mock Get-MpPreference           { throw (New-DeniedError) }
        Mock Get-MpComputerStatus       { throw (New-DeniedError) }

        $script:Section = New-TestSection
        $script:Section['antivirus'] = [ordered]@{ 'product_name' = 'Windows Defender' }

        Start-VKAcquisition -UnitId 'security.antivirus.products' -DataPaths @('security.antivirus.product_name')
        Complete-VKAcquisition -UnitId 'security.antivirus.products'

        Invoke-VKSecurityDefenderAdvanced -Data $script:Section -IsAdmin $true
        Invoke-VKSecurityFirewall         -Data $script:Section -IsAdmin $true
        Invoke-VKSecuritySMB              -Data $script:Section -IsAdmin $true
        Invoke-VKSecurityRDP              -Data $script:Section -IsAdmin $true
        Invoke-VKSecurityWinRM            -Data $script:Section -IsAdmin $true
        Invoke-VKSecurityUAC              -Data $script:Section -IsAdmin $true
        Invoke-VKSecurityFDE              -Data $script:Section -IsAdmin $true

        Complete-VKAcquisitionReport
        $script:Report = Get-VKAcquisitionReport
    }

    It 'registers unit <_>' -ForEach @(
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
    ) {
        $script:Report.Contains($_) | Should -BeTrue
    }

    It 'records no unit as success when every provider is denied' {
        $successes = @(
            $script:Report.Keys |
                Where-Object { $_ -ne 'security.antivirus.products' } |
                Where-Object { $script:Report[$_].acquisition_outcome -eq 'success' }
        )
        $successes -join ', ' | Should -BeNullOrEmpty
    }

    It 'leaves no unit pending or outside the permitted vocabulary' {
        foreach ($unitId in $script:Report.Keys) {
            @('success', 'failed', 'restricted', 'unavailable') |
                Should -Contain $script:Report[$unitId].acquisition_outcome
        }
    }

    It 'gives every unit populated data_paths and structured error data' {
        foreach ($unitId in $script:Report.Keys) {
            if ($unitId -eq 'security.antivirus.products') { continue }
            @($script:Report[$unitId].data_paths).Count | Should -BeGreaterThan 0
            $script:Report[$unitId].error | Should -Not -BeNullOrEmpty
            $script:Report[$unitId].error.category | Should -Not -BeNullOrEmpty
        }
    }

    It 'emits no fabricated substantive value anywhere in the section' {
        # Recursively walk the emitted payload. After a total provider
        # denial, no field may carry a value that reads as an observation.
        $findFabricated = {
            param($Node, $Path)

            $hits = @()

            if ($null -eq $Node) { return $hits }

            if ($Node -is [System.Collections.IDictionary]) {
                foreach ($key in $Node.Keys) {
                    $hits += & $findFabricated $Node[$key] "$Path.$key"
                }
            }
            elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
                $index = 0
                foreach ($item in $Node) {
                    $hits += & $findFabricated $item "$Path[$index]"
                    $index++
                }
            }
            elseif ($Node -is [string]) {
                if ($script:FabricatedValues -contains $Node) { $hits += "$Path = '$Node'" }
            }

            return $hits
        }

        $fabricated = @(& $findFabricated $script:Section 'security')
        $fabricated -join ' | ' | Should -BeNullOrEmpty
    }

    It 'emits no substantive boolean or zero for a denied collection' {
        # Any non-null leaf would be an assertion the host never made. The
        # only permitted non-null values are provenance markers, which are
        # never emitted on a failed read.
        $findNonNull = {
            param($Node, $Path)

            $hits = @()
            if ($null -eq $Node) { return $hits }

            if ($Node -is [System.Collections.IDictionary]) {
                foreach ($key in $Node.Keys) {
                    $hits += & $findNonNull $Node[$key] "$Path.$key"
                }
            }
            elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
                $index = 0
                foreach ($item in $Node) {
                    $hits += & $findNonNull $item "$Path[$index]"
                    $index++
                }
            }
            else {
                $hits += "$Path = '$Node'"
            }

            return $hits
        }

        # product_name is seeded by the test itself, so exclude it.
        $nonNull = @(& $findNonNull $script:Section 'security' | Where-Object { $_ -notlike '*antivirus.product_name*' })
        $nonNull -join ' | ' | Should -BeNullOrEmpty
    }
}
