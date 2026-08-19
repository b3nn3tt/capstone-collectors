<#
.SYNOPSIS
    Pester tests for the three Tranche 2A false-evidence corrections.

.DESCRIPTION
    Covers Security.LegacyProtocols, Security.HostSecurity and
    Security.Antivirus.

    Providers are MOCKED. No live host state is inspected: every registry
    read, CIM query, Defender call and native type load is intercepted.

    The property under test in every case is that a non-success collection
    produces NO substantive value - the schema 1.0 modules answered
    provider failures with $true, $false or "Not Detected", which
    fabricated observations the agent never made.

.NOTES
    Tranche 2A. Pester 5.5+ (developed against 6.1). See tests/README.md.
#>

BeforeAll {

    $script:AgentRoot = Split-Path -Parent $PSScriptRoot
    $script:SecModules = Join-Path $script:AgentRoot 'modules\security'

    # Config and utilities only declare variables and functions.
    . (Join-Path $script:AgentRoot 'core\VK.Config.ps1')
    . (Join-Path $script:AgentRoot 'core\VK.Utilities.ps1')

    # Module files under test define functions only; dot-sourcing them
    # does not collect anything.
    . (Join-Path $script:SecModules 'Security.LegacyProtocols.ps1')
    . (Join-Path $script:SecModules 'Security.HostSecurity.ps1')
    . (Join-Path $script:SecModules 'Security.Antivirus.ps1')

    function New-TestErrorRecord {
        param(
            [Parameter(Mandatory)][System.Exception]$Exception,
            [string]$ErrorId = 'TestError',
            [System.Management.Automation.ErrorCategory]$Category = [System.Management.Automation.ErrorCategory]::NotSpecified
        )
        return [System.Management.Automation.ErrorRecord]::new($Exception, $ErrorId, $Category, $null)
    }

    function New-TestSection { return [ordered]@{} }
}

# NOTE ON SETUP SCOPE
# Pester 6 rejects BeforeEach directly in the container root ("Each test setup
# is not supported in root"). The common per-test setup - a fresh acquisition
# store plus silenced console and log output - is therefore declared once per
# Describe, immediately below.
#
# Ordering is preserved: a Describe's BeforeEach runs before any nested
# Context's BeforeEach, so each Context still invokes its module against a
# clean acquisition store with Write-VKStatus and Write-LogMessage already
# mocked. Mocks declared at Describe level remain in force for tests in
# nested Contexts.


Describe 'Security.LegacyProtocols: LLMNR and mDNS never fabricate $true' {

    BeforeEach {
        Initialize-VKAcquisition

        # Silence console and log output. Write-LogMessage would otherwise
        # append to $script:ErrorLogPath, which is not set during tests.
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the registry read is denied' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                throw (New-TestErrorRecord `
                    -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied))
            }
            Mock Get-CimInstance { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityLegacyProtocols -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not set llmnr_enabled to $true' {
            # The schema 1.0 defect: the catch block set this to $true.
            $script:Section['legacy_protocols']['llmnr_enabled'] | Should -Not -BeTrue
            $script:Section['legacy_protocols']['llmnr_enabled'] | Should -BeNullOrEmpty
        }

        It 'does not set mdns_enabled to $true' {
            $script:Section['legacy_protocols']['mdns_enabled'] | Should -Not -BeTrue
            $script:Section['legacy_protocols']['mdns_enabled'] | Should -BeNullOrEmpty
        }

        It 'produces no inferred value_source for a failed read' {
            $script:Section['legacy_protocols']['llmnr_value_source'] | Should -BeNullOrEmpty
            $script:Section['legacy_protocols']['mdns_value_source']  | Should -BeNullOrEmpty
        }

        It 'records the LLMNR unit as restricted' {
            $script:Report['security.legacy_protocols.llmnr'].acquisition_outcome | Should -Be 'restricted'
            $script:Report['security.legacy_protocols.llmnr'].error.category      | Should -Be 'access_denied'
        }

        It 'records the mDNS unit as restricted' {
            $script:Report['security.legacy_protocols.mdns'].acquisition_outcome | Should -Be 'restricted'
        }

        It 'governs the corrected paths from the acquisition record' {
            $script:Report['security.legacy_protocols.llmnr'].data_paths |
                Should -Contain 'security.legacy_protocols.llmnr_enabled'
        }
    }

    Context 'when the policy key is absent and the read succeeds' {

        BeforeEach {
            # Key absent is a successful observation of "nothing configured",
            # not a failure. The documented Windows default then applies.
            Mock Test-Path { $false }
            Mock Get-ItemProperty { throw 'Get-ItemProperty should not be called when the key is absent.' }
            Mock Get-CimInstance { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityLegacyProtocols -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'applies the documented default for LLMNR' {
            $script:Section['legacy_protocols']['llmnr_enabled'] | Should -BeTrue
        }

        It 'marks the LLMNR value as default_inferred, not explicit' {
            $script:Section['legacy_protocols']['llmnr_value_source'] | Should -Be 'default_inferred'
        }

        It 'marks the mDNS value as default_inferred' {
            $script:Section['legacy_protocols']['mdns_enabled']      | Should -BeTrue
            $script:Section['legacy_protocols']['mdns_value_source'] | Should -Be 'default_inferred'
        }

        It 'records the units as success' {
            $script:Report['security.legacy_protocols.llmnr'].acquisition_outcome | Should -Be 'success'
            $script:Report['security.legacy_protocols.mdns'].acquisition_outcome  | Should -Be 'success'
        }
    }

    Context 'when an explicit policy value is present' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ItemProperty {
                [pscustomobject]@{ EnableMulticast = 0; EnableMDNS = 0; AutoDetect = 1 }
            }
            Mock Get-CimInstance { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityLegacyProtocols -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
        }

        It 'records the observed value' {
            $script:Section['legacy_protocols']['llmnr_enabled'] | Should -BeFalse
            $script:Section['legacy_protocols']['mdns_enabled']  | Should -BeFalse
        }

        It 'marks the value as explicit, distinguishing observation from inference' {
            $script:Section['legacy_protocols']['llmnr_value_source'] | Should -Be 'explicit'
            $script:Section['legacy_protocols']['mdns_value_source']  | Should -Be 'explicit'
        }
    }

    Context 'when the registry existence test itself fails' {

        # Distinct from the denied-read context above: here Test-Path is the
        # operation that fails. Without -ErrorAction Stop, Test-Path emits a
        # non-terminating error and returns $false, which the module would
        # read as "the key is genuinely absent" and use to license the
        # documented Windows default.
        BeforeEach {
            Mock Test-Path {
                throw (New-TestErrorRecord `
                    -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied))
            }
            Mock Get-ItemProperty { [pscustomobject]@{} }
            Mock Get-CimInstance  { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityLegacyProtocols -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not infer the LLMNR default from a failed existence test' {
            $script:Section['legacy_protocols']['llmnr_enabled']      | Should -BeNullOrEmpty
            $script:Section['legacy_protocols']['llmnr_value_source'] | Should -Not -Be 'default_inferred'
            $script:Section['legacy_protocols']['llmnr_value_source'] | Should -BeNullOrEmpty
        }

        It 'does not infer the mDNS default from a failed existence test' {
            $script:Section['legacy_protocols']['mdns_enabled']      | Should -BeNullOrEmpty
            $script:Section['legacy_protocols']['mdns_value_source'] | Should -Not -Be 'default_inferred'
            $script:Section['legacy_protocols']['mdns_value_source'] | Should -BeNullOrEmpty
        }

        It 'asserts no WPAD auto-detect value from a failed existence test' {
            $script:Section['legacy_protocols']['wpad_auto_detect'] | Should -BeNullOrEmpty
        }

        It 'withholds the TLS protocol collection from a failed existence test' {
            $script:Section['legacy_protocols']['tls_protocols'] | Should -BeNullOrEmpty
        }

        It 'records <_> as a non-success outcome' -ForEach @(
            'security.legacy_protocols.llmnr'
            'security.legacy_protocols.mdns'
            'security.legacy_protocols.wpad_auto_detect'
            'security.legacy_protocols.tls_protocols'
        ) {
            $script:Report[$_].acquisition_outcome | Should -Not -Be 'success'
            $script:Report[$_].error | Should -Not -BeNullOrEmpty
        }

        It 'classifies a denied existence test as restricted' {
            $script:Report['security.legacy_protocols.llmnr'].acquisition_outcome | Should -Be 'restricted'
            $script:Report['security.legacy_protocols.mdns'].acquisition_outcome  | Should -Be 'restricted'
        }

        It 'produces no default_inferred provenance anywhere in the section' {
            # Guards the whole module at once: a failed path test must never
            # license an inferred effective value on any field.
            $inferred = @(
                $script:Section['legacy_protocols'].Keys |
                    Where-Object { $_ -like '*_value_source' } |
                    Where-Object { $script:Section['legacy_protocols'][$_] -eq 'default_inferred' }
            )
            $inferred -join ', ' | Should -BeNullOrEmpty
        }
    }

    Context 'when the NetBIOS provider fails' {

        BeforeEach {
            Mock Test-Path { $false }
            Mock Get-ItemProperty { [pscustomobject]@{} }
            Mock Get-CimInstance {
                throw (New-TestErrorRecord -Exception ([System.InvalidOperationException]::new('CIM query failed.')))
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityLegacyProtocols -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not emit an empty adapter list that would read as "none enabled"' {
            $script:Section['legacy_protocols']['netbios_adapters'] | Should -BeNullOrEmpty
            $script:Section['legacy_protocols']['netbios_any_enabled'] | Should -BeNullOrEmpty
        }

        It 'records the NetBIOS unit as failed' {
            $script:Report['security.legacy_protocols.netbios'].acquisition_outcome | Should -Be 'failed'
        }

        It 'does not conceal the NetBIOS failure behind other successful units' {
            # LLMNR and mDNS succeeded in this scenario; NetBIOS did not.
            # Separate units are what make that visible.
            $script:Report['security.legacy_protocols.llmnr'].acquisition_outcome   | Should -Be 'success'
            $script:Report['security.legacy_protocols.netbios'].acquisition_outcome | Should -Be 'failed'
        }
    }
}


Describe 'Security.HostSecurity: native DMA query cannot fabricate a false' {

    # SOURCE-CONTRACT TEST.
    #
    # The native return path is not reachable through a Pester mock: the
    # NTSTATUS is produced inside compiled C# invoked as a static method,
    # so there is no PowerShell command to intercept. This test therefore
    # asserts the SOURCE CONTRACT of the embedded C#, which is what the
    # regression would actually consist of.
    #
    # It exists specifically to stop "non-zero status -> return 0" being
    # reintroduced. That shape made a failed native query indistinguishable
    # from an observed byte 0, which the caller reads as
    # kernel_dma_protection = $false and records as success.

    BeforeAll {
        $script:HostSecuritySource = Get-Content -Path (Join-Path $script:SecModules 'Security.HostSecurity.ps1') -Raw

        # The embedded C# lives in a single here-string.
        $script:NativeSource = ''
        if ($script:HostSecuritySource -match '(?s)\$bootDMAProtectionCheck\s*=\s*@"(.*?)"@') {
            $script:NativeSource = $Matches[1]
        }
    }

    It 'embeds the native DMA query as C# source' {
        $script:NativeSource | Should -Not -BeNullOrEmpty
        $script:NativeSource | Should -Match 'NtQuerySystemInformation'
        $script:NativeSource | Should -Match 'BootDmaCheck'
    }

    It 'throws on a non-zero NTSTATUS' {
        $script:NativeSource | Should -Match 'if\s*\(\s*result\s*!=\s*0\s*\)'
        $script:NativeSource | Should -Match 'throw\s+new\s+InvalidOperationException'
    }

    It 'includes the NTSTATUS value in the thrown message for triage' {
        $script:NativeSource | Should -Match 'result\.ToString\('
    }

    It 'contains no "non-zero status -> return 0" fallback' {
        # The precise regression being guarded against.
        $script:NativeSource | Should -Not -Match '(?m)^\s*return\s+0\s*;'
    }

    It 'does not gate the read behind a "result == 0" branch' {
        # The superseded shape, whose else-path was the silent return 0.
        $script:NativeSource | Should -Not -Match 'if\s*\(\s*result\s*==\s*0\s*\)'
    }

    It 'still returns the observed byte on NTSTATUS success' {
        # A returned byte of 0 under a successful status remains a valid
        # observed false and must not be suppressed by the fix.
        $script:NativeSource | Should -Match 'return\s+Marshal\.ReadByte\(\s*SystemInformation\s*,\s*0\s*\)\s*;'
    }

    It 'still frees the unmanaged buffer on every path' {
        $script:NativeSource | Should -Match 'finally'
        $script:NativeSource | Should -Match 'Marshal\.FreeHGlobal'
    }

    It 'routes a native failure to a non-success acquisition outcome' {
        # The PowerShell side of the contract: the catch must null the value
        # and record a failure, never complete the unit.
        $script:HostSecuritySource | Should -Match '\$securitySettings\["kernel_dma_protection"\]\s*=\s*\$null'
        $script:HostSecuritySource | Should -Match 'Set-VKAcquisitionFailure\s+-UnitId\s+\$dmaUnit'
    }

    It 'uses no type outside mscorlib, keeping the standalone dependency-free' {
        # InvalidOperationException is mscorlib; anything needing an extra
        # assembly reference could break Add-Type on a target machine.
        $script:NativeSource | Should -Not -Match 'using\s+System\.ComponentModel'
        $script:NativeSource | Should -Not -Match 'Win32Exception'
    }
}


Describe 'Security.HostSecurity: Device Guard failure never asserts false' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the Win32_DeviceGuard query fails' {

        BeforeEach {
            # Avoid loading and invoking the native DMA type during tests.
            Mock Add-Type { throw (New-TestErrorRecord -Exception ([System.InvalidOperationException]::new('Add-Type suppressed in tests.'))) }

            Mock Get-CimInstance {
                throw (New-TestErrorRecord `
                    -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied))
            } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }

            Mock Get-CimInstance {
                [pscustomobject]@{ DataExecutionPrevention_SupportPolicy = 2 }
            } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

            $script:Section = New-TestSection
            Invoke-VKSecurityHostSecurity -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not emit a populated security_services list' {
            # The schema 1.0 defect: a failed query produced a full list of
            # entries all reading configured=false, running=false.
            $script:Section['host_security']['security_services'] | Should -BeNullOrEmpty
        }

        It 'does not emit a populated security_properties list' {
            $script:Section['host_security']['security_properties'] | Should -BeNullOrEmpty
        }

        It 'does not assert a VBS status' {
            $script:Section['host_security']['vbs_status'] | Should -BeNullOrEmpty
        }

        It 'contains no confident false service state anywhere' {
            $services = $script:Section['host_security']['security_services']
            if ($services) {
                foreach ($service in $services) {
                    $service['configured'] | Should -Not -BeFalse
                    $service['running']    | Should -Not -BeFalse
                }
            }
            $services | Should -BeNullOrEmpty
        }

        It 'records the device_guard unit as restricted' {
            $script:Report['security.host_security.device_guard'].acquisition_outcome | Should -Be 'restricted'
        }

        It 'identifies all three governed Device Guard paths' {
            $paths = @($script:Report['security.host_security.device_guard'].data_paths)
            $paths | Should -Contain 'security.host_security.vbs_status'
            $paths | Should -Contain 'security.host_security.security_services'
            $paths | Should -Contain 'security.host_security.security_properties'
        }

        It 'does not let the successful DEP query conceal the Device Guard failure' {
            $script:Report['security.host_security.dep_policy'].acquisition_outcome   | Should -Be 'success'
            $script:Report['security.host_security.device_guard'].acquisition_outcome | Should -Be 'restricted'
        }
    }

    Context 'when the DEP provider answers with no value' {

        # Win32_OperatingSystem can answer without throwing and still supply
        # no instance, or an instance with no DataExecutionPrevention_
        # SupportPolicy. Casting $null to [int] yields 0, which maps to
        # "Always Off" - a confident negative the host never reported.
        BeforeEach {
            Mock Add-Type { throw (New-TestErrorRecord -Exception ([System.InvalidOperationException]::new('Add-Type suppressed in tests.'))) }

            Mock Get-CimInstance {
                [pscustomobject]@{
                    VirtualizationBasedSecurityStatus = 2
                    SecurityServicesConfigured        = @(1)
                    SecurityServicesRunning           = @(1)
                    AvailableSecurityProperties       = @(1)
                }
            } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }
        }

        Context 'because the instance itself is absent' {

            BeforeEach {
                Mock Get-CimInstance { $null } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

                $script:Section = New-TestSection
                Invoke-VKSecurityHostSecurity -Data $script:Section -IsAdmin $false
                Complete-VKAcquisitionReport
                $script:Report = Get-VKAcquisitionReport
            }

            It 'leaves dep_policy null' {
                $script:Section['host_security']['dep_policy'] | Should -BeNullOrEmpty
            }

            It 'never records "Always Off"' {
                $script:Section['host_security']['dep_policy'] | Should -Not -Be 'Always Off'
            }

            It 'records a non-success outcome' {
                $script:Report['security.host_security.dep_policy'].acquisition_outcome | Should -Not -Be 'success'
                $script:Report['security.host_security.dep_policy'].error.category | Should -Be 'provider_value_missing'
            }
        }

        Context 'because the property is absent from the instance' {

            BeforeEach {
                # An instance that answers, but carries no DEP property.
                Mock Get-CimInstance {
                    [pscustomobject]@{ Caption = 'Microsoft Windows 11 Enterprise' }
                } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

                $script:Section = New-TestSection
                Invoke-VKSecurityHostSecurity -Data $script:Section -IsAdmin $false
                Complete-VKAcquisitionReport
                $script:Report = Get-VKAcquisitionReport
            }

            It 'leaves dep_policy null' {
                $script:Section['host_security']['dep_policy'] | Should -BeNullOrEmpty
            }

            It 'never records "Always Off"' {
                $script:Section['host_security']['dep_policy'] | Should -Not -Be 'Always Off'
            }

            It 'records a non-success outcome' {
                $script:Report['security.host_security.dep_policy'].acquisition_outcome | Should -Not -Be 'success'
                $script:Report['security.host_security.dep_policy'].error.category | Should -Be 'provider_value_missing'
            }

            It 'does not let the DEP gap conceal the successful Device Guard query' {
                $script:Report['security.host_security.device_guard'].acquisition_outcome | Should -Be 'success'
            }
        }
    }

    Context 'when the DEP provider returns a genuine zero policy' {

        # Contrast case: 0 is a legitimate observed value meaning "Always
        # Off". The null guard must not suppress a real zero.
        BeforeEach {
            Mock Add-Type { throw (New-TestErrorRecord -Exception ([System.InvalidOperationException]::new('Add-Type suppressed in tests.'))) }

            Mock Get-CimInstance {
                [pscustomobject]@{ DataExecutionPrevention_SupportPolicy = 0 }
            } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

            Mock Get-CimInstance {
                throw (New-TestErrorRecord -Exception ([System.NotSupportedException]::new('No Device Guard.')))
            } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }

            $script:Section = New-TestSection
            Invoke-VKSecurityHostSecurity -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the observed "Always Off" value' {
            $script:Section['host_security']['dep_policy'] | Should -Be 'Always Off'
        }

        It 'records success, because the provider did answer' {
            $script:Report['security.host_security.dep_policy'].acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'when the Win32_DeviceGuard query succeeds' {

        BeforeEach {
            Mock Add-Type { throw (New-TestErrorRecord -Exception ([System.InvalidOperationException]::new('Add-Type suppressed in tests.'))) }

            Mock Get-CimInstance {
                [pscustomobject]@{
                    VirtualizationBasedSecurityStatus = 2
                    SecurityServicesConfigured        = @(1, 2)
                    SecurityServicesRunning           = @(1)
                    AvailableSecurityProperties       = @(1, 2)
                }
            } -ParameterFilter { $ClassName -eq 'Win32_DeviceGuard' }

            Mock Get-CimInstance {
                [pscustomobject]@{ DataExecutionPrevention_SupportPolicy = 2 }
            } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

            $script:Section = New-TestSection
            Invoke-VKSecurityHostSecurity -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the device_guard unit as success' {
            $script:Report['security.host_security.device_guard'].acquisition_outcome | Should -Be 'success'
        }

        It 'reports a configured and running service as true' {
            $credentialGuard = $script:Section['host_security']['security_services'] |
                Where-Object { $_['service_name'] -eq 'Credential Guard' }
            $credentialGuard['configured'] | Should -BeTrue
            $credentialGuard['running']    | Should -BeTrue
        }

        It 'reports false only where the returned data justifies it' {
            # Service id 2 is configured but not running, per the mock.
            $hvci = $script:Section['host_security']['security_services'] |
                Where-Object { $_['service_name'] -like 'HVCI*' }
            $hvci['configured'] | Should -BeTrue
            $hvci['running']    | Should -BeFalse
        }

        It 'retains the directly observed VBS status' {
            $script:Section['host_security']['vbs_status'] | Should -Be 'Enabled and running'
        }

        It 'retains existing null behaviour for the failed DMA probe' {
            $script:Section['host_security']['kernel_dma_protection'] | Should -BeNullOrEmpty
            $script:Report['security.host_security.kernel_dma_protection'].acquisition_outcome |
                Should -Not -Be 'success'
        }
    }
}


Describe 'Security.Antivirus: "Not Detected" never represents a failure' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the SecurityCenter2 query is denied' {

        BeforeEach {
            Mock Get-CimInstance {
                throw (New-TestErrorRecord `
                    -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied))
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityAntivirus -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not emit "Not Detected"' {
            # The schema 1.0 defect: -ErrorAction SilentlyContinue meant a
            # denied query produced product_name = "Not Detected", so an
            # acquisition failure presented as a C7 finding.
            $script:Section['antivirus']['product_name'] | Should -Not -Be 'Not Detected'
        }

        It 'emits no product evidence at all' {
            $script:Section['antivirus']['product_name']      | Should -BeNullOrEmpty
            $script:Section['antivirus']['product_state']     | Should -BeNullOrEmpty
            $script:Section['antivirus']['products_detected'] | Should -BeNullOrEmpty
        }

        It 'records the products unit as restricted' {
            $script:Report['security.antivirus.products'].acquisition_outcome | Should -Be 'restricted'
            $script:Report['security.antivirus.products'].error.category      | Should -Be 'access_denied'
        }

        It 'does not attempt Defender detail, and says so' {
            $entry = $script:Report['security.antivirus.defender_status']
            $entry.acquisition_outcome | Should -Be 'unavailable'
            $entry.error.category      | Should -Be 'precondition_not_met'
        }
    }

    Context 'when the SecurityCenter2 namespace is unavailable' {

        BeforeEach {
            Mock Get-CimInstance {
                throw (New-TestErrorRecord `
                    -Exception ([System.NotSupportedException]::new('Invalid namespace.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::NotImplemented))
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityAntivirus -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the products unit as unavailable, not failed' {
            $script:Report['security.antivirus.products'].acquisition_outcome | Should -Be 'unavailable'
        }

        It 'still emits no product evidence' {
            $script:Section['antivirus']['product_name'] | Should -BeNullOrEmpty
        }
    }

    Context 'when the query succeeds and returns zero products' {

        BeforeEach {
            Mock Get-CimInstance { @() }

            $script:Section = New-TestSection
            Invoke-VKSecurityAntivirus -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the products unit as success' {
            # A valid zero-result collection. This is what makes absence
            # ASSESSABLE downstream - it does not establish it here.
            $script:Report['security.antivirus.products'].acquisition_outcome | Should -Be 'success'
            $script:Report['security.antivirus.products'].error | Should -BeNullOrEmpty
        }

        It 'represents zero products structurally rather than with a prose sentinel' {
            $script:Section['antivirus']['products_detected'] | Should -Be 0
            $script:Section['antivirus']['product_name']      | Should -BeNullOrEmpty
        }

        It 'remains distinguishable from a failed query' {
            # Same payload question, two different acquisition outcomes.
            $zeroResultOutcome = $script:Report['security.antivirus.products'].acquisition_outcome

            Initialize-VKAcquisition
            Mock Get-CimInstance {
                throw (New-TestErrorRecord `
                    -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied))
            }
            $failedSection = New-TestSection
            Invoke-VKSecurityAntivirus -Data $failedSection -IsAdmin $false
            Complete-VKAcquisitionReport
            $failedOutcome = (Get-VKAcquisitionReport)['security.antivirus.products'].acquisition_outcome

            $zeroResultOutcome | Should -Be 'success'
            $failedOutcome     | Should -Be 'restricted'
            $zeroResultOutcome | Should -Not -Be $failedOutcome

            # And the payloads differ too: 0 versus null.
            $script:Section['antivirus']['products_detected'] | Should -Be 0
            $failedSection['antivirus']['products_detected']  | Should -BeNullOrEmpty
        }

        It 'marks Defender detail as not applicable' {
            $entry = $script:Report['security.antivirus.defender_status']
            $entry.acquisition_outcome | Should -Be 'unavailable'
            $entry.error.category      | Should -Be 'provider_not_applicable'
        }
    }

    Context 'when the query succeeds and returns a third-party product' {

        BeforeEach {
            Mock Get-CimInstance {
                @([pscustomobject]@{ displayName = 'Fixture Endpoint Protection'; productState = 397568 })
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityAntivirus -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'retains the observed product evidence' {
            $script:Section['antivirus']['product_name']      | Should -Be 'Fixture Endpoint Protection'
            $script:Section['antivirus']['products_detected'] | Should -Be 1
            $script:Section['antivirus']['product_state']['OperationalState'] | Should -Be 'On (Protection Enabled)'
        }

        It 'records the products unit as success' {
            $script:Report['security.antivirus.products'].acquisition_outcome | Should -Be 'success'
        }

        It 'marks Defender detail as not applicable rather than failed' {
            $script:Report['security.antivirus.defender_status'].error.category | Should -Be 'provider_not_applicable'
        }
    }

    Context 'when Defender is registered but its status provider returns null' {

        # Get-MpComputerStatus can return $null without throwing. Piping
        # that into Select-Object silently yields nothing, leaving every
        # Defender field null while the unit completes as SUCCESS - which
        # would record a successful empty observation the provider never
        # made.
        BeforeEach {
            Mock Get-CimInstance {
                @([pscustomobject]@{ displayName = 'Windows Defender'; productState = 397568 })
            }
            Mock Get-MpComputerStatus { $null }

            $script:Section = New-TestSection
            Invoke-VKSecurityAntivirus -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not record a successful empty observation' {
            $script:Report['security.antivirus.defender_status'].acquisition_outcome |
                Should -Not -Be 'success' -Because 'the provider returned nothing; it did not observe an empty state'
        }

        It 'records a non-success outcome with structured error data' {
            $entry = $script:Report['security.antivirus.defender_status']
            $entry.acquisition_outcome | Should -Be 'unavailable'
            $entry.error.category      | Should -Be 'provider_value_missing'
            $entry.error               | Should -Not -BeNullOrEmpty
        }

        It 'leaves the <_> Defender field null' -ForEach @(
            'running_mode'
            'real_time_protection'
            'antivirus_enabled'
            'antispyware_enabled'
            'antivirus_signature_updated'
            'antispyware_signature_updated'
        ) {
            $script:Section['antivirus'][$_] | Should -BeNullOrEmpty
        }

        It 'retains the product-level evidence that did succeed' {
            $script:Section['antivirus']['product_name'] | Should -Be 'Windows Defender'
            $script:Report['security.antivirus.products'].acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'when Defender is registered but its detail cannot be read' {

        BeforeEach {
            Mock Get-CimInstance {
                @([pscustomobject]@{ displayName = 'Windows Defender'; productState = 397568 })
            }
            Mock Get-MpComputerStatus {
                throw (New-TestErrorRecord `
                    -Exception ([System.UnauthorizedAccessException]::new('Access is denied.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::PermissionDenied))
            }

            $script:Section = New-TestSection
            Invoke-VKSecurityAntivirus -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'retains the product-level evidence that did succeed' {
            $script:Section['antivirus']['product_name'] | Should -Be 'Windows Defender'
            $script:Report['security.antivirus.products'].acquisition_outcome | Should -Be 'success'
        }

        It 'records the Defender unit as restricted without concealing it' {
            $script:Report['security.antivirus.defender_status'].acquisition_outcome | Should -Be 'restricted'
        }

        It 'asserts no Defender-level value' {
            $script:Section['antivirus']['real_time_protection'] | Should -BeNullOrEmpty
        }
    }
}
