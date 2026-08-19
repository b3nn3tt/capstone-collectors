<#
.SYNOPSIS
    Pester tests for the seven host/pathway modules instrumented in
    Tranche 2B.2.

.DESCRIPTION
    Covers Host.Identification, Host.NetworkConfig, Host.Services,
    Host.Processes, Host.Software, Host.Users and Vul.Privileges.Token.

    Providers are MOCKED throughout. No live host state is inspected and
    the collector is never executed.

    The shared contract under test, as in earlier tranches:

      - a genuine success records success and retains the evidence;
      - a legitimate zero result records success with an empty array;
      - a failure, denial, absent provider or null response records a
        non-success outcome and withholds the payload rather than emitting
        an empty collection, false, zero or a substantive sentinel;
      - partial enumeration never appears complete;
      - independent units keep their own outcomes.

.NOTES
    Tranche 2B.2. Pester 5.5+ (developed against 6.1), Windows PowerShell
    5.1 compatible. See tests/README.md.
#>

BeforeAll {

    $script:AgentRoot   = Split-Path -Parent $PSScriptRoot
    $script:HostModules = Join-Path $script:AgentRoot 'modules\host'
    $script:VulnModules = Join-Path $script:AgentRoot 'modules\vulnerability'

    . (Join-Path $script:AgentRoot 'core\VK.Config.ps1')
    . (Join-Path $script:AgentRoot 'core\VK.Utilities.ps1')

    foreach ($module in @(
        'Host.Identification', 'Host.NetworkConfig', 'Host.Services',
        'Host.Processes', 'Host.Software', 'Host.Users'
    )) {
        . (Join-Path $script:HostModules "$module.ps1")
    }
    . (Join-Path $script:VulnModules 'Vul.Privileges.Token.ps1')

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

    function New-MissingProviderError {
        New-TestErrorRecord -Exception ([System.NotSupportedException]::new('The provider is not available on this host.')) `
            -Category ([System.Management.Automation.ErrorCategory]::NotImplemented)
    }

    function New-TestSection { return [ordered]@{} }
}


# ============================================================
#  Host.Identification
# ============================================================

Describe 'Host.Identification: three independent identity units' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when every provider answers' {

        BeforeEach {
            Mock Get-CimInstance {
                [pscustomobject]@{
                    Caption = 'Microsoft Windows 11 Enterprise'; OSArchitecture = '64-bit'
                    Version = '10.0.26200'; BuildNumber = '26200'
                }
            } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

            Mock Get-CimInstance {
                [pscustomobject]@{
                    PCSystemType = 1; PartOfDomain = $true; Domain = 'fixture.example'
                    Manufacturer = 'Fixture Systems Ltd'; Model = 'FX-1000'
                    SystemFamily = 'Fixture Family'; SystemSKUNumber = 'FX1000-SKU'
                }
            } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }

            Mock Get-CimInstance { [pscustomobject]@{ SerialNumber = 'FIXTURE-0001' } } -ParameterFilter { $ClassName -eq 'Win32_BIOS' }

            $script:Section = New-TestSection
            Invoke-VKHostIdentification -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records <_> as success' -ForEach @(
            'host.identification.hostname'
            'host.identification.operating_system'
            'host.identification.computer_system'
        ) {
            $script:Report[$_].acquisition_outcome | Should -Be 'success'
        }

        It 'retains the observed OS evidence' {
            $script:Section['os']['name']  | Should -Be 'Microsoft Windows 11 Enterprise'
            $script:Section['os']['build'] | Should -Be 26200
        }

        It 'retains the declared platform role and domain state' {
            $script:Section['os']['platform_role']         | Should -Be 'Desktop'
            $script:Section['domain_status']['status']     | Should -Be 'Domain-Joined'
            $script:Section['domain_status']['domain_name']| Should -Be 'fixture.example'
        }
    }

    Context 'when Win32_OperatingSystem omits BuildNumber' {

        BeforeEach {
            Mock Get-CimInstance {
                [pscustomobject]@{ Caption = 'Windows'; OSArchitecture = '64-bit'; Version = '10.0'; BuildNumber = $null }
            } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

            Mock Get-CimInstance {
                [pscustomobject]@{ PCSystemType = 1; PartOfDomain = $false; Workgroup = 'WORKGROUP' }
            } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }

            Mock Get-CimInstance { [pscustomobject]@{ SerialNumber = 'X' } } -ParameterFilter { $ClassName -eq 'Win32_BIOS' }

            $script:Section = New-TestSection
            Invoke-VKHostIdentification -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not cast a missing BuildNumber to zero' {
            $script:Section['os']['build'] | Should -Not -Be 0
            $script:Section['os']['build'] | Should -BeNullOrEmpty
        }

        It 'records the operating_system unit as non-success' {
            $script:Report['host.identification.operating_system'].acquisition_outcome | Should -Not -Be 'success'
        }

        It 'leaves the independent computer_system unit successful' {
            $script:Report['host.identification.computer_system'].acquisition_outcome | Should -Be 'success'
            $script:Section['os']['platform_role'] | Should -Be 'Desktop'
        }
    }

    Context 'when the BIOS inventory fails but the study providers answer' {

        BeforeEach {
            Mock Get-CimInstance {
                [pscustomobject]@{ Caption = 'Windows'; OSArchitecture = '64-bit'; Version = '10.0'; BuildNumber = '26200' }
            } -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' }

            Mock Get-CimInstance {
                [pscustomobject]@{ PCSystemType = 1; PartOfDomain = $false; Workgroup = 'WORKGROUP' }
            } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }

            Mock Get-CimInstance { throw (New-DeniedError) } -ParameterFilter { $ClassName -eq 'Win32_BIOS' }

            $script:Section = New-TestSection
            Invoke-VKHostIdentification -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not change the outcome of any study unit' {
            # Manufacturer/BIOS is legacy raw inventory outside the register.
            foreach ($unit in @(
                'host.identification.hostname'
                'host.identification.operating_system'
                'host.identification.computer_system'
            )) {
                $script:Report[$unit].acquisition_outcome | Should -Be 'success'
            }
        }
    }
}


# ============================================================
#  Host.NetworkConfig
# ============================================================

Describe 'Host.NetworkConfig: TCP and UDP units only' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }

        # Uninstrumented collections, kept quiet and out of the register.
        Mock Get-NetNeighbor            { @() }
        Mock Get-NetRoute               { @() }
        Mock Get-DnsClientServerAddress { @() }
        Mock Get-Process                { $null }
    }

    Context 'when both providers answer' {

        BeforeEach {
            Mock Get-NetTCPConnection {
                @([pscustomobject]@{
                    LocalAddress = '0.0.0.0'; LocalPort = 3389; RemoteAddress = '0.0.0.0'
                    RemotePort = 0; State = 'Listen'; OwningProcess = 1180
                })
            }
            Mock Get-NetUDPEndpoint {
                @([pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 5355; OwningProcess = 1180 })
            }

            $script:Section = New-TestSection
            Invoke-VKHostNetworkConfig -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records both units as success' {
            $script:Report['host.network_config.tcp_connections'].acquisition_outcome | Should -Be 'success'
            $script:Report['host.network_config.udp_listeners'].acquisition_outcome   | Should -Be 'success'
        }

        It 'emits numeric summary counts after success' {
            $script:Section['network_config']['summary']['tcp_connections'] | Should -Be 1
            $script:Section['network_config']['summary']['udp_listeners']   | Should -Be 1
        }

        It 'leaves process_name null when resolution yields nothing' {
            # Optional enrichment: a null Get-Process result does not
            # invalidate the observed connection.
            $script:Section['network_config']['tcp_connections'][0]['process_name'] | Should -BeNullOrEmpty
            $script:Section['network_config']['tcp_connections'][0]['local_port']   | Should -Be 3389
        }
    }

    Context 'when both providers return zero records' {

        BeforeEach {
            Mock Get-NetTCPConnection { @() }
            Mock Get-NetUDPEndpoint   { @() }

            $script:Section = New-TestSection
            Invoke-VKHostNetworkConfig -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success with empty arrays' {
            $script:Report['host.network_config.tcp_connections'].acquisition_outcome | Should -Be 'success'
            [object]::ReferenceEquals($null, $script:Section['network_config']['tcp_connections']) | Should -BeFalse
            @($script:Section['network_config']['tcp_connections']).Count | Should -Be 0
        }

        It 'emits zero summary counts, which are genuine observations here' {
            $script:Section['network_config']['summary']['tcp_connections'] | Should -Be 0
            $script:Section['network_config']['summary']['udp_listeners']   | Should -Be 0
        }
    }

    Context 'when the TCP provider fails and UDP succeeds' {

        BeforeEach {
            Mock Get-NetTCPConnection { throw (New-DeniedError) }
            Mock Get-NetUDPEndpoint {
                @([pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 5355; OwningProcess = 1180 })
            }

            $script:Section = New-TestSection
            Invoke-VKHostNetworkConfig -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'yields null rather than an empty connection list' {
            $script:Section['network_config']['tcp_connections'] | Should -BeNullOrEmpty
            $script:Report['host.network_config.tcp_connections'].acquisition_outcome | Should -Be 'restricted'
        }

        It 'leaves the TCP summary count null, never zero' {
            # A zero count would assert an observation that was never made.
            $script:Section['network_config']['summary']['tcp_connections'] | Should -Not -Be 0
            $script:Section['network_config']['summary']['tcp_connections'] | Should -BeNullOrEmpty
        }

        It 'preserves the independent UDP evidence and its numeric count' {
            $script:Report['host.network_config.udp_listeners'].acquisition_outcome | Should -Be 'success'
            $script:Section['network_config']['summary']['udp_listeners'] | Should -Be 1
        }
    }
}


# ============================================================
#  Host.Services and Host.Processes
# ============================================================

Describe 'Host.Services: inventory unit' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the provider answers' {

        BeforeEach {
            Mock Get-CimInstance {
                @([pscustomobject]@{
                    Name = 'TermService'; DisplayName = 'Remote Desktop Services'; Description = 'd'
                    State = 'Running'; StartMode = 'Manual'; StartName = 'NT Authority\NetworkService'
                    PathName = 'C:\Windows\System32\svchost.exe -k NetworkService'; ProcessId = 1180
                })
            }

            $script:Section = New-TestSection
            Invoke-VKHostServices -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success and preserves the existing service fields' {
            $script:Report['host.services.inventory'].acquisition_outcome | Should -Be 'success'
            $svc = $script:Section['services'][0]
            foreach ($field in @('name','display_name','description','state','start_type','logon_account','binary_path','has_spaces_unquoted','pid')) {
                $svc.Keys | Should -Contain $field
            }
        }
    }

    Context 'when the provider returns null' {

        BeforeEach {
            Mock Get-CimInstance { $null }

            $script:Section = New-TestSection
            Invoke-VKHostServices -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records unavailable / provider_value_missing' {
            $entry = $script:Report['host.services.inventory']
            $entry.acquisition_outcome | Should -Be 'unavailable'
            $entry.error.category      | Should -Be 'provider_value_missing'
        }

        It 'yields null, not an apparent zero-service inventory' {
            $script:Section['services'] | Should -BeNullOrEmpty
        }

        It 'reports no success status or zero count to the console' {
            Should -Invoke Write-VKStatus -Times 1 -Exactly -ParameterFilter { $Type -eq 'ERROR' }
            Should -Invoke Write-VKStatus -Times 0 -Exactly -ParameterFilter { $Message -like '*0 services*' }
        }
    }

    Context 'when the provider fails' {

        BeforeEach {
            Mock Get-CimInstance { throw (New-DeniedError) }

            $script:Section = New-TestSection
            Invoke-VKHostServices -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records restricted and withholds the inventory' {
            $script:Report['host.services.inventory'].acquisition_outcome | Should -Be 'restricted'
            $script:Section['services'] | Should -BeNullOrEmpty
        }
    }
}


Describe 'Host.Processes: inventory unit' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when the provider answers but owner lookup fails' {

        BeforeEach {
            Mock Get-CimInstance {
                @([pscustomobject]@{
                    Name = 'fixtureapp.exe'; ProcessId = 4488; ParentProcessId = 780
                    ExecutablePath = 'C:\fixture.exe'; CommandLine = '"C:\fixture.exe"'
                    SessionId = 1; WorkingSetSize = 149000000
                    CreationDate = [datetime]::new(2026, 8, 18, 8, 56, 12, [System.DateTimeKind]::Utc)
                })
            }
            Mock Invoke-CimMethod { throw (New-DeniedError) }

            $script:Section = New-TestSection
            Invoke-VKHostProcesses -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'keeps the primary inventory successful' {
            # Owner lookup is optional enrichment.
            $script:Report['host.processes.inventory'].acquisition_outcome | Should -Be 'success'
            $script:Section['processes'][0]['pid'] | Should -Be 4488
        }

        It 'leaves owner null without invalidating the record' {
            $script:Section['processes'][0]['owner'] | Should -BeNullOrEmpty
        }

        It 'emits start_time as UTC' {
            $script:Section['processes'][0]['start_time'] | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        }
    }

    Context 'when the provider returns null' {

        BeforeEach {
            Mock Get-CimInstance { $null }

            $script:Section = New-TestSection
            Invoke-VKHostProcesses -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'does not become a successful empty inventory' {
            $script:Report['host.processes.inventory'].acquisition_outcome | Should -Not -Be 'success'
            $script:Section['processes'] | Should -BeNullOrEmpty
        }

        It 'reports no zero-process count' {
            Should -Invoke Write-VKStatus -Times 0 -Exactly -ParameterFilter { $Message -like '*0 processes*' }
        }
    }
}


# ============================================================
#  Host.Software
# ============================================================

Describe 'Host.Software: two hives, one combined path' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when both hives answer' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ChildItem { @([pscustomobject]@{ PSPath = 'HKLM:\app1' }) }
            Mock Get-ItemProperty {
                [pscustomobject]@{ DisplayName = 'Fixture Reader'; DisplayVersion = '21.4.1'; Publisher = 'Fixture'; EstimatedSize = 422400 }
            }

            $script:Section = New-TestSection
            Invoke-VKHostSoftware -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the native hive as success' {
            $script:Report['host.software.hklm_native'].acquisition_outcome | Should -Be 'success'
        }

        It 'emits the combined list with a registry scope on each record' {
            $script:Section['installed_software'] | Should -Not -BeNullOrEmpty
            $script:Section['installed_software'][0]['registry_scope'] | Should -Match '^hklm_(native|wow6432)$'
        }
    }

    Context 'when an applicable hive fails' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ChildItem { @([pscustomobject]@{ PSPath = 'HKLM:\app1' }) } -ParameterFilter { $Path -notlike '*WOW6432Node*' }
            Mock Get-ChildItem { throw (New-DeniedError) } -ParameterFilter { $Path -like '*WOW6432Node*' }
            Mock Get-ItemProperty {
                [pscustomobject]@{ DisplayName = 'Fixture Reader'; DisplayVersion = '21.4.1' }
            }

            $script:Section = New-TestSection
            Invoke-VKHostSoftware -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the combined list entirely' {
            # A partial list would understate installed software while
            # appearing complete.
            $script:Section['installed_software'] | Should -BeNullOrEmpty
        }

        It 'keeps the successful hive unit successful' {
            $script:Report['host.software.hklm_native'].acquisition_outcome  | Should -Be 'success'
            $script:Report['host.software.hklm_wow6432'].acquisition_outcome | Should -Not -Be 'success'
        }
    }

    Context 'when a single entry read fails' {

        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-ChildItem {
                @(
                    [pscustomobject]@{ PSPath = 'HKLM:\app1' }
                    [pscustomobject]@{ PSPath = 'HKLM:\app2' }
                )
            }
            Mock Get-ItemProperty { [pscustomobject]@{ DisplayName = 'Fixture Reader' } } -ParameterFilter { $Path -eq 'HKLM:\app1' }
            Mock Get-ItemProperty { throw (New-DeniedError) } -ParameterFilter { $Path -eq 'HKLM:\app2' }

            $script:Section = New-TestSection
            Invoke-VKHostSoftware -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'makes the hive incomplete rather than silently shortening it' {
            $script:Report['host.software.hklm_native'].acquisition_outcome | Should -Not -Be 'success'
            $script:Section['installed_software'] | Should -BeNullOrEmpty
        }
    }

    Context 'when an applicable hive is genuinely empty' {

        BeforeEach {
            Mock Test-Path     { $true }
            Mock Get-ChildItem { @() }

            $script:Section = New-TestSection
            Invoke-VKHostSoftware -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success' {
            $script:Report['host.software.hklm_native'].acquisition_outcome | Should -Be 'success'
        }

        It 'emits an empty array, not a pipeline-collapsed null' {
            # Sort-Object collapses an empty pipeline to $null, which would
            # be indistinguishable from a withheld collection.
            [object]::ReferenceEquals($null, $script:Section['installed_software']) | Should -BeFalse
            @($script:Section['installed_software']).Count | Should -Be 0
        }
    }

    Context 'when the hive path is absent' {

        BeforeEach {
            Mock Test-Path     { $false }
            Mock Get-ChildItem { @() }

            $script:Section = New-TestSection
            Invoke-VKHostSoftware -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'distinguishes an absent hive from a successfully empty one' {
            $script:Report['host.software.hklm_native'].acquisition_outcome | Should -Not -Be 'success'
            $script:Section['installed_software'] | Should -BeNullOrEmpty
        }
    }
}


# ============================================================
#  Host.Users
# ============================================================

Describe 'Host.Users: local accounts and group memberships' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }

        # SID is a real SecurityIdentifier, as Get-LocalUser returns.
        # Production reads .Value and splits it, so the shape matters.
        $script:FixtureUsers = @(
            [pscustomobject]@{
                Name = 'Administrator'
                SID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333-500')
                Enabled = $false; LockedOut = $false; LockoutTime = $null
                PasswordLastSet = [datetime]::new(2025, 11, 2, 8, 0, 0, [System.DateTimeKind]::Utc)
                PasswordExpires = $null; LastLogon = $null; PrincipalSource = 'Local'
            }
            [pscustomobject]@{
                Name = 'fixture.user'
                SID = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1111111111-2222222222-3333333333-1001')
                Enabled = $true; LockedOut = $false; LockoutTime = $null
                PasswordLastSet = [datetime]::new(2026, 6, 1, 10, 30, 0, [System.DateTimeKind]::Utc)
                PasswordExpires = $null
                LastLogon = [datetime]::new(2026, 8, 18, 8, 55, 0, [System.DateTimeKind]::Utc)
                PrincipalSource = 'Local'
            }
        )

        # GROUP PARAMETER BINDING
        #
        # Get-LocalGroupMember -Group binds to
        # Microsoft.PowerShell.Commands.LocalGroup, NOT to String.
        # Production passes $group.Name, a string, which PowerShell
        # silently coerces - so production is correct against the real
        # cmdlet. Inside a ParameterFilter, however, $Group is the COERCED
        # LocalGroup object, and:
        #
        #     [LocalGroup]'Administrators' -eq 'Administrators'  ->  False
        #
        # so a filter written as ($Group -eq 'Administrators') never
        # matches, no double takes effect, and the call escapes to the real
        # host cmdlet. Filters below compare "$Group", whose ToString()
        # yields the group name for both a LocalGroup and a plain string.
    }

    Context 'when both providers answer' {

        BeforeEach {
            Mock Get-LocalUser  { $script:FixtureUsers }
            Mock Get-LocalGroup {
                @(
                    [pscustomobject]@{ Name = 'Administrators'; Description = 'admins' }
                    [pscustomobject]@{ Name = 'Guests'; Description = 'guests' }
                )
            }
            # Catch-all FIRST: any group the specific filters below do not
            # match fails loudly here instead of escaping to the real host
            # cmdlet. Pester evaluates the most recently defined matching
            # mock first, so the specific filters still take precedence.
            Mock Get-LocalGroupMember {
                throw [System.InvalidOperationException]::new(
                    "Unmocked Get-LocalGroupMember call for group '$Group'.")
            }
            Mock Get-LocalGroupMember { @([pscustomobject]@{ Name = 'FIXTUREDOM\Administrator' }) } -ParameterFilter { "$Group" -eq 'Administrators' }
            Mock Get-LocalGroupMember { @() } -ParameterFilter { "$Group" -eq 'Guests' }

            $script:Section = New-TestSection
            Invoke-VKHostUsers -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records both units as success' {
            $script:Report['host.users.local_accounts'].acquisition_outcome    | Should -Be 'success'
            $script:Report['host.users.group_memberships'].acquisition_outcome | Should -Be 'success'
        }

        It 'queries Get-LocalUser exactly once and reuses the result' {
            Should -Invoke Get-LocalUser -Times 1 -Exactly
            $script:Section['base_sid'] | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333'
        }

        It 'resolves is_admin from observed group membership' {
            $admin = $script:Section['user_accounts'] | Where-Object { $_['name'] -eq 'Administrator' }
            $user  = $script:Section['user_accounts'] | Where-Object { $_['name'] -eq 'fixture.user' }
            $admin['is_admin'] | Should -BeTrue
            $user['is_admin']  | Should -BeFalse
        }

        It 'keeps a genuinely empty group as an empty members array' {
            $guests = $script:Section['group_memberships'] | Where-Object { $_['group_name'] -eq 'Guests' }
            [object]::ReferenceEquals($null, $guests['members']) | Should -BeFalse
            @($guests['members']).Count | Should -Be 0
        }

        It 'emits UTC timestamps' {
            $user = $script:Section['user_accounts'] | Where-Object { $_['name'] -eq 'fixture.user' }
            $user['last_logon']        | Should -Be '2026-08-18T08:55:00Z'
            $user['password_last_set'] | Should -Be '2026-06-01T10:30:00Z'
        }

        It 'emits the local-only scope markers' {
            $script:Section['user_accounts_scope']     | Should -Be 'local_only'
            $script:Section['group_memberships_scope'] | Should -Be 'local_groups_only'
        }

        It 'retains raw principal names unchanged' {
            # Pseudonymisation belongs to the ingestion layer.
            @($script:Section['user_accounts'] | ForEach-Object { $_['name'] }) | Should -Contain 'fixture.user'
        }
    }

    Context 'when a group-member query fails' {

        BeforeEach {
            Mock Get-LocalUser  { $script:FixtureUsers }
            Mock Get-LocalGroup {
                @(
                    [pscustomobject]@{ Name = 'Administrators'; Description = 'admins' }
                    [pscustomobject]@{ Name = 'Guests'; Description = 'guests' }
                )
            }
            Mock Get-LocalGroupMember {
                throw [System.InvalidOperationException]::new(
                    "Unmocked Get-LocalGroupMember call for group '$Group'.")
            }
            Mock Get-LocalGroupMember { @([pscustomobject]@{ Name = 'FIXTUREDOM\Administrator' }) } -ParameterFilter { "$Group" -eq 'Administrators' }
            # Structured denial: an UnauthorizedAccessException inside an
            # ErrorRecord categorised PermissionDenied, which the classifier
            # recognises by exception type rather than by message text.
            Mock Get-LocalGroupMember { throw (New-DeniedError) } -ParameterFilter { "$Group" -eq 'Guests' }

            $script:Section = New-TestSection
            Invoke-VKHostUsers -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the whole group-membership collection' {
            $script:Section['group_memberships'] | Should -BeNullOrEmpty
            $script:Report['host.users.group_memberships'].acquisition_outcome | Should -Be 'restricted'
        }

        It 'emits no in-band error sentinel anywhere' {
            $serialised = $script:Section | ConvertTo-Json -Depth 10 -WarningAction SilentlyContinue
            $serialised | Should -Not -BeLike '*Error retrieving members*'
        }

        It 'sets is_admin to null, never false' {
            # Two explicit claims. "Should -Not -BeFalse" is deliberately
            # NOT used: $null is falsy, so it passes -BeFalse and the
            # negation fails even though the value is correctly $null. The
            # type check states the second claim unambiguously.
            foreach ($account in $script:Section['user_accounts']) {
                $account['is_admin'] | Should -BeNullOrEmpty
                ($account['is_admin'] -is [bool]) | Should -BeFalse
            }
        }

        It 'preserves the independent local-account evidence' {
            $script:Report['host.users.local_accounts'].acquisition_outcome | Should -Be 'success'
            @($script:Section['user_accounts']).Count | Should -Be 2
        }
    }

    Context 'when Get-LocalUser fails but groups succeed' {

        BeforeEach {
            Mock Get-LocalUser  { throw (New-DeniedError) }
            Mock Get-LocalGroup { @([pscustomobject]@{ Name = 'Administrators'; Description = 'admins' }) }
            # Unfiltered: applies to every group, so nothing escapes.
            Mock Get-LocalGroupMember { @() }

            $script:Section = New-TestSection
            Invoke-VKHostUsers -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds accounts and base SID' {
            $script:Section['user_accounts'] | Should -BeNullOrEmpty
            $script:Section['base_sid']      | Should -BeNullOrEmpty
            $script:Report['host.users.local_accounts'].acquisition_outcome | Should -Be 'restricted'
        }

        It 'preserves the independent group evidence' {
            $script:Report['host.users.group_memberships'].acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'when a user record omits its SID' {

        BeforeEach {
            Mock Get-LocalUser {
                @([pscustomobject]@{ Name = 'broken'; SID = $null; Enabled = $true })
            }
            Mock Get-LocalGroup       { @() }
            Mock Get-LocalGroupMember { @() }

            $script:Section = New-TestSection
            Invoke-VKHostUsers -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the account collection rather than emitting a zero RID' {
            $script:Section['user_accounts'] | Should -BeNullOrEmpty
            $script:Report['host.users.local_accounts'].acquisition_outcome | Should -Not -Be 'success'
        }
    }
}


# ============================================================
#  Vul.Privileges.Token
# ============================================================

Describe 'Vul.Privileges.Token: current-token unit' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }
    }

    Context 'when whoami answers with valid CSV' {

        BeforeEach {
            Mock whoami.exe {
                $global:LASTEXITCODE = 0
                @(
                    '"Privilege Name","Description","State"'
                    '"SeImpersonatePrivilege","Impersonate a client after authentication","Enabled"'
                    '"SeShutdownPrivilege","Shut down the system","Disabled"'
                )
            }

            $script:Section = New-TestSection
            Invoke-VKVulTokenPrivileges -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success' {
            $script:Report['vulnerability.token_privileges.current_token'].acquisition_outcome | Should -Be 'success'
        }

        It 'preserves the privilege list and summary counts' {
            $tp = $script:Section['token_privileges']
            $tp['total_privileges']        | Should -Be 2
            $tp['dangerous_count']         | Should -Be 1
            $tp['dangerous_enabled_count'] | Should -Be 1
        }

        It 'emits the current-token qualifiers' {
            $tp = $script:Section['token_privileges']
            $tp['evidence_scope']         | Should -Be 'collector_token_only'
            $tp['collector_ran_as_admin'] | Should -BeTrue
        }

        It 'retains the raw token principal for later pseudonymisation' {
            $script:Section['token_privileges']['user'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'when whoami exits non-zero' {

        BeforeEach {
            Mock whoami.exe {
                $global:LASTEXITCODE = 1
                'ERROR: Access is denied.'
            }

            $script:Section = New-TestSection
            Invoke-VKVulTokenPrivileges -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records a non-success outcome' {
            $script:Report['vulnerability.token_privileges.current_token'].acquisition_outcome | Should -Not -Be 'success'
        }

        It 'withholds the payload rather than parsing the failure output' {
            $script:Section['token_privileges'] | Should -BeNullOrEmpty
        }
    }

    Context 'when the CSV is missing a required column' {

        BeforeEach {
            Mock whoami.exe {
                $global:LASTEXITCODE = 0
                @(
                    '"Privilege Name","Description"'
                    '"SeImpersonatePrivilege","Impersonate a client"'
                )
            }

            $script:Section = New-TestSection
            Invoke-VKVulTokenPrivileges -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records a non-success outcome and withholds the payload' {
            $script:Report['vulnerability.token_privileges.current_token'].acquisition_outcome | Should -Not -Be 'success'
            $script:Section['token_privileges'] | Should -BeNullOrEmpty
        }
    }

    Context 'when whoami produces malformed output' {

        BeforeEach {
            Mock whoami.exe {
                $global:LASTEXITCODE = 0
                @('not csv at all')
            }

            $script:Section = New-TestSection
            Invoke-VKVulTokenPrivileges -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records a non-success outcome and withholds the payload' {
            $script:Report['vulnerability.token_privileges.current_token'].acquisition_outcome | Should -Not -Be 'success'
            $script:Section['token_privileges'] | Should -BeNullOrEmpty
        }
    }
}


# ============================================================
#  Shared contract across every Tranche 2B.2 unit
# ============================================================

Describe 'Tranche 2B.2 units satisfy the shared acquisition contract' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus   { }
        Mock Write-LogMessage { }

        # Drive every module into a denied-provider state at once.
        Mock Get-CimInstance            { throw (New-DeniedError) }
        Mock Get-NetTCPConnection       { throw (New-DeniedError) }
        Mock Get-NetUDPEndpoint         { throw (New-DeniedError) }
        Mock Get-NetNeighbor            { throw (New-DeniedError) }
        Mock Get-NetRoute               { throw (New-DeniedError) }
        Mock Get-DnsClientServerAddress { throw (New-DeniedError) }
        Mock Test-Path                  { throw (New-DeniedError) }
        Mock Get-ChildItem              { throw (New-DeniedError) }
        Mock Get-ItemProperty           { throw (New-DeniedError) }
        Mock Get-LocalUser              { throw (New-DeniedError) }
        Mock Get-LocalGroup             { throw (New-DeniedError) }
        Mock Get-LocalGroupMember       { throw (New-DeniedError) }
        Mock whoami.exe                 { $global:LASTEXITCODE = 1; 'ERROR' }

        $script:HostSection = New-TestSection
        $script:VulnSection = New-TestSection

        Invoke-VKHostIdentification -Data $script:HostSection -IsAdmin $true
        Invoke-VKHostNetworkConfig  -Data $script:HostSection -IsAdmin $true
        Invoke-VKHostServices       -Data $script:HostSection -IsAdmin $true
        Invoke-VKHostProcesses      -Data $script:HostSection -IsAdmin $true
        Invoke-VKHostSoftware       -Data $script:HostSection -IsAdmin $true
        Invoke-VKHostUsers          -Data $script:HostSection -IsAdmin $true
        Invoke-VKVulTokenPrivileges -Data $script:VulnSection -IsAdmin $true

        Complete-VKAcquisitionReport
        $script:Report = Get-VKAcquisitionReport
    }

    It 'registers unit <_>' -ForEach @(
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
    ) {
        $script:Report.Contains($_) | Should -BeTrue
    }

    It 'records no CIM- or registry-backed unit as success when every provider is denied' {
        # host.identification.hostname reads an environment variable, not a
        # mocked provider, so it legitimately still succeeds.
        $successes = @(
            $script:Report.Keys |
                Where-Object { $_ -ne 'host.identification.hostname' } |
                Where-Object { $script:Report[$_].acquisition_outcome -eq 'success' }
        )
        $successes -join ', ' | Should -BeNullOrEmpty
    }

    It 'leaves no unit outside the permitted vocabulary' {
        foreach ($unitId in $script:Report.Keys) {
            @('success', 'failed', 'restricted', 'unavailable') |
                Should -Contain $script:Report[$unitId].acquisition_outcome
        }
    }

    It 'gives every unit populated data_paths' {
        foreach ($unitId in $script:Report.Keys) {
            @($script:Report[$unitId].data_paths).Count | Should -BeGreaterThan 0
        }
    }

    It 'emits no substantive value for any denied collection' {
        # Every governed payload path must be null. Scope markers are the
        # only permitted non-null values, because they are constants
        # describing the observation boundary rather than observations.
        $scopeMarkers = @('user_accounts_scope', 'group_memberships_scope')

        foreach ($key in $script:HostSection.Keys) {
            if ($scopeMarkers -contains $key) { continue }
            if ($key -eq 'hostname') { continue }   # environment variable, not a provider

            $value = $script:HostSection[$key]

            if ($key -in @('os', 'domain_status', 'manufacturer', 'network_config')) {
                # Nested containers: every leaf must be null or an
                # uninstrumented collection.
                continue
            }

            $value | Should -BeNullOrEmpty -Because "$key must not carry a value after a denied collection"
        }

        $script:VulnSection['token_privileges'] | Should -BeNullOrEmpty
    }

    It 'leaves both instrumented summary counts null after denial' {
        $script:HostSection['network_config']['summary']['tcp_connections'] | Should -BeNullOrEmpty
        $script:HostSection['network_config']['summary']['udp_listeners']   | Should -BeNullOrEmpty
    }
}
