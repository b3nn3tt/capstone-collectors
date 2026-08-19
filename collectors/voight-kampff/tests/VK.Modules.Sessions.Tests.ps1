<#
.SYNOPSIS
    Pester tests for Host.Sessions (Tranche 2C).

.DESCRIPTION
    Session and recent-profile telemetry. All providers are MOCKED at the
    PowerShell wrapper boundary (Initialize-VKWtsInterop,
    Get-VKWtsSessionRecords, Get-VKWtsSessionString,
    Get-VKWtsSessionProtocolType, Get-CimInstance), so no native call is
    made, no live session table is read and no live profile is inspected.

    Central property under test: the three units must not share fate.

    NOTE ON SETUP SCOPE
    Pester 6 rejects BeforeEach in the container root, so the common setup
    is declared once per Describe. Root BeforeAll remains valid.

.NOTES
    Tranche 2C. Pester 5.5+ (developed against 6.1), Windows PowerShell
    5.1 compatible. See tests/README.md.
#>

BeforeAll {

    $script:AgentRoot   = Split-Path -Parent $PSScriptRoot
    $script:HostModules = Join-Path $script:AgentRoot 'modules\host'

    . (Join-Path $script:AgentRoot 'core\VK.Config.ps1')
    . (Join-Path $script:AgentRoot 'core\VK.Utilities.ps1')
    . (Join-Path $script:HostModules 'Host.Sessions.ps1')

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

    function New-TestSection { return [ordered]@{} }

    # Realistic WTS record shape: SessionId int, WinStationName string,
    # State int (WTS_CONNECTSTATE_CLASS ordinal) - what the interop layer
    # returns.
    function New-WtsSession {
        param([int]$SessionId, [string]$WinStationName, [int]$State)
        return [pscustomobject]@{
            SessionId      = $SessionId
            WinStationName = $WinStationName
            State          = $State
        }
    }

    # Structured native failure carrying NativeErrorCode, as
    # VoightKampff.WtsException does. 5 = ERROR_ACCESS_DENIED.
    function New-WtsNativeError {
        param([int]$Code = 5, [string]$Message = 'WTSQuerySessionInformation failed.')
        $ex = [System.Exception]::new($Message)
        $ex | Add-Member -NotePropertyName 'NativeErrorCode' -NotePropertyValue $Code -Force
        return New-TestErrorRecord -Exception $ex
    }

    function New-UserProfile {
        param([string]$Sid, [bool]$Loaded, [bool]$Special, $LastUseTime)
        return [pscustomobject]@{
            SID         = $Sid
            Loaded      = $Loaded
            Special     = $Special
            LastUseTime = $LastUseTime
        }
    }

    $script:StateActive       = 0
    $script:StateDisconnected = 4
    $script:StateListen       = 6

    $script:ProtoConsole = 0
    $script:ProtoLegacy  = 1
    $script:ProtoRemote  = 2
}


# ============================================================
#  Current sessions (WTS enumeration)
# ============================================================

Describe 'Host.Sessions: current session evidence' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus         { }
        Mock Write-LogMessage       { }
        Mock Initialize-VKWtsInterop { }

        # Profiles answer by default so profile failures never explain a
        # session-unit result.
        Mock Get-CimInstance {
            @(New-UserProfile -Sid 'S-1-5-18' -Loaded $true -Special $true -LastUseTime ([datetime]::UtcNow))
        }
        # Catch-all: nothing escapes to a live provider.
        Mock Get-VKWtsSessionString { throw (New-WtsNativeError -Message 'Unmocked principal query.') }
    }

    Context 'active console session' {

        BeforeEach {
            Mock Get-VKWtsSessionRecords { @(New-WtsSession -SessionId 1 -WinStationName 'Console' -State $script:StateActive) }
            Mock Get-VKWtsSessionProtocolType { $script:ProtoConsole }
            Mock Get-VKWtsSessionString { 'alice' } -ParameterFilter { $InfoClass -eq 5 }
            Mock Get-VKWtsSessionString { 'FIXTUREDOM' } -ParameterFilter { $InfoClass -eq 7 }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the session unit as success' {
            $script:Report['host.sessions.current_sessions'].acquisition_outcome | Should -Be 'success'
        }

        It 'classifies console from the protocol type, not the session name' {
            $s = $script:Section['sessions']['current_sessions'][0]
            $s['session_type']        | Should -Be 'console'
            $s['protocol_type']       | Should -Be 0
            $s['session_type_source'] | Should -Be 'wts_client_protocol_type'
            $s['state']               | Should -Be 'Active'
        }

        It 'emits no excluded field' -ForEach @(
            'client_name', 'client_address', 'logon_time', 'idle_time',
            'application_name', 'working_directory'
        ) {
            $script:Section['sessions']['current_sessions'][0].Keys | Should -Not -Contain $_
        }
    }

    Context 'active RDP session' {

        BeforeEach {
            Mock Get-VKWtsSessionRecords { @(New-WtsSession -SessionId 2 -WinStationName 'RDP-Tcp#0' -State $script:StateActive) }
            Mock Get-VKWtsSessionProtocolType { $script:ProtoRemote }
            Mock Get-VKWtsSessionString { 'bob' } -ParameterFilter { $InfoClass -eq 5 }
            Mock Get-VKWtsSessionString { 'FIXTUREDOM' } -ParameterFilter { $InfoClass -eq 7 }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'classifies remote from the protocol type' {
            $s = $script:Section['sessions']['current_sessions'][0]
            $s['session_type']  | Should -Be 'remote'
            $s['protocol_type'] | Should -Be 2
            $s['state']         | Should -Be 'Active'
        }
    }

    Context 'disconnected RDP session' {

        BeforeEach {
            Mock Get-VKWtsSessionRecords { @(New-WtsSession -SessionId 3 -WinStationName 'RDP-Tcp#1' -State $script:StateDisconnected) }
            Mock Get-VKWtsSessionProtocolType { $script:ProtoRemote }
            Mock Get-VKWtsSessionString { 'carol' } -ParameterFilter { $InfoClass -eq 5 }
            Mock Get-VKWtsSessionString { 'FIXTUREDOM' } -ParameterFilter { $InfoClass -eq 7 }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'preserves Disconnected as a distinct state' {
            # Disconnected must never collapse into "no session".
            $s = $script:Section['sessions']['current_sessions'][0]
            $s['state']        | Should -Be 'Disconnected'
            $s['session_type'] | Should -Be 'remote'
            $script:Section['sessions']['current_sessions_summary']['disconnected'] | Should -Be 1
            $script:Section['sessions']['current_sessions_summary']['active']       | Should -Be 0
        }
    }

    Context 'multiple simultaneous sessions including a listener' {

        BeforeEach {
            Mock Get-VKWtsSessionRecords {
                @(
                    New-WtsSession -SessionId 1     -WinStationName 'Console'   -State $script:StateActive
                    New-WtsSession -SessionId 2     -WinStationName 'RDP-Tcp#0' -State $script:StateActive
                    New-WtsSession -SessionId 3     -WinStationName 'RDP-Tcp#1' -State $script:StateDisconnected
                    New-WtsSession -SessionId 65536 -WinStationName 'RDP-Tcp'   -State $script:StateListen
                )
            }
            Mock Get-VKWtsSessionProtocolType { $script:ProtoConsole } -ParameterFilter { $SessionId -eq 1 }
            Mock Get-VKWtsSessionProtocolType { $script:ProtoRemote }  -ParameterFilter { $SessionId -in @(2, 3) }
            Mock Get-VKWtsSessionString { 'user{0}' -f $SessionId } -ParameterFilter { $InfoClass -eq 5 }
            Mock Get-VKWtsSessionString { 'FIXTUREDOM' } -ParameterFilter { $InfoClass -eq 7 }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'produces correct summary arithmetic' {
            $sum = $script:Section['sessions']['current_sessions_summary']
            $sum['total']        | Should -Be 4
            $sum['active']       | Should -Be 2
            $sum['disconnected'] | Should -Be 1
            $sum['console']      | Should -Be 1
            $sum['remote']       | Should -Be 2
            $sum['listener']     | Should -Be 1
        }

        It 'classifies the listener from connect state without a protocol query' {
            $listener = $script:Section['sessions']['current_sessions'] | Where-Object { $_['state'] -eq 'Listen' }
            $listener['session_type']        | Should -Be 'listener'
            $listener['session_type_source'] | Should -Be 'connect_state'
            $listener['protocol_type']       | Should -BeNullOrEmpty

            Should -Invoke Get-VKWtsSessionProtocolType -Times 0 -Exactly -ParameterFilter { $SessionId -eq 65536 }
        }

        It 'never queries a principal for the listener session' {
            # Microsoft documents listener sessions as having no logged-on user.
            Should -Invoke Get-VKWtsSessionString -Times 0 -Exactly -ParameterFilter { $SessionId -eq 65536 }
            @($script:Section['sessions']['session_principals']).Count | Should -Be 3
        }
    }

    Context 'successful zero-result enumeration' {

        BeforeEach {
            Mock Get-VKWtsSessionRecords { @() }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success with a genuine non-null empty array' {
            $script:Report['host.sessions.current_sessions'].acquisition_outcome | Should -Be 'success'
            [object]::ReferenceEquals($null, $script:Section['sessions']['current_sessions']) | Should -BeFalse
            @($script:Section['sessions']['current_sessions']).Count | Should -Be 0
        }

        It 'emits a numeric zero summary, which is a genuine observation' {
            $script:Section['sessions']['current_sessions_summary']['total'] | Should -Be 0
        }
    }

    Context 'enumeration denied' {

        BeforeEach {
            Mock Get-VKWtsSessionRecords { throw (New-WtsNativeError -Code 5 -Message 'WTSEnumerateSessions failed.') }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'classifies on the native error code as restricted / access_denied' {
            $entry = $script:Report['host.sessions.current_sessions']
            $entry.acquisition_outcome | Should -Be 'restricted'
            $entry.error.category      | Should -Be 'access_denied'
        }

        It 'yields null payload and null summary, never a zero count' {
            $script:Section['sessions']['current_sessions']         | Should -BeNullOrEmpty
            $script:Section['sessions']['current_sessions_summary'] | Should -BeNullOrEmpty
        }

        It 'marks principals as precondition_not_met rather than inventing a result' {
            $entry = $script:Report['host.sessions.session_principals']
            $entry.acquisition_outcome | Should -Be 'unavailable'
            $entry.error.category      | Should -Be 'precondition_not_met'
        }

        It 'does not attempt any principal query' {
            Should -Invoke Get-VKWtsSessionString -Times 0 -Exactly
        }

        It 'leaves the independent profile unit successful' {
            $script:Report['host.sessions.user_profiles'].acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'interop unavailable' {

        BeforeEach {
            # Add-Type blocked by policy, or wtsapi32 entry point missing.
            Mock Initialize-VKWtsInterop {
                throw (New-TestErrorRecord -Exception ([System.NotSupportedException]::new('Add-Type is blocked by policy.')) `
                    -Category ([System.Management.Automation.ErrorCategory]::NotImplemented))
            }
            Mock Get-VKWtsSessionRecords { throw 'should not be reached' }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the session unit as unavailable' {
            $script:Report['host.sessions.current_sessions'].acquisition_outcome | Should -Be 'unavailable'
        }

        It 'never reaches the enumeration call' {
            Should -Invoke Get-VKWtsSessionRecords -Times 0 -Exactly
        }

        It 'still emits the observation window' {
            $script:Section['sessions']['observation_window']['window_duration_hours'] | Should -Be 24
        }
    }

    Context 'protocol query fails for one session' {

        BeforeEach {
            Mock Get-VKWtsSessionRecords { @(New-WtsSession -SessionId 4 -WinStationName 'RDP-Tcp#2' -State $script:StateActive) }
            Mock Get-VKWtsSessionProtocolType { throw (New-WtsNativeError -Code 5) }
            Mock Get-VKWtsSessionString { 'dave' } -ParameterFilter { $InfoClass -eq 5 }
            Mock Get-VKWtsSessionString { 'FIXTUREDOM' } -ParameterFilter { $InfoClass -eq 7 }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'retains the observed connection state' {
            $script:Report['host.sessions.current_sessions'].acquisition_outcome | Should -Be 'success'
            $script:Section['sessions']['current_sessions'][0]['state'] | Should -Be 'Active'
        }

        It 'does not infer console or remote from the session name' {
            $s = $script:Section['sessions']['current_sessions'][0]
            $s['session_type']        | Should -Be 'other'
            $s['protocol_type']       | Should -BeNullOrEmpty
            $s['session_type_source'] | Should -Be 'connect_state'
        }
    }
}


# ============================================================
#  Session principals
# ============================================================

Describe 'Host.Sessions: session principal evidence' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus          { }
        Mock Write-LogMessage        { }
        Mock Initialize-VKWtsInterop { }
        Mock Get-CimInstance {
            @(New-UserProfile -Sid 'S-1-5-18' -Loaded $true -Special $true -LastUseTime ([datetime]::UtcNow))
        }
        Mock Get-VKWtsSessionRecords {
            @(
                New-WtsSession -SessionId 1 -WinStationName 'Console'   -State $script:StateActive
                New-WtsSession -SessionId 2 -WinStationName 'RDP-Tcp#0' -State $script:StateActive
            )
        }
        Mock Get-VKWtsSessionProtocolType { $script:ProtoConsole } -ParameterFilter { $SessionId -eq 1 }
        Mock Get-VKWtsSessionProtocolType { $script:ProtoRemote }  -ParameterFilter { $SessionId -eq 2 }
        Mock Get-VKWtsSessionString { throw (New-WtsNativeError -Message 'Unmocked principal query.') }
    }

    Context 'successful resolution' {

        BeforeEach {
            Mock Get-VKWtsSessionString { 'alice' }      -ParameterFilter { $InfoClass -eq 5 -and $SessionId -eq 1 }
            Mock Get-VKWtsSessionString { 'FIXTUREDOM' } -ParameterFilter { $InfoClass -eq 7 -and $SessionId -eq 1 }
            Mock Get-VKWtsSessionString { 'bob' }        -ParameterFilter { $InfoClass -eq 5 -and $SessionId -eq 2 }
            Mock Get-VKWtsSessionString { 'FIXTUREDOM' } -ParameterFilter { $InfoClass -eq 7 -and $SessionId -eq 2 }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records success and joins by session_id' {
            $script:Report['host.sessions.session_principals'].acquisition_outcome | Should -Be 'success'
            $p = $script:Section['sessions']['session_principals'] | Where-Object { $_['session_id'] -eq 2 }
            $p['user_name']         | Should -Be 'bob'
            $p['domain_name']       | Should -Be 'FIXTUREDOM'
            $p['principal_present'] | Should -BeTrue
        }

        It 'retains raw principal names unchanged' {
            # No hashing, redaction or pseudonymisation in the agent.
            @($script:Section['sessions']['session_principals'] | ForEach-Object { $_['user_name'] }) |
                Should -Contain 'alice'
        }

        It 'does not emit is_domain_principal' {
            # Domain/local/AzureAD classification belongs to ingestion.
            $script:Section['sessions']['session_principals'][0].Keys | Should -Not -Contain 'is_domain_principal'
        }
    }

    Context 'successful query returning empty strings' {

        BeforeEach {
            Mock Get-VKWtsSessionString { '' }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'treats an empty return as observed absence, not failure' {
            $script:Report['host.sessions.session_principals'].acquisition_outcome | Should -Be 'success'
            foreach ($p in $script:Section['sessions']['session_principals']) {
                $p['principal_present'] | Should -BeFalse
                $p['user_name']         | Should -BeNullOrEmpty
            }
        }
    }

    Context 'one required principal query fails' {

        BeforeEach {
            Mock Get-VKWtsSessionString { 'alice' } -ParameterFilter { $SessionId -eq 1 }
            Mock Get-VKWtsSessionString { throw (New-WtsNativeError -Code 5) } -ParameterFilter { $SessionId -eq 2 }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'withholds the complete principal collection and its summary' {
            $script:Section['sessions']['session_principals']         | Should -BeNullOrEmpty
            $script:Section['sessions']['session_principals_summary'] | Should -BeNullOrEmpty
        }

        It 'classifies as restricted from the native error code' {
            $entry = $script:Report['host.sessions.session_principals']
            $entry.acquisition_outcome | Should -Be 'restricted'
            $entry.error.category      | Should -Be 'access_denied'
        }

        It 'RETAINS the successfully observed session state evidence' {
            # The defining independence property of this design.
            $script:Report['host.sessions.current_sessions'].acquisition_outcome | Should -Be 'success'
            @($script:Section['sessions']['current_sessions']).Count | Should -Be 2
            $script:Section['sessions']['current_sessions_summary']['total'] | Should -Be 2
        }
    }
}


# ============================================================
#  Recent profile proxy
# ============================================================

Describe 'Host.Sessions: recent profile proxy evidence' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus          { }
        Mock Write-LogMessage        { }
        Mock Initialize-VKWtsInterop { }
        Mock Get-VKWtsSessionRecords { @() }
        Mock Get-VKWtsSessionString  { '' }
        Mock Get-VKWtsSessionProtocolType { $script:ProtoConsole }
    }

    Context 'profiles inside and outside the window' {

        BeforeEach {
            $now = (Get-Date).ToUniversalTime()
            Mock Get-CimInstance {
                @(
                    New-UserProfile -Sid 'S-1-5-21-1-2-3-1001' -Loaded $true  -Special $false -LastUseTime $now.AddHours(-2)
                    New-UserProfile -Sid 'S-1-5-21-1-2-3-1002' -Loaded $false -Special $false -LastUseTime $now.AddHours(-72)
                    New-UserProfile -Sid 'S-1-5-18'            -Loaded $true  -Special $true  -LastUseTime $now.AddMinutes(-5)
                )
            }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records the profile unit as success' {
            $script:Report['host.sessions.user_profiles'].acquisition_outcome | Should -Be 'success'
        }

        It 'flags in-window and out-of-window profiles correctly' {
            $inWindow  = $script:Section['sessions']['user_profiles'] | Where-Object { $_['sid'] -eq 'S-1-5-21-1-2-3-1001' }
            $outWindow = $script:Section['sessions']['user_profiles'] | Where-Object { $_['sid'] -eq 'S-1-5-21-1-2-3-1002' }
            $inWindow['last_use_within_window']  | Should -BeTrue
            $outWindow['last_use_within_window'] | Should -BeFalse
        }

        It 'marks every record as proxy evidence, never a logon record' {
            foreach ($record in $script:Section['sessions']['user_profiles']) {
                $record['evidence_strength'] | Should -Be 'profile_use_proxy'
            }
        }

        It 'keeps special profiles identifiable for downstream exclusion' {
            $special = $script:Section['sessions']['user_profiles'] | Where-Object { $_['sid'] -eq 'S-1-5-18' }
            $special['special'] | Should -BeTrue
            $special['loaded']  | Should -BeTrue
            $script:Section['sessions']['user_profiles_summary']['special'] | Should -Be 1
            $script:Section['sessions']['user_profiles_summary']['loaded']  | Should -Be 2
        }

        It 'emits UTC timestamps' {
            foreach ($record in $script:Section['sessions']['user_profiles']) {
                $record['last_use_time'] | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
            }
        }

        It 'emits no excluded profile field' -ForEach @('local_path', 'roaming_configured', 'LocalPath', 'RoamingConfigured') {
            $script:Section['sessions']['user_profiles'][0].Keys | Should -Not -Contain $_
        }
    }

    Context 'provider returns nothing' {

        BeforeEach {
            Mock Get-CimInstance { @() }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'is unavailable / provider_value_missing, not a successful empty' {
            $entry = $script:Report['host.sessions.user_profiles']
            $entry.acquisition_outcome | Should -Be 'unavailable'
            $entry.error.category      | Should -Be 'provider_value_missing'
            $script:Section['sessions']['user_profiles'] | Should -BeNullOrEmpty
        }

        It 'still emits the observation window on failure' {
            $window = $script:Section['sessions']['observation_window']
            $window['window_start']          | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
            $window['window_end']            | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
            $window['window_duration_hours'] | Should -Be 24
            $window['window_source']         | Should -Be 'configured'
        }

        It 'leaves the independent WTS units unaffected' {
            $script:Report['host.sessions.current_sessions'].acquisition_outcome   | Should -Be 'success'
            $script:Report['host.sessions.session_principals'].acquisition_outcome | Should -Be 'success'
        }
    }

    Context 'provider denied' {

        BeforeEach {
            Mock Get-CimInstance { throw (New-DeniedError) }

            $script:Section = New-TestSection
            Invoke-VKHostSessions -Data $script:Section -IsAdmin $false
            Complete-VKAcquisitionReport
            $script:Report = Get-VKAcquisitionReport
        }

        It 'records restricted and withholds both profile paths' {
            $script:Report['host.sessions.user_profiles'].acquisition_outcome | Should -Be 'restricted'
            $script:Section['sessions']['user_profiles']         | Should -BeNullOrEmpty
            $script:Section['sessions']['user_profiles_summary'] | Should -BeNullOrEmpty
        }
    }
}


# ============================================================
#  Shared contract
# ============================================================

Describe 'Host.Sessions: shared acquisition contract' {

    BeforeEach {
        Initialize-VKAcquisition
        Mock Write-VKStatus          { }
        Mock Write-LogMessage        { }
        Mock Initialize-VKWtsInterop { }

        Mock Get-VKWtsSessionRecords      { throw (New-WtsNativeError -Code 5) }
        Mock Get-VKWtsSessionString       { throw (New-WtsNativeError -Code 5) }
        Mock Get-VKWtsSessionProtocolType { throw (New-WtsNativeError -Code 5) }
        Mock Get-CimInstance              { throw (New-DeniedError) }

        $script:Section = New-TestSection
        Invoke-VKHostSessions -Data $script:Section -IsAdmin $true
        Complete-VKAcquisitionReport
        $script:Report = Get-VKAcquisitionReport
    }

    It 'registers unit <_>' -ForEach @(
        'host.sessions.current_sessions'
        'host.sessions.session_principals'
        'host.sessions.user_profiles'
    ) {
        $script:Report.Contains($_) | Should -BeTrue
    }

    It 'records no unit as success when every provider fails' {
        $successes = @($script:Report.Keys | Where-Object { $script:Report[$_].acquisition_outcome -eq 'success' })
        $successes -join ', ' | Should -BeNullOrEmpty
    }

    It 'keeps every outcome within the permitted vocabulary' {
        foreach ($unitId in $script:Report.Keys) {
            @('success', 'failed', 'restricted', 'unavailable') |
                Should -Contain $script:Report[$unitId].acquisition_outcome
        }
    }

    It 'gives every unit populated data_paths and structured error data' {
        foreach ($unitId in $script:Report.Keys) {
            @($script:Report[$unitId].data_paths).Count | Should -BeGreaterThan 0
            $script:Report[$unitId].error          | Should -Not -BeNullOrEmpty
            $script:Report[$unitId].error.category | Should -Not -BeNullOrEmpty
        }
    }

    It 'emits no fabricated value for any withheld collection' {
        foreach ($key in @(
            'current_sessions', 'current_sessions_summary',
            'session_principals', 'session_principals_summary',
            'user_profiles', 'user_profiles_summary'
        )) {
            $script:Section['sessions'][$key] | Should -BeNullOrEmpty -Because "$key must carry no value after total failure"
        }
    }

    It 'still emits a complete observation window' {
        # The artefact stays self-describing even when nothing was collected.
        $window = $script:Section['sessions']['observation_window']
        foreach ($field in @('window_start', 'window_end', 'window_duration_hours', 'window_source')) {
            $window.Keys | Should -Contain $field
        }
    }
}


# ============================================================
#  WTS interop source contract (static)
# ============================================================

Describe 'Host.Sessions: WTS interop source contract' {

    # The native paths cannot be reached through a mock, so the embedded
    # C# source contract is asserted directly - the form a regression
    # would actually take.

    BeforeAll {
        # Test-only semantic analysis helpers; never part of the collector.
        . (Join-Path $PSScriptRoot 'helpers\VK.StaticAnalysis.ps1')

        $script:SessionsPath   = Join-Path $script:HostModules 'Host.Sessions.ps1'
        $script:SessionsSource = Get-Content -Path $script:SessionsPath -Raw
        $script:SessionsAst    = ConvertTo-VKScriptAst -Path $script:SessionsPath
        $script:NativeSource   = Get-VKEmbeddedCSharpSource -Source $script:SessionsSource
    }

    It 'embeds the WTS interop as C# source' {
        $script:NativeSource | Should -Not -BeNullOrEmpty
        $script:NativeSource | Should -Match 'WTSEnumerateSessionsW'
        $script:NativeSource | Should -Match 'WTSQuerySessionInformationW'
    }

    It 'imports only wtsapi32.dll' {
        $imports = @([regex]::Matches($script:NativeSource, 'DllImport\("([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $imports | Should -Be @('wtsapi32.dll')
    }

    It 'releases every native buffer through WTSFreeMemory' {
        # One WTSFreeMemory per allocating call, each inside a finally.
        $allocations = @([regex]::Matches($script:NativeSource, 'IntPtr buffer = IntPtr\.Zero;')).Count
        $frees       = @([regex]::Matches($script:NativeSource, 'WTSFreeMemory\(buffer\);')).Count
        $finallies   = @([regex]::Matches($script:NativeSource, '(?s)finally\s*\{[^}]*WTSFreeMemory')).Count

        $allocations | Should -BeGreaterThan 0
        $frees       | Should -Be $allocations
        $finallies   | Should -Be $allocations -Because 'the exception path must free memory as reliably as the success path'
    }

    It 'raises a structured exception carrying the native error code' {
        $script:NativeSource | Should -Match 'class WtsException'
        $script:NativeSource | Should -Match 'NativeErrorCode'
        $script:NativeSource | Should -Match 'Marshal\.GetLastWin32Error\(\)'
    }

    It 'targets the local server only' {
        $script:NativeSource | Should -Match 'IntPtr LocalServer = IntPtr\.Zero'
        $script:NativeSource | Should -Not -Match 'WTSOpenServer'
    }

    It 'guards type creation so repeat invocation does not recompile' {
        $script:SessionsSource | Should -Match "PSTypeName\]\`$script:VKWtsTypeName\)\.Type"
    }

    # --- EXCLUSION TESTS: semantic, not textual ---------------------
    #
    # These assert EXECUTABLE USE via the AST. The module's comment-based
    # help legitimately names WTSLogonTime, quser.exe, qwinsta.exe,
    # wevtutil.exe and 4624 while DOCUMENTING their exclusion; comments are
    # not AST nodes, so that documentation cannot trigger a finding, while
    # a genuine invocation still fails.

    It 'invokes no external session-collection executable' {
        $findings = Get-VKExternalCommandUsage -Ast $script:SessionsAst
        $findings -join ', ' | Should -BeNullOrEmpty
    }

    It 'contains no executable Event Log collection path' {
        # Broader than any single command: cmdlets, the external tool, the
        # CIM class and the .NET reader types are all checked, so the claim
        # "no executable Event Log collection exists" is established rather
        # than merely "Get-WinEvent is absent".
        $findings = Get-VKEventLogCollectionUsage -Ast $script:SessionsAst
        $findings -join ', ' | Should -BeNullOrEmpty
    }

    It 'admits only WTS information classes 5, 7 and 16' {
        # The complete admitted set, which subsumes the previous per-term
        # checks for WTSLogonTime (18), WTSClientAddress and WTSClientName.
        $used = Get-VKWtsInfoClassUsage -Ast $script:SessionsAst
        $used | Should -Be @(5, 7, 16)
        $used | Should -Not -Contain 18
    }

    It 'makes no active WTS query for information class 18' {
        # C# comments stripped first, so the exclusion note survives while
        # an active call would be caught. The module passes a parameter
        # named infoClass plus the literal 16, so 16 is the only literal.
        $literals = Get-VKCSharpWtsInfoClassLiteral -CSharpSource $script:NativeSource
        $literals | Should -Not -Contain 18
        $literals | Should -Be @(16)
    }

    It 'detects a prohibited external invocation (negative control)' {
        # Parsed, never executed. Proves the detector fires on real use.
        $syntheticAst = ConvertTo-VKScriptAst -Text @'
# quser and wevtutil named in a comment must NOT be flagged
& 'C:\Windows\System32\quser.exe'
qwinsta /server:localhost
'@
        $findings = Get-VKExternalCommandUsage -Ast $syntheticAst
        @($findings).Count | Should -Be 2
        $findings -join ', ' | Should -BeLike '*quser.exe*'
        $findings -join ', ' | Should -BeLike '*qwinsta*'
    }

    It 'detects Event Log collection and info class 18 (negative control)' {
        $syntheticAst = ConvertTo-VKScriptAst -Text @'
# Get-WinEvent and WTSLogonTime in a comment must NOT be flagged
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624 }
Get-CimInstance -ClassName 'Win32_NTLogEvent'
$reader = [System.Diagnostics.Eventing.Reader.EventLogQuery]
Get-VKWtsSessionString -SessionId 1 -InfoClass 18
'@
        @(Get-VKEventLogCollectionUsage -Ast $syntheticAst).Count | Should -BeGreaterThan 2
        Get-VKWtsInfoClassUsage -Ast $syntheticAst | Should -Contain 18

        # And the C# side, with an active class-18 call.
        Get-VKCSharpWtsInfoClassLiteral -CSharpSource @'
// WTSQuerySessionInformation(LocalServer, sessionId, 18, out b, out n) in a comment
if (!WTSQuerySessionInformation(LocalServer, sessionId, 18, out buffer, out bytes)) { }
'@ | Should -Be @(18)

        # CONTRAST: numerals that are NOT WTS information classes must be
        # ignored. The generated standalone concatenates every module, so a
        # wildcard rule previously harvested 0 from Host.WindowsUpdates'
        # QueryHistory(0, $maxHistory) COM start index.
        $unrelatedAst = ConvertTo-VKScriptAst -Text @'
$history = $updateSearcher.QueryHistory(0, $maxHistory)
$other   = [Some.Other.Type]::QueryString(0, 18)
Get-SomethingElse -InfoClass 0
$script:VKWtsInfoLookalike = 18
$protocolMap = @{ 0 = "console"; 1 = "legacy"; 2 = "remote" }
'@
        Get-VKWtsInfoClassUsage -Ast $unrelatedAst | Should -BeNullOrEmpty -Because 'only the named Host.Sessions positions carry a WTS information class'
    }
}
