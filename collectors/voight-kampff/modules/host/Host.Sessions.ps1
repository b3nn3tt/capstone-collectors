<#
.SYNOPSIS
    Module: Interactive Sessions and Recent Profile Use

.DESCRIPTION
    Collects local session and recent-profile evidence in support of
    C5 (interactive use) and C6 (low-privilege pathway).

    Providers, both local and dependency-free:
      - Terminal Services (WTS) APIs in wtsapi32.dll, via P/Invoke
      - root\CIMV2:Win32_UserProfile, via the existing CIM approach

    SCHEMA 1.1 ACQUISITION
    Three INDEPENDENT collection units, which must not share fate:

        host.sessions.current_sessions    (WTS enumeration)
        host.sessions.session_principals  (WTS per-session user/domain)
        host.sessions.user_profiles       (Win32_UserProfile)

      - failure to resolve principals does NOT discard successfully
        observed session state;
      - profile failure does NOT affect either WTS unit;
      - WTS failure does NOT affect profile evidence.

    EVIDENCE SEMANTICS - READ THIS BEFORE USING THE DATA
    Two different kinds of evidence live here and must never be conflated.

      current_sessions is DIRECT, POINT-IN-TIME evidence. WTS enumerates
      the live session table; the result is authoritative for the
      observation instant and says nothing about any other moment.

      user_profiles[].last_use_time is a RETROSPECTIVE PROXY. It is NOT an
      interactive-logon event. Win32_UserProfile.LastUseTime advances on
      profile load and unload and can also advance from background or
      service activity touching the hive, and it is not reliably updated
      on every logoff path. It therefore establishes "this profile was
      touched within the window", NOT "a user interactively logged on".
      Every record carries evidence_strength = "profile_use_proxy" so no
      consumer can mistake it for a logon record, and 'special' is emitted
      so system profiles remain identifiable for downstream exclusion.

    C5 REMAINS PARTIAL. A single observation instant cannot characterise a
    24-hour window, and the profile proxy cannot substitute for interactive
    logon evidence.

    DELIBERATELY EXCLUDED
      - Security Event Log 4624. Its empty results can never be shown to
        mean "no recent logon", because Windows exposes only the CURRENT
        audit policy, not policy history across the observation window.
        Collection success alone would not imply temporal coverage.
      - quser.exe / qwinsta.exe / wevtutil.exe and any free-text parsing.
      - Client name, client address, display info, working directory,
        application name, byte counts, idle time, credentials and tokens.
      - WTSLogonTime: documented by Microsoft as not supported.
      - Host role: already collected by Host.Identification.
      - LocalPath and RoamingConfigured from Win32_UserProfile.

    PRIVACY
    Raw user names, domains and SIDs are retained UNCHANGED in the secured
    raw evidence. The agent performs no hashing, redaction, pseudonymisation
    or analytical filtering; those belong to the separate ingestion
    artefact. Raw output therefore remains suitable for Voight-Kampff's
    wider non-dissertation use.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

# ============================================================
#  WTS interop
# ============================================================
# Native buffers returned by WTSEnumerateSessions and
# WTSQuerySessionInformation are owned by the caller and must be released
# with WTSFreeMemory. Every allocation below is freed in a finally block,
# so the exception path releases memory as reliably as the success path.
#
# Failures raise VoightKampff.WtsException, which carries the native
# error code. Classification uses that structured code rather than
# message text.
# ============================================================

$script:VKWtsTypeName = 'VoightKampff.WtsNative'

# WTS_CONNECTSTATE_CLASS
$script:VKWtsConnectStates = @{
    0 = "Active"
    1 = "Connected"
    2 = "ConnectQuery"
    3 = "Shadow"
    4 = "Disconnected"
    5 = "Idle"
    6 = "Listen"
    7 = "Reset"
    8 = "Down"
    9 = "Init"
}

# WTS_INFO_CLASS members actually used
$script:VKWtsInfoUserName     = 5
$script:VKWtsInfoDomainName   = 7
$script:VKWtsInfoProtocolType = 16

# WTSClientProtocolType values
$script:VKWtsProtocolTypes = @{
    0 = "console"
    1 = "legacy"
    2 = "remote"
}

$script:VKWtsSourceCodeDefinition = @'
namespace VoightKampff
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;

    // Carries the native error code so callers classify on structured
    // information rather than on message text.
    public class WtsException : Exception
    {
        private int nativeErrorCode;
        public int NativeErrorCode { get { return nativeErrorCode; } }

        public WtsException(string message, int errorCode) : base(message)
        {
            nativeErrorCode = errorCode;
        }
    }

    public class WtsSession
    {
        public int SessionId;
        public string WinStationName;
        public int State;
    }

    public static class WtsNative
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int SessionId;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pWinStationName;
            public int State;
        }

        // WTS_CURRENT_SERVER_HANDLE: local server only. No remote
        // collection is performed or supported by this module.
        private static readonly IntPtr LocalServer = IntPtr.Zero;

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WTSEnumerateSessionsW")]
        private static extern bool WTSEnumerateSessions(
            IntPtr hServer, int Reserved, int Version,
            out IntPtr ppSessionInfo, out int pCount);

        [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "WTSQuerySessionInformationW")]
        private static extern bool WTSQuerySessionInformation(
            IntPtr hServer, int sessionId, int wtsInfoClass,
            out IntPtr ppBuffer, out int pBytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        public static WtsSession[] EnumerateSessions()
        {
            IntPtr buffer = IntPtr.Zero;
            int count = 0;
            List<WtsSession> results = new List<WtsSession>();

            try
            {
                if (!WTSEnumerateSessions(LocalServer, 0, 1, out buffer, out count))
                {
                    throw new WtsException(
                        "WTSEnumerateSessions failed.", Marshal.GetLastWin32Error());
                }

                int stride = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                long cursor = buffer.ToInt64();

                for (int i = 0; i < count; i++)
                {
                    WTS_SESSION_INFO info = (WTS_SESSION_INFO)Marshal.PtrToStructure(
                        new IntPtr(cursor), typeof(WTS_SESSION_INFO));
                    cursor += stride;

                    WtsSession session = new WtsSession();
                    session.SessionId = info.SessionId;
                    session.WinStationName = info.pWinStationName;
                    session.State = info.State;
                    results.Add(session);
                }
            }
            finally
            {
                // Released on both the success and the exception path.
                if (buffer != IntPtr.Zero) { WTSFreeMemory(buffer); }
            }

            return results.ToArray();
        }

        public static string QueryString(int sessionId, int infoClass)
        {
            IntPtr buffer = IntPtr.Zero;
            int bytes = 0;

            try
            {
                if (!WTSQuerySessionInformation(LocalServer, sessionId, infoClass, out buffer, out bytes))
                {
                    throw new WtsException(
                        "WTSQuerySessionInformation failed for info class " + infoClass
                        + " on session " + sessionId + ".", Marshal.GetLastWin32Error());
                }

                // A successful call returning an empty buffer is a genuine
                // observed absence, not a failure.
                if (buffer == IntPtr.Zero) { return string.Empty; }

                string value = Marshal.PtrToStringUni(buffer);
                return value == null ? string.Empty : value;
            }
            finally
            {
                if (buffer != IntPtr.Zero) { WTSFreeMemory(buffer); }
            }
        }

        public static int QueryProtocolType(int sessionId)
        {
            IntPtr buffer = IntPtr.Zero;
            int bytes = 0;

            try
            {
                if (!WTSQuerySessionInformation(LocalServer, sessionId, 16, out buffer, out bytes))
                {
                    throw new WtsException(
                        "WTSQuerySessionInformation(WTSClientProtocolType) failed on session "
                        + sessionId + ".", Marshal.GetLastWin32Error());
                }

                if (buffer == IntPtr.Zero || bytes < 2)
                {
                    throw new WtsException(
                        "WTSClientProtocolType returned no value for session " + sessionId + ".", 0);
                }

                return (int)Marshal.ReadInt16(buffer);
            }
            finally
            {
                if (buffer != IntPtr.Zero) { WTSFreeMemory(buffer); }
            }
        }
    }
}
'@


function Initialize-VKWtsInterop {
    <#
    .SYNOPSIS
        Compiles the WTS interop type once per session.

    .DESCRIPTION
        Guarded by a PSTypeName check so repeat invocations do not
        re-compile. Throws if the type cannot be created - for example
        where AppLocker or WDAC blocks the in-box compiler - so the caller
        can classify that as unavailable rather than as a query failure.
    #>
    if (-not ([System.Management.Automation.PSTypeName]$script:VKWtsTypeName).Type) {
        Add-Type -TypeDefinition $script:VKWtsSourceCodeDefinition -ErrorAction Stop
    }
}


function Get-VKWtsSessionRecords {
    <#
    .SYNOPSIS
        Returns the local WTS session table. Wrapper over the native call
        so the provider boundary is mockable in tests.
    #>
    return [VoightKampff.WtsNative]::EnumerateSessions()
}


function Get-VKWtsSessionString {
    <#
    .SYNOPSIS
        Returns a string-valued WTS session property.
    #>
    param(
        [Parameter(Mandatory)][int]$SessionId,
        [Parameter(Mandatory)][int]$InfoClass
    )
    return [VoightKampff.WtsNative]::QueryString($SessionId, $InfoClass)
}


function Get-VKWtsSessionProtocolType {
    <#
    .SYNOPSIS
        Returns WTSClientProtocolType for a session.
    #>
    param(
        [Parameter(Mandatory)][int]$SessionId
    )
    return [VoightKampff.WtsNative]::QueryProtocolType($SessionId)
}


function Get-VKWtsNativeErrorCode {
    <#
    .SYNOPSIS
        Extracts the native error code from a WtsException anywhere in the
        exception chain.

    .DESCRIPTION
        Returns $null when no structured code is present. Callers fall back
        to the shared classifier only in that case, so structured native
        information is always preferred over message text.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$ErrorRecord
    )

    if ($null -eq $ErrorRecord) { return $null }

    $exception = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        $ErrorRecord.Exception
    }
    else { $ErrorRecord }

    $guard = 0
    while ($exception -and $guard -lt 8) {
        if ($exception.PSObject.Properties.Name -contains 'NativeErrorCode') {
            return [int]$exception.NativeErrorCode
        }
        $exception = $exception.InnerException
        $guard++
    }

    return $null
}


function Set-VKWtsAcquisitionFailure {
    <#
    .SYNOPSIS
        Records a WTS failure, classifying on the native error code where
        one is available.

    .DESCRIPTION
        ERROR_ACCESS_DENIED (5) and ERROR_PRIVILEGE_NOT_HELD (1314) are
        recorded as restricted: querying another user's session normally
        requires elevation, and re-collecting elevated is the remedy.

        Where no structured code is present the shared classifier decides,
        which is the only path that can reach message-text matching.
    #>
    param(
        [Parameter(Mandatory)][string]$UnitId,
        [Parameter(Mandatory)][AllowNull()]$ErrorRecord,
        [Parameter(Mandatory)][string]$Provider
    )

    $nativeCode = Get-VKWtsNativeErrorCode -ErrorRecord $ErrorRecord

    if ($null -ne $nativeCode) {
        switch ($nativeCode) {
            5 {
                Set-VKAcquisitionFailure -UnitId $UnitId -ErrorRecord $ErrorRecord -Provider $Provider `
                    -Outcome "restricted" -Category "access_denied"
                return
            }
            1314 {
                Set-VKAcquisitionFailure -UnitId $UnitId -ErrorRecord $ErrorRecord -Provider $Provider `
                    -Outcome "restricted" -Category "insufficient_privilege"
                return
            }
            1722 {
                Set-VKAcquisitionFailure -UnitId $UnitId -ErrorRecord $ErrorRecord -Provider $Provider `
                    -Outcome "unavailable" -Category "provider_not_found"
                return
            }
            7022 {
                Set-VKAcquisitionFailure -UnitId $UnitId -ErrorRecord $ErrorRecord -Provider $Provider `
                    -Outcome "unavailable" -Category "capability_not_supported"
                return
            }
            0 {
                Set-VKAcquisitionFailure -UnitId $UnitId -ErrorRecord $ErrorRecord -Provider $Provider `
                    -Outcome "unavailable" -Category "provider_value_missing"
                return
            }
        }
    }

    Set-VKAcquisitionFailure -UnitId $UnitId -ErrorRecord $ErrorRecord -Provider $Provider
}


function Invoke-VKHostSessions {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating interactive sessions" -Type "PROCESSING"

    $sessionsUnit   = "host.sessions.current_sessions"
    $principalsUnit = "host.sessions.session_principals"
    $profilesUnit   = "host.sessions.user_profiles"

    $wtsProvider     = "wtsapi32.dll:WTSEnumerateSessions"
    $wtsUserProvider = "wtsapi32.dll:WTSQuerySessionInformation(WTSUserName/WTSDomainName)"
    $profileProvider = "root\CIMV2:Win32_UserProfile"

    # Single captured UTC reference time for the window and every profile
    # comparison, so all derived values in one artefact are consistent.
    $referenceUtc = (Get-Date).ToUniversalTime()

    $windowHours = if ($null -ne $script:VKSessionWindowHours) { [int]$script:VKSessionWindowHours } else { 24 }
    $windowStart = $referenceUtc.AddHours(-$windowHours)

    # Every governed value initialised to $null.
    $sessionData = [ordered]@{
        # Written unconditionally so an artefact is self-describing even
        # when every collection fails. Governed by the user_profiles unit,
        # because it qualifies LastUseTime and nothing else.
        "observation_window" = [ordered]@{
            "window_start"          = $windowStart.ToString("yyyy-MM-ddTHH:mm:ssZ")
            "window_end"            = $referenceUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            "window_duration_hours" = $windowHours
            "window_source"         = "configured"
        }
        "current_sessions"           = $null
        "current_sessions_summary"   = $null
        "session_principals"         = $null
        "session_principals_summary" = $null
        "user_profiles"              = $null
        "user_profiles_summary"      = $null
    }

    Start-VKAcquisition -UnitId $sessionsUnit -Provider $wtsProvider -DataPaths @(
        "host.sessions.current_sessions"
        "host.sessions.current_sessions_summary"
    )
    Start-VKAcquisition -UnitId $principalsUnit -Provider $wtsUserProvider -DataPaths @(
        "host.sessions.session_principals"
        "host.sessions.session_principals_summary"
    )
    Start-VKAcquisition -UnitId $profilesUnit -Provider $profileProvider -DataPaths @(
        "host.sessions.observation_window"
        "host.sessions.user_profiles"
        "host.sessions.user_profiles_summary"
    )


    # --------------------------------------------------------
    #  Current sessions (WTS enumeration)
    # --------------------------------------------------------
    # No IsAdmin precondition is hard-coded: the provider call is attempted
    # and the actual error is classified. Enumeration frequently succeeds
    # for a standard user even where per-session queries do not.

    $sessionRecords   = $null
    $sessionsResolved = $false

    try {
        Initialize-VKWtsInterop

        $rawSessions = @(Get-VKWtsSessionRecords)

        $sessions = @()

        foreach ($raw in $rawSessions) {
            if ($null -eq $raw -or $null -eq $raw.SessionId) {
                throw [System.InvalidOperationException]::new("A WTS session record returned no SessionId.")
            }

            $stateCode = [int]$raw.State
            if (-not $script:VKWtsConnectStates.ContainsKey($stateCode)) {
                throw [System.InvalidOperationException]::new(
                    "WTS returned unrecognised connection state '$stateCode' for session $($raw.SessionId).")
            }

            $stateName = $script:VKWtsConnectStates[$stateCode]

            $protocolType      = $null
            $sessionType       = "other"
            $sessionTypeSource = "connect_state"

            if ($stateName -eq "Listen") {
                # A listener is classified directly from its connection
                # state and, per Microsoft, has no logged-on user.
                $sessionType = "listener"
            }
            else {
                # WTSClientProtocolType is the primary console/RDP source.
                # The session name is never used to infer console or RDP.
                try {
                    $rawProtocol = Get-VKWtsSessionProtocolType -SessionId ([int]$raw.SessionId)

                    if ($null -ne $rawProtocol) {
                        $protocolType      = [int]$rawProtocol
                        $sessionTypeSource = "wts_client_protocol_type"
                        $sessionType       = if ($script:VKWtsProtocolTypes.ContainsKey($protocolType)) {
                            $script:VKWtsProtocolTypes[$protocolType]
                        }
                        else { "other" }
                    }
                }
                catch {
                    # Per-session enrichment. The connection state - which
                    # is the frozen requirement - was still observed, so the
                    # record is retained with protocol_type null and
                    # session_type_source recording that the classification
                    # fell back to connect_state.
                    $protocolType      = $null
                    $sessionType       = "other"
                    $sessionTypeSource = "connect_state"
                }
            }

            $sessions += [ordered]@{
                "session_id"          = [int]$raw.SessionId
                "session_name"        = if ($raw.WinStationName) { [string]$raw.WinStationName } else { $null }
                "state"               = $stateName
                "protocol_type"       = $protocolType
                "session_type"        = $sessionType
                "session_type_source" = $sessionTypeSource
            }
        }

        # A successful zero-result enumeration is a genuine empty.
        $sessionData["current_sessions"] = $sessions
        $sessionData["current_sessions_summary"] = [ordered]@{
            "total"        = $sessions.Count
            "active"       = @($sessions | Where-Object { $_["state"] -eq "Active" }).Count
            "disconnected" = @($sessions | Where-Object { $_["state"] -eq "Disconnected" }).Count
            "console"      = @($sessions | Where-Object { $_["session_type"] -eq "console" }).Count
            "remote"       = @($sessions | Where-Object { $_["session_type"] -eq "remote" }).Count
            "listener"     = @($sessions | Where-Object { $_["session_type"] -eq "listener" }).Count
        }

        $sessionRecords   = $sessions
        $sessionsResolved = $true

        Complete-VKAcquisition -UnitId $sessionsUnit
    }
    catch {
        $sessionData["current_sessions"]         = $null
        $sessionData["current_sessions_summary"] = $null

        Write-LogMessage -Section "Host.Sessions" -Message "Unable to enumerate WTS sessions: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $sessionsUnit -Provider $wtsProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKWtsAcquisitionFailure -UnitId $sessionsUnit -ErrorRecord $_ -Provider $wtsProvider
        }
    }


    # --------------------------------------------------------
    #  Session principals
    # --------------------------------------------------------
    # Stored separately and joined to session evidence by session_id, so a
    # principal-resolution failure cannot discard observed session state.

    if (-not $sessionsResolved) {
        # The session set itself was never established, so there is nothing
        # to resolve principals against.
        $reason = "The WTS session enumeration did not succeed, so principals could not be resolved."

        Set-VKAcquisitionUnavailable -UnitId $principalsUnit -Provider $wtsUserProvider `
            -Category "precondition_not_met" -Message $reason
    }
    else {
        try {
            $principals = @()

            foreach ($session in $sessionRecords) {
                # Listener sessions are documented as having no logged-on
                # user and are not queried at all.
                if ($session["session_type"] -eq "listener") { continue }

                $sessionId = $session["session_id"]

                $userName   = Get-VKWtsSessionString -SessionId $sessionId -InfoClass $script:VKWtsInfoUserName
                $domainName = Get-VKWtsSessionString -SessionId $sessionId -InfoClass $script:VKWtsInfoDomainName

                # A successful query returning an empty string is an
                # observed absence, which is not the same as a failed call.
                $hasUser = -not [string]::IsNullOrEmpty($userName)

                $principals += [ordered]@{
                    "session_id"        = $sessionId
                    "user_name"         = if ($hasUser) { $userName } else { $null }
                    "domain_name"       = if (-not [string]::IsNullOrEmpty($domainName)) { $domainName } else { $null }
                    "principal_present" = $hasUser
                }
            }

            $sessionData["session_principals"] = $principals
            $sessionData["session_principals_summary"] = [ordered]@{
                "total"             = $principals.Count
                "with_principal"    = @($principals | Where-Object { $_["principal_present"] -eq $true }).Count
                "without_principal" = @($principals | Where-Object { $_["principal_present"] -eq $false }).Count
            }

            Complete-VKAcquisition -UnitId $principalsUnit
        }
        catch {
            # The acquisition vocabulary has no partial outcome, so any
            # required principal query failure withholds the COMPLETE
            # collection. A shorter list would appear complete and could
            # understate who holds a session.
            $sessionData["session_principals"]         = $null
            $sessionData["session_principals_summary"] = $null

            Write-LogMessage -Section "Host.Sessions" -Message "Unable to resolve session principals: $($_.Exception.Message)" -Level "WARNING"

            if ($_.Exception -is [System.InvalidOperationException]) {
                Set-VKAcquisitionUnavailable -UnitId $principalsUnit -Provider $wtsUserProvider `
                    -Category "provider_value_missing" -Message $_.Exception.Message
            }
            else {
                Set-VKWtsAcquisitionFailure -UnitId $principalsUnit -ErrorRecord $_ -Provider $wtsUserProvider
            }
        }
    }


    # --------------------------------------------------------
    #  Recent profile use (proxy evidence)
    # --------------------------------------------------------

    try {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop

        $profileList = @($profiles)

        # Win32_UserProfile always reports at least the system profiles, so
        # nothing at all means the provider did not answer. This is NOT a
        # successful empty result.
        if ($null -eq $profiles -or $profileList.Count -eq 0) {
            throw [System.InvalidOperationException]::new(
                "Win32_UserProfile returned no profiles.")
        }

        $profileRecords = @()

        # NB: the loop variable must NOT be $profile - that is a PowerShell
        # automatic variable, and assigning to it can have side effects.
        foreach ($userProfile in $profileList) {
            if ([string]::IsNullOrWhiteSpace($userProfile.SID)) {
                throw [System.InvalidOperationException]::new(
                    "A user profile record returned no SID value.")
            }

            if ($null -eq $userProfile.Loaded) {
                throw [System.InvalidOperationException]::new(
                    "User profile '$($userProfile.SID)' returned no Loaded value.")
            }

            # Converted to UTC before the Z suffix is applied.
            $lastUseUtc  = $null
            $lastUseText = $null
            if ($null -ne $userProfile.LastUseTime) {
                $lastUseUtc  = ([datetime]$userProfile.LastUseTime).ToUniversalTime()
                $lastUseText = $lastUseUtc.ToString("yyyy-MM-ddTHH:mm:ssZ")
            }

            # Compared against the single captured reference time.
            $withinWindow = if ($null -ne $lastUseUtc) {
                ($lastUseUtc -ge $windowStart -and $lastUseUtc -le $referenceUtc)
            }
            else { $null }

            $profileRecords += [ordered]@{
                "sid"                    = [string]$userProfile.SID
                "loaded"                 = [bool]$userProfile.Loaded
                "special"                = if ($null -ne $userProfile.Special) { [bool]$userProfile.Special } else { $null }
                "last_use_time"          = $lastUseText
                "last_use_within_window" = $withinWindow
                # Constant marker. LastUseTime is not a logon record.
                "evidence_strength"      = "profile_use_proxy"
            }
        }

        $sessionData["user_profiles"] = $profileRecords
        $sessionData["user_profiles_summary"] = [ordered]@{
            "total"                 = $profileRecords.Count
            "loaded"                = @($profileRecords | Where-Object { $_["loaded"] -eq $true }).Count
            "special"               = @($profileRecords | Where-Object { $_["special"] -eq $true }).Count
            "used_within_window"    = @($profileRecords | Where-Object { $_["last_use_within_window"] -eq $true }).Count
        }

        Complete-VKAcquisition -UnitId $profilesUnit
    }
    catch {
        $sessionData["user_profiles"]         = $null
        $sessionData["user_profiles_summary"] = $null

        Write-LogMessage -Section "Host.Sessions" -Message "Unable to enumerate user profiles: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $profilesUnit -Provider $profileProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $profilesUnit -ErrorRecord $_ -Provider $profileProvider
        }
    }

    $Data["sessions"] = $sessionData

    Write-VKStatus -Message "Session enumeration complete" -Type "SUCCESS"
}
