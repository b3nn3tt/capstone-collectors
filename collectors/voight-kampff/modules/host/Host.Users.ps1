<#
.SYNOPSIS
    Module: Local Users and Groups

.DESCRIPTION
    Enumerates local user accounts and group memberships:
    - Base SID for the machine
    - Local groups with their members
    - All local user accounts with detailed audit data

    SCHEMA 1.1 ACQUISITION
    Two collection units:

        host.users.local_accounts   ->  host.base_sid, host.user_accounts
        host.users.group_memberships ->  host.group_memberships,
                                         host.user_accounts[].is_admin

    UNIT INDEPENDENCE
    Get-LocalUser is queried ONCE and its result reused for both the
    account records and the base SID. Local-account evidence survives a
    separate group-membership failure: only is_admin, which derives from
    the Administrators group, is withheld in that case.

    FAIL-CLOSED NOTES
    - The literal "Error retrieving members" in-band sentinel is REMOVED.
      It was inserted into members[] on a per-group failure and would be
      parsed downstream as a principal name.
    - A failure enumerating ANY group withholds the whole
      group_memberships collection. A shorter list would appear complete
      and could understate administrator membership.
    - is_admin is $null - never $false - whenever group-membership
      evidence did not succeed. $false would assert that the account is
      not an administrator, which was never observed.
    - RID, SID, LockedOut and date properties are guarded before
      conversion; a missing property never becomes $false or 0.

    TIME HANDLING
    All timestamps are converted to UTC before the "Z" suffix is applied.
    The previous module appended "Z" to local time, mislabelling it. A
    SINGLE reference time is captured per invocation and used for every
    derived day count, so counts within one artefact are mutually
    consistent.

    SCOPE MARKERS
    Emitted additively:
        user_accounts_scope      = "local_only"
        group_memberships_scope  = "local_groups_only"

    Get-LocalUser and Get-LocalGroupMember observe the LOCAL SAM database
    only. On a domain-joined host the accounts that actually log in
    interactively are domain accounts and are invisible here, and nested
    domain groups conferring local administrator rights are not expanded.

    SCOPE NOTE - LastLogon is not domain-aware interactive use
    user_accounts[].last_logon reflects local-account logon only. It does
    NOT establish domain-aware interactive use, which depends on the
    separate session extension.

    PRIVACY
    Raw principal names and SIDs are retained UNCHANGED in the secured raw
    evidence. No pseudonymisation, hashing or obfuscation is performed in
    the agent: a stable experiment-specific mapping is applied in the
    ingestion layer before analytical datasets are produced.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKHostUsers {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating local users and groups" -Type "PROCESSING"

    $accountsUnit = "host.users.local_accounts"
    $groupsUnit   = "host.users.group_memberships"

    $userProvider  = "Get-LocalUser"
    $groupProvider = "Get-LocalGroup/Get-LocalGroupMember"

    # A single reference time for every derived day count in this module.
    $referenceTime = Get-Date

    # Known system account names
    $systemAccountNames = @("Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount")

    # Governed paths initialised to $null.
    $Data["base_sid"]          = $null
    $Data["user_accounts"]     = $null
    $Data["group_memberships"] = $null

    # Additive scope markers.
    $Data["user_accounts_scope"]     = "local_only"
    $Data["group_memberships_scope"] = "local_groups_only"

    Start-VKAcquisition -UnitId $accountsUnit -Provider $userProvider -DataPaths @(
        "host.base_sid"
        "host.user_accounts"
    )
    Start-VKAcquisition -UnitId $groupsUnit -Provider $groupProvider -DataPaths @(
        "host.group_memberships"
        "host.user_accounts[].is_admin"
    )


    # --------------------------------------------------------
    #  Group memberships (resolved first: is_admin depends on it)
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating local groups" -Type "PROCESSING"

    $adminAccountNames = $null
    $groupsSucceeded   = $false

    try {
        $groups = @(Get-LocalGroup -ErrorAction Stop | Sort-Object -Property Name)

        $groupMemberships = @()
        $administrators   = @()

        foreach ($group in $groups) {
            if ($null -eq $group.Name) {
                throw [System.InvalidOperationException]::new("A local group returned no Name value.")
            }

            $groupDetails = [ordered]@{
                "group_name"  = $group.Name
                "description" = $group.Description
                "members"     = @()
            }

            # -ErrorAction Stop: a failure here withholds the WHOLE
            # collection. Previously it inserted the literal string
            # "Error retrieving members" into members[].
            $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop)

            $memberNames = @()
            foreach ($member in $members) {
                if ($null -eq $member.Name) {
                    throw [System.InvalidOperationException]::new(
                        "A member of group '$($group.Name)' returned no Name value.")
                }

                $cleanedName = $member.Name -split '\\' | Select-Object -Last 1
                $memberNames += $cleanedName

                if ($group.Name -eq "Administrators") {
                    $administrators += $cleanedName
                }
            }

            # A genuinely empty group keeps an empty members array.
            $groupDetails["members"] = $memberNames
            $groupMemberships += $groupDetails
        }

        $Data["group_memberships"] = $groupMemberships
        $adminAccountNames         = $administrators
        $groupsSucceeded           = $true

        Complete-VKAcquisition -UnitId $groupsUnit
    }
    catch {
        # $null, not a shorter list: a partial collection would appear
        # complete and could understate administrator membership.
        $Data["group_memberships"] = $null
        $adminAccountNames         = $null

        Write-LogMessage -Section "Host.Users" -Message "Unable to enumerate local groups or members: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $groupsUnit -Provider $groupProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $groupsUnit -ErrorRecord $_ -Provider $groupProvider
        }
    }


    # --------------------------------------------------------
    #  Local user accounts and base SID
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating local user accounts" -Type "PROCESSING"

    try {
        # Queried ONCE; reused for both the records and the base SID.
        $users = @(Get-LocalUser -ErrorAction Stop)

        $userAccounts = @()
        $baseSid      = $null

        foreach ($user in $users) {
            if ($null -eq $user.Name) {
                throw [System.InvalidOperationException]::new("A local user returned no Name value.")
            }

            if ($null -eq $user.SID -or [string]::IsNullOrWhiteSpace($user.SID.Value)) {
                throw [System.InvalidOperationException]::new(
                    "Local user '$($user.Name)' returned no SID value.")
            }

            $sidValue = $user.SID.Value

            # Base SID derived from the first account with a usable SID.
            if ($null -eq $baseSid) {
                $baseSid = $sidValue -replace '-\d+$'
            }

            # RID guarded: a malformed SID must not silently become 0.
            $ridPart = ($sidValue -split '-')[-1]
            $rid = $null
            $parsedRid = 0
            if ([int]::TryParse($ridPart, [ref]$parsedRid)) { $rid = $parsedRid }

            # is_admin depends entirely on group-membership evidence.
            #
            # NOTE ON THE VARIABLE NAME. This must NOT be called $isAdmin.
            # PowerShell variable names are case-insensitive, so $isAdmin
            # resolves to this function's [bool]$IsAdmin PARAMETER. Because
            # that parameter is type-constrained, assigning $null to it is
            # silently coerced to $false - which turned "group membership
            # was never established" into the substantive claim "this
            # account is not an administrator", and additionally corrupted
            # the $IsAdmin parameter for the remainder of the call.
            #
            # $groupsSucceeded is the single authoritative completion flag:
            # initialised $false, set $true only after every required
            # Get-LocalGroup and Get-LocalGroupMember call has completed,
            # and left $false by the catch on any failure.
            $accountIsAdmin = if ($groupsSucceeded) {
                ($adminAccountNames -contains $user.Name)
            }
            else {
                $null
            }

            $isSystemAccount = $user.Name -in $systemAccountNames

            # Lockout: guarded, never defaulted to $false.
            $lockedOut = if ($null -ne $user.LockedOut) { [bool]$user.LockedOut } else { $null }

            $lockoutDate = if ($lockedOut -eq $true -and $null -ne $user.LockoutTime) {
                $user.LockoutTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            else { $null }

            # Password details, all UTC-converted before the Z suffix.
            $passwordLastSet = if ($null -ne $user.PasswordLastSet) {
                $user.PasswordLastSet.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            else { $null }

            $daysSincePasswordSet = if ($null -ne $user.PasswordLastSet) {
                ($referenceTime - $user.PasswordLastSet).Days
            }
            else { $null }

            # PasswordExpires is a DateTime or $null.
            #   $null      -> the password never expires
            #   past date  -> expired
            #   future date-> not expired
            $passwordNeverExpires = ($null -eq $user.PasswordExpires)

            $passwordExpired = if ($null -ne $user.PasswordExpires) {
                ($user.PasswordExpires -lt $referenceTime)
            }
            else { $false }

            $lastLogon = if ($null -ne $user.LastLogon) {
                $user.LastLogon.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            else { $null }

            $daysSinceLastLogon = if ($null -ne $user.LastLogon) {
                ($referenceTime - $user.LastLogon).Days
            }
            else { $null }

            $principalSource = switch ($user.PrincipalSource) {
                "Local"            { "Local" }
                "ActiveDirectory"  { "Active Directory" }
                "MicrosoftAccount" { "Microsoft Account" }
                "AzureAD"          { "Azure AD" }
                default            { $null }
            }

            $userAccounts += [ordered]@{
                "rid"                    = $rid
                "name"                   = $user.Name
                "enabled"                = if ($null -ne $user.Enabled) { [bool]$user.Enabled } else { $null }
                "is_admin"               = $accountIsAdmin
                "is_system_account"      = $isSystemAccount
                "password_last_set"      = $passwordLastSet
                "days_since_password_set"= $daysSincePasswordSet
                "password_expired"       = $passwordExpired
                "password_never_expires" = $passwordNeverExpires
                "last_logon"             = $lastLogon
                "days_since_last_logon"  = $daysSinceLastLogon
                "is_locked_out"          = $lockedOut
                "lockout_time"           = $lockoutDate
                "principal_source"       = $principalSource
            }
        }

        $Data["base_sid"]      = $baseSid
        $Data["user_accounts"] = $userAccounts

        Complete-VKAcquisition -UnitId $accountsUnit
    }
    catch {
        $Data["base_sid"]      = $null
        $Data["user_accounts"] = $null

        Write-LogMessage -Section "Host.Users" -Message "Unable to enumerate local users: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $accountsUnit -Provider $userProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $accountsUnit -ErrorRecord $_ -Provider $userProvider
        }
    }

    Write-VKStatus -Message "User enumeration complete" -Type "SUCCESS"
}
