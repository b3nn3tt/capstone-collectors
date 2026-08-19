<#
.SYNOPSIS
    Module: Firewall Enumeration

.DESCRIPTION
    Enumerates Windows Firewall configuration:
    - Firewall profiles (Domain, Private, Public) with enabled state
      and default inbound/outbound actions
    - Enabled inbound firewall rules with display name, direction, and action

    SCHEMA 1.1 ACQUISITION
    Two independent collection units:

        security.firewall.profiles
        security.firewall.inbound_rules

    FAIL-CLOSED NOTES
    - Both collections previously remained @() on failure, so a failed
      query was byte-identical to a host with no profiles and no enabled
      inbound rules. Both now yield $null with a non-success outcome.
    - A successful query returning no enabled inbound rules is a genuine
      zero result and is still represented by an empty array.
    - A profile missing Enabled, DefaultInboundAction or
      DefaultOutboundAction is treated as malformed: [int]$null is 0, which
      the maps below resolve to "Disabled" and "Block" - substantive states
      the host never reported.

    NOT IN THIS TRANCHE
    The active firewall profile per interface is still not recorded, so the
    applicable default inbound action cannot be determined from agent
    evidence alone. That extension is deliberately deferred.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityFirewall {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    $profilesUnit = "security.firewall.profiles"
    $rulesUnit    = "security.firewall.inbound_rules"
    $provider     = "Get-NetFirewallProfile/Get-NetFirewallRule (ActiveStore)"

    # Governed paths initialised to $null, never to an empty collection.
    $Data["firewall_profiles"] = $null
    $Data["firewall_rules"]    = $null

    Start-VKAcquisition -UnitId $profilesUnit -Provider "Get-NetFirewallProfile (ActiveStore)" -DataPaths @(
        "security.firewall_profiles"
    )
    Start-VKAcquisition -UnitId $rulesUnit -Provider "Get-NetFirewallRule (ActiveStore)" -DataPaths @(
        "security.firewall_rules"
    )


    # --------------------------------------------------------
    #  Firewall Profiles
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating firewall profiles" -Type "PROCESSING"

    $profileEnabledMap  = @{ 0 = "Disabled"; 1 = "Enabled" }
    $profileInboundMap  = @{ 1 = "Allow"; 4 = "Block" }
    $profileOutboundMap = @{ 0 = "Block"; 2 = "Allow" }

    try {
        $fwProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)

        if ($fwProfiles.Count -eq 0) {
            # Windows always exposes the three profiles. None at all means
            # the provider did not answer, not that no profile exists.
            throw [System.InvalidOperationException]::new(
                "Get-NetFirewallProfile returned no profiles.")
        }

        $profiles = @()

        foreach ($fwProfile in $fwProfiles) {
            foreach ($required in @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction')) {
                if ($null -eq $fwProfile.$required) {
                    throw [System.InvalidOperationException]::new(
                        "Firewall profile '$($fwProfile.Name)' returned no $required value.")
                }
            }

            $profiles += [ordered]@{
                "name"            = $fwProfile.Name
                "enabled"         = Resolve-LookupValue -Value ([int]$fwProfile.Enabled) -LookupTable $profileEnabledMap
                "inbound_action"  = Resolve-LookupValue -Value ([int]$fwProfile.DefaultInboundAction) -LookupTable $profileInboundMap
                "outbound_action" = Resolve-LookupValue -Value ([int]$fwProfile.DefaultOutboundAction) -LookupTable $profileOutboundMap
            }
        }

        $Data["firewall_profiles"] = $profiles
        Complete-VKAcquisition -UnitId $profilesUnit
    }
    catch {
        $Data["firewall_profiles"] = $null

        Write-LogMessage -Section "Security.Firewall" -Message "Error collecting firewall profile data: $($_.Exception.Message)" -Level "ERROR"
        Write-VKStatus -Message "Error collecting firewall profile data." -Type "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $profilesUnit -Provider "Get-NetFirewallProfile (ActiveStore)" `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $profilesUnit -ErrorRecord $_ -Provider "Get-NetFirewallProfile (ActiveStore)"
        }
    }


    # --------------------------------------------------------
    #  Firewall Rules (enabled inbound only)
    # --------------------------------------------------------

    Write-VKStatus -Message "Collecting firewall rules" -Type "PROCESSING"

    $ruleDirectionMap = @{ 1 = "Inbound"; 2 = "Outbound" }
    $ruleActionMap    = @{ 1 = "Block"; 2 = "Allow" }

    try {
        $fwRules = @(
            Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { $_.Enabled -eq $true -and $_.Direction -eq "Inbound" } |
                Sort-Object DisplayName
        )

        $rules = @()

        foreach ($rule in $fwRules) {
            foreach ($required in @('Direction', 'Action')) {
                if ($null -eq $rule.$required) {
                    throw [System.InvalidOperationException]::new(
                        "Firewall rule '$($rule.DisplayName)' returned no $required value.")
                }
            }

            $rules += [ordered]@{
                "display_name" = $rule.DisplayName
                "id"           = $rule.ID
                "direction"    = Resolve-LookupValue -Value ([int]$rule.Direction) -LookupTable $ruleDirectionMap
                "action"       = Resolve-LookupValue -Value ([int]$rule.Action) -LookupTable $ruleActionMap
            }
        }

        # Genuine zero result: the provider answered and no enabled inbound
        # rule matched. An empty array is correct here.
        $Data["firewall_rules"] = $rules
        Complete-VKAcquisition -UnitId $rulesUnit
    }
    catch {
        # $null, not @(): an empty array would read as "no inbound rules are
        # enabled", which was never established.
        $Data["firewall_rules"] = $null

        Write-LogMessage -Section "Security.Firewall" -Message "Error collecting firewall rules: $($_.Exception.Message)" -Level "ERROR"
        Write-VKStatus -Message "Error collecting firewall rules." -Type "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $rulesUnit -Provider "Get-NetFirewallRule (ActiveStore)" `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $rulesUnit -ErrorRecord $_ -Provider "Get-NetFirewallRule (ActiveStore)"
        }
    }

    Write-VKStatus -Message "Firewall enumeration complete" -Type "SUCCESS"
}
