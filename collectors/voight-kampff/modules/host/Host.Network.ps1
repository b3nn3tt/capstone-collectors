<#
.SYNOPSIS
    Module: Network Enumeration

.DESCRIPTION
    Enumerates network configuration:
    - Active network interfaces (name, IP address, MAC address)
    - SMB shares (name, path, type, state, permissions, writability)

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKHostNetwork {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    # --------------------------------------------------------
    #  Network Interfaces
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating network interfaces" -Type "PROCESSING"

    $networkInterfaces = @()

    try {
        Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
            $adapter = $_
            try {
                # Retrieve valid IPv4 addresses (exclude APIPA and loopback)
                $ipDetails = Get-NetIPAddress -InterfaceIndex $adapter.IfIndex -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" }

                if ($adapter.MacAddress -and $ipDetails) {
                    foreach ($ip in $ipDetails) {
                        $networkInterfaces += [ordered]@{
                            "interface"   = $adapter.Name
                            "ip_address"  = $ip.IPAddress
                            "prefix_length" = $ip.PrefixLength
                            "mac_address" = $adapter.MacAddress
                            "link_speed"  = $adapter.LinkSpeed
                            "media_type"  = $adapter.MediaType
                        }
                    }
                }
            }
            catch {
                Write-LogMessage -Section "Host.Network" -Message "Unable to retrieve IP details for adapter $($adapter.Name): $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    catch {
        Write-LogMessage -Section "Host.Network" -Message "Unable to enumerate network adapters: $($_.Exception.Message)" -Level "ERROR"
    }

    $Data["network_interfaces"] = $networkInterfaces


    # --------------------------------------------------------
    #  SMB Shares
    # --------------------------------------------------------

    Write-VKStatus -Message "Enumerating SMB shares" -Type "PROCESSING"

    $sharesList = @()

    try {
        $smbShares = Get-SmbShare -ErrorAction Stop

        foreach ($share in $smbShares) {
            $rawState = [int]$share.ShareState

            $shareDetails = [ordered]@{
                "name"        = $share.Name
                "path"        = $share.Path
                "description" = $share.Description
                "type"        = if ($share.Name -like "*$") { "Admin/Hidden" } else { "Regular" }
                "state"       = Resolve-LookupValue -Value $rawState -LookupTable $script:VKShareStates
                "permissions" = @()
                "writable"    = $false
            }

            # Retrieve share permissions
            try {
                $permissions = Get-SmbShareAccess -Name $share.Name -ErrorAction Stop

                foreach ($permission in $permissions) {
                    $accessType = if ($permission.AccessControlType -eq 0) { "Allow" } else { "Deny" }
                    $accessRight = switch ($permission.AccessRight) {
                        "Full"   { "Full Control" }
                        "Change" { "Change" }
                        "Read"   { "Read" }
                        default  { "Unknown" }
                    }

                    # Flag as writable if a non-admin account has write access
                    if ($accessRight -in @("Full Control", "Change") -and $permission.AccountName -notlike "*Admin*") {
                        $shareDetails["writable"] = $true
                    }

                    $shareDetails["permissions"] += [ordered]@{
                        "account"      = $permission.AccountName
                        "access_type"  = $accessType
                        "access_right" = $accessRight
                    }
                }
            }
            catch {
                Write-LogMessage -Section "Host.Network" -Message "Failed to retrieve permissions for share $($share.Name): $($_.Exception.Message)" -Level "ERROR"
            }

            $sharesList += $shareDetails
        }
    }
    catch {
        Write-LogMessage -Section "Host.Network" -Message "Failed to enumerate SMB shares: $($_.Exception.Message)" -Level "ERROR"
    }

    $Data["network_shares"] = $sharesList

    Write-VKStatus -Message "Network enumeration complete" -Type "SUCCESS"
}