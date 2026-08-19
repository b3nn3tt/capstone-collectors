<#
.SYNOPSIS
    Module: Network Configuration

.DESCRIPTION
    Enumerates active network configuration beyond interfaces and shares
    (which are covered by Host.Network):
    - ARP table (network neighbours)
    - Routing table
    - Active TCP connections with owning process
    - Active UDP listeners with owning process
    - DNS server configuration per adapter

    No admin required. Some process name resolution may be limited
    without admin.

    SCHEMA 1.1 ACQUISITION
    Two study collection units:

        host.network_config.tcp_connections
        host.network_config.udp_listeners

    ARP, routing and DNS are deliberately OUTSIDE the study acquisition
    register. Their existing behaviour is unchanged and they are not
    admitted to analytical datasets.

    SCOPE NOTE - local bind state is not remote reachability
    A listening socket establishes only that a process is bound to a port
    in this host's own network namespace. It does not establish that the
    port is reachable from anywhere else: that additionally depends on the
    active host firewall profile and on network-level filtering, neither of
    which this module observes. Remote reachability requires external
    corroboration.

    SUMMARY COUNTS
    summary.tcp_connections and summary.udp_listeners are numeric ONLY
    after the corresponding unit succeeded. After a non-success outcome
    they are $null, never 0 - a zero count would assert an observation
    that was never made.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKHostNetworkConfig {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating network configuration" -Type "PROCESSING"

    $tcpUnit = "host.network_config.tcp_connections"
    $udpUnit = "host.network_config.udp_listeners"

    $tcpProvider = "Get-NetTCPConnection"
    $udpProvider = "Get-NetUDPEndpoint"

    $netConfig = [ordered]@{}

    Start-VKAcquisition -UnitId $tcpUnit -Provider $tcpProvider -DataPaths @(
        "host.network_config.tcp_connections"
        "host.network_config.summary.tcp_connections"
    )
    Start-VKAcquisition -UnitId $udpUnit -Provider $udpProvider -DataPaths @(
        "host.network_config.udp_listeners"
        "host.network_config.summary.udp_listeners"
    )

    $tcpSucceeded = $false
    $udpSucceeded = $false


    # --------------------------------------------------------
    #  ARP Table  (not instrumented - outside the study register)
    # --------------------------------------------------------

    Write-VKStatus -Message "Collecting ARP table" -Type "PROCESSING"

    try {
        $arpEntries = @()
        $arpOutput = Get-NetNeighbor -ErrorAction Stop | Where-Object {
            $_.State -ne "Unreachable" -and $_.IPAddress -notlike "ff0*" -and $_.IPAddress -notlike "224.*"
        }

        foreach ($entry in $arpOutput) {
            $arpEntries += [ordered]@{
                "ip_address"    = $entry.IPAddress
                "mac_address"   = $entry.LinkLayerAddress
                "state"         = $entry.State.ToString()
                "interface_index" = $entry.InterfaceIndex
                "interface_alias" = $entry.InterfaceAlias
            }
        }

        $netConfig["arp_table"] = $arpEntries
    }
    catch {
        Write-LogMessage -Section "Host.NetworkConfig" -Message "Unable to retrieve ARP table: $($_.Exception.Message)" -Level "ERROR"
        $netConfig["arp_table"] = @()
    }


    # --------------------------------------------------------
    #  Routing Table  (not instrumented - outside the study register)
    # --------------------------------------------------------

    Write-VKStatus -Message "Collecting routing table" -Type "PROCESSING"

    try {
        $routes = @()
        $routeOutput = Get-NetRoute -ErrorAction Stop | Where-Object {
            $_.DestinationPrefix -ne "ff00::/8" -and $_.DestinationPrefix -ne "255.255.255.255/32"
        }

        foreach ($route in $routeOutput) {
            $routes += [ordered]@{
                "destination"     = $route.DestinationPrefix
                "next_hop"        = $route.NextHop
                "metric"          = $route.RouteMetric
                "interface_index" = $route.InterfaceIndex
                "interface_alias" = $route.InterfaceAlias
                "address_family"  = if ($route.AddressFamily -eq 2) { "IPv4" } else { "IPv6" }
            }
        }

        $netConfig["routing_table"] = $routes
    }
    catch {
        Write-LogMessage -Section "Host.NetworkConfig" -Message "Unable to retrieve routing table: $($_.Exception.Message)" -Level "ERROR"
        $netConfig["routing_table"] = @()
    }


    # --------------------------------------------------------
    #  Active TCP Connections  (INSTRUMENTED)
    # --------------------------------------------------------

    Write-VKStatus -Message "Collecting active connections" -Type "PROCESSING"

    $netConfig["tcp_connections"] = $null

    try {
        $tcpOutput = @(
            Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                $_.State -ne "Bound" -and $_.State -ne "TimeWait"
            }
        )

        $tcpConnections = @()

        foreach ($conn in $tcpOutput) {
            foreach ($required in @('LocalAddress', 'LocalPort', 'State')) {
                if ($null -eq $conn.$required) {
                    throw [System.InvalidOperationException]::new(
                        "A TCP connection record returned no $required value.")
                }
            }

            # Process-name resolution is OPTIONAL ENRICHMENT. Failing to
            # resolve a name does not invalidate the observed connection,
            # so it stays null rather than failing the unit.
            $processName = $null
            try {
                if ($conn.OwningProcess -and $conn.OwningProcess -ne 0) {
                    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    $processName = if ($proc) { $proc.ProcessName } else { $null }
                }
            }
            catch { $processName = $null }

            $tcpConnections += [ordered]@{
                "local_address"  = $conn.LocalAddress
                "local_port"     = $conn.LocalPort
                "remote_address" = $conn.RemoteAddress
                "remote_port"    = $conn.RemotePort
                "state"          = $conn.State.ToString()
                "pid"            = $conn.OwningProcess
                "process_name"   = $processName
            }
        }

        # Genuine zero result: the provider answered and nothing matched.
        $netConfig["tcp_connections"] = $tcpConnections
        $tcpSucceeded = $true
        Complete-VKAcquisition -UnitId $tcpUnit
    }
    catch {
        # $null, not @(): an empty array would read as "no connections",
        # which was never established.
        $netConfig["tcp_connections"] = $null

        Write-LogMessage -Section "Host.NetworkConfig" -Message "Unable to retrieve TCP connections: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $tcpUnit -Provider $tcpProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $tcpUnit -ErrorRecord $_ -Provider $tcpProvider
        }
    }


    # --------------------------------------------------------
    #  Active UDP Listeners  (INSTRUMENTED)
    # --------------------------------------------------------

    $netConfig["udp_listeners"] = $null

    try {
        $udpOutput = @(Get-NetUDPEndpoint -ErrorAction Stop)

        $udpListeners = @()

        foreach ($udp in $udpOutput) {
            foreach ($required in @('LocalAddress', 'LocalPort')) {
                if ($null -eq $udp.$required) {
                    throw [System.InvalidOperationException]::new(
                        "A UDP endpoint record returned no $required value.")
                }
            }

            # Optional enrichment, as above.
            $processName = $null
            try {
                if ($udp.OwningProcess -and $udp.OwningProcess -ne 0) {
                    $proc = Get-Process -Id $udp.OwningProcess -ErrorAction SilentlyContinue
                    $processName = if ($proc) { $proc.ProcessName } else { $null }
                }
            }
            catch { $processName = $null }

            $udpListeners += [ordered]@{
                "local_address" = $udp.LocalAddress
                "local_port"    = $udp.LocalPort
                "pid"           = $udp.OwningProcess
                "process_name"  = $processName
            }
        }

        $netConfig["udp_listeners"] = $udpListeners
        $udpSucceeded = $true
        Complete-VKAcquisition -UnitId $udpUnit
    }
    catch {
        $netConfig["udp_listeners"] = $null

        Write-LogMessage -Section "Host.NetworkConfig" -Message "Unable to retrieve UDP endpoints: $($_.Exception.Message)" -Level "ERROR"

        if ($_.Exception -is [System.InvalidOperationException]) {
            Set-VKAcquisitionUnavailable -UnitId $udpUnit -Provider $udpProvider `
                -Category "provider_value_missing" -Message $_.Exception.Message
        }
        else {
            Set-VKAcquisitionFailure -UnitId $udpUnit -ErrorRecord $_ -Provider $udpProvider
        }
    }


    # --------------------------------------------------------
    #  DNS Server Configuration  (not instrumented)
    # --------------------------------------------------------

    try {
        $dnsServers = @()
        $dnsConfig = Get-DnsClientServerAddress -ErrorAction Stop | Where-Object {
            $_.ServerAddresses.Count -gt 0
        }

        foreach ($dns in $dnsConfig) {
            $dnsServers += [ordered]@{
                "interface_alias"  = $dns.InterfaceAlias
                "interface_index"  = $dns.InterfaceIndex
                "address_family"   = if ($dns.AddressFamily -eq 2) { "IPv4" } else { "IPv6" }
                "server_addresses" = $dns.ServerAddresses
            }
        }

        $netConfig["dns_servers"] = $dnsServers
    }
    catch {
        Write-LogMessage -Section "Host.NetworkConfig" -Message "Unable to retrieve DNS configuration: $($_.Exception.Message)" -Level "ERROR"
        $netConfig["dns_servers"] = @()
    }


    # --------------------------------------------------------
    #  Summary
    # --------------------------------------------------------
    # The two instrumented counts are numeric only where the governing
    # unit succeeded; otherwise $null. ARP and route counts retain their
    # existing uninstrumented behaviour.

    $netConfig["summary"] = [ordered]@{
        "arp_entries"     = @($netConfig["arp_table"]).Count
        "routes"          = @($netConfig["routing_table"]).Count
        "tcp_connections" = if ($tcpSucceeded) { @($netConfig["tcp_connections"]).Count } else { $null }
        "udp_listeners"   = if ($udpSucceeded) { @($netConfig["udp_listeners"]).Count } else { $null }
    }

    $Data["network_config"] = $netConfig

    Write-VKStatus -Message "Network configuration enumeration complete" -Type "SUCCESS"
}
