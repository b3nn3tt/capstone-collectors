<#
.SYNOPSIS
    Minimal SYNTHETIC schema 1.0 legacy-evidence fixture.

.DESCRIPTION
    Represents evidence collected by agent 2.0 under schema 1.0, before the
    acquisition section existed. Four top-level sections, no acquisition.

    This fixture exists to prove the LEGACY READING RULE from
    docs/dissertation-agent-evidence-contract.md section 5.5.2:

        Directly observed presence may remain inspectable, but empty or
        missing results cannot support confirmed absence.

    Under schema 1.0 there is no way to distinguish a successful
    zero-result collection from failure, restriction or unavailability, so
    every empty or missing value here is UNKNOWN, never absent.

    It deliberately includes the three schema 1.0 fabricated-value shapes
    the Tranche 2A corrections removed, so tests can assert that legacy
    artefacts are identified as legacy and are not read as schema 1.1:

        legacy_protocols.llmnr_enabled = $true with no value_source
        host_security.security_services populated entirely with $false
        antivirus.product_name = "Not Detected"

    This fixture is NOT a target shape. Nothing here should be reproduced
    by the current agent.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>

[ordered]@{

    "scan_metadata" = [ordered]@{
        "schema_version"        = "1.0"
        "agent_version"         = "2.0"
        "hostname"              = "LEGACY-FIXTURE-01"
        "running_user"          = "FIXTUREDOM\legacy.user"
        "running_user_sid"      = "S-1-5-21-9999999999-8888888888-7777777777-1001"
        "scan_start"            = "2026-03-02T11:00:00Z"
        "scan_end"              = "2026-03-02T11:02:10Z"
        "scan_duration_seconds" = 130.0
        "ran_as_admin"          = $false
        "modules_executed"      = @(
            "security.antivirus"
            "security.host_security"
            "security.legacy_protocols"
        )
    }

    # NOTE: no "acquisition" section. That is correct for schema 1.0 - this
    # artefact predates the contract rather than violating it.

    "host" = [ordered]@{
        "hostname" = "LEGACY-FIXTURE-01"
        "os" = [ordered]@{
            "name"          = "Microsoft Windows 10 Enterprise"
            "architecture"  = "64-bit"
            "version"       = "10.0.19045"
            "build"         = 19045
            "platform_role" = "Desktop"
        }
        # Empty under schema 1.0. Indistinguishable from a failed read,
        # therefore UNKNOWN - it cannot support confirmed absence.
        "network_shares" = @()
    }

    "security" = [ordered]@{

        # Schema 1.0 conflated "no AV registered" with "query failed or
        # was denied". This value cannot be read as protection degradation.
        "antivirus" = [ordered]@{
            "product_name"  = "Not Detected"
            "product_state" = $null
        }

        # Schema 1.0 emitted a fully populated list of $false even when the
        # Win32_DeviceGuard query failed. These values are unreliable in
        # both directions and must not be read as absence of mitigation.
        "host_security" = [ordered]@{
            "kernel_dma_protection" = $null
            "dep_policy"            = "Opt-Out (All Processes)"
            "vbs_status"            = $null
            "security_services"     = @(
                [ordered]@{ "service_name" = "Credential Guard"; "configured" = $false; "running" = $false }
                [ordered]@{ "service_name" = "HVCI (Hypervisor Code Integrity)"; "configured" = $false; "running" = $false }
            )
            "security_properties"   = @(
                [ordered]@{ "property_name" = "Hypervisor support"; "available" = $false }
            )
        }

        # Schema 1.0 set these to $true on a read failure, with no
        # provenance marker to separate observation from inference.
        "legacy_protocols" = [ordered]@{
            "llmnr_enabled"       = $true
            "mdns_enabled"        = $true
            "netbios_any_enabled" = $null
            "tls_protocols"       = @()
        }
    }

    "vulnerability" = [ordered]@{
        # Empty under schema 1.0 - unknown, not absent.
        "token_privileges" = [ordered]@{
            "user"             = "FIXTUREDOM\legacy.user"
            "total_privileges" = 0
            "privileges"       = @()
        }
    }
}
