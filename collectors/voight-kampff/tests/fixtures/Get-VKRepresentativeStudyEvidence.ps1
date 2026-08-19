<#
.SYNOPSIS
    Representative synthetic study-evidence fixture for the Voight-Kampff output contract.

.DESCRIPTION
    Returns a four-key envelope populated with SYNTHETIC data that mirrors the
    shape of the agent's real output for the study-relevant C1-C7 paths.

    This fixture exists so the output-contract tests never depend on live host
    configuration. Nothing here is collected from the machine running the tests.

    Coverage is deliberately shape-focused rather than value-focused. It includes
    the deepest nesting the agent currently produces, so that the JSON depth
    contract can be verified:

        host.windows_updates.pending_updates[].kb_numbers[]      (5 levels)
        host.network_shares[].permissions[].account              (5 levels)

    Values are chosen to be obviously synthetic (RFC 5737 documentation IP
    ranges, placeholder principal names) so that a fixture leaking into real
    output is immediately recognisable.

    SCHEMA 1.1
    Updated for Tranche 2A. The envelope now has five ordered sections and
    carries an acquisition entry for every collection unit instrumented so
    far. Acquisition entries deliberately exercise all four permitted
    outcomes so the vocabulary and error-shape tests have real material:

        success      security.legacy_protocols.llmnr, .mdns, .netbios,
                     .wpad_service, .tls_protocols,
                     security.host_security.dep_policy, .device_guard,
                     security.antivirus.products, .defender_status
        failed       security.legacy_protocols.wpad_auto_detect
        restricted   security.host_security.kernel_dma_protection

    Only the three modules migrated in Tranche 2A appear here. The
    remaining study-relevant modules are instrumented in Tranche 2B.

    NOTE: the full present / absent / unknown / restricted / failed payload
    fixture set is roadmap item 10 and is NOT implemented here.

.OUTPUTS
    System.Collections.Specialized.OrderedDictionary
#>

[ordered]@{

    "scan_metadata" = [ordered]@{
        "schema_version"        = "1.1"
        "agent_version"         = "2.1.0"
        "hostname"              = "FIXTURE-HOST-01"
        "running_user"          = "FIXTUREDOM\fixture.user"
        "running_user_sid"      = "S-1-5-21-1111111111-2222222222-3333333333-1001"
        "scan_start"            = "2026-08-18T09:14:00Z"
        "scan_end"              = "2026-08-18T09:16:30Z"
        "scan_duration_seconds" = 150.0
        "ran_as_admin"          = $true
        "modules_executed"      = @(
            "host.identification"
            "host.network"
            "host.network_config"
            "host.users"
            "host.software"
            "host.services"
            "host.processes"
            "host.windows_updates"
            "security.antivirus"
            "security.defender_advanced"
            "security.rdp"
            "security.winrm"
            "security.smb"
            "security.legacy_protocols"
            "security.host_security"
            "security.firewall"
            "security.uac"
            "vul.privileges.token"
        )
    }

    # ------------------------------------------------------------------
    #  ACQUISITION  (schema 1.1)
    # ------------------------------------------------------------------
    # Records only WHETHER COLLECTION WORKED. Keyed by stable dotted
    # collection-unit identifier. Payload data is never duplicated here -
    # each entry points at the payload through data_paths.
    # ------------------------------------------------------------------
    "acquisition" = [ordered]@{

        # --- Security.LegacyProtocols ---
        "security.legacy_protocols.llmnr" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:01Z"
            "observation_end"     = "2026-08-18T09:15:01Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.legacy_protocols.llmnr_enabled"
                "security.legacy_protocols.llmnr_value_source"
            )
            "error"               = $null
        }

        "security.legacy_protocols.mdns" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:01Z"
            "observation_end"     = "2026-08-18T09:15:02Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.legacy_protocols.mdns_enabled"
                "security.legacy_protocols.mdns_value_source"
            )
            "error"               = $null
        }

        "security.legacy_protocols.netbios" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:02Z"
            "observation_end"     = "2026-08-18T09:15:03Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.legacy_protocols.netbios_adapters"
                "security.legacy_protocols.netbios_any_enabled"
            )
            "error"               = $null
        }

        "security.legacy_protocols.wpad_service" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:03Z"
            "observation_end"     = "2026-08-18T09:15:03Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.legacy_protocols.wpad_service_state"
                "security.legacy_protocols.wpad_service_start_type"
            )
            "error"               = $null
        }

        # Non-success example: unexpected error during a registry read.
        "security.legacy_protocols.wpad_auto_detect" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:03Z"
            "observation_end"     = "2026-08-18T09:15:04Z"
            "acquisition_outcome" = "failed"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.legacy_protocols.wpad_auto_detect")
            "error"               = [ordered]@{
                "category"       = "unexpected_error"
                "provider"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                "message"        = "The registry value could not be read because the key handle was invalid."
                "exception_type" = "System.IO.IOException"
            }
        }

        "security.legacy_protocols.tls_protocols" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:04Z"
            "observation_end"     = "2026-08-18T09:15:05Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.legacy_protocols.tls_protocols")
            "error"               = $null
        }

        # --- Security.HostSecurity ---
        # Non-success example: permission or policy denial.
        "security.host_security.kernel_dma_protection" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:05Z"
            "observation_end"     = "2026-08-18T09:15:05Z"
            "acquisition_outcome" = "restricted"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.host_security.kernel_dma_protection")
            "error"               = [ordered]@{
                "category"       = "access_denied"
                "provider"       = "ntdll.dll:NtQuerySystemInformation(SystemDmaGuardPolicyInformation)"
                "message"        = "Access is denied."
                "exception_type" = "System.UnauthorizedAccessException"
            }
        }

        "security.host_security.dep_policy" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:05Z"
            "observation_end"     = "2026-08-18T09:15:06Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.host_security.dep_policy")
            "error"               = $null
        }

        "security.host_security.device_guard" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:06Z"
            "observation_end"     = "2026-08-18T09:15:07Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.host_security.vbs_status"
                "security.host_security.security_services"
                "security.host_security.security_properties"
            )
            "error"               = $null
        }

        # --- Security.Antivirus ---
        "security.antivirus.products" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:07Z"
            "observation_end"     = "2026-08-18T09:15:08Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.antivirus.product_name"
                "security.antivirus.product_state"
                "security.antivirus.products_detected"
            )
            "error"               = $null
        }

        "security.antivirus.defender_status" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:08Z"
            "observation_end"     = "2026-08-18T09:15:09Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.antivirus.running_mode"
                "security.antivirus.real_time_protection"
                "security.antivirus.antivirus_enabled"
                "security.antivirus.antispyware_enabled"
                "security.antivirus.antivirus_signature_updated"
                "security.antivirus.antispyware_signature_updated"
            )
            "error"               = $null
        }

        # ============================================================
        #  Tranche 2B.1 units
        # ============================================================

        # --- Security.DefenderAdvanced ---
        "security.defender_advanced.asr_rules" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:09Z"
            "observation_end"     = "2026-08-18T09:15:10Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.defender_advanced.asr_rules"
                "security.defender_advanced.asr_rules_count"
                "security.defender_advanced.asr_rules_blocking"
            )
            "error"               = $null
        }

        "security.defender_advanced.protection_preferences" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:09Z"
            "observation_end"     = "2026-08-18T09:15:10Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.defender_advanced.network_protection"
                "security.defender_advanced.controlled_folder_access"
                "security.defender_advanced.pua_protection"
                "security.defender_advanced.cloud_protection"
                "security.defender_advanced.sample_submission"
            )
            "error"               = $null
        }

        "security.defender_advanced.tamper_protection" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:10Z"
            "observation_end"     = "2026-08-18T09:15:11Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.defender_advanced.tamper_protection")
            "error"               = $null
        }

        # --- Security.Firewall ---
        "security.firewall.profiles" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:11Z"
            "observation_end"     = "2026-08-18T09:15:12Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.firewall_profiles")
            "error"               = $null
        }

        "security.firewall.inbound_rules" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:12Z"
            "observation_end"     = "2026-08-18T09:15:13Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.firewall_rules")
            "error"               = $null
        }

        # --- Security.SMB ---
        "security.smb.smbv1" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:13Z"
            "observation_end"     = "2026-08-18T09:15:14Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.smb.smbv1_enabled"
                "security.smb.smbv1_value_source"
            )
            "error"               = $null
        }

        "security.smb.server_registry" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:14Z"
            "observation_end"     = "2026-08-18T09:15:15Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.smb.server_signing_required"
                "security.smb.server_signing_enabled"
                "security.smb.server_encrypt_data"
                "security.smb.server_reject_unencrypted"
                "security.smb.null_session_pipes"
                "security.smb.null_session_shares"
                "security.smb.restrict_null_session_access"
                "security.smb.server_value_sources"
            )
            "error"               = $null
        }

        "security.smb.client_registry" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:15Z"
            "observation_end"     = "2026-08-18T09:15:16Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.smb.client_signing_required"
                "security.smb.client_signing_enabled"
                "security.smb.client_insecure_guest_auth"
                "security.smb.client_value_sources"
            )
            "error"               = $null
        }

        # Non-success example: a non-elevated scan cannot read this.
        "security.smb.server_configuration" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:16Z"
            "observation_end"     = "2026-08-18T09:15:16Z"
            "acquisition_outcome" = "restricted"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.smb.smb2_enabled"
                "security.smb.server_multichannel"
                "security.smb.server_leasing"
                "security.smb.max_channel_per_session"
            )
            "error"               = [ordered]@{
                "category"       = "insufficient_privilege"
                "provider"       = "Get-SmbServerConfiguration"
                "message"        = "Get-SmbServerConfiguration requires administrative privileges."
                "exception_type" = $null
            }
        }

        # --- Security.RDP ---
        "security.rdp.terminal_server" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:17Z"
            "observation_end"     = "2026-08-18T09:15:17Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.rdp.rdp_enabled"
                "security.rdp.restricted_admin_enabled"
            )
            "error"               = $null
        }

        "security.rdp.rdp_tcp" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:17Z"
            "observation_end"     = "2026-08-18T09:15:18Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.rdp.port"
                "security.rdp.port_value_source"
                "security.rdp.nla_required"
                "security.rdp.security_layer"
                "security.rdp.encryption_level"
                "security.rdp.idle_timeout_ms"
                "security.rdp.disconnect_timeout_ms"
                "security.rdp.session_limit_ms"
            )
            "error"               = $null
        }

        "security.rdp.allowed_users" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:18Z"
            "observation_end"     = "2026-08-18T09:15:19Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.rdp.allowed_users")
            "error"               = $null
        }

        # --- Security.WinRM ---
        "security.winrm.service" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:19Z"
            "observation_end"     = "2026-08-18T09:15:20Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.winrm.service_state"
                "security.winrm.service_start_type"
            )
            "error"               = $null
        }

        # Non-success example: server settings denied without elevation.
        "security.winrm.server_registry" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:20Z"
            "observation_end"     = "2026-08-18T09:15:20Z"
            "acquisition_outcome" = "restricted"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.winrm.allow_unencrypted"
                "security.winrm.server_auth"
                "security.winrm.server_value_sources"
            )
            "error"               = [ordered]@{
                "category"       = "access_denied"
                "provider"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service"
                "message"        = "Requested registry access is not allowed."
                "exception_type" = "System.Security.SecurityException"
            }
        }

        "security.winrm.client_registry" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:20Z"
            "observation_end"     = "2026-08-18T09:15:21Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.winrm.client_auth"
                "security.winrm.client_allow_unencrypted"
                "security.winrm.client_value_sources"
            )
            "error"               = $null
        }

        "security.winrm.trusted_hosts" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:21Z"
            "observation_end"     = "2026-08-18T09:15:21Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.winrm.trusted_hosts")
            "error"               = $null
        }

        "security.winrm.listeners" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:21Z"
            "observation_end"     = "2026-08-18T09:15:22Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.winrm.listeners")
            "error"               = $null
        }

        # --- Security.UAC ---
        "security.uac.configuration" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:22Z"
            "observation_end"     = "2026-08-18T09:15:23Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "security.uac.uac_enabled"
                "security.uac.admin_approval_mode"
                "security.uac.consent_prompt_admin"
                "security.uac.consent_prompt_admin_text"
                "security.uac.consent_prompt_standard"
                "security.uac.consent_prompt_standard_text"
                "security.uac.secure_desktop_enabled"
                "security.uac.detect_installations"
                "security.uac.validate_admin_code_signatures"
                "security.uac.built_in_admin_approval_mode"
                "security.uac.only_elevate_signed"
                "security.uac.only_elevate_ui_access"
            )
            "error"               = $null
        }

        # --- Security.FDE ---
        "security.fde.os_drive" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:23Z"
            "observation_end"     = "2026-08-18T09:15:24Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.fde_os_drive")
            "error"               = $null
        }

        # Non-success example: a provider that is not present on the host.
        "security.fde.additional_volumes" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:24Z"
            "observation_end"     = "2026-08-18T09:15:24Z"
            "acquisition_outcome" = "unavailable"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("security.fde_additional_volumes")
            "error"               = [ordered]@{
                "category"       = "command_not_found"
                "provider"       = "Get-BitLockerVolume"
                "message"        = "The term 'Get-BitLockerVolume' is not recognised as a cmdlet on this host."
                "exception_type" = "System.Management.Automation.CommandNotFoundException"
            }
        }

        # ============================================================
        #  Tranche 2B.2 units (host and pathway modules)
        # ============================================================

        # --- Host.Identification ---
        "host.identification.hostname" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:01Z"
            "observation_end"     = "2026-08-18T09:14:01Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("host.hostname")
            "error"               = $null
        }

        "host.identification.operating_system" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:01Z"
            "observation_end"     = "2026-08-18T09:14:02Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.os.name"
                "host.os.architecture"
                "host.os.version"
                "host.os.build"
            )
            "error"               = $null
        }

        "host.identification.computer_system" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:02Z"
            "observation_end"     = "2026-08-18T09:14:03Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.os.platform_role"
                "host.domain_status.status"
                "host.domain_status.domain_name"
                "host.domain_status.workgroup_name"
            )
            "error"               = $null
        }

        # --- Host.NetworkConfig (TCP and UDP only) ---
        "host.network_config.tcp_connections" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:05Z"
            "observation_end"     = "2026-08-18T09:14:06Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.network_config.tcp_connections"
                "host.network_config.summary.tcp_connections"
            )
            "error"               = $null
        }

        "host.network_config.udp_listeners" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:06Z"
            "observation_end"     = "2026-08-18T09:14:07Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.network_config.udp_listeners"
                "host.network_config.summary.udp_listeners"
            )
            "error"               = $null
        }

        # --- Host.Services ---
        "host.services.inventory" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:08Z"
            "observation_end"     = "2026-08-18T09:14:10Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("host.services")
            "error"               = $null
        }

        # --- Host.Processes ---
        "host.processes.inventory" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:10Z"
            "observation_end"     = "2026-08-18T09:14:12Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("host.processes")
            "error"               = $null
        }

        # --- Host.Software: two hives governing ONE combined path ---
        # The combined list is emitted only because BOTH applicable
        # machine-scope hives succeeded. See the shared-path rule.
        "host.software.hklm_native" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:13Z"
            "observation_end"     = "2026-08-18T09:14:14Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("host.installed_software")
            "error"               = $null
        }

        "host.software.hklm_wow6432" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:14Z"
            "observation_end"     = "2026-08-18T09:14:15Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("host.installed_software")
            "error"               = $null
        }

        # --- Host.Users ---
        "host.users.local_accounts" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:16Z"
            "observation_end"     = "2026-08-18T09:14:17Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.base_sid"
                "host.user_accounts"
            )
            "error"               = $null
        }

        "host.users.group_memberships" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:17Z"
            "observation_end"     = "2026-08-18T09:14:18Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.group_memberships"
                "host.user_accounts[].is_admin"
            )
            "error"               = $null
        }

        # ============================================================
        #  Tranche 2C units (session and recent-profile telemetry)
        # ============================================================

        "host.sessions.current_sessions" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:19Z"
            "observation_end"     = "2026-08-18T09:14:19Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.sessions.current_sessions"
                "host.sessions.current_sessions_summary"
            )
            "error"               = $null
        }

        # Non-success example: querying another user's session normally
        # requires elevation. Session STATE evidence above survives this.
        "host.sessions.session_principals" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:19Z"
            "observation_end"     = "2026-08-18T09:14:20Z"
            "acquisition_outcome" = "restricted"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.sessions.session_principals"
                "host.sessions.session_principals_summary"
            )
            "error"               = [ordered]@{
                "category"       = "access_denied"
                "provider"       = "wtsapi32.dll:WTSQuerySessionInformation(WTSUserName/WTSDomainName)"
                "message"        = "WTSQuerySessionInformation failed for info class 5 on session 2."
                "exception_type" = "VoightKampff.WtsException"
            }
        }

        "host.sessions.user_profiles" = [ordered]@{
            "observation_start"   = "2026-08-18T09:14:20Z"
            "observation_end"     = "2026-08-18T09:14:21Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @(
                "host.sessions.observation_window"
                "host.sessions.user_profiles"
                "host.sessions.user_profiles_summary"
            )
            "error"               = $null
        }

        # --- Vul.Privileges.Token ---
        "vulnerability.token_privileges.current_token" = [ordered]@{
            "observation_start"   = "2026-08-18T09:15:59Z"
            "observation_end"     = "2026-08-18T09:16:00Z"
            "acquisition_outcome" = "success"
            "agent_version"       = "2.1.0"
            "schema_version"      = "1.1"
            "data_paths"          = @("vulnerability.token_privileges")
            "error"               = $null
        }
    }

    # ------------------------------------------------------------------
    #  HOST
    # ------------------------------------------------------------------
    "host" = [ordered]@{

        "hostname" = "FIXTURE-HOST-01"

        # C2 / C5 - component state and host role
        "os" = [ordered]@{
            "name"          = "Microsoft Windows 11 Enterprise"
            "architecture"  = "64-bit"
            "version"       = "10.0.26200"
            "build"         = 26200
            "platform_role" = "Desktop"
        }

        "domain_status" = [ordered]@{
            "status"      = "Domain-Joined"
            "domain_name" = "fixture.example"
        }

        "manufacturer" = [ordered]@{
            "manufacturer"  = "Fixture Systems Ltd"
            "model"         = "FX-1000"
            "serial_number" = "FIXTURE-SERIAL-0001"
            "system_family" = "Fixture Family"
            "system_sku"    = "FX1000-SKU"
        }

        # C1 - local interface state
        "network_interfaces" = @(
            [ordered]@{
                "interface"     = "Ethernet"
                "ip_address"    = "192.0.2.10"
                "prefix_length" = 24
                "mac_address"   = "00-00-5E-00-53-01"
                "link_speed"    = "1 Gbps"
                "media_type"    = "802.3"
            }
        )

        # C1 / C6 - share exposure. DEEPEST PATH: permissions[].account (5 levels)
        "network_shares" = @(
            [ordered]@{
                "name"        = "FixtureData"
                "path"        = "D:\FixtureData"
                "description" = "Synthetic share for contract testing"
                "type"        = "Regular"
                "state"       = "Online"
                "permissions" = @(
                    [ordered]@{
                        "account"      = "FIXTUREDOM\Domain Users"
                        "access_type"  = "Allow"
                        "access_right" = "Change"
                    }
                    [ordered]@{
                        "account"      = "BUILTIN\Administrators"
                        "access_type"  = "Allow"
                        "access_right" = "Full Control"
                    }
                )
                "writable"    = $true
            }
        )

        # C1 - local bind state (NOT remote reachability)
        "network_config" = [ordered]@{
            "arp_table" = @(
                [ordered]@{
                    "ip_address"      = "192.0.2.1"
                    "mac_address"     = "00-00-5E-00-53-FE"
                    "state"           = "Reachable"
                    "interface_index" = 12
                    "interface_alias" = "Ethernet"
                }
            )
            "routing_table" = @(
                [ordered]@{
                    "destination"     = "0.0.0.0/0"
                    "next_hop"        = "192.0.2.1"
                    "metric"          = 25
                    "interface_index" = 12
                    "interface_alias" = "Ethernet"
                    "address_family"  = "IPv4"
                }
            )
            "tcp_connections" = @(
                [ordered]@{
                    "local_address"  = "0.0.0.0"
                    "local_port"     = 3389
                    "remote_address" = "0.0.0.0"
                    "remote_port"    = 0
                    "state"          = "Listen"
                    "pid"            = 1180
                    "process_name"   = "svchost"
                }
                [ordered]@{
                    "local_address"  = "192.0.2.10"
                    "local_port"     = 51544
                    "remote_address" = "198.51.100.25"
                    "remote_port"    = 443
                    "state"          = "Established"
                    "pid"            = 4488
                    "process_name"   = "fixtureapp"
                }
            )
            "udp_listeners" = @(
                [ordered]@{
                    "local_address" = "0.0.0.0"
                    "local_port"    = 5355
                    "pid"           = 1180
                    "process_name"  = "svchost"
                }
            )
            "dns_servers" = @(
                [ordered]@{
                    "interface_alias"  = "Ethernet"
                    "interface_index"  = 12
                    "address_family"   = "IPv4"
                    "server_addresses" = @("192.0.2.53", "192.0.2.54")
                }
            )
            "summary" = [ordered]@{
                "arp_entries"     = 1
                "routes"          = 1
                "tcp_connections" = 2
                "udp_listeners"   = 1
            }
        }

        # C5 / C6 - session and recent-profile telemetry.
        #
        # current_sessions is DIRECT, point-in-time evidence.
        # user_profiles[].last_use_time is a RETROSPECTIVE PROXY and is not
        # an interactive-logon record, which evidence_strength records.
        "sessions" = [ordered]@{

            # Qualifies LastUseTime only; WTS sessions are point-in-time.
            "observation_window" = [ordered]@{
                "window_start"          = "2026-08-17T09:14:20Z"
                "window_end"            = "2026-08-18T09:14:20Z"
                "window_duration_hours" = 24
                "window_source"         = "configured"
            }

            "current_sessions" = @(
                [ordered]@{
                    "session_id"          = 1
                    "session_name"        = "Console"
                    "state"               = "Active"
                    "protocol_type"       = 0
                    "session_type"        = "console"
                    "session_type_source" = "wts_client_protocol_type"
                }
                [ordered]@{
                    "session_id"          = 2
                    "session_name"        = "RDP-Tcp#0"
                    "state"               = "Disconnected"
                    "protocol_type"       = 2
                    "session_type"        = "remote"
                    "session_type_source" = "wts_client_protocol_type"
                }
                [ordered]@{
                    # A listener is classified from its connection state and
                    # is never queried for a principal.
                    "session_id"          = 65536
                    "session_name"        = "RDP-Tcp"
                    "state"               = "Listen"
                    "protocol_type"       = $null
                    "session_type"        = "listener"
                    "session_type_source" = "connect_state"
                }
            )

            "current_sessions_summary" = [ordered]@{
                "total"        = 3
                "active"       = 1
                "disconnected" = 1
                "console"      = 1
                "remote"       = 1
                "listener"     = 1
            }

            # host.sessions.session_principals is 'restricted' in this
            # fixture, so both principal paths stay null while the session
            # STATE evidence above is retained.
            "session_principals"         = $null
            "session_principals_summary" = $null

            "user_profiles" = @(
                [ordered]@{
                    "sid"                    = "S-1-5-21-1111111111-2222222222-3333333333-1001"
                    "loaded"                 = $true
                    "special"                = $false
                    "last_use_time"          = "2026-08-18T08:55:00Z"
                    "last_use_within_window" = $true
                    "evidence_strength"      = "profile_use_proxy"
                }
                [ordered]@{
                    "sid"                    = "S-1-5-21-1111111111-2222222222-3333333333-1002"
                    "loaded"                 = $false
                    "special"                = $false
                    "last_use_time"          = "2026-08-02T11:20:00Z"
                    "last_use_within_window" = $false
                    "evidence_strength"      = "profile_use_proxy"
                }
                [ordered]@{
                    # Special profiles stay identifiable so downstream
                    # ingestion can exclude them.
                    "sid"                    = "S-1-5-18"
                    "loaded"                 = $true
                    "special"                = $true
                    "last_use_time"          = "2026-08-18T09:10:00Z"
                    "last_use_within_window" = $true
                    "evidence_strength"      = "profile_use_proxy"
                }
            )

            "user_profiles_summary" = [ordered]@{
                "total"              = 3
                "loaded"             = 2
                "special"            = 1
                "used_within_window" = 2
            }
        }

        # C6 - local principals and admin membership.
        # Scope markers are additive and make the observation boundary
        # explicit: Get-LocalUser and Get-LocalGroupMember see the local
        # SAM database only.
        "user_accounts_scope"     = "local_only"
        "group_memberships_scope" = "local_groups_only"

        "base_sid" = "S-1-5-21-1111111111-2222222222-3333333333"

        "group_memberships" = @(
            [ordered]@{
                "group_name"  = "Administrators"
                "description" = "Administrators have complete access"
                "members"     = @("Administrator", "fixture.admin")
            }
            [ordered]@{
                "group_name"  = "Remote Desktop Users"
                "description" = "Members can log on remotely"
                "members"     = @("fixture.user")
            }
        )

        "user_accounts" = @(
            [ordered]@{
                "rid"                     = 500
                "name"                    = "Administrator"
                "enabled"                 = $false
                "is_admin"                = $true
                "is_system_account"       = $true
                "password_last_set"       = "2025-11-02T08:00:00Z"
                "days_since_password_set" = 289
                "password_expired"        = $false
                "password_never_expires"  = $true
                "last_logon"              = $null
                "days_since_last_logon"   = $null
                "is_locked_out"           = $false
                "lockout_time"            = $null
                "principal_source"        = "Local"
            }
            [ordered]@{
                "rid"                     = 1001
                "name"                    = "fixture.user"
                "enabled"                 = $true
                "is_admin"                = $false
                "is_system_account"       = $false
                "password_last_set"       = "2026-06-01T10:30:00Z"
                "days_since_password_set" = 78
                "password_expired"        = $false
                "password_never_expires"  = $false
                "last_logon"              = "2026-08-18T08:55:00Z"
                "days_since_last_logon"   = 0
                "is_locked_out"           = $false
                "lockout_time"            = $null
                "principal_source"        = "Local"
            }
        )

        # C2 - installed software
        "installed_software" = @(
            [ordered]@{
                "name"           = "Fixture Reader"
                "version"        = "21.4.1"
                "publisher"      = "Fixture Software"
                "install_date"   = "2026-02-14"
                "size_mb"        = 412.5
                "registry_scope" = "hklm_native"
            }
            [ordered]@{
                "name"           = "Fixture Runtime"
                "version"        = "8.0.11"
                "publisher"      = "Fixture Software"
                "install_date"   = "2026-05-20"
                "size_mb"        = 88.25
                "registry_scope" = "hklm_wow6432"
            }
        )

        # C1 / C2 - service state
        "services" = @(
            [ordered]@{
                "name"                = "TermService"
                "display_name"        = "Remote Desktop Services"
                "description"         = "Allows users to connect interactively"
                "state"               = "Running"
                "start_type"          = "Manual"
                "logon_account"       = "NT Authority\NetworkService"
                "binary_path"         = "C:\Windows\System32\svchost.exe -k NetworkService"
                "has_spaces_unquoted" = $false
                "pid"                 = 1180
            }
            [ordered]@{
                "name"                = "FixtureAgent"
                "display_name"        = "Fixture Agent Service"
                "description"         = "Synthetic service entry"
                "state"               = "Running"
                "start_type"          = "Auto"
                "logon_account"       = "LocalSystem"
                "binary_path"         = "C:\Program Files\Fixture\agent service.exe"
                "has_spaces_unquoted" = $true
                "pid"                 = 4488
            }
        )

        # C2 / C5 - process state
        "processes" = @(
            [ordered]@{
                "name"         = "fixtureapp.exe"
                "pid"          = 4488
                "parent_pid"   = 780
                "owner"        = "FIXTUREDOM\fixture.user"
                "executable"   = "C:\Program Files\Fixture\fixtureapp.exe"
                "command_line" = "`"C:\Program Files\Fixture\fixtureapp.exe`" --profile default"
                "session_id"   = 1
                "memory_mb"    = 142.75
                "start_time"   = "2026-08-18T08:56:12Z"
            }
        )

        # C2 - patch state. DEEPEST PATH: pending_updates[].kb_numbers[] (5 levels)
        "windows_updates" = [ordered]@{
            "reboot_pending"        = $true
            "reboot_reasons"        = @("Windows Update")
            "last_check"            = "2026-08-17T22:05:00Z"
            "last_install"          = "2026-08-11T03:12:00Z"
            "days_since_last_check" = 0
            "pending_count"         = 1
            "pending_updates"       = @(
                [ordered]@{
                    "title"         = "2026-08 Cumulative Update for Windows 11 (KB5099999)"
                    "kb_numbers"    = @("KB5099999", "KB5088888")
                    "severity"      = "Critical"
                    "is_downloaded" = $true
                    "is_mandatory"  = $false
                    "categories"    = @("Security Updates", "Windows 11")
                }
            )
            "installed_recent" = @(
                [ordered]@{
                    "title"     = "2026-07 Cumulative Update for Windows 11 (KB5077777)"
                    "kb_number" = "KB5077777"
                    "date"      = "2026-08-11T03:12:00Z"
                    "result"    = "Succeeded"
                    "operation" = "Installation"
                }
            )
        }
    }

    # ------------------------------------------------------------------
    #  SECURITY
    # ------------------------------------------------------------------
    "security" = [ordered]@{

        # C7 - protection state
        "antivirus" = [ordered]@{
            "product_name"                  = "Windows Defender"
            "products_detected"             = 1
            "product_state"                 = [ordered]@{
                "ProductState"     = 397568
                "HexadecimalState" = "0x61100"
                "OperationalState" = "On (Protection Enabled)"
                "SignatureStatus"  = "Up to Date"
            }
            "running_mode"                  = "Normal"
            "real_time_protection"          = $true
            "antivirus_enabled"             = $true
            "antispyware_enabled"           = $true
            "antivirus_signature_updated"   = "2026-08-18T06:00:00Z"
            "antispyware_signature_updated" = "2026-08-18T06:00:00Z"
        }

        # C4 / C7 - Defender mitigations
        "defender_advanced" = [ordered]@{
            "asr_rules" = @(
                [ordered]@{
                    "guid"        = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
                    "name"        = "Block credential stealing from LSASS"
                    "action"      = 1
                    "action_text" = "Block"
                }
                [ordered]@{
                    "guid"        = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
                    "name"        = "Block all Office applications from creating child processes"
                    "action"      = 2
                    "action_text" = "Audit"
                }
            )
            "asr_rules_count"          = 2
            "asr_rules_blocking"       = 1
            "network_protection"       = "Enabled"
            "controlled_folder_access" = "Disabled"
            "pua_protection"           = "Enabled"
            "cloud_protection"         = "Advanced"
            "sample_submission"        = "Send safe samples automatically"
            "tamper_protection"        = $true
        }

        # C4 - platform mitigations
        "host_security" = [ordered]@{
            # $null, not $false: this unit's acquisition outcome is
            # 'restricted', so no substantive negative assertion is made.
            "kernel_dma_protection" = $null
            "dep_policy"            = "Opt-Out (All Processes)"
            "vbs_status"            = "Enabled and running"
            "security_services"     = @(
                [ordered]@{ "service_name" = "Credential Guard"; "configured" = $true; "running" = $true }
                [ordered]@{ "service_name" = "HVCI (Hypervisor Code Integrity)"; "configured" = $true; "running" = $true }
                [ordered]@{ "service_name" = "System Guard Secure Launch"; "configured" = $false; "running" = $false }
            )
            "security_properties"   = @(
                [ordered]@{ "property_name" = "Hypervisor support"; "available" = $true }
                [ordered]@{ "property_name" = "Secure Boot"; "available" = $true }
            )
        }

        # C1 / C4 - firewall
        "firewall_profiles" = @(
            [ordered]@{ "name" = "Domain"; "enabled" = "Enabled"; "inbound_action" = "Block"; "outbound_action" = "Allow" }
            [ordered]@{ "name" = "Private"; "enabled" = "Enabled"; "inbound_action" = "Block"; "outbound_action" = "Allow" }
            [ordered]@{ "name" = "Public"; "enabled" = "Enabled"; "inbound_action" = "Block"; "outbound_action" = "Allow" }
        )

        "firewall_rules" = @(
            [ordered]@{
                "display_name" = "Remote Desktop - User Mode (TCP-In)"
                "id"           = "RemoteDesktop-UserMode-In-TCP"
                "direction"    = "Inbound"
                "action"       = "Allow"
            }
        )

        # C4 / C6 - UAC
        "uac" = [ordered]@{
            "uac_enabled"                    = $true
            "admin_approval_mode"            = $false
            "consent_prompt_admin"           = 5
            "consent_prompt_admin_text"      = "Prompt for consent for non-Windows binaries"
            "consent_prompt_standard"        = 3
            "consent_prompt_standard_text"   = "Prompt for credentials"
            "secure_desktop_enabled"         = $true
            "detect_installations"           = $false
            "validate_admin_code_signatures" = $false
            "built_in_admin_approval_mode"   = $false
            "only_elevate_signed"            = $false
            "only_elevate_ui_access"         = $true
        }

        # C3 / C6 - RDP entry point
        "rdp" = [ordered]@{
            "rdp_enabled"              = $true
            "port"                     = 3389
            # Absent PortNumber: the documented 3389 default applies and is
            # marked as inferred rather than observed.
            "port_value_source"        = "default_inferred"
            "nla_required"             = $true
            "security_layer"           = "SSL/TLS"
            "encryption_level"         = "High"
            "idle_timeout_ms"          = 0
            "disconnect_timeout_ms"    = 0
            "session_limit_ms"         = 0
            "restricted_admin_enabled" = $false
            "allowed_users"            = @("fixture.user")
        }

        # C3 / C6 - WinRM entry point
        "winrm" = [ordered]@{
            "service_state"            = "Running"
            "service_start_type"       = "Auto"
            # security.winrm.server_registry is 'restricted' in this
            # fixture, so every server-side path stays null.
            "allow_unencrypted"        = $null
            "server_auth"              = $null
            "server_value_sources"     = $null
            "client_auth"              = [ordered]@{
                "basic"     = $false
                "kerberos"  = $true
                "negotiate" = $true
                "credssp"   = $false
            }
            "client_allow_unencrypted" = $false
            "client_value_sources"     = [ordered]@{
                "client_auth.basic"        = "explicit"
                "client_auth.kerberos"     = "default_inferred"
                "client_auth.negotiate"    = "default_inferred"
                "client_auth.credssp"      = "default_inferred"
                "client_allow_unencrypted" = "default_inferred"
            }
            "trusted_hosts"            = $null
            "listeners"                = @(
                [ordered]@{
                    "address"                = "*"
                    "transport"              = "HTTP"
                    "port"                   = 5985
                    "hostname"               = ""
                    "enabled"                = $true
                    "certificate_thumbprint" = $null
                }
            )
        }

        # C3 - SMB prerequisites
        "smb" = [ordered]@{
            "smbv1_enabled"                = $false
            # Registry-explicit, as opposed to feature_observed.
            "smbv1_value_source"           = "explicit"
            "server_signing_required"      = $false
            "server_signing_enabled"       = $true
            "server_encrypt_data"          = $false
            "server_reject_unencrypted"    = $true
            "null_session_pipes"           = @()
            "null_session_shares"          = @()
            "restrict_null_session_access" = $true
            "server_value_sources"         = [ordered]@{
                "server_signing_required"      = "explicit"
                "server_signing_enabled"       = "default_inferred"
                "server_encrypt_data"          = "default_inferred"
                "server_reject_unencrypted"    = "default_inferred"
                "restrict_null_session_access" = "default_inferred"
                "null_session_pipes"           = "default_inferred"
                "null_session_shares"          = "default_inferred"
            }
            "client_signing_required"      = $false
            "client_signing_enabled"       = $true
            "client_insecure_guest_auth"   = $false
            "client_value_sources"         = [ordered]@{
                "client_signing_required"    = "explicit"
                "client_signing_enabled"     = "default_inferred"
                "client_insecure_guest_auth" = "default_inferred"
            }
            # security.smb.server_configuration is 'restricted' in this
            # fixture, so the four cmdlet-sourced fields stay null.
            "smb2_enabled"                 = $null
            "server_multichannel"          = $null
            "server_leasing"               = $null
            "max_channel_per_session"      = $null
        }

        # Irrelevant telemetry varied by controlled Case 9. Does not
        # contribute to C1-C7 scoring.
        "fde_os_drive" = [ordered]@{
            "mount_point"             = "C:"
            "volume_status"           = "Fully Encrypted"
            "protection_status"       = "Protection On"
            "encryption_method"       = "XTS-AES 128-bit"
            "primary_key_protectors"  = @("TPM")
            "recovery_key_protectors" = @("Recovery Password")
        }

        # security.fde.additional_volumes is 'unavailable' in this fixture,
        # so this is $null rather than an empty array: an empty array would
        # read as "no additional volumes exist", which was never observed.
        "fde_additional_volumes" = $null

        # C3 - legacy protocol prerequisites
        "legacy_protocols" = [ordered]@{
            # Explicit policy value observed in the registry.
            "llmnr_enabled"           = $false
            "llmnr_value_source"      = "explicit"
            # Read succeeded, value genuinely absent - documented Windows
            # default applies, marked as inferred rather than observed.
            "mdns_enabled"            = $true
            "mdns_value_source"       = "default_inferred"
            "netbios_adapters"        = @(
                [ordered]@{
                    "description" = "Fixture Gigabit Network Connection"
                    "setting"     = "Disabled"
                    "raw_value"   = 2
                }
            )
            "netbios_any_enabled"     = $false
            "wpad_service_state"      = "Stopped"
            "wpad_service_start_type" = "Manual"
            # $null: this unit's acquisition outcome is 'failed', so no
            # value is asserted for it.
            "wpad_auto_detect"        = $null
            "tls_protocols"           = @(
                [ordered]@{
                    "protocol"                        = "TLS 1.0"
                    "client_enabled"                  = $false
                    "client_disabled_by_default"      = $true
                    "server_enabled"                  = $false
                    "server_disabled_by_default"      = $true
                }
                [ordered]@{
                    "protocol"                        = "TLS 1.2"
                    "client_enabled"                  = $true
                    "client_disabled_by_default"      = $false
                    "server_enabled"                  = $true
                    "server_disabled_by_default"      = $false
                }
            )
        }
    }

    # ------------------------------------------------------------------
    #  VULNERABILITY
    # ------------------------------------------------------------------
    "vulnerability" = [ordered]@{

        # C6 - privileges held by the COLLECTING account only
        "token_privileges" = [ordered]@{
            # Raw principal retained for ingestion-layer pseudonymisation.
            "user"                    = "FIXTUREDOM\fixture.user"
            # Qualifiers bounding how this evidence may be read: it
            # describes the COLLECTOR's token and nothing else.
            "evidence_scope"          = "collector_token_only"
            "collector_ran_as_admin"  = $true
            "total_privileges"        = 3
            "dangerous_count"         = 1
            "dangerous_enabled_count" = 1
            "privileges"              = @(
                [ordered]@{
                    "privilege"    = "SeImpersonatePrivilege"
                    "description"  = "Impersonate a client after authentication"
                    "state"        = "Enabled"
                    "is_dangerous" = $true
                }
                [ordered]@{
                    "privilege"    = "SeChangeNotifyPrivilege"
                    "description"  = "Bypass traverse checking"
                    "state"        = "Enabled"
                    "is_dangerous" = $false
                }
                [ordered]@{
                    "privilege"    = "SeShutdownPrivilege"
                    "description"  = "Shut down the system"
                    "state"        = "Disabled"
                    "is_dangerous" = $false
                }
            )
        }
    }
}
