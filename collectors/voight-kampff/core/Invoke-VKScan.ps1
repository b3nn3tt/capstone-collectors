<#
.SYNOPSIS
    Voight-Kampff Scanner - Main Orchestrator

.DESCRIPTION
    Initialises the scan environment, loads core utilities and config,
    dot-sources modules, executes checks, and assembles the final JSON output.

    Output follows the schema 1.1 five-key envelope:
        scan_metadata  - about the scan itself (includes schema_version for API contract)
        acquisition    - per-collection-unit acquisition outcomes (schema 1.1)
        host           - Section 1: host enumeration findings
        security       - Section 2: security configuration findings
        vulnerability  - Section 3: vulnerability assessment findings

    The acquisition section records only WHETHER COLLECTION WORKED. It is
    separate from condition applicability, contextual evidence state, and
    confirmed presence or absence, all of which are downstream concerns.

    Acquisition is fail-closed: a unit is registered before its query runs
    and only becomes 'success' on explicit completion. Invocation alone
    never produces success. See the helper documentation in VK.Utilities.ps1.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
    GitHub:  https://github.com/b3nn3tt
#>


# ============================================================
#  RESOLVE PATHS
# ============================================================
# Core path is where the runner lives (agent/core/).
# Project root is two levels up (agent/core/ -> agent/ -> project root).
# Output folder sits at the project root, separate from all scripts.
# ============================================================

$script:CorePath    = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:AgentRoot   = Split-Path -Parent $script:CorePath
$script:ProjectRoot = Split-Path -Parent $script:AgentRoot
$script:HostModules = Join-Path $script:AgentRoot "modules\host"
$script:SecModules  = Join-Path $script:AgentRoot "modules\security"
$script:VulnModules = Join-Path $script:AgentRoot "modules\vulnerability"


# ============================================================
#  LOAD CORE FILES
# ============================================================

. (Join-Path $script:CorePath "VK.Config.ps1")
. (Join-Path $script:CorePath "VK.Utilities.ps1")


# ============================================================
#  INITIALISATION
# ============================================================

# --- Banner ---
Write-VKBanner

# --- Admin Check ---
$script:CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] $script:CurrentIdentity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

Write-SectionHeader -Title "Privilege Status Check"

if ($script:IsAdmin) {
    Write-VKStatus -Message "Running with Administrative privileges." -Type "SUCCESS"
}
else {
    Write-VKStatus -Message "Running without Administrative privileges. Some checks may be skipped." -Type "WARNING"
}

# --- Output Paths ---
$outputFolder = Join-Path -Path $script:ProjectRoot -ChildPath $script:VKOutputFolder

if (-not (Test-Path -Path $outputFolder)) {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
}

# Dynamic filename: HOSTNAME_YYYYMMDD_HHMMSS.json
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")
$outputFileName = "{0}_{1}.json" -f $env:COMPUTERNAME, $timestamp

$script:OutputPath   = Join-Path -Path $outputFolder -ChildPath $outputFileName
$script:ErrorLogPath = Join-Path -Path $outputFolder -ChildPath $script:VKErrorLogFile

# Clear previous error log
if (Test-Path $script:ErrorLogPath) {
    Remove-Item $script:ErrorLogPath
}

# --- Initialise Data Envelope (schema 1.1: five ordered sections) ---
$data = [ordered]@{
    "scan_metadata" = [ordered]@{}
    "acquisition"   = [ordered]@{}
    "host"          = [ordered]@{}
    "security"      = [ordered]@{}
    "vulnerability" = [ordered]@{}
}

# --- Initialise the fail-closed acquisition store ---
Initialize-VKAcquisition

# Track which modules executed successfully
$modulesExecuted = [System.Collections.ArrayList]::new()

# --- Scan Start ---
$scanStart = (Get-Date).ToUniversalTime()


# ============================================================
#  LOAD AND EXECUTE MODULES
# ============================================================

# --- Section 1: Host Enumeration ---
Write-SectionHeader -Title "SECTION 1: Host Enumeration"

# Host Identification
. (Join-Path $script:HostModules "Host.Identification.ps1")
Invoke-VKHostIdentification -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.identification") | Out-Null

# Host Hardware
. (Join-Path $script:HostModules "Host.Hardware.ps1")
Invoke-VKHostHardware -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.hardware") | Out-Null

# Host Boot
. (Join-Path $script:HostModules "Host.Boot.ps1")
Invoke-VKHostBoot -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.boot") | Out-Null

# Host Storage
. (Join-Path $script:HostModules "Host.Storage.ps1")
Invoke-VKHostStorage -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.storage") | Out-Null

# Host Network
. (Join-Path $script:HostModules "Host.Network.ps1")
Invoke-VKHostNetwork -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.network") | Out-Null

# Host Network Configuration
. (Join-Path $script:HostModules "Host.NetworkConfig.ps1")
Invoke-VKHostNetworkConfig -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.network_config") | Out-Null

# Host Users
. (Join-Path $script:HostModules "Host.Users.ps1")
Invoke-VKHostUsers -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.users") | Out-Null

# Host Sessions
. (Join-Path $script:HostModules "Host.Sessions.ps1")
Invoke-VKHostSessions -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.sessions") | Out-Null

# Host Software
. (Join-Path $script:HostModules "Host.Software.ps1")
Invoke-VKHostSoftware -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.software") | Out-Null

# Host Windows Updates
. (Join-Path $script:HostModules "Host.WindowsUpdates.ps1")
Invoke-VKHostWindowsUpdates -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.windows_updates") | Out-Null

# Host Processes
. (Join-Path $script:HostModules "Host.Processes.ps1")
Invoke-VKHostProcesses -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.processes") | Out-Null

# Host Services
. (Join-Path $script:HostModules "Host.Services.ps1")
Invoke-VKHostServices -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.services") | Out-Null

# Host Drivers
. (Join-Path $script:HostModules "Host.Drivers.ps1")
Invoke-VKHostDrivers -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.drivers") | Out-Null

# Host USB History
. (Join-Path $script:HostModules "Host.USBHistory.ps1")
Invoke-VKHostUSBHistory -Data $data["host"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("host.usb_history") | Out-Null

# --- Section 2: Security Configuration ---
Write-SectionHeader -Title "SECTION 2: Security Configuration"

# Security Antivirus
. (Join-Path $script:SecModules "Security.Antivirus.ps1")
Invoke-VKSecurityAntivirus -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.antivirus") | Out-Null

# Security FDE
. (Join-Path $script:SecModules "Security.FDE.ps1")
Invoke-VKSecurityFDE -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.fde") | Out-Null

# Security Password Policy
. (Join-Path $script:SecModules "Security.PasswordPolicy.ps1")
Invoke-VKSecurityPasswordPolicy -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.password_policy") | Out-Null

# Security Firewall
. (Join-Path $script:SecModules "Security.Firewall.ps1")
Invoke-VKSecurityFirewall -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.firewall") | Out-Null

# Security Host Security
. (Join-Path $script:SecModules "Security.HostSecurity.ps1")
Invoke-VKSecurityHostSecurity -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.host_security") | Out-Null

# Security UAC
. (Join-Path $script:SecModules "Security.UAC.ps1")
Invoke-VKSecurityUAC -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.uac") | Out-Null

# Security RDP
. (Join-Path $script:SecModules "Security.RDP.ps1")
Invoke-VKSecurityRDP -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.rdp") | Out-Null

# Security SMB
. (Join-Path $script:SecModules "Security.SMB.ps1")
Invoke-VKSecuritySMB -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.smb") | Out-Null

# Security Legacy Protocols
. (Join-Path $script:SecModules "Security.LegacyProtocols.ps1")
Invoke-VKSecurityLegacyProtocols -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.legacy_protocols") | Out-Null

# Security WinRM
. (Join-Path $script:SecModules "Security.WinRM.ps1")
Invoke-VKSecurityWinRM -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.winrm") | Out-Null

# Security LSA Protection
. (Join-Path $script:SecModules "Security.LSAProtection.ps1")
Invoke-VKSecurityLSAProtection -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.lsa_protection") | Out-Null

# Security Audit Policy
. (Join-Path $script:SecModules "Security.AuditPolicy.ps1")
Invoke-VKSecurityAuditPolicy -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.audit_policy") | Out-Null

# Security Defender Advanced
. (Join-Path $script:SecModules "Security.DefenderAdvanced.ps1")
Invoke-VKSecurityDefenderAdvanced -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.defender_advanced") | Out-Null

# Security Certificate Store
. (Join-Path $script:SecModules "Security.CertificateStore.ps1")
Invoke-VKSecurityCertificateStore -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.certificate_store") | Out-Null

# Security Authenticode Audit
. (Join-Path $script:SecModules "Security.AuthenticodeAudit.ps1")
Invoke-VKSecurityAuthenticodeAudit -Data $data["security"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("security.authenticode_audit") | Out-Null

# --- Section 3: Vulnerability Assessment ---
Write-SectionHeader -Title "SECTION 3: Vulnerability Assessment"

# Vulnerability Token Privileges
. (Join-Path $script:VulnModules "Vul.Privileges.Token.ps1")
Invoke-VKVulTokenPrivileges -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.privileges.token") | Out-Null

# Vulnerability Autologon
. (Join-Path $script:VulnModules "Vul.Autologon.ps1")
Invoke-VKVulAutologon -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.autologon") | Out-Null

# Vulnerability Service Weak Permissions
. (Join-Path $script:VulnModules "Vul.Services.WeakPermissions.ps1")
Invoke-VKVulServiceWeakPermissions -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.services.weak_permissions") | Out-Null

# Vulnerability Service Binary Permissions
. (Join-Path $script:VulnModules "Vul.Services.BinaryPermissions.ps1")
Invoke-VKVulServiceBinaryPermissions -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.services.binary_permissions") | Out-Null

# Vulnerability Service Unquoted Paths
. (Join-Path $script:VulnModules "Vul.Services.UnquotedPaths.ps1")
Invoke-VKVulServiceUnquotedPaths -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.services.unquoted_paths") | Out-Null

# Vulnerability Auto-Elevate
. (Join-Path $script:VulnModules "Vul.AutoElevate.ps1")
Invoke-VKVulAutoElevate -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.auto_elevate") | Out-Null

# Vulnerability Passwords in Files
. (Join-Path $script:VulnModules "Vul.Passwords.Files.ps1")
Invoke-VKVulPasswordsFiles -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.passwords.files") | Out-Null

# Vulnerability Passwords in Registry
. (Join-Path $script:VulnModules "Vul.Passwords.Registry.ps1")
Invoke-VKVulPasswordsRegistry -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.passwords.registry") | Out-Null

# Vulnerability Scheduled Tasks
. (Join-Path $script:VulnModules "Vul.ScheduledTasks.ps1")
Invoke-VKVulScheduledTasks -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.scheduled_tasks") | Out-Null

# Vulnerability Filesystem Weak Permissions
. (Join-Path $script:VulnModules "Vul.FileSystem.WeakPermissions.ps1")
Invoke-VKVulFileSystemWeakPermissions -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.filesystem.weak_permissions") | Out-Null

# Vulnerability Registry Weak Permissions
. (Join-Path $script:VulnModules "Vul.Registry.WeakPermissions.ps1")
Invoke-VKVulRegistryWeakPermissions -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.registry.weak_permissions") | Out-Null

# Vulnerability Autoruns
. (Join-Path $script:VulnModules "Vul.Autoruns.ps1")
Invoke-VKVulAutoruns -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.autoruns") | Out-Null

# Vulnerability AlwaysInstallElevated
. (Join-Path $script:VulnModules "Vul.AlwaysInstallElevated.ps1")
Invoke-VKVulAlwaysInstallElevated -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.always_install_elevated") | Out-Null

# Vulnerability DLL Search Order
. (Join-Path $script:VulnModules "Vul.DLL.SearchOrder.ps1")
Invoke-VKVulDLLSearchOrder -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.dll.search_order") | Out-Null

# Vulnerability PowerShell v2
. (Join-Path $script:VulnModules "Vul.PowerShellV2.ps1")
Invoke-VKVulPowerShellV2 -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.powershell_v2") | Out-Null

# Vulnerability LAPS
. (Join-Path $script:VulnModules "Vul.LAPS.ps1")
Invoke-VKVulLAPS -Data $data["vulnerability"] -IsAdmin $script:IsAdmin
$modulesExecuted.Add("vul.laps") | Out-Null


# ============================================================
#  OUTPUT
# ============================================================

# --- Scan Metadata ---
$scanEnd = (Get-Date).ToUniversalTime()
$duration = $scanEnd - $scanStart

$data["scan_metadata"] = [ordered]@{
    "schema_version"        = $script:VKSchemaVersion
    "agent_version"         = $script:VKAgentVersion
    "hostname"              = $env:COMPUTERNAME
    "running_user"          = $script:CurrentIdentity.Name
    "running_user_sid"      = $script:CurrentIdentity.User.Value
    "scan_start"            = $scanStart.ToString("yyyy-MM-ddTHH:mm:ssZ")
    "scan_end"              = $scanEnd.ToString("yyyy-MM-ddTHH:mm:ssZ")
    "scan_duration_seconds" = [math]::Round($duration.TotalSeconds, 2)
    "ran_as_admin"          = $script:IsAdmin
    "modules_executed"      = @($modulesExecuted)
}

# --- Acquisition Section (schema 1.1) ---
# Fail-closed backstop: any unit still unresolved becomes
# failed / incomplete_collection. Must run before serialisation.
Complete-VKAcquisitionReport
$data["acquisition"] = Get-VKAcquisitionReport

# --- Export JSON ---
$jsonOutput = $data | ConvertTo-Json -Depth $script:VKJsonDepth
$jsonOutput | Out-File -FilePath $script:OutputPath -Encoding utf8

Write-SectionHeader -Title "Scan Complete"
Write-VKStatus -Message "Results saved to: $($script:OutputPath)" -Type "SUCCESS"
