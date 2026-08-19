<#
.SYNOPSIS
    Builds the Voight-Kampff standalone agent.

.DESCRIPTION
    Concatenates the core files and all modules into a single PowerShell
    script that can be deployed and run on any Windows 10+ endpoint
    without the full project structure.

    The built file is saved to agent/dist/ with a version-stamped filename.

    The generated script is the controlled-collection artefact. It must
    remain dependency-free on target machines: no Pester, no Python, no
    PowerShell Gallery modules, no API, database or network access. It
    depends only on Windows PowerShell 5.1 and built-in Windows providers.

    The build concatenates VK.Config.ps1 and VK.Utilities.ps1 first, so the
    schema 1.1 acquisition helpers are always present in the generated
    script before any module or runner logic references them.

    Usage:
        .\Build-Standalone.ps1
        .\Build-Standalone.ps1 -OutputPath "C:\Custom\Path"
        .\Build-Standalone.ps1 -OutputPath $TestDrive -Quiet -PassThru

.PARAMETER OutputPath
    Directory to write the generated script to. Defaults to agent/dist.

.PARAMETER Quiet
    Suppresses console output. Intended for automated generation from the
    Pester suite into a temporary test location.

.PARAMETER PassThru
    Emits the full path of the generated script so a caller can inspect it.
    Building the script does NOT execute the collector - the output is
    written to disk and never invoked.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

param(
    [string]$OutputPath = $null,

    [switch]$Quiet,

    [switch]$PassThru
)

function Write-BuildMessage {
    param(
        [string]$Message,
        [string]$Colour = "Cyan"
    )
    if (-not $Quiet) { Write-Host $Message -ForegroundColor $Colour }
}

# ============================================================
#  RESOLVE PATHS
# ============================================================

$buildRoot   = Split-Path -Parent $MyInvocation.MyCommand.Definition
$agentRoot   = Split-Path -Parent $buildRoot
$corePath    = Join-Path $agentRoot "core"
$hostModules = Join-Path $agentRoot "modules\host"
$secModules  = Join-Path $agentRoot "modules\security"
$vulnModules = Join-Path $agentRoot "modules\vulnerability"
$distPath    = Join-Path $agentRoot "dist"

if (-not $OutputPath) {
    $OutputPath = $distPath
}

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Read agent and schema versions from the central config, so the generated
# script and the modular runner can never drift apart.
. (Join-Path $corePath "VK.Config.ps1")
$version       = $script:VKAgentVersion
$schemaVersion = $script:VKSchemaVersion


# ============================================================
#  DEFINE MODULE ORDER
# ============================================================
# Modules are loaded in the same order as the runner.
# If you add new modules, add them here in the correct position.
# ============================================================

$hostModuleFiles = @(
    "Host.Identification.ps1",
    "Host.Hardware.ps1",
    "Host.Boot.ps1",
    "Host.Storage.ps1",
    "Host.Network.ps1",
    "Host.NetworkConfig.ps1",
    "Host.Users.ps1",
    "Host.Sessions.ps1",
    "Host.Software.ps1",
    "Host.WindowsUpdates.ps1",
    "Host.Processes.ps1",
    "Host.Services.ps1",
    "Host.Drivers.ps1",
    "Host.USBHistory.ps1"
)

$securityModuleFiles = @(
    "Security.Antivirus.ps1",
    "Security.FDE.ps1",
    "Security.PasswordPolicy.ps1",
    "Security.Firewall.ps1",
    "Security.HostSecurity.ps1",
    "Security.UAC.ps1",
    "Security.RDP.ps1",
    "Security.SMB.ps1",
    "Security.LegacyProtocols.ps1",
    "Security.WinRM.ps1",
    "Security.LSAProtection.ps1",
    "Security.AuditPolicy.ps1",
    "Security.DefenderAdvanced.ps1",
    "Security.CertificateStore.ps1",
    "Security.AuthenticodeAudit.ps1"
)

$vulnModuleFiles = @(
    "Vul.Privileges.Token.ps1",
    "Vul.Autologon.ps1",
    "Vul.Services.WeakPermissions.ps1",
    "Vul.Services.BinaryPermissions.ps1",
    "Vul.Services.UnquotedPaths.ps1",
    "Vul.AutoElevate.ps1",
    "Vul.Passwords.Files.ps1",
    "Vul.Passwords.Registry.ps1",
    "Vul.ScheduledTasks.ps1",
    "Vul.FileSystem.WeakPermissions.ps1",
    "Vul.Registry.WeakPermissions.ps1",
    "Vul.Autoruns.ps1",
    "Vul.AlwaysInstallElevated.ps1",
    "Vul.DLL.SearchOrder.ps1",
    "Vul.PowerShellV2.ps1",
    "Vul.LAPS.ps1"
)


# ============================================================
#  HELPER: Read file content with error checking
# ============================================================

function Read-ModuleFile {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        Write-Warning "Module file not found: $FilePath"
        return $null
    }

    return Get-Content -Path $FilePath -Raw
}


# ============================================================
#  BUILD THE STANDALONE SCRIPT
# ============================================================

Write-BuildMessage "`n============================================"
Write-BuildMessage "  Voight-Kampff Standalone Agent Builder"
Write-BuildMessage "============================================`n"

$sb = [System.Text.StringBuilder]::new()

# --- Header ---
[void]$sb.AppendLine("<#")
[void]$sb.AppendLine(".SYNOPSIS")
[void]$sb.AppendLine("    Voight-Kampff Standalone Agent v$version")
[void]$sb.AppendLine("")
[void]$sb.AppendLine(".DESCRIPTION")
[void]$sb.AppendLine("    Endpoint security assessment tool for Windows systems.")
[void]$sb.AppendLine("    This is an auto-generated standalone build - do not edit directly.")
[void]$sb.AppendLine("    Make changes in the modular source and rebuild.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("    Dependency-free: requires only Windows PowerShell 5.1 and built-in")
[void]$sb.AppendLine("    Windows providers. No Pester, no Python, no gallery modules, no API,")
[void]$sb.AppendLine("    database or network access.")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("    Emits the schema $schemaVersion five-section envelope:")
[void]$sb.AppendLine("        scan_metadata, acquisition, host, security, vulnerability")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("    Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$sb.AppendLine("")
[void]$sb.AppendLine(".NOTES")
[void]$sb.AppendLine("    Author:  b3nn3tt@hbcomputersecurity.co.uk")
[void]$sb.AppendLine("    Version: $version")
[void]$sb.AppendLine("    Schema:  $schemaVersion")
[void]$sb.AppendLine("    GitHub:  https://github.com/b3nn3tt")
[void]$sb.AppendLine("#>")
[void]$sb.AppendLine("")


# --- Core: Config ---
Write-BuildMessage "[1/5] Loading core config..." "Yellow"
$configContent = Read-ModuleFile (Join-Path $corePath "VK.Config.ps1")
if ($configContent) {
    [void]$sb.AppendLine("# ============================================================")
    [void]$sb.AppendLine("#  CORE: Configuration")
    [void]$sb.AppendLine("# ============================================================")
    [void]$sb.AppendLine($configContent)
    [void]$sb.AppendLine("")
}


# --- Core: Utilities ---
Write-BuildMessage "[2/5] Loading core utilities..." "Yellow"
$utilsContent = Read-ModuleFile (Join-Path $corePath "VK.Utilities.ps1")
if ($utilsContent) {
    [void]$sb.AppendLine("# ============================================================")
    [void]$sb.AppendLine("#  CORE: Utilities")
    [void]$sb.AppendLine("# ============================================================")
    [void]$sb.AppendLine($utilsContent)
    [void]$sb.AppendLine("")
}


# --- Modules: Host ---
Write-BuildMessage "[3/5] Loading host modules ($($hostModuleFiles.Count))..." "Yellow"
$hostCount = 0
foreach ($file in $hostModuleFiles) {
    $content = Read-ModuleFile (Join-Path $hostModules $file)
    if ($content) {
        [void]$sb.AppendLine("# --- Module: $file ---")
        [void]$sb.AppendLine($content)
        [void]$sb.AppendLine("")
        $hostCount++
    }
}


# --- Modules: Security ---
Write-BuildMessage "[4/5] Loading security modules ($($securityModuleFiles.Count))..." "Yellow"
$secCount = 0
foreach ($file in $securityModuleFiles) {
    $content = Read-ModuleFile (Join-Path $secModules $file)
    if ($content) {
        [void]$sb.AppendLine("# --- Module: $file ---")
        [void]$sb.AppendLine($content)
        [void]$sb.AppendLine("")
        $secCount++
    }
}


# --- Modules: Vulnerability ---
Write-BuildMessage "[5/5] Loading vulnerability modules ($($vulnModuleFiles.Count))..." "Yellow"
$vulnCount = 0
foreach ($file in $vulnModuleFiles) {
    $content = Read-ModuleFile (Join-Path $vulnModules $file)
    if ($content) {
        [void]$sb.AppendLine("# --- Module: $file ---")
        [void]$sb.AppendLine($content)
        [void]$sb.AppendLine("")
        $vulnCount++
    }
}


# --- Runner Logic ---
# This replaces the dot-sourcing and path resolution in Invoke-VKScan.ps1
# with direct function calls since everything is now in the same file.

[void]$sb.AppendLine("# ============================================================")
[void]$sb.AppendLine("#  RUNNER")
[void]$sb.AppendLine("# ============================================================")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("# --- Banner ---")
[void]$sb.AppendLine("Write-VKBanner")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("# --- Admin Check ---")
[void]$sb.AppendLine('# Identity is captured so the generated script can emit the same')
[void]$sb.AppendLine('# running_user / running_user_sid metadata as the modular runner.')
[void]$sb.AppendLine('$script:CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()')
[void]$sb.AppendLine('$script:IsAdmin = ([Security.Principal.WindowsPrincipal] $script:CurrentIdentity).IsInRole(')
[void]$sb.AppendLine('    [Security.Principal.WindowsBuiltInRole]::Administrator')
[void]$sb.AppendLine(')')
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Write-SectionHeader -Title 'Privilege Status Check'")
[void]$sb.AppendLine("")
[void]$sb.AppendLine('if ($script:IsAdmin) {')
[void]$sb.AppendLine('    Write-VKStatus -Message "Running with Administrative privileges." -Type "SUCCESS"')
[void]$sb.AppendLine('}')
[void]$sb.AppendLine('else {')
[void]$sb.AppendLine('    Write-VKStatus -Message "Running without Administrative privileges. Some checks may be skipped." -Type "WARNING"')
[void]$sb.AppendLine('}')
[void]$sb.AppendLine("")
[void]$sb.AppendLine("# --- Output Paths ---")
[void]$sb.AppendLine('$outputFolder = Join-Path -Path (Get-Location) -ChildPath $script:VKOutputFolder')
[void]$sb.AppendLine("")
[void]$sb.AppendLine('if (-not (Test-Path -Path $outputFolder)) {')
[void]$sb.AppendLine('    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null')
[void]$sb.AppendLine('}')
[void]$sb.AppendLine("")
[void]$sb.AppendLine('$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmss")')
[void]$sb.AppendLine('$outputFileName = "{0}_{1}.json" -f $env:COMPUTERNAME, $timestamp')
[void]$sb.AppendLine('$script:OutputPath   = Join-Path -Path $outputFolder -ChildPath $outputFileName')
[void]$sb.AppendLine('$script:ErrorLogPath = Join-Path -Path $outputFolder -ChildPath $script:VKErrorLogFile')
[void]$sb.AppendLine("")
[void]$sb.AppendLine('if (Test-Path $script:ErrorLogPath) { Remove-Item $script:ErrorLogPath }')
[void]$sb.AppendLine("")
[void]$sb.AppendLine("# --- Initialise Data (schema 1.1: five ordered sections) ---")
[void]$sb.AppendLine('$data = [ordered]@{')
[void]$sb.AppendLine('    "scan_metadata" = [ordered]@{}')
[void]$sb.AppendLine('    "acquisition"   = [ordered]@{}')
[void]$sb.AppendLine('    "host"          = [ordered]@{}')
[void]$sb.AppendLine('    "security"      = [ordered]@{}')
[void]$sb.AppendLine('    "vulnerability" = [ordered]@{}')
[void]$sb.AppendLine('}')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('# --- Initialise the fail-closed acquisition store ---')
[void]$sb.AppendLine('Initialize-VKAcquisition')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('$modulesExecuted = [System.Collections.ArrayList]::new()')
[void]$sb.AppendLine('$scanStart = (Get-Date).ToUniversalTime()')
[void]$sb.AppendLine("")

# Host module calls
[void]$sb.AppendLine("# --- Section 1: Host Enumeration ---")
[void]$sb.AppendLine("Write-SectionHeader -Title 'SECTION 1: Host Enumeration'")
[void]$sb.AppendLine("")

$hostFunctionMap = @{
    "Host.Identification.ps1"  = @{ Func = "Invoke-VKHostIdentification"; Id = "host.identification" }
    "Host.Hardware.ps1"        = @{ Func = "Invoke-VKHostHardware"; Id = "host.hardware" }
    "Host.Boot.ps1"            = @{ Func = "Invoke-VKHostBoot"; Id = "host.boot" }
    "Host.Storage.ps1"         = @{ Func = "Invoke-VKHostStorage"; Id = "host.storage" }
    "Host.Network.ps1"         = @{ Func = "Invoke-VKHostNetwork"; Id = "host.network" }
    "Host.NetworkConfig.ps1"   = @{ Func = "Invoke-VKHostNetworkConfig"; Id = "host.network_config" }
    "Host.Users.ps1"           = @{ Func = "Invoke-VKHostUsers"; Id = "host.users" }
    "Host.Sessions.ps1"        = @{ Func = "Invoke-VKHostSessions"; Id = "host.sessions" }
    "Host.Software.ps1"        = @{ Func = "Invoke-VKHostSoftware"; Id = "host.software" }
    "Host.WindowsUpdates.ps1"  = @{ Func = "Invoke-VKHostWindowsUpdates"; Id = "host.windows_updates" }
    "Host.Processes.ps1"       = @{ Func = "Invoke-VKHostProcesses"; Id = "host.processes" }
    "Host.Services.ps1"        = @{ Func = "Invoke-VKHostServices"; Id = "host.services" }
    "Host.Drivers.ps1"         = @{ Func = "Invoke-VKHostDrivers"; Id = "host.drivers" }
    "Host.USBHistory.ps1"      = @{ Func = "Invoke-VKHostUSBHistory"; Id = "host.usb_history" }
}

foreach ($file in $hostModuleFiles) {
    $map = $hostFunctionMap[$file]
    if ($map) {
        [void]$sb.AppendLine("$($map.Func) -Data `$data[`"host`"] -IsAdmin `$script:IsAdmin")
        [void]$sb.AppendLine("`$modulesExecuted.Add(`"$($map.Id)`") | Out-Null")
        [void]$sb.AppendLine("")
    }
}

# Security module calls
[void]$sb.AppendLine("# --- Section 2: Security Configuration ---")
[void]$sb.AppendLine("Write-SectionHeader -Title 'SECTION 2: Security Configuration'")
[void]$sb.AppendLine("")

$secFunctionMap = @{
    "Security.Antivirus.ps1"        = @{ Func = "Invoke-VKSecurityAntivirus"; Id = "security.antivirus" }
    "Security.FDE.ps1"              = @{ Func = "Invoke-VKSecurityFDE"; Id = "security.fde" }
    "Security.PasswordPolicy.ps1"   = @{ Func = "Invoke-VKSecurityPasswordPolicy"; Id = "security.password_policy" }
    "Security.Firewall.ps1"         = @{ Func = "Invoke-VKSecurityFirewall"; Id = "security.firewall" }
    "Security.HostSecurity.ps1"     = @{ Func = "Invoke-VKSecurityHostSecurity"; Id = "security.host_security" }
    "Security.UAC.ps1"              = @{ Func = "Invoke-VKSecurityUAC"; Id = "security.uac" }
    "Security.RDP.ps1"              = @{ Func = "Invoke-VKSecurityRDP"; Id = "security.rdp" }
    "Security.SMB.ps1"              = @{ Func = "Invoke-VKSecuritySMB"; Id = "security.smb" }
    "Security.LegacyProtocols.ps1"  = @{ Func = "Invoke-VKSecurityLegacyProtocols"; Id = "security.legacy_protocols" }
    "Security.WinRM.ps1"            = @{ Func = "Invoke-VKSecurityWinRM"; Id = "security.winrm" }
    "Security.LSAProtection.ps1"    = @{ Func = "Invoke-VKSecurityLSAProtection"; Id = "security.lsa_protection" }
    "Security.AuditPolicy.ps1"      = @{ Func = "Invoke-VKSecurityAuditPolicy"; Id = "security.audit_policy" }
    "Security.DefenderAdvanced.ps1" = @{ Func = "Invoke-VKSecurityDefenderAdvanced"; Id = "security.defender_advanced" }
    "Security.CertificateStore.ps1" = @{ Func = "Invoke-VKSecurityCertificateStore"; Id = "security.certificate_store" }
    "Security.AuthenticodeAudit.ps1"= @{ Func = "Invoke-VKSecurityAuthenticodeAudit"; Id = "security.authenticode_audit" }
}

foreach ($file in $securityModuleFiles) {
    $map = $secFunctionMap[$file]
    if ($map) {
        [void]$sb.AppendLine("$($map.Func) -Data `$data[`"security`"] -IsAdmin `$script:IsAdmin")
        [void]$sb.AppendLine("`$modulesExecuted.Add(`"$($map.Id)`") | Out-Null")
        [void]$sb.AppendLine("")
    }
}

# Vulnerability module calls
[void]$sb.AppendLine("# --- Section 3: Vulnerability Assessment ---")
[void]$sb.AppendLine("Write-SectionHeader -Title 'SECTION 3: Vulnerability Assessment'")
[void]$sb.AppendLine("")

$vulnFunctionMap = @{
    "Vul.Privileges.Token.ps1"          = @{ Func = "Invoke-VKVulTokenPrivileges"; Id = "vul.privileges.token" }
    "Vul.Autologon.ps1"                 = @{ Func = "Invoke-VKVulAutologon"; Id = "vul.autologon" }
    "Vul.Services.WeakPermissions.ps1"  = @{ Func = "Invoke-VKVulServiceWeakPermissions"; Id = "vul.services.weak_permissions" }
    "Vul.Services.BinaryPermissions.ps1"= @{ Func = "Invoke-VKVulServiceBinaryPermissions"; Id = "vul.services.binary_permissions" }
    "Vul.Services.UnquotedPaths.ps1"   = @{ Func = "Invoke-VKVulServiceUnquotedPaths"; Id = "vul.services.unquoted_paths" }
    "Vul.AutoElevate.ps1"              = @{ Func = "Invoke-VKVulAutoElevate"; Id = "vul.auto_elevate" }
    "Vul.Passwords.Files.ps1"          = @{ Func = "Invoke-VKVulPasswordsFiles"; Id = "vul.passwords.files" }
    "Vul.Passwords.Registry.ps1"       = @{ Func = "Invoke-VKVulPasswordsRegistry"; Id = "vul.passwords.registry" }
    "Vul.ScheduledTasks.ps1"           = @{ Func = "Invoke-VKVulScheduledTasks"; Id = "vul.scheduled_tasks" }
    "Vul.FileSystem.WeakPermissions.ps1"= @{ Func = "Invoke-VKVulFileSystemWeakPermissions"; Id = "vul.filesystem.weak_permissions" }
    "Vul.Registry.WeakPermissions.ps1" = @{ Func = "Invoke-VKVulRegistryWeakPermissions"; Id = "vul.registry.weak_permissions" }
    "Vul.Autoruns.ps1"                 = @{ Func = "Invoke-VKVulAutoruns"; Id = "vul.autoruns" }
    "Vul.AlwaysInstallElevated.ps1"    = @{ Func = "Invoke-VKVulAlwaysInstallElevated"; Id = "vul.always_install_elevated" }
    "Vul.DLL.SearchOrder.ps1"          = @{ Func = "Invoke-VKVulDLLSearchOrder"; Id = "vul.dll.search_order" }
    "Vul.PowerShellV2.ps1"             = @{ Func = "Invoke-VKVulPowerShellV2"; Id = "vul.powershell_v2" }
    "Vul.LAPS.ps1"                     = @{ Func = "Invoke-VKVulLAPS"; Id = "vul.laps" }
}

foreach ($file in $vulnModuleFiles) {
    $map = $vulnFunctionMap[$file]
    if ($map) {
        [void]$sb.AppendLine("$($map.Func) -Data `$data[`"vulnerability`"] -IsAdmin `$script:IsAdmin")
        [void]$sb.AppendLine("`$modulesExecuted.Add(`"$($map.Id)`") | Out-Null")
        [void]$sb.AppendLine("")
    }
}

# Output section
[void]$sb.AppendLine("# ============================================================")
[void]$sb.AppendLine("#  OUTPUT")
[void]$sb.AppendLine("# ============================================================")
[void]$sb.AppendLine("")
[void]$sb.AppendLine('$scanEnd = (Get-Date).ToUniversalTime()')
[void]$sb.AppendLine('$duration = $scanEnd - $scanStart')
[void]$sb.AppendLine("")
[void]$sb.AppendLine('# Metadata parity with the modular runner. All ten required fields are')
[void]$sb.AppendLine('# emitted, including schema_version, running_user and running_user_sid,')
[void]$sb.AppendLine('# which earlier builds omitted.')
[void]$sb.AppendLine('$data["scan_metadata"] = [ordered]@{')
[void]$sb.AppendLine('    "schema_version"        = $script:VKSchemaVersion')
[void]$sb.AppendLine('    "agent_version"         = $script:VKAgentVersion')
[void]$sb.AppendLine('    "hostname"              = $env:COMPUTERNAME')
[void]$sb.AppendLine('    "running_user"          = $script:CurrentIdentity.Name')
[void]$sb.AppendLine('    "running_user_sid"      = $script:CurrentIdentity.User.Value')
[void]$sb.AppendLine('    "scan_start"            = $scanStart.ToString("yyyy-MM-ddTHH:mm:ssZ")')
[void]$sb.AppendLine('    "scan_end"              = $scanEnd.ToString("yyyy-MM-ddTHH:mm:ssZ")')
[void]$sb.AppendLine('    "scan_duration_seconds" = [math]::Round($duration.TotalSeconds, 2)')
[void]$sb.AppendLine('    "ran_as_admin"          = $script:IsAdmin')
[void]$sb.AppendLine('    "modules_executed"      = @($modulesExecuted)')
[void]$sb.AppendLine('}')
[void]$sb.AppendLine("")
[void]$sb.AppendLine('# --- Acquisition Section (schema 1.1) ---')
[void]$sb.AppendLine('# Fail-closed backstop: any unresolved unit becomes')
[void]$sb.AppendLine('# failed / incomplete_collection. Must run before serialisation.')
[void]$sb.AppendLine('Complete-VKAcquisitionReport')
[void]$sb.AppendLine('$data["acquisition"] = Get-VKAcquisitionReport')
[void]$sb.AppendLine("")
[void]$sb.AppendLine('$jsonOutput = $data | ConvertTo-Json -Depth $script:VKJsonDepth')
[void]$sb.AppendLine('$jsonOutput | Out-File -FilePath $script:OutputPath -Encoding utf8')
[void]$sb.AppendLine("")
[void]$sb.AppendLine("Write-SectionHeader -Title 'Scan Complete'")
[void]$sb.AppendLine('Write-VKStatus -Message "Results saved to: $($script:OutputPath)" -Type "SUCCESS"')


# ============================================================
#  WRITE OUTPUT FILE
# ============================================================

$outputFile = Join-Path $OutputPath "VoightKampff_Standalone_v$version.ps1"
$sb.ToString() | Out-File -FilePath $outputFile -Encoding utf8

$lineCount = ($sb.ToString() -split "`n").Count
$fileSize = [math]::Round((Get-Item $outputFile).Length / 1KB, 1)

Write-BuildMessage ""
Write-BuildMessage "Build complete!" "Green"
Write-BuildMessage "  Modules:  $hostCount host + $secCount security + $vulnCount vulnerability = $($hostCount + $secCount + $vulnCount) total"
Write-BuildMessage "  Output:   $outputFile"
Write-BuildMessage "  Version:  $version (schema $schemaVersion)"
Write-BuildMessage "  Lines:    $lineCount"
Write-BuildMessage "  Size:     $fileSize KB"
Write-BuildMessage ""

if ($PassThru) { return $outputFile }