<#
.SYNOPSIS
    Module: Host Security Settings

.DESCRIPTION
    Enumerates host hardening features:
    - Kernel DMA Protection (via NtQuerySystemInformation)
    - Data Execution Prevention (DEP) policy
    - Virtualization-Based Security (VBS) status
    - Device Guard security services (Credential Guard, HVCI, etc.)
    - Device Guard security properties (Secure Boot, DMA protection, etc.)

    SCHEMA 1.1 ACQUISITION
    Three independent collection units, one per provider:

        security.host_security.kernel_dma_protection
        security.host_security.dep_policy
        security.host_security.device_guard

    The Device Guard unit governs vbs_status, security_services and
    security_properties together, because all three derive from the single
    Win32_DeviceGuard query and therefore share its fate.

    NEGATIVE-ASSERTION RULE
    A security service or property is reported as $false ONLY when the
    Win32_DeviceGuard query completed successfully and the returned
    configured/running/available lists justify that reading. If the query
    is restricted, unavailable or failed, the governed paths are set to
    $null and no substantive negative assertion is made.

    This corrects the schema 1.0 defect where a failed query produced a
    fully populated list asserting that every security service was
    unconfigured and not running.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityHostSecurity {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating host security settings" -Type "PROCESSING"

    $securitySettings = [ordered]@{}


    # --------------------------------------------------------
    #  Kernel DMA Protection
    # --------------------------------------------------------

    $dmaUnit = "security.host_security.kernel_dma_protection"

    Start-VKAcquisition -UnitId $dmaUnit -Provider "ntdll.dll:NtQuerySystemInformation(SystemDmaGuardPolicyInformation)" -DataPaths @(
        "security.host_security.kernel_dma_protection"
    )

    try {
        # Add the C# type for querying DMA guard policy via ntdll
        $bootDMAProtectionCheck = @"
namespace SystemInfo
{
    using System;
    using System.Runtime.InteropServices;

    public static class NativeMethods
    {
        internal enum SYSTEM_INFORMATION_CLASS : int
        {
            SystemDmaGuardPolicyInformation = 202
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            Int32 SystemInformationLength,
            out Int32 ReturnLength);

        public static byte BootDmaCheck()
        {
            Int32 SystemInformationLength = 1;
            IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
            try
            {
                Int32 ReturnLength;
                Int32 result = NtQuerySystemInformation(
                    SYSTEM_INFORMATION_CLASS.SystemDmaGuardPolicyInformation,
                    SystemInformation,
                    SystemInformationLength,
                    out ReturnLength);

                // FAIL-CLOSED. A non-zero NTSTATUS means the query did not
                // answer the question. It must NOT be flattened to 0, which
                // the caller reads as a confident "DMA protection is off" -
                // a negative assertion the host never made. Throwing routes
                // it to the PowerShell catch, which yields $null and a
                // non-success acquisition outcome.
                //
                // Do not reintroduce a "non-zero status -> return 0" path.
                if (result != 0)
                {
                    throw new InvalidOperationException(
                        "NtQuerySystemInformation(SystemDmaGuardPolicyInformation) failed with NTSTATUS 0x"
                        + result.ToString("X8") + ".");
                }

                // NTSTATUS success: a returned byte of 0 here is a genuine
                // observed value and remains a valid observed false.
                return Marshal.ReadByte(SystemInformation, 0);
            }
            finally
            {
                Marshal.FreeHGlobal(SystemInformation);
            }
        }
    }
}
"@

        # Only add the type if it hasn't been loaded already (avoids errors on re-run)
        if (-not ([System.Management.Automation.PSTypeName]'SystemInfo.NativeMethods').Type) {
            Add-Type -TypeDefinition $bootDMAProtectionCheck
        }

        $dmaResult = [SystemInfo.NativeMethods]::BootDmaCheck()
        $securitySettings["kernel_dma_protection"] = ($dmaResult -ne 0)

        Complete-VKAcquisition -UnitId $dmaUnit
    }
    catch {
        Write-LogMessage -Section "Security.HostSecurity" -Message "Error querying Kernel DMA Protection: $($_.Exception.Message)" -Level "ERROR"
        $securitySettings["kernel_dma_protection"] = $null

        Set-VKAcquisitionFailure -UnitId $dmaUnit -ErrorRecord $_ `
            -Provider "ntdll.dll:NtQuerySystemInformation(SystemDmaGuardPolicyInformation)"
    }


    # --------------------------------------------------------
    #  DEP (Data Execution Prevention)
    # --------------------------------------------------------

    $depUnit     = "security.host_security.dep_policy"
    $depProvider = "root\CIMV2:Win32_OperatingSystem"

    Start-VKAcquisition -UnitId $depUnit -Provider $depProvider -DataPaths @(
        "security.host_security.dep_policy"
    )

    try {
        # The provider can answer without throwing and still supply no
        # instance, or an instance without the property. Casting $null to
        # [int] yields 0, which Resolve-LookupValue maps to "Always Off" -
        # a confident negative the host never reported. Both cases are
        # therefore checked BEFORE any conversion or lookup.
        $osInstance = @(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop) |
            Select-Object -First 1

        $depPolicy = if ($null -ne $osInstance) { $osInstance.DataExecutionPrevention_SupportPolicy } else { $null }

        if ($null -eq $depPolicy) {
            $securitySettings["dep_policy"] = $null

            $missingReason = if ($null -eq $osInstance) {
                "Win32_OperatingSystem returned no instance."
            }
            else {
                "Win32_OperatingSystem returned no DataExecutionPrevention_SupportPolicy value."
            }

            Write-LogMessage -Section "Security.HostSecurity" -Message "Unable to determine DEP status: $missingReason" -Level "ERROR"
            Set-VKAcquisitionUnavailable -UnitId $depUnit -Provider $depProvider `
                -Category "provider_value_missing" -Message $missingReason
        }
        else {
            $securitySettings["dep_policy"] = Resolve-LookupValue -Value ([int]$depPolicy) -LookupTable $script:VKDepPolicies
            Complete-VKAcquisition -UnitId $depUnit
        }
    }
    catch {
        Write-LogMessage -Section "Security.HostSecurity" -Message "Error retrieving DEP status: $($_.Exception.Message)" -Level "ERROR"
        $securitySettings["dep_policy"] = $null

        Set-VKAcquisitionFailure -UnitId $depUnit -ErrorRecord $_ -Provider $depProvider
    }


    # --------------------------------------------------------
    #  Device Guard: VBS, security services, security properties
    # --------------------------------------------------------
    # One provider, one collection unit, three governed paths.
    #
    # Every value below is derived from $DeviceGuardState. If the query did
    # not succeed there is no authority for ANY of them, so all three are
    # set to $null. They are never populated with $false, which would
    # assert that the mitigations are absent.

    $deviceGuardUnit     = "security.host_security.device_guard"
    $deviceGuardProvider = "root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard"

    Start-VKAcquisition -UnitId $deviceGuardUnit -Provider $deviceGuardProvider -DataPaths @(
        "security.host_security.vbs_status"
        "security.host_security.security_services"
        "security.host_security.security_properties"
    )

    try {
        $DeviceGuardState = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction Stop

        if ($null -eq $DeviceGuardState) {
            # Query completed but returned no instance. The class exists on
            # editions that do not implement Device Guard, so this is a
            # capability gap rather than an error - and still not evidence
            # that the mitigations are switched off.
            throw [System.NotSupportedException]::new("Win32_DeviceGuard returned no instance on this host.")
        }

        # --- VBS status ---
        $vbsStatus = [int]$DeviceGuardState.VirtualizationBasedSecurityStatus
        $securitySettings["vbs_status"] = Resolve-LookupValue -Value $vbsStatus -LookupTable $script:VKVbsStates

        # --- Security services ---
        # The provider returns authoritative configured/running lists, so a
        # service absent from them is genuinely not configured/running.
        $servicesConfigured = @($DeviceGuardState.SecurityServicesConfigured)
        $servicesRunning    = @($DeviceGuardState.SecurityServicesRunning)

        $serviceDetails = @()
        foreach ($service in $script:VKSecurityServices) {
            $serviceDetails += [ordered]@{
                "service_name" = $service.name
                "configured"   = ($servicesConfigured -contains $service.id)
                "running"      = ($servicesRunning -contains $service.id)
            }
        }

        $securitySettings["security_services"] = $serviceDetails

        # --- Security properties ---
        $propertiesAvailable = @($DeviceGuardState.AvailableSecurityProperties)

        $propertyDetails = @()
        foreach ($property in $script:VKSecurityProperties) {
            $propertyDetails += [ordered]@{
                "property_name" = $property.name
                "available"     = ($propertiesAvailable -contains $property.id)
            }
        }

        $securitySettings["security_properties"] = $propertyDetails

        Complete-VKAcquisition -UnitId $deviceGuardUnit
    }
    catch {
        # No substantive negative assertion for any governed path.
        $securitySettings["vbs_status"]          = $null
        $securitySettings["security_services"]   = $null
        $securitySettings["security_properties"] = $null

        Write-LogMessage -Section "Security.HostSecurity" -Message "Error querying Device Guard state: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $deviceGuardUnit -ErrorRecord $_ -Provider $deviceGuardProvider
    }

    $Data["host_security"] = $securitySettings

    Write-VKStatus -Message "Host security enumeration complete" -Type "SUCCESS"
}