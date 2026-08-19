<#
.SYNOPSIS
    Module: LSA Protection

.DESCRIPTION
    Enumerates LSA and credential protection settings:
    - RunAsPPL (LSASS as Protected Process Light)
    - Credential Guard status (via Device Guard, supplements HostSecurity)
    - WDigest authentication (plaintext credentials in memory)
    - Cached logon credentials count
    - LM hash storage policy
    - LAN Manager authentication level

    These settings directly impact resistance to credential theft
    tools like Mimikatz, and are key findings in security assessments.

    No admin required - all registry reads.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKSecurityLSAProtection {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating LSA protection settings" -Type "PROCESSING"

    $lsaData = [ordered]@{}

    $lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"


    # --------------------------------------------------------
    #  RunAsPPL (LSASS Protected Process Light)
    # --------------------------------------------------------
    # When enabled, LSASS runs as a protected process, preventing
    # non-protected processes from reading its memory (blocks Mimikatz).
    # RunAsPPL: 1 = enabled, 0 or absent = disabled

    try {
        $runAsPPL = Get-ItemProperty -Path $lsaRegPath -Name "RunAsPPL" -ErrorAction SilentlyContinue

        $lsaData["run_as_ppl"] = if ($null -ne $runAsPPL.RunAsPPL) {
            ($runAsPPL.RunAsPPL -eq 1)
        }
        else { $false }
    }
    catch {
        $lsaData["run_as_ppl"] = $null
        Write-LogMessage -Section "Security.LSAProtection" -Message "Unable to determine RunAsPPL status: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  WDigest Authentication
    # --------------------------------------------------------
    # When enabled, plaintext passwords are stored in LSASS memory.
    # UseLogonCredential: 1 = enabled (insecure), 0 or absent = disabled
    # Disabled by default since Windows 8.1 / Server 2012 R2

    try {
        $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        $wdigest = Get-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue

        $lsaData["wdigest_plaintext_enabled"] = if ($null -ne $wdigest.UseLogonCredential) {
            ($wdigest.UseLogonCredential -eq 1)
        }
        else { $false }  # Default is disabled on modern Windows
    }
    catch {
        $lsaData["wdigest_plaintext_enabled"] = $null
        Write-LogMessage -Section "Security.LSAProtection" -Message "Unable to determine WDigest status: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  Cached Logon Credentials
    # --------------------------------------------------------
    # Number of domain logon credentials cached locally.
    # Default is 10. Higher values increase credential theft risk.
    # CachedLogonsCount in registry is a string value.

    try {
        $cachedLogons = Get-ItemProperty -Path $lsaRegPath -Name "CachedLogonsCount" -ErrorAction SilentlyContinue

        $lsaData["cached_logons_count"] = if ($null -ne $cachedLogons.CachedLogonsCount) {
            [int]$cachedLogons.CachedLogonsCount
        }
        else { 10 }  # Windows default
    }
    catch {
        $lsaData["cached_logons_count"] = $null
        Write-LogMessage -Section "Security.LSAProtection" -Message "Unable to determine cached logon count: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  LM Hash Storage
    # --------------------------------------------------------
    # NoLMHash: 1 = do not store LM hash (secure), 0 = store LM hash (insecure)
    # Default is 1 (disabled) since Windows Vista / Server 2008

    try {
        $noLmHash = Get-ItemProperty -Path $lsaRegPath -Name "NoLMHash" -ErrorAction SilentlyContinue

        $lsaData["lm_hash_stored"] = if ($null -ne $noLmHash.NoLMHash) {
            ($noLmHash.NoLMHash -eq 0)
        }
        else { $false }  # Default is not stored on modern Windows
    }
    catch {
        $lsaData["lm_hash_stored"] = $null
        Write-LogMessage -Section "Security.LSAProtection" -Message "Unable to determine LM hash storage status: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  LAN Manager Authentication Level
    # --------------------------------------------------------
    # LmCompatibilityLevel determines NTLM authentication behaviour:
    # 0 = Send LM & NTLM responses
    # 1 = Send LM & NTLM, use NTLMv2 session security if negotiated
    # 2 = Send NTLM response only
    # 3 = Send NTLMv2 response only
    # 4 = Send NTLMv2, refuse LM
    # 5 = Send NTLMv2, refuse LM & NTLM
    # Default is 3 on modern Windows. Values 0-2 are insecure.

    $lmCompatMap = @{
        0 = "Send LM and NTLM responses"
        1 = "Send LM and NTLM, use NTLMv2 session security if negotiated"
        2 = "Send NTLM response only"
        3 = "Send NTLMv2 response only"
        4 = "Send NTLMv2, refuse LM"
        5 = "Send NTLMv2, refuse LM and NTLM"
    }

    try {
        $lmCompat = Get-ItemProperty -Path $lsaRegPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

        if ($null -ne $lmCompat.LmCompatibilityLevel) {
            $lsaData["lm_compatibility_level"] = [int]$lmCompat.LmCompatibilityLevel
            $lsaData["lm_compatibility_text"] = Resolve-LookupValue -Value ([int]$lmCompat.LmCompatibilityLevel) -LookupTable $lmCompatMap
        }
        else {
            $lsaData["lm_compatibility_level"] = 3  # Windows default
            $lsaData["lm_compatibility_text"] = "Send NTLMv2 response only"
        }
    }
    catch {
        $lsaData["lm_compatibility_level"] = $null
        $lsaData["lm_compatibility_text"] = $null
        Write-LogMessage -Section "Security.LSAProtection" -Message "Unable to determine LM compatibility level: $($_.Exception.Message)" -Level "ERROR"
    }


    # --------------------------------------------------------
    #  Credential Guard (LSASS Credential Isolation)
    # --------------------------------------------------------
    # LsaCfgFlags: 0 = disabled, 1 = enabled with UEFI lock, 2 = enabled without lock
    # This supplements the Device Guard data in Security.HostSecurity

    try {
        $lsaCfg = Get-ItemProperty -Path $lsaRegPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue

        $credGuardMap = @{
            0 = "Disabled"
            1 = "Enabled with UEFI lock"
            2 = "Enabled without UEFI lock"
        }

        if ($null -ne $lsaCfg.LsaCfgFlags) {
            $lsaData["credential_guard"] = Resolve-LookupValue -Value ([int]$lsaCfg.LsaCfgFlags) -LookupTable $credGuardMap
            $lsaData["credential_guard_raw"] = [int]$lsaCfg.LsaCfgFlags
        }
        else {
            $lsaData["credential_guard"] = "Not Configured"
            $lsaData["credential_guard_raw"] = $null
        }
    }
    catch {
        $lsaData["credential_guard"] = $null
        Write-LogMessage -Section "Security.LSAProtection" -Message "Unable to determine Credential Guard status: $($_.Exception.Message)" -Level "ERROR"
    }

    $Data["lsa_protection"] = $lsaData

    Write-VKStatus -Message "LSA protection enumeration complete" -Type "SUCCESS"
}