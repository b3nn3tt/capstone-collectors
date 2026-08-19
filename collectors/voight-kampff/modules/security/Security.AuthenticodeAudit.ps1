<#
.SYNOPSIS
    Module: Authenticode Integrity Audit

.DESCRIPTION
    Validates the authenticode signature and hash integrity of critical
    system binaries. A hash mismatch or invalid signature on these files
    may indicate tampering, rootkit activity, or a compromised system.

    By default, checks a curated list of security-critical binaries.
    To expand the check:
    - Add paths to the $targetBinaries array below
    - Each entry needs a Path and a Category
    - The module handles non-existent paths gracefully

    Signature statuses:
    - Valid:          Signature is intact and trusted
    - HashMismatch:   File has been modified since signing (CRITICAL)
    - NotSigned:      File has no authenticode signature
    - UnknownError:   Unable to verify
    - NotTrusted:     Signature present but certificate not trusted

    No admin required - file signature checks work as standard user.
    Some protected system files may return limited data without admin.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKSecurityAuthenticodeAudit {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Validating authenticode signatures on critical binaries" -Type "PROCESSING"


    # ================================================================
    #  TARGET BINARIES
    # ================================================================
    #  To expand this check, add entries to the array below.
    #  Each entry requires:
    #    Path     = Full path to the binary (environment variables OK)
    #    Category = Grouping label for reporting
    #
    #  Example:
    #    @{ Path = "$env:SystemRoot\System32\YourBinary.exe"; Category = "Custom" }
    # ================================================================

    $targetBinaries = @(

        # --- Core OS / Kernel ---
        @{ Path = "$env:SystemRoot\System32\ntoskrnl.exe";    Category = "Kernel" }
        @{ Path = "$env:SystemRoot\System32\ntdll.dll";       Category = "Kernel" }
        @{ Path = "$env:SystemRoot\System32\kernel32.dll";    Category = "Kernel" }
        @{ Path = "$env:SystemRoot\System32\kernelbase.dll";  Category = "Kernel" }
        @{ Path = "$env:SystemRoot\System32\hal.dll";         Category = "Kernel" }

        # --- Authentication / Credentials ---
        @{ Path = "$env:SystemRoot\System32\lsass.exe";       Category = "Authentication" }
        @{ Path = "$env:SystemRoot\System32\lsaiso.exe";      Category = "Authentication" }
        @{ Path = "$env:SystemRoot\System32\msv1_0.dll";      Category = "Authentication" }
        @{ Path = "$env:SystemRoot\System32\kerberos.dll";    Category = "Authentication" }
        @{ Path = "$env:SystemRoot\System32\wdigest.dll";     Category = "Authentication" }
        @{ Path = "$env:SystemRoot\System32\tspkg.dll";       Category = "Authentication" }
        @{ Path = "$env:SystemRoot\System32\pku2u.dll";       Category = "Authentication" }
        @{ Path = "$env:SystemRoot\System32\LogonController.dll"; Category = "Authentication" }

        # --- Critical System Processes ---
        @{ Path = "$env:SystemRoot\System32\csrss.exe";       Category = "System Process" }
        @{ Path = "$env:SystemRoot\System32\winlogon.exe";    Category = "System Process" }
        @{ Path = "$env:SystemRoot\System32\wininit.exe";     Category = "System Process" }
        @{ Path = "$env:SystemRoot\System32\smss.exe";        Category = "System Process" }
        @{ Path = "$env:SystemRoot\System32\services.exe";    Category = "System Process" }
        @{ Path = "$env:SystemRoot\System32\svchost.exe";     Category = "System Process" }
        @{ Path = "$env:SystemRoot\System32\conhost.exe";     Category = "System Process" }
        @{ Path = "$env:SystemRoot\System32\dwm.exe";         Category = "System Process" }

        # --- Networking ---
        @{ Path = "$env:SystemRoot\System32\ws2_32.dll";      Category = "Networking" }
        @{ Path = "$env:SystemRoot\System32\winhttp.dll";     Category = "Networking" }
        @{ Path = "$env:SystemRoot\System32\wininet.dll";     Category = "Networking" }
        @{ Path = "$env:SystemRoot\System32\dnsapi.dll";      Category = "Networking" }
        @{ Path = "$env:SystemRoot\System32\netapi32.dll";    Category = "Networking" }

        # --- Security / Crypto ---
        @{ Path = "$env:SystemRoot\System32\bcrypt.dll";      Category = "Cryptography" }
        @{ Path = "$env:SystemRoot\System32\ncrypt.dll";      Category = "Cryptography" }
        @{ Path = "$env:SystemRoot\System32\crypt32.dll";     Category = "Cryptography" }
        @{ Path = "$env:SystemRoot\System32\schannel.dll";    Category = "Cryptography" }

        # --- PowerShell / Scripting ---
        @{ Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"; Category = "Scripting" }
        @{ Path = "$env:SystemRoot\System32\cmd.exe";         Category = "Scripting" }
        @{ Path = "$env:SystemRoot\System32\wscript.exe";     Category = "Scripting" }
        @{ Path = "$env:SystemRoot\System32\cscript.exe";     Category = "Scripting" }
        @{ Path = "$env:SystemRoot\System32\mshta.exe";       Category = "Scripting" }

        # --- Windows Defender ---
        @{ Path = "$env:ProgramFiles\Windows Defender\MsMpEng.exe";    Category = "Defender" }
        @{ Path = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe";   Category = "Defender" }

        # ================================================================
        #  ADD CUSTOM ENTRIES BELOW THIS LINE
        # ================================================================

    )


    $results = @()
    $findings = @()

    $validCount = 0
    $mismatchCount = 0
    $notSignedCount = 0
    $notTrustedCount = 0
    $errorCount = 0

    foreach ($target in $targetBinaries) {
        $filePath = $target.Path
        $category = $target.Category

        if (-not (Test-Path $filePath -ErrorAction SilentlyContinue)) { continue }

        try {
            $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop

            $status = $sig.Status.ToString()
            $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            $timeStamper = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }

            # Count by status
            switch ($status) {
                "Valid"         { $validCount++ }
                "HashMismatch"  { $mismatchCount++ }
                "NotSigned"     { $notSignedCount++ }
                "NotTrusted"    { $notTrustedCount++ }
                default         { $errorCount++ }
            }

            $entry = [ordered]@{
                "file_path"   = $filePath
                "category"    = $category
                "status"      = $status
                "signer"      = $signer
            }

            $results += $entry

            # Flag anything that isn't Valid as a finding
            if ($status -ne "Valid") {
                $findings += [ordered]@{
                    "file_path"    = $filePath
                    "category"     = $category
                    "status"       = $status
                    "signer"       = $signer
                    "time_stamper" = $timeStamper
                    "status_message" = $sig.StatusMessage
                }
            }
        }
        catch {
            $errorCount++
            $results += [ordered]@{
                "file_path" = $filePath
                "category"  = $category
                "status"    = "Error"
                "signer"    = $null
            }
        }
    }

    $Data["authenticode_audit"] = [ordered]@{
        "summary" = [ordered]@{
            "binaries_checked" = $results.Count
            "valid"            = $validCount
            "hash_mismatch"    = $mismatchCount
            "not_signed"       = $notSignedCount
            "not_trusted"      = $notTrustedCount
            "errors"           = $errorCount
            "findings_count"   = $findings.Count
        }
        "findings" = $findings
        "all_results" = $results
    }

    Write-VKStatus -Message "Authenticode audit complete ($($results.Count) checked, $($findings.Count) findings)" -Type "SUCCESS"
}