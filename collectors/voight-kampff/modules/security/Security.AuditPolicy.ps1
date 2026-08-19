<#
.SYNOPSIS
    Module: Audit Policy

.DESCRIPTION
    Enumerates the Windows advanced audit policy configuration via auditpol.exe:
    - All audit policy categories and subcategories
    - Current setting for each (Success, Failure, Success and Failure, No Auditing)

    Audit policy determines what security events Windows logs. Gaps in
    audit coverage are a common finding - without proper logging,
    incident response and forensics are severely hampered.

    Requires admin - auditpol.exe needs elevated privileges.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKSecurityAuditPolicy {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    if (-not $IsAdmin) {
        Write-VKStatus -Message "Skipping audit policy enumeration - requires admin privileges." -Type "BYPASS"
        return
    }

    Write-VKStatus -Message "Enumerating audit policy" -Type "PROCESSING"

    try {
        # Export audit policy as CSV for reliable parsing
        $auditOutput = auditpol.exe /get /category:* /r 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-LogMessage -Section "Security.AuditPolicy" -Message "auditpol.exe returned exit code $LASTEXITCODE" -Level "ERROR"
            return
        }

        # Parse CSV output - skip empty lines
        $csvLines = $auditOutput | Where-Object { $_ -and $_.Trim() }

        # First line is the header
        $policies = @()
        $header = $null

        foreach ($line in $csvLines) {
            if (-not $header) {
                $header = $line
                continue
            }

            # CSV format: Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
            $fields = $line -split ','

            if ($fields.Count -ge 5) {
                $subcategory = $fields[2].Trim()
                $setting = $fields[4].Trim()

                # Skip empty subcategories
                if (-not $subcategory) { continue }

                $policies += [ordered]@{
                    "subcategory" = $subcategory
                    "setting"     = $setting
                }
            }
        }

        # Build a summary of audit coverage
        $totalPolicies = $policies.Count
        $noAuditing = ($policies | Where-Object { $_["setting"] -eq "No Auditing" }).Count
        $successOnly = ($policies | Where-Object { $_["setting"] -eq "Success" }).Count
        $failureOnly = ($policies | Where-Object { $_["setting"] -eq "Failure" }).Count
        $successAndFailure = ($policies | Where-Object { $_["setting"] -eq "Success and Failure" }).Count

        $Data["audit_policy"] = [ordered]@{
            "summary" = [ordered]@{
                "total_policies"      = $totalPolicies
                "no_auditing"         = $noAuditing
                "success_only"        = $successOnly
                "failure_only"        = $failureOnly
                "success_and_failure" = $successAndFailure
            }
            "policies" = $policies
        }
    }
    catch {
        Write-LogMessage -Section "Security.AuditPolicy" -Message "Failed to enumerate audit policy: $($_.Exception.Message)" -Level "ERROR"
    }

    Write-VKStatus -Message "Audit policy enumeration complete" -Type "SUCCESS"
}