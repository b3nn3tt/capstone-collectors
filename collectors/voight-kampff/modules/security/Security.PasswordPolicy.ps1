<#
.SYNOPSIS
    Module: Password Policy Assessment

.DESCRIPTION
    Evaluates local password and account lockout policy:
    - Exports policy via secedit and parses the output
    - Password age, length, complexity, history
    - Account lockout threshold, duration, reset counter
    - Miscellaneous settings (blank passwords, plaintext, admin lockout)

    All values captured as raw data for backend compliance evaluation.

    Note: secedit export works without admin but some values may be
    incomplete on non-admin sessions depending on system configuration.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKSecurityPasswordPolicy {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    if (-not $IsAdmin) {
        Write-VKStatus -Message "Skipping password policy enumeration - requires admin privileges." -Type "BYPASS"
        return
    }

    Write-VKStatus -Message "Enumerating password policy" -Type "PROCESSING"

    $tempPolicyFile = $null

    try {
        # Export security policy to a temporary file
        $tempPolicyFile = New-TemporaryFile
        secedit /export /cfg $tempPolicyFile.FullName /quiet | Out-Null

        $policyContent = Get-Content -Path $tempPolicyFile.FullName -Raw

        # Helper to extract a value from the policy export
        function Get-PolicyValue {
            param([string]$Pattern)
            if ($policyContent -match $Pattern) {
                return $matches[1]
            }
            return $null
        }

        # Extract raw values - cast numeric ones to int where possible
        $minPwAge       = Get-PolicyValue "MinimumPasswordAge\s*=\s*(\d+)"
        $maxPwAge       = Get-PolicyValue "MaximumPasswordAge\s*=\s*(-?\d+)"
        $minPwLength    = Get-PolicyValue "MinimumPasswordLength\s*=\s*(\d+)"
        $pwComplexity   = Get-PolicyValue "PasswordComplexity\s*=\s*(\d+)"
        $pwHistory      = Get-PolicyValue "PasswordHistorySize\s*=\s*(\d+)"
        $clearTextPw    = Get-PolicyValue "ClearTextPassword\s*=\s*(\d+)"
        $lockoutCount   = Get-PolicyValue "LockoutBadCount\s*=\s*(\d+)"
        $lockoutDuration = Get-PolicyValue "LockoutDuration\s*=\s*(-?\d+)"
        $resetLockout   = Get-PolicyValue "ResetLockoutCount\s*=\s*(\d+)"
        $adminLockout   = Get-PolicyValue "AllowAdministratorLockout\s*=\s*(\d+)"
        $pwExpiryWarn   = Get-PolicyValue "PasswordExpiryWarning\s*=\s*(\d+)"
        $limitBlankPw   = Get-PolicyValue "LimitBlankPasswordUse\s*=\s*(\d+)"
        $disablePwChange = Get-PolicyValue "DisablePasswordChange\s*=\s*(\d+)"
        $enablePlainText = Get-PolicyValue "EnablePlainTextPassword\s*=\s*(\d+)"

        $Data["password_policy"] = [ordered]@{
            "minimum_password_age"       = if ($null -ne $minPwAge)       { [int]$minPwAge }       else { $null }
            "maximum_password_age"       = if ($null -ne $maxPwAge)       { [int]$maxPwAge }       else { $null }
            "minimum_password_length"    = if ($null -ne $minPwLength)    { [int]$minPwLength }    else { $null }
            "password_complexity"        = if ($null -ne $pwComplexity)   { [int]$pwComplexity -eq 1 } else { $null }
            "password_history_size"      = if ($null -ne $pwHistory)      { [int]$pwHistory }      else { $null }
            "clear_text_password"        = if ($null -ne $clearTextPw)    { [int]$clearTextPw -eq 1 } else { $null }
            "lockout_threshold"          = if ($null -ne $lockoutCount)   { [int]$lockoutCount }   else { $null }
            "lockout_duration"           = if ($null -ne $lockoutDuration) { [int]$lockoutDuration } else { $null }
            "reset_lockout_count"        = if ($null -ne $resetLockout)   { [int]$resetLockout }   else { $null }
            "allow_administrator_lockout"= if ($null -ne $adminLockout)  { [int]$adminLockout -eq 1 } else { $null }
            "password_expiry_warning"    = if ($null -ne $pwExpiryWarn)   { [int]$pwExpiryWarn }   else { $null }
            "limit_blank_password_use"   = if ($null -ne $limitBlankPw)   { [int]$limitBlankPw -eq 1 } else { $null }
            "disable_password_change"    = if ($null -ne $disablePwChange) { [int]$disablePwChange -eq 1 } else { $null }
            "enable_plain_text_password" = if ($null -ne $enablePlainText) { [int]$enablePlainText -eq 1 } else { $null }
        }
    }
    catch {
        Write-LogMessage -Section "Security.PasswordPolicy" -Message "Failed to parse password policy: $($_.Exception.Message)" -Level "ERROR"
    }
    finally {
        # Cleanup temp file
        if ($tempPolicyFile -and (Test-Path $tempPolicyFile.FullName)) {
            Remove-Item -Path $tempPolicyFile.FullName -Force
        }
    }

    Write-VKStatus -Message "Password policy enumeration complete" -Type "SUCCESS"
}