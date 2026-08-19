<#
.SYNOPSIS
    Module: Certificate Store Audit

.DESCRIPTION
    Audits the local machine and current user certificate stores:
    - Expired certificates
    - Certificates expiring soon (within 30 days)
    - Certificates using SHA1 signature algorithm (deprecated)
    - Certificates with weak key lengths (RSA < 2048 bits)
    - Self-signed certificates
    - Certificate store summary (total, expired, expiring, weak)

    Scans the following stores:
    - LocalMachine\My (Personal)
    - LocalMachine\Root (Trusted Root CAs)
    - LocalMachine\CA (Intermediate CAs)
    - LocalMachine\TrustedPublisher
    - CurrentUser\My (Personal)
    - CurrentUser\Root (Trusted Root CAs)

    No admin required - certificate stores are readable by standard users.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>

function Invoke-VKSecurityCertificateStore {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Auditing certificate stores" -Type "PROCESSING"

    $stores = @(
        @{ Location = "LocalMachine"; Name = "My";               Label = "Local Machine - Personal" },
        @{ Location = "LocalMachine"; Name = "Root";             Label = "Local Machine - Trusted Root CAs" },
        @{ Location = "LocalMachine"; Name = "CA";               Label = "Local Machine - Intermediate CAs" },
        @{ Location = "LocalMachine"; Name = "TrustedPublisher"; Label = "Local Machine - Trusted Publishers" },
        @{ Location = "CurrentUser";  Name = "My";               Label = "Current User - Personal" },
        @{ Location = "CurrentUser";  Name = "Root";             Label = "Current User - Trusted Root CAs" }
    )

    $now = Get-Date
    $expiryWarningDays = 30
    $expiryThreshold = $now.AddDays($expiryWarningDays)

    $findings = @()

    # Counters
    $totalCerts = 0
    $expiredCount = 0
    $expiringCount = 0
    $sha1Count = 0
    $weakKeyCount = 0
    $selfSignedCount = 0

    foreach ($store in $stores) {
        $certPath = "Cert:\$($store.Location)\$($store.Name)"

        try {
            if (-not (Test-Path $certPath -ErrorAction SilentlyContinue)) { continue }

            $certs = Get-ChildItem -Path $certPath -ErrorAction SilentlyContinue

            foreach ($cert in $certs) {
                $totalCerts++

                # Basic cert info
                $subject = $cert.Subject
                $issuer = $cert.Issuer
                $thumbprint = $cert.Thumbprint
                $notBefore = $cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                $notAfter = $cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

                # Signature algorithm
                $sigAlgorithm = $cert.SignatureAlgorithm.FriendlyName

                # Key length
                $keyLength = $null
                try {
                    if ($cert.PublicKey.Key) {
                        $keyLength = $cert.PublicKey.Key.KeySize
                    }
                    elseif ($cert.PublicKey.EncodedKeyValue) {
                        # Fallback for CNG keys
                        $keyLength = $cert.PublicKey.EncodedKeyValue.RawData.Length * 8
                    }
                }
                catch { }

                # Determine issues
                $issues = @()

                # Expired
                $isExpired = ($cert.NotAfter -lt $now)
                if ($isExpired) {
                    $expiredCount++
                    $issues += "Expired"
                }

                # Expiring soon
                $isExpiring = (-not $isExpired -and $cert.NotAfter -lt $expiryThreshold)
                if ($isExpiring) {
                    $expiringCount++
                    $issues += "Expiring within $expiryWarningDays days"
                }

                # SHA1
                if ($sigAlgorithm -match "^sha1") {
                    $sha1Count++
                    $issues += "SHA1 signature (deprecated)"
                }

                # Weak key
                if ($keyLength -and $keyLength -lt 2048) {
                    $weakKeyCount++
                    $issues += "Weak key length ($keyLength bits)"
                }

                # Self-signed
                $isSelfSigned = ($cert.Subject -eq $cert.Issuer)
                if ($isSelfSigned) {
                    $selfSignedCount++
                }

                # Only add to findings if there's an issue
                if ($issues.Count -gt 0) {
                    $findings += [ordered]@{
                        "store"           = $store.Label
                        "subject"         = $subject
                        "issuer"          = $issuer
                        "thumbprint"      = $thumbprint
                        "not_before"      = $notBefore
                        "not_after"       = $notAfter
                        "sig_algorithm"   = $sigAlgorithm
                        "key_length"      = $keyLength
                        "is_self_signed"  = $isSelfSigned
                        "issues"          = $issues
                    }
                }
            }
        }
        catch {
            Write-LogMessage -Section "Security.CertificateStore" -Message "Unable to read store $certPath : $($_.Exception.Message)" -Level "ERROR"
        }
    }

    $Data["certificate_store"] = [ordered]@{
        "summary" = [ordered]@{
            "total_certificates" = $totalCerts
            "expired"            = $expiredCount
            "expiring_soon"      = $expiringCount
            "sha1_signatures"    = $sha1Count
            "weak_keys"          = $weakKeyCount
            "self_signed"        = $selfSignedCount
            "findings_count"     = $findings.Count
        }
        "findings" = $findings
    }

    Write-VKStatus -Message "Certificate store audit complete ($totalCerts certs, $($findings.Count) findings)" -Type "SUCCESS"
}