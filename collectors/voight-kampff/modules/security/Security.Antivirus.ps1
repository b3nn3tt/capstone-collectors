<#
.SYNOPSIS
    Module: Antivirus Assessment

.DESCRIPTION
    Evaluates antivirus posture:
    - Detects installed AV product via SecurityCenter2 WMI namespace
    - Decodes productState bitmask (operational state, signature status)
    - Windows Defender deep inspection when detected:
      - Running mode, real-time protection status
      - Antivirus and antispyware signature update timestamps
    - Third-party AV basic detection

    The productState decoding is DATA ENRICHMENT - translating a bitmask
    into human-readable values. Compliance evaluation is handled by the backend.

    SCHEMA 1.1 ACQUISITION
    Two independent collection units:

        security.antivirus.products         (root\SecurityCenter2:AntiVirusProduct)
        security.antivirus.defender_status  (Get-MpComputerStatus)

    OUTCOME DISTINCTIONS
    The schema 1.0 module queried SecurityCenter2 with
    -ErrorAction SilentlyContinue, so a failed or denied query and a host
    with genuinely no antivirus both produced product_name = "Not Detected".
    An acquisition failure therefore presented as a substantive C7 finding.
    That is now separated:

        query succeeds, one or more products -> success, product evidence
        query succeeds, zero products        -> success, products_detected = 0
        access denied / policy restriction   -> restricted, no product evidence
        namespace or provider unavailable    -> unavailable, no product evidence
        unexpected query or parse error      -> failed, no product evidence

    COMPATIBILITY CHOICE
    The "Not Detected" prose sentinel has been REMOVED. A successful
    zero-product result is now represented structurally:

        product_name      = $null
        product_state     = $null
        products_detected = 0

    A non-success result sets products_detected to $null, so "we looked and
    found none" and "we could not look" are distinguishable in the payload
    as well as in the acquisition record. Downstream consumers that
    previously tested for the string "Not Detected" must instead read
    products_detected together with the acquisition outcome. Per the
    evidence contract, a successful zero-product result makes absence
    ASSESSABLE; it does not by itself establish confirmed absence.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.1.0
#>

function Invoke-VKSecurityAntivirus {
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$Data,

        [bool]$IsAdmin = $false
    )

    Write-VKStatus -Message "Enumerating antivirus status" -Type "PROCESSING"

    $productsUnit     = "security.antivirus.products"
    $productsProvider = "root\SecurityCenter2:AntiVirusProduct"
    $defenderUnit     = "security.antivirus.defender_status"
    $defenderProvider = "Get-MpComputerStatus"

    # Every path declared in the two units' data_paths is pre-initialised to
    # $null, so a declared path is always present and explicitly "not
    # observed" rather than silently absent. Values are only ever replaced
    # by a successfully observed one.
    $avData = [ordered]@{
        "product_name"                  = $null
        "product_state"                 = $null
        "products_detected"             = $null
        "running_mode"                  = $null
        "real_time_protection"          = $null
        "antivirus_enabled"             = $null
        "antispyware_enabled"           = $null
        "antivirus_signature_updated"   = $null
        "antispyware_signature_updated" = $null
    }

    Start-VKAcquisition -UnitId $productsUnit -Provider $productsProvider -DataPaths @(
        "security.antivirus.product_name"
        "security.antivirus.product_state"
        "security.antivirus.products_detected"
    )

    Start-VKAcquisition -UnitId $defenderUnit -Provider $defenderProvider -DataPaths @(
        "security.antivirus.running_mode"
        "security.antivirus.real_time_protection"
        "security.antivirus.antivirus_enabled"
        "security.antivirus.antispyware_enabled"
        "security.antivirus.antivirus_signature_updated"
        "security.antivirus.antispyware_signature_updated"
    )

    $avInfo = $null
    $productsQuerySucceeded = $false

    # --------------------------------------------------------
    #  Registered antivirus products
    # --------------------------------------------------------

    try {
        # -ErrorAction Stop, NOT SilentlyContinue: a denied or failed query
        # must surface as an exception, not as an empty result.
        $avInfo = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop)

        $productsQuerySucceeded = $true
        $avData["products_detected"] = $avInfo.Count

        if ($avInfo.Count -eq 0) {
            # Successful zero-result collection. Absence is now assessable
            # downstream; it is not asserted here.
            Write-VKStatus -Message "No antivirus product registered with SecurityCenter2." -Type "WARNING"
        }
        else {
            $primary = $avInfo[0]

            $avData["product_name"] = if ($primary.displayName) { $primary.displayName } else { "Unknown" }

            $avData["product_state"] = if ($primary.productState) {
                Get-ProductStateDescription -ProductState $primary.productState
            }
            else {
                [ordered]@{
                    "ProductState"     = $null
                    "HexadecimalState" = $null
                    "OperationalState" = "Unknown"
                    "SignatureStatus"  = "Unknown"
                }
            }
        }

        Complete-VKAcquisition -UnitId $productsUnit
    }
    catch {
        # No product evidence of any kind on a non-success outcome.
        $avData["product_name"]      = $null
        $avData["product_state"]     = $null
        $avData["products_detected"] = $null

        Write-LogMessage -Section "Security.Antivirus" -Message "Unable to retrieve antivirus details: $($_.Exception.Message)" -Level "ERROR"
        Set-VKAcquisitionFailure -UnitId $productsUnit -ErrorRecord $_ -Provider $productsProvider
    }

    # --------------------------------------------------------
    #  Windows Defender deep inspection
    # --------------------------------------------------------

    $isDefender = $productsQuerySucceeded -and
                  ($avData["product_name"] -match "Windows Defender|Microsoft Defender")

    if (-not $productsQuerySucceeded) {
        # We could not establish which product is registered, so Defender
        # detail was never attempted. Nothing is asserted about it.
        Set-VKAcquisitionUnavailable -UnitId $defenderUnit -Provider $defenderProvider `
            -Category "precondition_not_met" `
            -Message "The registered-product query did not succeed, so Defender status could not be attempted."
    }
    elseif (-not $isDefender) {
        # A legitimate, informative capability gap rather than an error.
        Set-VKAcquisitionUnavailable -UnitId $defenderUnit -Provider $defenderProvider `
            -Category "provider_not_applicable" `
            -Message "Microsoft Defender is not the registered antivirus product on this host."
    }
    else {
        try {
            # Get-MpComputerStatus can return $null without throwing. Piping
            # that straight into Select-Object yields nothing, every Defender
            # field stays $null, and the unit would previously have been
            # completed as SUCCESS - recording "we looked and Defender
            # reported nothing" when in fact the provider never answered.
            # The response is therefore checked before completion.
            $defenderStatus = Get-MpComputerStatus -ErrorAction Stop

            if ($null -eq $defenderStatus) {
                # All Defender-specific fields remain $null.
                $noStatusReason = "Get-MpComputerStatus returned no status object."

                Write-LogMessage -Section "Security.Antivirus" -Message "Unable to query Defender details: $noStatusReason" -Level "WARNING"
                Set-VKAcquisitionUnavailable -UnitId $defenderUnit -Provider $defenderProvider `
                    -Category "provider_value_missing" -Message $noStatusReason
            }
            else {
                $defender = $defenderStatus |
                    Select-Object -Property AMRunningMode, RealTimeProtectionEnabled,
                        AntispywareEnabled, AntivirusEnabled,
                        AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated

                $avData["running_mode"]           = $defender.AMRunningMode
                $avData["real_time_protection"]   = $defender.RealTimeProtectionEnabled
                $avData["antivirus_enabled"]      = $defender.AntivirusEnabled
                $avData["antispyware_enabled"]    = $defender.AntispywareEnabled

                $avData["antivirus_signature_updated"] = if ($defender.AntivirusSignatureLastUpdated) {
                    $defender.AntivirusSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ssZ")
                } else { $null }

                $avData["antispyware_signature_updated"] = if ($defender.AntispywareSignatureLastUpdated) {
                    $defender.AntispywareSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ssZ")
                } else { $null }

                Complete-VKAcquisition -UnitId $defenderUnit
            }
        }
        catch {
            # Defender is the registered product but its detail could not be
            # read - commonly when a third-party product manages it. The
            # product-level evidence above is retained; no Defender-level
            # value is asserted.
            Write-LogMessage -Section "Security.Antivirus" -Message "Unable to query Defender details: $($_.Exception.Message)" -Level "WARNING"
            Set-VKAcquisitionFailure -UnitId $defenderUnit -ErrorRecord $_ -Provider $defenderProvider
        }
    }

    $Data["antivirus"] = $avData

    Write-VKStatus -Message "Antivirus enumeration complete" -Type "SUCCESS"
}