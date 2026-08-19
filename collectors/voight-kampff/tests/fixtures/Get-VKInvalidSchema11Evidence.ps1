<#
.SYNOPSIS
    Deliberately INVALID schema 1.1 fixtures, for validation tests.

.DESCRIPTION
    Returns a hashtable of named schema 1.1 artefacts that each violate the
    contract in exactly one way. Tests assert that a conformance check
    IDENTIFIES each as invalid.

    Per docs/dissertation-agent-evidence-contract.md section 5.5.1:

        Missing required acquisition metadata makes the input
        schema-invalid and subject to quarantine. Ingestion must NOT
        invent an outcome - absent metadata is a schema-validity problem,
        not an acquisition outcome.

    These fixtures therefore exist to prove that the invalid input is
    REJECTED, not silently repaired into a 'failed' entry.

    Cases:
        MissingAcquisitionSection  schema 1.1 with no acquisition section
        MissingUnitEntry           a governed payload path with no entry
        MissingRequiredField       an entry lacking acquisition_outcome
        InvalidOutcomeValue        an entry using a non-permitted outcome
        PendingLeaked              an internal state leaked into JSON
        SuccessWithError           success carrying a non-null error
        NonSuccessWithoutError     non-success carrying a null error
        EmptyDataPaths             an entry governing no payload path

.OUTPUTS
    System.Collections.Hashtable of named [ordered] artefacts.
#>

function New-VKMinimalValidArtefact {
    <#
    .SYNOPSIS
        A minimal, VALID schema 1.1 artefact used as the mutation base.
    #>
    return [ordered]@{
        "scan_metadata" = [ordered]@{
            "schema_version"        = "1.1"
            "agent_version"         = "2.1.0"
            "hostname"              = "INVALID-FIXTURE-01"
            "running_user"          = "FIXTUREDOM\fixture.user"
            "running_user_sid"      = "S-1-5-21-1111111111-2222222222-3333333333-1001"
            "scan_start"            = "2026-08-18T09:14:00Z"
            "scan_end"              = "2026-08-18T09:14:30Z"
            "scan_duration_seconds" = 30.0
            "ran_as_admin"          = $true
            "modules_executed"      = @("security.antivirus")
        }
        "acquisition" = [ordered]@{
            "security.antivirus.products" = [ordered]@{
                "observation_start"   = "2026-08-18T09:14:10Z"
                "observation_end"     = "2026-08-18T09:14:11Z"
                "acquisition_outcome" = "success"
                "agent_version"       = "2.1.0"
                "schema_version"      = "1.1"
                "data_paths"          = @("security.antivirus.product_name")
                "error"               = $null
            }
        }
        "host"          = [ordered]@{ "hostname" = "INVALID-FIXTURE-01" }
        "security"      = [ordered]@{
            "antivirus" = [ordered]@{ "product_name" = "Windows Defender" }
        }
        "vulnerability" = [ordered]@{}
    }
}

$cases = @{}

# --- 1. No acquisition section at all, but declaring schema 1.1 ---------
$case = New-VKMinimalValidArtefact
$case.Remove("acquisition")
$cases["MissingAcquisitionSection"] = $case

# --- 2. Governed payload present, no corresponding acquisition entry ---
$case = New-VKMinimalValidArtefact
$case["acquisition"] = [ordered]@{}
$cases["MissingUnitEntry"] = $case

# --- 3. Entry missing a required field ---------------------------------
$case = New-VKMinimalValidArtefact
$case["acquisition"]["security.antivirus.products"].Remove("acquisition_outcome")
$cases["MissingRequiredField"] = $case

# --- 4. Outcome outside the permitted four-value vocabulary ------------
$case = New-VKMinimalValidArtefact
$case["acquisition"]["security.antivirus.products"]["acquisition_outcome"] = "partial"
$cases["InvalidOutcomeValue"] = $case

# --- 5. Internal 'pending' state leaked into emitted JSON --------------
$case = New-VKMinimalValidArtefact
$case["acquisition"]["security.antivirus.products"]["acquisition_outcome"] = "pending"
$cases["PendingLeaked"] = $case

# --- 6. success carrying a non-null error ------------------------------
$case = New-VKMinimalValidArtefact
$case["acquisition"]["security.antivirus.products"]["error"] = [ordered]@{
    "category"       = "access_denied"
    "provider"       = "root\SecurityCenter2:AntiVirusProduct"
    "message"        = "Access is denied."
    "exception_type" = "System.UnauthorizedAccessException"
}
$cases["SuccessWithError"] = $case

# --- 7. Non-success carrying a null error ------------------------------
$case = New-VKMinimalValidArtefact
$case["acquisition"]["security.antivirus.products"]["acquisition_outcome"] = "restricted"
$case["acquisition"]["security.antivirus.products"]["error"] = $null
$cases["NonSuccessWithoutError"] = $case

# --- 8. Entry governing no payload path --------------------------------
$case = New-VKMinimalValidArtefact
$case["acquisition"]["security.antivirus.products"]["data_paths"] = @()
$cases["EmptyDataPaths"] = $case

$cases
