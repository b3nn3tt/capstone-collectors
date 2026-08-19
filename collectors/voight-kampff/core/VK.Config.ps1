<#
.SYNOPSIS
    Agent configuration for Voight-Kampff.

.DESCRIPTION
    Defines agent behaviour settings such as output paths and scan options.
    
    Compliance rules and thresholds are NOT defined here - they live in the
    backend application where they can be updated without re-running scans.

    The agent is a pure data collector. It captures and enriches raw data
    from the endpoint but does not make compliance judgements.

.NOTES
    Author:  b3nn3tt@hbcomputersecurity.co.uk
    Version: 2.0
#>


# ============================================================
#  AGENT METADATA
# ============================================================
# VERSIONING POLICY
#
#   Agent version  - semantic versioning (MAJOR.MINOR.PATCH).
#                    MAJOR: incompatible collector behaviour.
#                    MINOR: new capability, backwards compatible.
#                    PATCH: bug fix with no contract change.
#
#   Schema version - describes the emitted evidence contract.
#                    MINOR increments are ADDITIVE: existing sections and
#                    field paths are preserved, new sections may be added.
#                    MAJOR increments are BREAKING: existing sections or
#                    field paths change meaning, shape or position.
#
#   The validated collection version will be FROZEN before controlled
#   evidence generation. Once frozen, any change to the evidence contract
#   requires a schema increment and re-validation.
#
#   Schema 1.1 adds the top-level "acquisition" section. It is additive for
#   consumers that read only the original four sections, but it is REQUIRED
#   by the schema 1.1 study contract: a study-relevant collection unit with
#   no conforming acquisition entry makes the artefact schema-invalid.
# ============================================================

$script:VKAgentVersion  = "2.1.0"
$script:VKSchemaVersion = "1.1"


# ============================================================
#  OUTPUT CONFIGURATION
# ============================================================
# The output folder sits at the project root, separate from
# all scripts. It is created automatically if it does not exist.
#
# Output filename format: HOSTNAME_YYYYMMDD_HHMMSS.json
# This ensures uniqueness across hosts and repeat scans.
# ============================================================

$script:VKOutputFolder = "outputs"    # Resolved to project root by the runner
$script:VKErrorLogFile = "error.log"

# JSON serialisation depth.
#
# Raised from 5 to 10 for schema 1.1. Depth 5 preserved the schema 1.0
# payload with zero headroom; the acquisition section and the approved
# extensions need margin. Windows PowerShell 5.1 truncates SILENTLY,
# substituting a .NET type name for the lost content, so this value must be
# re-verified by the depth tests whenever nesting changes.
$script:VKJsonDepth    = 10


# ============================================================
#  SESSION / RECENT-PROFILE OBSERVATION WINDOW
# ============================================================
# Recent-activity window for Host.Sessions, in hours.
#
# This qualifies Win32_UserProfile.LastUseTime ONLY. Current WTS
# sessions are point-in-time observations governed by their own
# acquisition timestamps and are not windowed.
#
# The emitted observation_window block is authoritative for any given
# artefact: consumers must read the window from the evidence rather
# than assuming this value.
# ============================================================

$script:VKSessionWindowHours = 24


# ============================================================
#  DATA ENRICHMENT LOOKUPS
# ============================================================
# These are NOT compliance rules. They translate Windows-native
# values (enum codes, bitmasks, IDs) into human-readable strings
# so the backend doesn't need to understand Windows internals.
# ============================================================

# --- Platform Role (Win32_ComputerSystem.PCSystemType) ---
$script:VKPlatformRoles = @{
    0 = "Unspecified"
    1 = "Desktop"
    2 = "Mobile"
    3 = "Workstation"
    4 = "Enterprise Server"
    5 = "SOHO Server"
    6 = "Appliance PC"
    7 = "Performance Server"
    8 = "Slate"
}

# --- SMBIOS Memory Types (Win32_PhysicalMemory.SMBIOSMemoryType) ---
# Source: SMBIOS Reference Specification DSP0134 3.2.0
$script:VKMemoryTypes = @{
    0  = "Unknown";      1  = "Other";        2  = "DRAM"
    3  = "Synchronous DRAM"; 4 = "Cache DRAM"; 5 = "EDO"
    6  = "EDRAM";        7  = "VRAM";         8  = "SRAM"
    9  = "RAM";          10 = "ROM";          11 = "Flash"
    12 = "EEPROM";       13 = "FEPROM";       14 = "EPROM"
    15 = "CDRAM";        16 = "3DRAM";        17 = "SDRAM"
    18 = "SGRAM";        19 = "RDRAM";        20 = "DDR"
    21 = "DDR2";         22 = "DDR2 FB-DIMM"; 24 = "DDR3"
    25 = "FBD2";         26 = "DDR4";         27 = "LPDDR"
    28 = "LPDDR2";       29 = "LPDDR3";       30 = "LPDDR4"
    31 = "DDR5";         32 = "LPDDR5";       33 = "Reserved"
    34 = "LPDDR5X";      35 = "Logical non-volatile device"
}

# --- TPM Manufacturer IDs ---
$script:VKTpmManufacturers = @{
    1095582720 = "AMD";           1095652352 = "Ant Group"
    1096043852 = "Atmel";         129730080  = "Broadcom (Legacy)"
    1112687437 = "Broadcom";      1129530191 = "Cisco"
    1179408723 = "Flyslice Technologies"; 1196379975 = "Google"
    1212765001 = "Huawei";        1213220096 = "HPE"
    1213221120 = "HPI";           1229081856 = "IBM"
    1229346816 = "Infineon (Legacy)"; 1398033472 = "Infineon"
    1229870147 = "Intel";         1279610368 = "Lenovo"
    1297303124 = "Microsoft";     1314080512 = "NSING"
    1314082080 = "National Semiconductor"; 1729382752 = "Nuvoton (Legacy)"
    1314145024 = "Nuvoton Technology"; 1314150912 = "Nationz"
    30360832   = "Qualcomm (Legacy)"; 1363365709 = "Qualcomm"
    1380926275 = "Fuzhou Rockchip"; 1397047628 = "Wisekey"
    1397048133 = "SecEdge";       1397576515 = "SMSC"
    1397576526 = "Samsung";       1397641984 = "Sinosun"
    855638016  = "STMicroelectronics (Legacy)"; 1398033696 = "STMicroelectronics"
    1415073280 = "Texas Instruments"; 1464156928 = "Winbond"
}

# --- BitLocker Encryption Methods ---
$script:VKEncryptionMethods = @{
    "XtsAes128" = "XTS-AES 128-bit"
    "XtsAes256" = "XTS-AES 256-bit"
    "Aes128"    = "AES 128-bit"
    "Aes256"    = "AES 256-bit"
    "None"      = "None or Not Encrypted"
}

# --- BitLocker Key Protector Types ---
$script:VKKeyProtectorTypes = @{
    "TPM"              = "TPM"
    "TPMAndPIN"        = "TPM with PIN"
    "TpmPin"           = "TPM with PIN"
    "TPMAndStartupKey" = "TPM with USB Key"
    "RecoveryPassword" = "Recovery Password"
    "NumericalPassword"= "Numerical Password"
}

# --- SMB Share State Codes ---
$script:VKShareStates = @{
    0 = "Offline"
    1 = "Online"
    2 = "Continuously Available"
}

# --- DEP Policy Codes ---
$script:VKDepPolicies = @{
    0 = "Always Off"
    1 = "Opt-In (Essential Programs Only)"
    2 = "Opt-Out (All Processes)"
    3 = "Always On"
}

# --- VBS Status Codes ---
$script:VKVbsStates = @{
    0 = "Not enabled"
    1 = "Enabled but not running"
    2 = "Enabled and running"
}

# --- Drive Type Codes (Win32_LogicalDisk.DriveType) ---
$script:VKDriveTypes = @{
    2 = "Removable Disk"
    3 = "Local Disk"
    4 = "Network Drive"
    5 = "Compact Disc"
    6 = "RAM Disk"
}

# --- Security Services (Device Guard) ---
$script:VKSecurityServices = @(
    @{ id = 1; name = "Credential Guard" }
    @{ id = 2; name = "HVCI (Hypervisor Code Integrity)" }
    @{ id = 3; name = "System Guard Secure Launch" }
    @{ id = 4; name = "SMM Firmware Measurement" }
    @{ id = 5; name = "Kernel-mode Hardware-enforced Stack Protection" }
    @{ id = 6; name = "Kernel-mode Hardware-enforced Stack Protection (Audit Mode)" }
    @{ id = 7; name = "Hypervisor-Enforced Paging Translation" }
)

# --- Security Properties (Device Guard) ---
$script:VKSecurityProperties = @(
    @{ id = 1; name = "Hypervisor support" }
    @{ id = 2; name = "Secure Boot" }
    @{ id = 3; name = "DMA protection" }
    @{ id = 4; name = "Secure Memory Overwrite" }
    @{ id = 5; name = "NX protections" }
    @{ id = 6; name = "SMM mitigations" }
    @{ id = 7; name = "MBEC/GMET" }
    @{ id = 8; name = "APIC virtualization" }
)