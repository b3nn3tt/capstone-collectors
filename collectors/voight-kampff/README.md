# Voight-Kampff Agent

A PowerShell-based Windows evidence collector that produces versioned JSON output with explicit acquisition provenance. The agent runs locally on a host, executes modular checks, and records structured endpoint observations that a separate artefact can ingest.

**Current state:** integration-pilot candidate.

**Versions:** agent 2.1.0; schema 1.1; JSON depth 10.

## Design principles

- Native Windows execution with Windows PowerShell 5.1.
- Minimal environmental assumptions — depends only on built-in Windows providers.
- Graceful degradation when not elevated.
- Evidence collection first, analytical judgement second.

## Data model

The agent produces a structured JSON envelope with **five** top-level sections:

```json
{
  "scan_metadata": {},
  "acquisition": {},
  "host": {},
  "security": {},
  "vulnerability": {}
}
```

### scan_metadata

Ten required fields: `hostname`, `agent_version`, `schema_version`, `scan_start`, `scan_end`, `scan_duration_seconds`, `ran_as_admin`, `running_user`, `running_user_sid`, and `modules_executed`.

### acquisition

An ordered collection keyed by stable dotted unit identifiers, recording per-unit observation start and end, outcome, agent version, schema version, governed `data_paths`, and structured error detail.

### host, security, vulnerability

Module payloads organised by category. The sections contain raw observations; no analytical interpretation is applied by the collector.

## Acquisition outcomes

Every collection unit emits one of four outcomes:

| Outcome | Meaning |
| --- | --- |
| `success` | The query completed and the data was obtained, even if the result is empty. |
| `failed` | The query ran but encountered an unexpected error. |
| `restricted` | The query was denied due to permissions or policy. |
| `unavailable` | The required provider, namespace, command or capability was not present. |

Successful-empty results are distinguishable from unsuccessful acquisition. A `success` outcome with zero items means "none observed"; a non-success outcome means "could not observe".

Governed payloads are withheld on unsuccessful acquisition rather than silently skipped or populated with invented values.

## File map

```text
collectors/voight-kampff/
├── build/
│   └── Build-Standalone.ps1
├── core/
│   ├── Invoke-VKScan.ps1
│   ├── VK.Config.ps1
│   └── VK.Utilities.ps1
├── docs/
│   └── dissertation-agent-evidence-contract.md
├── modules/
│   ├── host/
│   │   ├── Host.Boot.ps1
│   │   ├── Host.Drivers.ps1
│   │   ├── Host.Hardware.ps1
│   │   ├── Host.Identification.ps1
│   │   ├── Host.Network.ps1
│   │   ├── Host.NetworkConfig.ps1
│   │   ├── Host.Processes.ps1
│   │   ├── Host.Services.ps1
│   │   ├── Host.Sessions.ps1
│   │   ├── Host.Software.ps1
│   │   ├── Host.Storage.ps1
│   │   ├── Host.USBHistory.ps1
│   │   ├── Host.Users.ps1
│   │   └── Host.WindowsUpdates.ps1
│   ├── security/
│   │   └── ... (15 modules)
│   └── vulnerability/
│       └── ... (16 modules)
├── tests/
│   └── ... (test suites and fixtures)
├── CHANGELOG.md
└── README.md
```

Key entry points:

- [Invoke-VKScan.ps1](core/Invoke-VKScan.ps1) — the modular runner
- [VK.Utilities.ps1](core/VK.Utilities.ps1) — acquisition helpers
- [VK.Config.ps1](core/VK.Config.ps1) — version and depth configuration
- [Build-Standalone.ps1](build/Build-Standalone.ps1) — standalone script generator

## Execution modes

### Modular mode

Used during development and testing.

```powershell
Set-Location ".\collectors\voight-kampff\core"
.\Invoke-VKScan.ps1
```

### Standalone mode

Used for packaging and single-file execution.

```powershell
Set-Location ".\collectors\voight-kampff\dist"
.\VoightKampff_Standalone_v2.1.0.ps1
```

### Building the standalone

```powershell
Set-Location ".\collectors\voight-kampff\build"
.\Build-Standalone.ps1
```

The build concatenates source files and produces a single-file script that depends only on Windows PowerShell 5.1 and built-in Windows providers.

## Elevation model

The agent is usable as either a standard user collector or an elevated collector.

- Some modules work fully without elevation.
- Some modules return partial data without elevation.
- Some modules require elevation and produce `restricted` when not elevated.

The `ran_as_admin`, `running_user`, `running_user_sid` and per-unit acquisition outcomes allow downstream consumers to interpret the results correctly.

## Responsibility boundary

**Voight-Kampff** collects raw endpoint evidence and acquisition provenance.

**The separate dissertation artefact** validates, pseudonymises, normalises, reconciles and applies analytical judgement.

The collector does not evaluate C1–C7, calculate scores, determine compliance or make remediation decisions. Those operations belong to the dissertation artefact, not to this collection tool.

## Feature-state collection

Windows feature-state collection remains conditional on the frozen contextual registry supplying exact identifiers and authoritative mappings. General feature inventory is out of scope for the collector.

## Current verification

| Item | Value |
| --- | --- |
| Runtime | Windows PowerShell 5.1 |
| Test framework | Pester 6.1.0 |
| Test result | 617 passed, 0 failed, 0 skipped, 0 not run |
| Coverage | 18 modules, 46 acquisition units |

A green suite establishes that the implemented contract behaves as specified. It does not, by itself, make the collector ready for final controlled evidence collection — the tests verify contract behaviour against mocked providers, not live provider behaviour on target hosts.

## Running the tests

Prerequisite: Pester 5.5 or later (developed against 6.1.0).

```powershell
Get-Module -ListAvailable Pester | Select-Object Name, Version
```

If a suitable version is not present:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

Full suite from the agent directory:

```powershell
Set-Location ".\collectors\voight-kampff"
Invoke-Pester -Path .\tests -Output Detailed
```

## What the agent does not do

- Make the final compliance decision — authoritative logic lives downstream.
- Parse or validate its own output.
- Contact any network endpoint.
- Depend on third-party PowerShell modules.

## Author

Christopher Hunter-Bennett — b3nn3tt@hbcomputersecurity.co.uk
