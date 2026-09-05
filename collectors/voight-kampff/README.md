# Voight-Kampff Agent

A PowerShell-based Windows evidence collector that produces versioned JSON output with explicit acquisition provenance. The agent runs locally on a host, executes modular checks, and records structured endpoint observations that a separate artefact can ingest.

**Current state, as recorded on 2026-09-05.** Agent 2.3.0 is mock-tested and development live-validated. It is committed on branch `feat/voight-2.3-evidence-expansion`; at the time of this record it is **pending merge**, and it is **untagged and unfrozen**. It is **not** formally pilot-ready or campaign-ready. Merge, tag and freeze states change independently of this file - treat the repository, not this paragraph, as authoritative for them.

**Versions:** agent 2.3.0; schema 1.2; JSON depth 10.

Agent 2.3.0 is a MINOR, backwards-compatible evidence expansion. It adds the complete Windows optional-feature inventory as raw endpoint evidence, under one new governed acquisition unit. **Schema 1.2 is ADDITIVE over 1.1**: the five-section envelope, the acquisition entry shape and the four-value outcome vocabulary are unchanged, no existing field path moves, vanishes or changes meaning, and a 1.1 consumer that ignores the new section reads a 1.2 artefact exactly as it read a 1.1 one. JSON depth 10 is retained, confirmed by the depth tests against the new structure rather than assumed. See the [changelog](CHANGELOG.md).

**Mock-tested and development live-validated.** The complete 2.3.0 suite passed **753/753** tests under Windows PowerShell Desktop 5.1.26100.9168 and Pester 6.1.0, with 0 failed, 0 skipped, 0 inconclusive and 0 not run. The focused optional-feature suite contributed **48/48**. A separate development live validation on 2026-09-05 returned 137 valid optional-feature records, 48/48 successful acquisition units, no duplicate feature names, no malformed records and correct ordinal ordering.

**Development state.** Agent 2.3.0 was developed on branch `feat/voight-2.3-evidence-expansion`, based on `main` revision `336194bc087e0b40d14f75be8acddc9e081f0701`. Its source provenance is implementation commit `2f93b4b9bd19329952c22de47ee587483882f1f3`. Mocked validation and development live validation have both passed. **At the time of this record the branch is pending merge; the agent is untagged, unfrozen, and neither pilot-ready nor campaign-ready.**

**Agent 2.2.0 (historical).** A MINOR acquisition uplift adding one governed Windows Update acquisition unit. Suite: 659/659. A disposable live run reproduced HRESULT `0x8024402C` and emitted one `failed` / `provider_query_failed` unit with both pending-update values `null`; the remaining 46 units succeeded.

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
│   │   ├── Host.WindowsOptionalFeatures.ps1
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
.\VoightKampff_Standalone_v2.3.0.ps1
```

### Building the standalone

```powershell
Set-Location ".\collectors\voight-kampff\build"
.\Build-Standalone.ps1
```

The build reads every source module as strict UTF-8, concatenates the verified text and produces a single-file script that depends only on Windows PowerShell 5.1 and built-in Windows providers.

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

**Superseded at agent 2.3.0.** The collector now emits the **complete** Windows optional-feature inventory as raw evidence, under `host.windows_optional_features`, governed by the single acquisition unit `host.windows_optional_features.inventory`.

The earlier position — that feature collection had to wait on a frozen contextual registry supplying exact identifiers and authoritative mappings — coupled a *collection* question to an *analysis* question. Collecting everything removes that coupling: the identifiers the research needs are already in the artefact, whatever the registry eventually says.

Each record carries exactly two fields:

| Field | Meaning |
| --- | --- |
| `feature_name` | The provider's `FeatureName`, preserved exactly as supplied. |
| `state` | The provider's own state string, preserved verbatim. |

`state` is **never reduced to a Boolean** and never remapped. `Enabled`, `Disabled`, `DisabledWithPayloadRemoved`, `EnablePending` and `DisablePending` are five distinct observations; collapsing them would destroy the payload distinction and would misrepresent the two pending states as settled ones.

The module emits no `DisplayName`, `Description`, `RestartRequired`, `CustomProperties`, category, security label or any other derived interpretation.

**Research-specific extraction belongs downstream.** There is deliberately **no project-specific feature allowlist in the collector**. Selecting dissertation-relevant identifiers, assessing CVE applicability, classifying risk and making compliance judgements are all operations of the separate dissertation artefact. Voight-Kampff records what the host reported and nothing more.

Records are ordered deterministically by `feature_name` using an **ordinal** comparison, so the same inventory serialises identically regardless of the collecting host's locale.

Rejected as malformed provider output, with the whole inventory withheld rather than partially emitted: a case-insensitive duplicate feature name, a record with no feature name, and a record with no state. A **zero-record response is not a genuine Windows state** — every serviceable Windows installation reports optional features — so it is recorded as a non-success outcome with category `provider_value_missing`, never as a successful empty inventory.

Without elevation the provider is **not invoked at all** — no servicing session is opened — and the unit records `restricted` / `insufficient_privilege` with the payload retained as `null`.

## Current verification

| Item | Value |
| --- | --- |
| Runtime | Windows PowerShell **Desktop 5.1.26100.9168** |
| Test framework | Pester **6.1.0** |
| Caller-imposed StrictMode | **Off** |
| Total | **753** |
| Passed | **753** |
| Failed / Skipped / Inconclusive / Not run | **0 / 0 / 0 / 0** |
| Suite result | **`Passed`** |
| Coverage | **20 instrumented (study-relevant) modules; 46 modules and 48 acquisition units** at agent 2.3.0 |
| Focused optional-feature suite | 48 passed, 0 failed |
| Development live validation at 2.3.0 | 2026-09-05 - 137 valid optional-feature records, 48/48 acquisition units `success`, no duplicates, no malformed records, correct ordinal ordering. **Development validation only: not formal-pilot output, not research evidence, not a freeze identity.** |
| Agent 2.2.0 baseline (historical) | 659 passed, 0 failed, 0 skipped, 0 inconclusive, 0 not run |
| Agent 2.1.1 baseline (historical) | 646 passed, 0 failed, 0 skipped, 0 inconclusive, 0 not run |
| Agent 2.1.0 baseline (historical) | 617 passed, 0 failed, 0 skipped, 0 not run |

A green suite establishes that the implemented contract behaves as specified. It does not, by itself, make the collector ready for final controlled evidence collection — the tests verify contract behaviour against mocked providers, not live provider behaviour on target hosts.

**On the earlier 21-failure result.** An earlier validation attempt reported 21 failures. That was **validation-harness contamination caused by caller-imposed `StrictMode`, not 21 production defects.** The clean rerun against the committed source, with caller-imposed StrictMode `Off`, passed all **646** tests. The 21-failure figure must not be cited as a defect count.

**Live provider behaviour at 2.3.0.** A development live validation was performed on 2026-09-05: 137 valid optional-feature records, 48/48 acquisition units `success`, no duplicate feature names, no malformed records and correct ordinal ordering. **This was development validation only.** The live run and the generated standalone are development artefacts - **not formal-pilot output, not research evidence, and not a freeze identity** - and no output from 2.3.0 may be cited as controlled campaign evidence.

**Live provider behaviour at 2.2.0 (historical).** A non-campaign 2.2.0 run on `CAPSTONE-WIN-01` completed from `2026-09-04T08:34:01.0192409Z` to `2026-09-04T08:34:27.2928748Z`. It reproduced HRESULT `0x8024402C`; `host.windows_updates.pending_updates` reported `failed` / `provider_query_failed`, while `pending_count` and `pending_updates` were both `null`. The remaining 46 units succeeded. Evidence SHA-256: `d4347b5fd992ce9286c402b9bcc54a69cb9c574e2860a9b31014107c9ea93d57`. The VM was subsequently reverted to `POST-REHEARSAL__PRE-VK-2.2.0-TEST`.

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
