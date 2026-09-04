# Voight-Kampff Agent Tests

Pester suite covering the runner contract, the schema 1.1 output contract, the fail-closed acquisition helpers, every migrated module across **all current tranches through 2C**, and modular/standalone parity.

**Authoritative mocked execution result — agent 2.2.0:** Windows PowerShell **Desktop 5.1.26100.9168**, Pester **6.1.0**, StrictMode **Off** — **659 total, 659 passed, 0 failed, 0 skipped, 0 inconclusive, 0 not run**, suite result **`Passed`**, duration **`00:00:15.6003025`**. Coverage spans **18 study-relevant modules and 47 acquisition units** at schema 1.1 and JSON depth 10.

**Agent 2.1.1 baseline (historical):** 646/646 passed.

**Agent 2.1.0 baseline (historical):** 617/617 passed.

**On the earlier 21-failure result.** An earlier validation attempt of the 2.1.1 suite reported 21 failures. That was **validation-harness contamination caused by caller-imposed `StrictMode` — not 21 production defects.** The clean rerun against the committed source, with caller-imposed StrictMode `Off`, **passed all 646 tests**. The 21-failure figure is not a defect count and must not be cited as one.

**Agent 2.2.0 adds 13 tests:** 10 focused Windows Update cases, one output-contract case and two standalone-parity/UTF-8 cases.

**Agent 2.1.1 added 29 tests** covering Host.Software, Security.WinRM, Security.DefenderAdvanced and version-stamped standalone generation.

A green suite establishes that the implemented contract behaves as specified. It does **not** make the collector pilot-ready; see the remaining blockers below.

**This suite is mocked throughout, so it is not itself live-provider validation.** A separate disposable live run reproduced the rehearsal failure and confirmed the new machine-readable failure semantics. Successful-query paths remain covered by mocks.

**Pester is development assurance only.** It is never included in, and never required by, the generated collector. The standalone script depends only on Windows PowerShell 5.1 and built-in Windows providers — the parity suite asserts this explicitly.

## Design principles

1. **Nothing here runs the collector.** The runner and build source are inspected by parsing them with the PowerShell AST parser, which reads a file without executing it. Module functions are exercised only with **mocked providers**. `VK.Config.ps1`, `VK.Utilities.ps1` and the module files under test are dot-sourced because they declare variables and functions and have no side effects.
2. **Nothing here depends on live host configuration.** All data comes from the synthetic fixtures. Every registry read, CIM query, Defender call and native type load in the module tests is mocked, so results are identical on any machine.
3. **Generating the standalone script is not collecting.** `VK.StandaloneParity.Tests.ps1` invokes the build with `-OutputPath $TestDrive -Quiet -PassThru`. The build concatenates source files and writes an output file; it never invokes the result. The generated script is only ever parsed and pattern-matched.
4. **Depth assertions are behavioural.** The suite serialises at whatever depth `VK.Config.ps1` declares, on whatever PowerShell edition is running, and asserts on the real result — catching both a reduced depth setting and a Windows PowerShell 5.1 vs 7.x accounting difference.

## Layout

```text
tests/
|-- README.md
|-- VK.RunnerContract.Tests.ps1        Static AST analysis of runner and build template
|-- VK.OutputContract.Tests.ps1        Schema 1.1 envelope, acquisition, versions, depth
|-- VK.Acquisition.Tests.ps1           Fail-closed helper behaviour
|-- VK.Modules.WindowsUpdates.Tests.ps1 Focused pending-update semantics
|-- VK.Modules.Acquisition.Tests.ps1   The three Tranche 2A corrections (mocked providers)
|-- VK.Modules.Tranche2B1.Tests.ps1    The seven Tranche 2B.1 modules (mocked providers)
|-- VK.Modules.Tranche2B2.Tests.ps1    The seven Tranche 2B.2 modules (mocked providers)
|-- VK.Modules.Sessions.Tests.ps1      Host.Sessions, Tranche 2C (mocked providers)
|-- VK.StandaloneParity.Tests.ps1      Modular/standalone parity, generated-agent integrity
|-- helpers/
|   `-- VK.SchemaValidation.ps1        TEST-ONLY schema conformance checks
`-- fixtures/
    |-- Get-VKRepresentativeStudyEvidence.ps1   Schema 1.1, five sections, all four outcomes
    |-- Get-VKLegacySchema10Evidence.ps1        Schema 1.0 legacy, no acquisition section
    `-- Get-VKInvalidSchema11Evidence.ps1       Eight deliberately invalid artefacts
```

`helpers/VK.SchemaValidation.ps1` is test-only and is **not** referenced by the build template. The parity suite asserts that it never appears in the generated script.

## Prerequisite

Pester **5.5 or later**. The suite is developed against Pester 6.1.0 and must remain executable under Windows PowerShell 5.1, which is the controlled-collection runtime.

```powershell
Get-Module -ListAvailable Pester | Select-Object Name, Version
```

If a suitable version is not present:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

> The Windows built-in Pester 3.4.0 **cannot** run this suite — it does not support `-ForEach`, `-Skip:` on `Describe`, or Pester 5 scoping.

## Commands to run

Full suite from the agent root:

```powershell
Set-Location "C:\path\to\capstone-collectors\collectors\voight-kampff"
Invoke-Pester -Path .\tests -Output Detailed
```

Under Windows PowerShell 5.1 — **the controlled-collection runtime, and the authoritative run**:

```powershell
powershell.exe -NoProfile -Command "Set-Location 'C:\path\to\capstone-collectors\collectors\voight-kampff'; Invoke-Pester -Path .\tests -Output Detailed"
```

Individual files:

```powershell
Invoke-Pester -Path .\tests\VK.RunnerContract.Tests.ps1      -Output Detailed
Invoke-Pester -Path .\tests\VK.OutputContract.Tests.ps1      -Output Detailed
Invoke-Pester -Path .\tests\VK.Acquisition.Tests.ps1         -Output Detailed
Invoke-Pester -Path .\tests\VK.Modules.Acquisition.Tests.ps1 -Output Detailed
Invoke-Pester -Path .\tests\VK.StandaloneParity.Tests.ps1    -Output Detailed
```

Record a run for the dissertation:

```powershell
Invoke-Pester -Path .\tests -Output Detailed -PassThru |
    Export-Clixml -Path .\tests\last-run.xml
```

## What is covered

### VK.RunnerContract.Tests.ps1

Static AST analysis. `Host.NetworkConfig` invoked exactly once by the runner and listed once by the build source; no host module invoked twice; runner and build agree on module order; the **five**-section envelope is declared in contract order; `schema_version` and JSON depth come from central config; the acquisition store is initialised before modules run and swept before serialisation.

### VK.OutputContract.Tests.ps1

| Area | Asserts |
| --- | --- |
| Central config | agent 2.2.0, schema 1.1, depth 10 |
| Envelope | **exactly five** sections, in order — an exact match, deliberately not a subset or containment check |
| Metadata | all ten required fields, ISO 8601 UTC timestamps, no duplicate in `modules_executed` |
| Acquisition | **exact schema-1.1 coverage of all 47 units, asserted in both directions**, including `host.windows_updates.pending_updates`; permitted outcomes; exact governed paths; structured failure data |
| Schema validity | all eight invalid fixtures identified as invalid; missing metadata reported, **never repaired into an invented outcome**; representative fixture accepted (positive control) |
| Legacy 1.0 | recognised as legacy not invalid; four sections; **cannot support empty-result absence** on any path; contrast case showing schema 1.1 success makes absence assessable |
| Depth 10 | deepest payload paths and acquisition `data_paths`/`error` survive; **negative controls** confirm shallow serialisation genuinely truncates |

### VK.Acquisition.Tests.ps1

Fail-closed default (registered-but-untouched ⇒ `failed`/`incomplete_collection`); registration alone never yields success; bulk invocation-only units all fail closed; `pending` never emitted even without the sweep; completing an unregistered unit ⇒ `failed`/`unregistered_unit`; explicit completion ⇒ `success`; a successful **zero-result** collection is still `success`; conservative classification of access denial ⇒ `restricted`, absent capability ⇒ `unavailable`, unexpected error ⇒ `failed`; classification precedence (type, then `FullyQualifiedErrorId`, then `ErrorCategory`); classification never returns `success`; emitted entry field order; message bounding, stack-trace stripping and user-path redaction.

### VK.Modules.Acquisition.Tests.ps1

All providers mocked.

- **LegacyProtocols** — a denied read never sets `llmnr_enabled`/`mdns_enabled` to `$true` and produces no `value_source`; an absent key with a successful read yields the documented default marked `default_inferred`; an explicit value is marked `explicit`; a NetBIOS failure emits no empty adapter list and does not hide behind the successful LLMNR unit. A failing **`Test-Path`** — distinct from a failing read — produces no inferred value on any field, no `default_inferred` provenance anywhere in the section, and a non-success outcome for all four affected units.
- **HostSecurity** — a Device Guard failure emits **no** populated `security_services`/`security_properties` and no `vbs_status`; on success, `$false` appears only where the returned lists justify it; a successful DEP query does not conceal the Device Guard failure. A **null DEP response** — whether the instance or only the property is missing — leaves `dep_policy` null with `provider_value_missing`, and never becomes `"Always Off"`, while a genuine returned `0` still records `"Always Off"` with `success`. A **source-contract** suite guards the native `BootDmaCheck` against reintroducing "non-zero NTSTATUS → return 0".
- **Antivirus** — a denied query never emits `"Not Detected"` and emits no product evidence; an unavailable namespace is `unavailable` not `failed`; a successful zero-product result is `success` with `products_detected = 0` and is **directly contrasted** against the failure case in one test; Defender detail is `provider_not_applicable` or `precondition_not_met` rather than silently absent; a Defender-detail failure retains the product-level evidence that did succeed. A **null `Get-MpComputerStatus` response** is never recorded as a successful empty observation — it yields `provider_value_missing` with all six Defender fields null.

**On the native DMA source-contract tests.** The NTSTATUS is produced inside compiled C# invoked as a static method, so there is no PowerShell command for Pester to intercept and the return path cannot be mocked. Those tests therefore assert the *source contract* of the embedded C#, which is what a regression would actually consist of: they require a `result != 0` throw, forbid any `return 0;` and any `if (result == 0)` gate, confirm the observed byte is still returned on success, confirm the unmanaged buffer is still freed, and confirm no type outside mscorlib is used (which would need an extra `Add-Type` assembly reference on a target machine).

### VK.Modules.WindowsUpdates.Tests.ps1

All Windows Update providers are mocked. Ten focused tests distinguish a successful empty result from search and session-creation failures. Failure withholds both governed payload values and records a machine-readable `failed` / `provider_query_failed` outcome.
### VK.StandaloneParity.Tests.ps1

Static parity of all ten metadata fields and all five envelope sections. The generated standalone parses successfully; declares schema 1.1, agent 2.2.0 and depth 10; contains all 47 acquisition units; preserves strict UTF-8 source text; remains self-contained; and is never executed by the test suite.

**No test is silently skipped.** Generation runs in a `BeforeAll` during the run phase, never behind a `-Skip:` expression evaluated at discovery. If the build fails, that is surfaced as a **failing test** carrying the captured `GenerationError`, and the dependent tests fail on their own assertions rather than disappearing from the report. The authoritative run records **0 skipped and 0 not run**.

### VK.Modules.Tranche2B1.Tests.ps1

The seven modules migrated in Tranche 2B.1, all providers mocked. Per module: a representative success; a legitimate zero result; failed / restricted / unavailable outcomes; null provider responses and missing required properties; and preservation of a sibling unit's successful evidence when one unit fails.

Highlights: DefenderAdvanced's precondition handling and a `Should -Invoke Get-CimInstance -Times 0` assertion proving it no longer re-queries SecurityCenter2; the mismatched-ASR case proving the missing action never defaults to `"Disabled"` while protection preferences survive; SMB's `explicit` vs `default_inferred` vs `feature_observed` provenance and the no-admin `insufficient_privilege` path; RDP's separated registry units and guarded properties; WinRM's `"Unknown"` removal and part-way listener failure; UAC's absent-value guards; FDE's non-elevated registration and malformed-volume withholding.

**Agent 2.1.1 additions in this file (executed and passing).** `Security.WinRM` gains a present-but-**value-empty** WSMAN key case — documented server and client defaults applied with every field marked `default_inferred`, both registry units `success`, `trusted_hosts` `$null` with a `success` outcome and no manufactured host list — directly contrasted against a **thrown** read, which still yields non-success on all three units and licenses no inferred default, and against **explicit** values, including an explicit `AllowKerberos = 0` that contradicts the documented default and must not be overwritten by it. `Security.DefenderAdvanced` gains the live **ASR no-rule sentinel** (a matched pair of single-`$null` arrays) resolving to `success` with `@()` / `0` / `0`, asserted off-pipeline with `ReferenceEquals`, plus four neighbouring shapes that must all still fail closed — null id with non-null action, non-null id with null action, a null inside an otherwise populated result, and an unequal pair where one side is the sentinel — and a single genuinely configured rule that must not be mistaken for the sentinel.

A final **parameterised** Describe drives all seven modules into a total provider denial at once and asserts the shared contract: every unit registered, none `success`, all within the permitted vocabulary, all with populated `data_paths` and structured error data — plus two recursive payload walks proving no fabricated value (`"Unknown"`, `"Not Found"`, `"Disabled"`, `"Not Fully Encrypted"`, `"Protection Off"`) and no non-null leaf survives anywhere in the section.

### VK.Modules.Tranche2B2.Tests.ps1

The seven host/pathway modules migrated in Tranche 2B.2, all providers mocked.

Highlights: Identification's guarded `BuildNumber` (never cast to `0`) and proof that a BIOS/manufacturer failure cannot change any study unit's outcome; NetworkConfig's summary counts staying **`$null` rather than `0`** after a failed TCP collection while the independent UDP unit keeps its numeric count; Services and Processes never emitting a zero-count console line after failure (asserted with `Should -Invoke … -ParameterFilter`); Software's per-entry failure making a hive incomplete, the combined list withheld when any applicable hive fails, and a genuinely empty hive staying `@()` rather than collapsing to `$null` through `Sort-Object`; Users' removed in-band sentinel, `is_admin` null-not-false after a member-query failure, UTC timestamp formatting and local-only scope markers; and the token unit's non-zero-exit, malformed-CSV and missing-column paths plus the `collector_token_only` / `collector_ran_as_admin` qualifiers.

**Agent 2.1.1 additions in this file (executed and passing).** `Host.Software` gains a **value-empty uninstall subkey** case: the provider completes without error and emits no object, the subkey is skipped like any entry with no `DisplayName`, other named applications from the same hive survive, both applicable hive units resolve to `success` and the combined machine-scope inventory is emitted. It is directly contrasted against a hive holding both a value-empty subkey and a **thrown** read failure, which must still withhold the combined payload and record a non-success outcome.

A final parameterised Describe denies every provider at once and asserts the shared contract across all twelve units — including that both instrumented summary counts remain null. `host.identification.hostname` is legitimately excluded from the "no successes" assertion because it reads an environment variable rather than a mocked provider.

The output-contract suite additionally asserts **exact 47-unit coverage in both directions** and exact governed `data_paths`, including `host.windows_updates.pending_updates`. Standalone parity verifies all current unit identifiers and strict UTF-8 generation.

### VK.Modules.Sessions.Tests.ps1

`Host.Sessions` (Tranche 2C). Providers are mocked at the **PowerShell wrapper boundary** (`Initialize-VKWtsInterop`, `Get-VKWtsSessionRecords`, `Get-VKWtsSessionString`, `Get-VKWtsSessionProtocolType`, `Get-CimInstance`), so no native call is made and no live session table or profile is read. Catch-all mocks prevent any unmatched call escaping to a live provider.

Covers: active console, active RDP, disconnected RDP, multiple simultaneous sessions, listener classified from connect state with **no** protocol or principal query, successful zero enumeration (`ReferenceEquals` + count), enumeration denial classified from the **native error code**, interop unavailability, successful principal resolution, successful empty principal strings, and the defining independence case — one required principal query failing while `current_sessions` survives intact.

Profile coverage: inside/outside the 24-hour window, loaded and special handling, zero/null provider response as `unavailable`/`provider_value_missing` rather than successful empty, UTC formatting, excluded fields, and observation-window emission **on failure**.

A shared-contract Describe fails every provider at once and asserts no unit succeeds, no fabricated value survives, and the window is still emitted. A static **WTS source-contract** Describe asserts the interop imports only `wtsapi32.dll`, releases every buffer through `WTSFreeMemory` inside a `finally`, raises a structured exception carrying the native error code, targets the local server only, guards type creation, and references no Event Log or external session tool.

`VK.RunnerContract.Tests.ps1` additionally carries a **static case-collision guard**: it walks every `Invoke-VK*` function and fails on any assignment whose target differs from a declared parameter only by case — the `$isAdmin`/`[bool]$IsAdmin` silent-coercion defect. A companion assertion guards the guard itself against silently inspecting nothing.

## What is NOT covered yet

Existing-module migration completed at 2B.2; the session extension landed at 2C. Deferred:

- registry-restricted Windows feature-state collection (C2/C3) — **a pilot blocker**;
- Event 4624 recent-logon evidence — **deliberately excluded**, not deferred (audit-policy history is not observable, so empty results could never mean "no recent logon");
- validation of both extensions and the collection freeze;
- the active-firewall-profile extension (enhancement, not a prerequisite);
- per-user software hives (explicitly excluded);
- analytical ingestion, pseudonymisation and scoring;
- payload-level conformance of a generated collection.

No output from the current partial implementation may be used as controlled research evidence. See the banner in [docs/dissertation-agent-evidence-contract.md](../docs/dissertation-agent-evidence-contract.md).
