# Changelog — Voight-Kampff Agent

All notable changes to the collector and its evidence contract.

**Versioning policy** (declared in [core/VK.Config.ps1](core/VK.Config.ps1)):

- **Agent version** follows semantic versioning. MAJOR for incompatible collector behaviour, MINOR for new backwards-compatible capability, PATCH for a bug fix with no contract change.
- **Schema version** describes the emitted evidence contract. MINOR increments are **additive**; MAJOR increments are **breaking**.
- The validated collection version will be **frozen** before controlled evidence generation.

---

## [2.1.1] — live-provider edge-case repair

**Schema version: 1.1 — unchanged. JSON depth: 10 — unchanged. 45 modules and 46 acquisition units — unchanged.**

A PATCH increment: three bug fixes with **no evidence-contract change**. No field path is added, removed or changed in meaning, no acquisition unit is added or removed, and no analytical or compliance judgement is introduced.

> **Authored, not executed.** The `617 passed / 0 failed / 0 skipped / 0 not run` result recorded below for 2.1.0 remains the **last executed** verification and is preserved as the 2.1.0 baseline. The 2.1.1 repair and its **29** new regression tests (static suite total **646**) are **authored but unexecuted**; no 2.1.1 test result is claimed.

### Context

An elevated standalone run completed structurally — all 45 modules executed, all 46 acquisition units emitted, 41 `success`, 5 `unavailable`, 0 `failed`, 0 `restricted`, schema validation passed. Read-only follow-up established that all five `unavailable` outcomes shared one shape: **a provider that answered successfully but represented a genuine zero result in a form the module read as malformed or absent**. In each case the fail-closed guard was correct in principle and mis-scoped in practice, so a legitimate observation was suppressed rather than a fabricated one prevented.

None of the three defects fabricated evidence. Each **withheld** evidence the host had in fact supplied, which is the milder failure direction but still understates what was observed.

### Fixed — three live edge cases

1. **`Host.Software` — a value-empty uninstall subkey failed the whole hive.** Both uninstall hives existed and were readable (native: 17 subkeys, 6 readable objects, 11 empty property results, 0 read errors; WOW6432: 20 / 9 / 11 / 0). The stock `AddressBook` subkey holds no registry values at all, so `Get-ItemProperty` completed **without error and emitted no object**. `Get-VKSoftwareHiveEntries` treated that `$null` as an unreadable entry and threw, which under the shared-path completeness rule withheld the entire combined `host.installed_software` inventory and recorded both hive units `unavailable`. A successfully read, value-empty key is now **skipped exactly like an entry with no `DisplayName`** — a documented filter, not a failure. `-ErrorAction Stop` is retained unchanged: a genuine provider or read failure still throws, still fails the hive closed, and still withholds the combined payload.

2. **`Security.WinRM` — a present, value-empty WSMAN key was read as absent.** The WSMAN Client key existed, was readable, held no property values, and had no configured `TrustedHosts` value. `Get-ItemProperty` emitted no object, and both `security.winrm.client_registry` and `security.winrm.trusted_hosts` recorded `unavailable` — contradicting the module's own documented contract, which states that absent values take the documented Windows defaults with provenance `default_inferred`, and that an absent `TrustedHosts` value is a genuine observation meaning no trusted hosts are configured. A key that exists and is read successfully but emits no property object is now treated as a **present, value-empty key**: server and client authentication and `AllowUnencrypted` take their documented defaults, every inferred field is marked `default_inferred`, the applicable unit completes `success`, and `trusted_hosts` is recorded as `$null` with `security.winrm.trusted_hosts = success`. No configured `TrustedHosts` value is ever manufactured. A **missing** key (terminating `Test-Path` returns false) and a **thrown** read or access error both remain non-success and fail closed. Server and client handling are repaired identically, so the two can no longer diverge. New module-scope helper `Get-VKWinRMRegistryValue` reads named values through the `PSObject` property table rather than direct property access, so a `$null` object and an absent value behave identically and the module does not depend on permissive missing-property behaviour under `Set-StrictMode`.

3. **`Security.DefenderAdvanced` — the live no-rule ASR sentinel was read as malformed.** `Get-MpPreference` returned both ASR properties present, raw identifier count 1, raw action count 1, non-null identifier count 0, non-null action count 0 — PowerShell's live representation of **no configured ASR rules**: a matched pair each holding one `$null` item. The null-identifier guard rejected it, so `security.defender_advanced.asr_rules` recorded `unavailable` where the module's documented contract requires a successful empty result. That **exact** matched pair — both arrays of length 1, both elements `$null` — is now normalised to two empty arrays before count validation and iteration, yielding `asr_rules = @()`, `asr_rules_count = 0`, `asr_rules_blocking = 0` and outcome `success`. The normalisation is deliberately narrow and does **not** filter arbitrary nulls: unequal counts, a null identifier paired with a non-null action, a non-null identifier paired with a null action, and a null element inside an otherwise populated result all still reach the existing guards and still withhold the ASR unit.

### Changed

- **Agent version 2.1.0 → 2.1.1.** Schema **1.1** and JSON depth **10** are unchanged, as is the 45-module / 46-acquisition-unit contract.
- The generated standalone filename expectation moves to `VoightKampff_Standalone_v2.1.1.ps1`. The builder already derives that name from `$script:VKAgentVersion`, so no builder logic changed; the parity suite now asserts the resulting filename explicitly.
- Version headers updated in the three repaired modules and in `build/Build-Standalone.ps1`. The representative and invalid schema-1.1 test fixtures move to `agent_version = "2.1.1"`, because the output-contract suite asserts fixture `agent_version` equals the configured agent version.

### Added — 29 regression tests

- **`Host.Software` (6)** — a value-empty `AddressBook`-style subkey is skipped; other named applications from the same hive remain present; both applicable hive units resolve to `success`; the combined machine-scope inventory is emitted rather than withheld; and, in direct contrast, a hive holding both a value-empty subkey and a **thrown** read failure still withholds the combined payload and still records a non-success acquisition.
- **`Security.WinRM` (12)** — a present, value-empty server key produces the documented server defaults with `default_inferred` and a successful unit; the same for the client key; the same client key yields `trusted_hosts = $null` with a successful acquisition and no manufactured value; thrown registry errors leave all three units non-success and license no inferred default anywhere; and explicit values remain `explicit` and are not overwritten by defaults, asserted with an explicit `AllowKerberos = 0` that contradicts the documented default of `$true`.
- **`Security.DefenderAdvanced` (10)** — the exact null/null sentinel becomes a successful empty result (asserted off-pipeline with `ReferenceEquals`, plus zero counts); null/non-null, non-null/null and null-inside-populated pairs all remain malformed; a single genuinely configured rule is not mistaken for the sentinel and still records `success`; and an unequal pair whose one side is the sentinel retains the existing unequal-count behaviour while leaving the independent protection-preference evidence intact.
- **Standalone parity (1)** — the generated artefact is written to the `2.1.1` version-stamped filename, so a missed version bump cannot ship an artefact whose name contradicts its declared agent version.

### Not changed

Schema 1.1; JSON depth 10; the 45-module and 46-acquisition-unit contract; the four-value outcome vocabulary; fail-closed behaviour for any actual provider error; VulnSight. No target-specific exception was added and no host name is referenced anywhere in the repair.

**Still not pilot-ready.** The blockers recorded against 2.1.0 below are unchanged, and no output from this build may be used as controlled research evidence.

---

## [2.1.0] — Tranche 2A — schema 1.1 acquisition foundation

**Schema version: 1.1** (additive minor increment over 1.0)

> **NOT CONTROLLED-COLLECTION READY.** The collector may proceed to the integration pilot, but feature-state resolution, live validation and the final collection freeze remain outstanding. No output produced by this version is eligible for use as controlled research evidence.
>
> Migration of the existing study-relevant modules completed at Tranche 2B.2, and the session/recent-profile extension landed at Tranche 2C — **18 modules across 46 acquisition units**. Session and recent-profile telemetry is **no longer a blocker**, and generated-standalone metadata and contract parity are implemented and asserted against generated output.
>
> **Verified post-2C state:** Windows PowerShell 5.1.26100.9168, Pester 6.1.0 — **617 passed, 0 failed, 0 skipped, 0 not run**. A green suite establishes that the implemented contract behaves as specified; it does **not** make the collector controlled-collection ready and the collection version is **not frozen**.
>
> The remaining blockers are:
>
> 1. registry-restricted Windows feature-state collection (C2/C3);
> 2. validation of that extension, then live pilot validation and the collection freeze.
>
> Active-firewall-profile collection is a possible enhancement, not a frozen prerequisite. Per-user software hives remain excluded.
>
> *(Tranche history: 2A instrumented 3 modules / 11 units; 2B.1 brought the total to 10 modules / 31 units; 2B.2 completed existing-module migration at 17 modules / 43 units; 2C added the session extension at 18 modules / 46 units.)*

### Added

- **Fifth top-level `acquisition` section.** An ordered collection keyed by stable dotted collection-unit identifiers, recording per-unit observation start and end, acquisition outcome, agent version, schema version, the exact governed `data_paths`, and structured `error` detail for non-success outcomes. Module payload data is never duplicated beneath it.
- **Fail-closed acquisition helpers** in [core/VK.Utilities.ps1](core/VK.Utilities.ps1): `Initialize-VKAcquisition`, `Start-VKAcquisition`, `Complete-VKAcquisition`, `Set-VKAcquisitionFailure`, `Set-VKAcquisitionUnavailable`, `Get-VKAcquisitionClassification`, `Complete-VKAcquisitionReport`, `Get-VKAcquisitionReport`. A unit is registered *before* its query runs and only becomes `success` on explicit completion — invocation alone never produces success. Any unresolved unit becomes `failed` / `incomplete_collection` at serialisation. The internal `pending` state can never appear in emitted JSON.
- **Conservative error classification** preferring exception type, then `FullyQualifiedErrorId`, then `ErrorCategory`, then HRESULT, with message-text matching only as a documented last resort. Permission or policy denial → `restricted`; missing provider, namespace, command or capability → `unavailable`; anything else → `failed`.
- **Value provenance** for inferred legacy-protocol defaults: `llmnr_value_source` and `mdns_value_source`, each `explicit` or `default_inferred`.
- **`security.antivirus.products_detected`**, a structural count replacing the `"Not Detected"` prose sentinel.
- **`-Quiet` and `-PassThru` build parameters** so the test suite can generate a standalone script into a temporary location without executing the collector.
- **Test suites**: `VK.Acquisition.Tests.ps1`, `VK.Modules.Acquisition.Tests.ps1`, `VK.StandaloneParity.Tests.ps1`; fixtures for legacy schema 1.0 evidence and eight deliberately invalid schema 1.1 artefacts; a test-only schema validator under `tests/helpers/`.

### Changed

- **Agent version 2.0 → 2.1.0**; **schema version 1.0 → 1.1**; **JSON depth 5 → 10**. Depth 5 preserved the schema 1.0 payload with zero headroom; the acquisition section and the approved extensions need margin. Windows PowerShell 5.1 truncates silently, so the depth contract is asserted behaviourally by the tests.
- `schema_version` is now read from `$script:VKSchemaVersion` in both the runner and the build source, rather than being a hardcoded literal in the runner.
- The output-contract test asserting **exactly four** top-level sections now asserts **exactly five**. It remains an exact match, deliberately not a subset check.

### Fixed — standalone metadata parity

The generated standalone script previously omitted `schema_version`, `running_user` and `running_user_sid` from `scan_metadata`, so the two execution modes did not produce the same evidence contract. Since the generated script is the controlled-collection artefact, and `schema_version` is what ingestion uses to route and validate, this was blocking. The build now captures `$script:CurrentIdentity` and emits all ten required metadata fields, the five-section envelope, the acquisition section, and the configured JSON depth. Parity is asserted against the **generated output**, not merely the build template.

### Fixed — three false-evidence pathways

Each of these caused the agent to assert an observation it never made. Every other failure mode loses information; these three manufactured it.

1. **`Security.LegacyProtocols`** — a failed registry read set `llmnr_enabled` and `mdns_enabled` to `$true`, recording a read failure as a positive assertion that the protocol was enabled. A failed, restricted or unavailable read now yields `$null` with no `value_source`. A *successful* read of an absent policy value still applies the documented Windows default, but is now marked `default_inferred` so inference is distinguishable from observation. NetBIOS, WPAD service, WPAD auto-detect and SCHANNEL protocols were given their own units so one successful query cannot conceal another's failure.
2. **`Security.HostSecurity`** — a failed `Win32_DeviceGuard` query produced a fully populated `security_services[]` asserting that Credential Guard, HVCI and every other service was unconfigured and not running, manufacturing apparent *absence of mitigation*. `vbs_status`, `security_services` and `security_properties` are now governed by a single unit and set to `$null` unless the query succeeded. `$false` is emitted only where the returned configured/running/available lists justify it.
3. **`Security.Antivirus`** — the `root\SecurityCenter2` query used `-ErrorAction SilentlyContinue`, so a failed or denied query and a genuinely AV-free host both produced `product_name = "Not Detected"`, meaning an acquisition failure presented as a serious C7 finding. The query now uses `-ErrorAction Stop`, and a successful zero-product result (`products_detected = 0`) is structurally distinct from `restricted`, `unavailable` and `failed`, all of which emit no product evidence at all.

### Fixed — four residual fail-closed gaps (pre-pilot hardening)

Found by review after the suite went green at 268/268. All four shared one shape: a provider that **answered without throwing but supplied nothing**, which the module then converted into a confident value and a `success` outcome. They are corrections to the same unreleased Tranche 2A change set, so agent 2.1.0, schema 1.1 and JSON depth 10 are unchanged.

1. **`Security.LegacyProtocols` — registry existence tests could not fail.** `Test-Path` emits a *non-terminating* error and returns `$false` when the provider errors, which is indistinguishable from a genuinely absent key. A denied or otherwise unreadable key therefore licensed the documented Windows default and completed as `success`. All four study-relevant existence tests — LLMNR, mDNS, WPAD auto-detect, and each SCHANNEL protocol/role subkey — now use `-ErrorAction Stop`, so only a *successful* negative existence test may be read as "nothing configured". The legitimate distinction is preserved: a successful absent-key result still yields the documented default marked `default_inferred`, while an undeterminable key yields `$null`, no `value_source`, and a non-success outcome.
2. **`Security.HostSecurity` — the native DMA query could fabricate a false.** The embedded C# `BootDmaCheck` returned byte `0` when `NtQuerySystemInformation` returned a non-zero NTSTATUS. PowerShell read that as `kernel_dma_protection = $false` and recorded `success` — a failed query presenting as observed absence of protection. A non-zero NTSTATUS now throws an `InvalidOperationException` carrying the status code, reaching the existing catch, which yields `$null` and a non-success outcome. NTSTATUS success with a returned byte of `0` remains a valid observed `false`. `InvalidOperationException` is mscorlib, so the standalone build needs no additional assembly reference.
3. **`Security.HostSecurity` — a null DEP response became "Always Off".** `(Get-CimInstance Win32_OperatingSystem).DataExecutionPrevention_SupportPolicy` can be `$null` without throwing; `[int]$null` is `0`, which maps to `Always Off`. Both the instance and the property are now checked for null **before** any cast or lookup. A missing singleton or property leaves `dep_policy` `$null` and records `unavailable` / `provider_value_missing`. A genuine returned `0` still records `Always Off` with `success`.
4. **`Security.Antivirus` — a null Defender status completed as success.** `Get-MpComputerStatus` can return `$null` without throwing; piping that into `Select-Object` silently yields nothing, leaving every Defender field null while the unit was completed as `success` — a successful empty observation the provider never made. The response is now checked before completion; a null response records `unavailable` / `provider_value_missing` and leaves all six Defender fields null.

**Additive shape change:** `security.antivirus` now pre-initialises all six Defender fields to `$null`, so every path declared in a unit's `data_paths` is always present and explicitly *not observed*, rather than silently absent on non-Defender hosts. No path is added or removed; declared paths simply always exist.

New category `provider_value_missing` distinguishes "the provider answered but supplied no value" from an exception. It is an `unavailable` outcome, since the capability was not furnished by the host.

### Added — Tranche 2B.1: seven further security modules instrumented

Agent 2.1.0, schema 1.1 and JSON depth 10 remain **unchanged**; this completes the same unreleased acquisition-contract release. Twenty new collection units bring the total to **31**.

`Security.DefenderAdvanced`, `Security.Firewall`, `Security.SMB`, `Security.RDP`, `Security.WinRM`, `Security.UAC` and `Security.FDE`. `Security.FDE` is included because controlled Case 9 varies disk-encryption state as irrelevant telemetry; it does not contribute to C1–C7 scoring, but its acquisition outcome must be equally trustworthy.

**Fabricated-state paths corrected:**

- **DefenderAdvanced** no longer re-queries SecurityCenter2. It uses `security.antivirus.products`' outcome and product evidence as an explicit precondition (`precondition_not_met` when unknown, `provider_not_applicable` when Defender is not active), so "not active" and "probe failed" are no longer both an absent section. A mismatched ASR id/action pair no longer defaults the missing action to `0`/`"Disabled"`; it withholds the ASR unit while leaving independently valid protection-preference evidence intact.
- **Firewall** no longer leaves both collections at `@()` on failure — a failed query yields `$null`. A genuine zero-rule result is still `@()`.
- **SMB** replaces `SilentlyContinue` on the SMBv1 probe, distinguishes registry-explicit from `feature_observed` state, exposes per-field `explicit` / `default_inferred` provenance via `server_value_sources` and `client_value_sources`, licenses no default after a failed read, and records no-admin access to `Get-SmbServerConfiguration` as `restricted` / `insufficient_privilege` instead of omitting the fields.
- **RDP** splits the two registry keys into separate units so one failure no longer discards the other, guards every property before comparison or `[int]` conversion (`$null -eq 0` previously read as "RDP disabled"; `[int]$null` mapped to the least-secure security layer), adds `port_value_source` for the retained 3389 default, and yields `$null` rather than an empty list when group enumeration fails.
- **WinRM** replaces the `"Unknown"` service-state sentinel with `$null`, uses terminating `Test-Path` and enumeration, exposes provenance for retained defaults, and withholds the whole listener collection on a part-way failure rather than emitting a shorter list that reads as complete.
- **UAC** pre-initialises all twelve fields to `$null` and guards every property. Absent values previously became confident `false`, and `[int]$null` mapped to "Elevate without prompting" and "Automatically deny elevation requests". No default is asserted: after a successful read an absent value stays `$null`.
- **FDE** replaces `Invoke-IfAdmin`, which swallowed errors and prevented classification. Both units are now registered even without elevation (`restricted` / `insufficient_privilege`), null CIM and BitLocker results are guarded, and a volume missing `VolumeStatus`, `ProtectionStatus` or `EncryptionMethod` withholds the collection instead of rendering "Not Fully Encrypted", "Protection Off" or "Unknown or Not Encrypted".

**Test-surface correction.** `error.exception_type` contractually holds a .NET type name (e.g. `System.Management.Automation.CommandNotFoundException`), which collided with the truncation-marker scan and would have tripped on any real collection where a cmdlet is absent. The scan now blanks that field's value only; every other position is still scanned unchanged, and a new assertion guards the exclusion from becoming over-broad.

**Not pilot-ready.** Host and pathway modules remain uninstrumented. No output from this tranche may be used as controlled research evidence.

### Added — Tranche 2B.2: the seven remaining host/pathway modules instrumented

Agent 2.1.0, schema 1.1 and JSON depth 10 remain **unchanged**. Twelve new units bring the total from 31 to **43**, completing migration of every existing study-relevant module.

`Host.Identification` (3 units), `Host.NetworkConfig` (2), `Host.Services` (1), `Host.Processes` (1), `Host.Software` (2), `Host.Users` (2), `Vul.Privileges.Token` (1).

Deliberately excluded: `Host.WindowsUpdates` (Table A2 defines C2's current agent sources as services, processes and installed software), `Host.Network`, the ARP/routing/DNS collections, manufacturer and BIOS inventory for analytical use, and all other vulnerability and permission modules.

**Ambiguity and partial-result pathways corrected:**

- **Identification** — `[int]` on an absent `BuildNumber` became build `0`; every required property is now guarded. Manufacturer/BIOS is retained as legacy raw inventory, uninstrumented and outside the analytical allow-list, and a failure there can no longer affect the three study units.
- **NetworkConfig** — all five sub-collections previously became `@()` in `catch`, so a failed query was byte-identical to a genuinely empty host and `summary` reported `0`. TCP and UDP now yield `$null` with a non-success outcome, and their summary counts are `$null` rather than `0`. ARP, routing and DNS remain uninstrumented and outside the study register.
- **Services / Processes** — the assignment sat inside the `try`, so a failure left the key absent, and the console reported `"(0 services)"` / `"(0 processes)"` after a total failure. Both now yield `$null` with a recorded outcome and no count. Per-process owner lookup remains optional enrichment.
- **Software** — split into two hive units that **share one governed path**. A per-entry read failure now makes that hive incomplete instead of silently shortening it, and the combined list is withheld as `$null` unless every applicable hive succeeded. `Sort-Object` collapsing an empty pipeline to `$null` is corrected so a successful empty result stays `@()`. Each record carries an additive `registry_scope`. WOW6432Node applicability is decided from the OS architecture, never from a failed path check.
- **Users** — the literal `"Error retrieving members"` in-band sentinel is **removed**; a member-query failure now withholds the whole collection rather than emitting a shorter list. `is_admin` is `$null`, never `$false`, when group evidence did not succeed. Timestamps are converted to UTC before the `Z` suffix (previously local time was mislabelled), and a single reference time is used for all derived day counts. Additive `user_accounts_scope` / `group_memberships_scope` markers record the local-only observation boundary.
- **Token privileges** — `whoami … 2>&1 | ConvertFrom-Csv` fed error records into the parser. The native exit code is now checked first and the required CSV columns validated before completion. Additive `evidence_scope = "collector_token_only"` and `collector_ran_as_admin` qualifiers make explicit that this describes **only the collector's own token** — when run elevated it describes an administrator's token and must never be read as a low-privilege pathway.

Raw principal-bearing evidence is retained unchanged; pseudonymisation remains an ingestion-layer responsibility. `command_line` stays excluded from the analytical allow-list.

### Added — Tranche 2C: session and recent-profile telemetry

New module `Host.Sessions.ps1` / `Invoke-VKHostSessions`, invoked immediately after `Host.Users`. Agent 2.1.0, schema 1.1 and JSON depth 10 **unchanged**; three new units bring the total to **46** across **18** modules.

Two dependency-free local providers only: **WTS APIs in `wtsapi32.dll`** via the established `Add-Type`/P-Invoke precedent, and **`Win32_UserProfile`** via the existing CIM approach.

- **`host.sessions.current_sessions`** — session id, name, documented WTS connection state, protocol type and derived session type. `session_type` comes from `WTSClientProtocolType` (0 console, 1 legacy, 2 remote); the session **name is never used** to infer console or RDP, and `session_type_source` records which source was used. A `Listen` entry is classified `listener` from its connection state alone.
- **`host.sessions.session_principals`** — stored separately and joined by `session_id`, so principal-resolution failure cannot discard observed session state. Listener sessions are never queried. An empty returned string is a successful observed absence (`principal_present = false`), which is *not* the same as a failed call; because the vocabulary has no partial outcome, any required query failure withholds the whole collection.
- **`host.sessions.user_profiles`** — `sid`, `loaded`, `special`, `last_use_time`, `last_use_within_window`, and a constant `evidence_strength = "profile_use_proxy"`.

**Evidence semantics.** WTS sessions are **direct, point-in-time** evidence. `LastUseTime` is a **retrospective proxy**: it advances on profile load and unload and from background activity, so it means "this profile was touched within the window", not "a user interactively logged on". **C5 remains partial.**

**Event 4624 deliberately excluded.** Windows exposes only current audit policy, not policy history, so an empty 4624 result could never be shown to mean "no recent logon". `quser.exe`, `qwinsta.exe`, `wevtutil.exe` and free-text parsing are also excluded.

**Memory safety.** Every native buffer from `WTSEnumerateSessions` and `WTSQuerySessionInformation` is released through `WTSFreeMemory` inside a `finally`, so the exception path frees as reliably as the success path. Failures raise `VoightKampff.WtsException` carrying the **native error code**, and classification uses that structured code rather than message text (5 → `restricted`/`access_denied`, 1314 → `insufficient_privilege`, 1722/7022 → `unavailable`). No `IsAdmin` precondition is hard-coded.

**Observation window.** New `$script:VKSessionWindowHours = 24` in `VK.Config.ps1`. It qualifies `LastUseTime` only, so `observation_window` is governed by the profile unit, and is emitted **unconditionally** — including on total failure — so an artefact is always self-describing. A single captured UTC reference time drives the window and every comparison.

**Privacy unchanged.** Raw user names, domains and SIDs are retained unchanged in the secured raw evidence; no agent-side pseudonymisation, hashing or analytical filtering. `is_domain_principal` is deliberately *not* emitted — that classification belongs to ingestion. Raw output remains suitable for Voight-Kampff's wider non-dissertation use.

**Regression guard added.** A static test walks every `Invoke-VK*` function and fails on any assignment whose target differs from a declared parameter only by case — the `$isAdmin`/`[bool]$IsAdmin` silent-coercion defect fixed in Tranche 2B.2.

### Compatibility note

The `"Not Detected"` prose sentinel has been **removed**. Consumers that tested for that string must instead read `security.antivirus.products_detected` together with the governing acquisition outcome. Per the evidence contract, a successful zero-product result makes absence *assessable*; it does not by itself establish confirmed absence.

### Not included in this tranche

Deferred to Tranche 2B: instrumentation of the remaining study-relevant modules; session and recent-profile telemetry; Windows feature-state collection; per-user software-hive expansion (excluded by decision); active-firewall-profile collection.

---

## [2.0.1] — Tranche 1 — duplicate execution correction

**Schema version: 1.0** (unchanged — no contract change)

### Fixed

- **Duplicate `Host.NetworkConfig` execution removed** from [core/Invoke-VKScan.ps1](core/Invoke-VKScan.ps1). The module was invoked twice: once in its intended position and again between `Host.Drivers` and `Host.USBHistory`. The second run **silently overwrote** the first, so retained ARP, TCP and UDP data reflected an observation point later than the module order implied, and `modules_executed` listed `host.network_config` twice. The build template listed the module only once and needed no change.

### Added

- `docs/dissertation-agent-evidence-contract.md` — the C1–C7 evidence audit, the acquisition-contract proposal, and the change-controlled decisions.
- Initial Pester structure: `VK.RunnerContract.Tests.ps1`, `VK.OutputContract.Tests.ps1`, and the representative synthetic fixture.

### Note on this version number

Tranche 1 shipped without a version increment, because the project had no stated versioning policy at the time and the instruction was not to change versions. The fix is recorded here as 2.0.1 for changelog continuity; `$script:VKAgentVersion` moved directly from `"2.0"` to `"2.1.0"` in Tranche 2A.

---

## [2.0] — Baseline

Modular PowerShell collector with a four-section schema 1.0 envelope (`scan_metadata`, `host`, `security`, `vulnerability`), 44 modules across host, security and vulnerability groups, and a standalone build.

Known limitations of this baseline, catalogued in the evidence contract: no per-module acquisition outcome, so collection failure was indistinguishable from a true negative; a non-durable out-of-band error log excluded from the JSON; and `modules_executed` recording invocation rather than success.
