# Voight-Kampff Agent — Dissertation Evidence Contract

**Status:** **Tranche 2C implemented.** Schema 1.1 acquisition foundation in place, modular/standalone parity maintained, all seventeen existing study-relevant modules migrated, and the **session and recent-profile extension** now added — **18 modules across 46 collection units**. See §8 (2A), §9 (2B.1), §10 (2B.2) and §11 (2C).
**Agent version:** 2.1.0 (`$script:VKAgentVersion`, [VK.Config.ps1](../core/VK.Config.ps1))
**Schema version:** 1.1 (`$script:VKSchemaVersion`; five-section envelope)
**JSON depth:** 10 (raised from 5 — see §2.3)
**Audit date:** 18 August 2026 (Tranche 1 audit). Implementation records: §8 (2A), §9 (2B.1), §10 (2B.2), §11 (2C).
**Latest verification:** Windows PowerShell 5.1.26100.9168, Pester 6.1.0 — **617 passed, 0 failed, 0 skipped, 0 not run** (§11.10)
**Scope:** the Voight-Kampff PowerShell agent only. Backend, compliance engine, frontend, contextual scoring and Priority Index calculation are out of scope and unmodified. The approved C1–C7 meanings, contextual rules, weights, applicability and inference boundaries are unchanged.

> ### ⚠ Not pilot-ready
>
> **No output produced by this implementation may be used as controlled research evidence.**
>
> Migration of the existing study-relevant modules is **complete**, and the session/recent-profile extension is **implemented** (18 modules, 46 units), so two earlier blockers — uninstrumented modules emitting payload with no acquisition metadata, and the absence of session telemetry — are resolved. Generated-standalone metadata and contract parity are implemented and asserted against generated output (§7.2).
>
> The remaining blockers are:
>
> 1. **registry-restricted Windows feature-state collection** for C2/C3;
> 2. **validation of that extension**, then **live pilot validation** and the **collection freeze**.
>
> Active-firewall-profile collection remains a possible enhancement, **not** a frozen prerequisite. Per-user software hives remain explicitly excluded (§7.5). Event 4624 is deliberately excluded, not deferred (§11.3).

## Note on document location

No `docs/` directory previously existed, and no alternative established documentation location was found — the repository contained only a root `README.md`, with `dist/` and `tests/` present but empty. This document therefore creates `docs/` as the documentation location, matching the path named in the governing task. The root `README.md` remains the operational agent guide; this document is the evidence-contract reference for the dissertation artefact.

---

## 1. Purpose and boundaries

Voight-Kampff is an **upstream evidence collector**. Its raw JSON is preserved as source evidence in the secured raw zone. The following are explicitly *not* agent responsibilities and are performed by the separate dissertation artefact in the ingestion and analysis layers:

- validation and schema conformance enforcement;
- pseudonymisation of principals;
- condition applicability determination;
- reconciliation against Nessus and CIS-CAT;
- contextual scoring and Priority Index calculation.

This document records what the agent **currently** contributes to conditions C1–C7, what it demonstrably **cannot** establish, and where collection failure is currently **indistinguishable** from a true negative. It then proposes — but does not implement — a per-module acquisition envelope to remove that ambiguity.

### 1.1 Two interpretive rules that constrain every mapping below

These rules are load-bearing and are applied consistently throughout §3.

**Rule 1 — Local listener state does not prove remote reachability.**
A listening socket observed on the host establishes only that a process is bound to a port in the host's own network namespace. It does not establish that the port is reachable from any other host. Reachability additionally depends on host firewall rule evaluation for the *active* profile, network-level filtering (ACLs, segmentation, NAT), and the position of the would-be source. The agent observes none of the network-level factors. C1 is therefore **partial by construction** from agent evidence alone and requires Nessus corroboration for the remote half of the claim.

**Rule 2 — A successful empty collection makes absence *assessable*, not *confirmed*.**

> A successful empty collection makes absence assessable, but confirmed absence may be asserted only where the condition-specific applicability, coverage, authority and field-semantics rules permit it. Otherwise, the contextual evidence remains unknown or neutral. Any acquisition outcome other than `success` can never support confirmed absence.

This is the governing principle for every absence claim in the study, and it operates in two stages.

**Stage one — acquisition.** `success` is a *necessary* precondition. Because the current agent cannot signal per-module acquisition outcome (§4), an empty array, a `null`, or a missing key may equally mean *nothing was there*, *the query failed*, *permission was denied*, or *the provider was unavailable*. Until the acquisition envelope in §5 is implemented, **no empty agent result may be read as confirmed absence** in any analytical dataset.

**Stage two — condition-specific qualification.** `success` is *not sufficient*. Even a confirmed successful empty collection only opens the question. Confirmed absence additionally requires that the condition's own rules permit the inference on four axes:

- **applicability** — does the condition apply to this host at all?
- **coverage** — did the collection unit actually span the scope the condition asks about? A successful empty `installed_software` read of the two HKLM hives does not cover per-user software (§3, C2), so it cannot support absence of a user-scope application.
- **authority** — is this collection unit an authoritative source for the claim? A successful empty `tcp_connections` result is authoritative for local bind state and not for remote reachability (Rule 1).
- **field semantics** — does an empty value in this specific field mean "none exist"? An empty `asr_rules[]` means "Defender returned no configured rules", which is not the same proposition as "no ASR rule applies" (§3, C4).

Where any axis fails, the contextual evidence state remains **unknown or neutral**. It does not become a negative finding. Deciding these axes is a downstream rule-registry responsibility (§5.2) — the agent neither makes nor records that judgement.

---

## 2. Envelope, serialisation and execution mechanics as found

### 2.1 Runner and module mechanism

| Concern | Finding |
| --- | --- |
| Source-of-truth runner | [core/Invoke-VKScan.ps1](../core/Invoke-VKScan.ps1) |
| Standalone build template | [build/Build-Standalone.ps1](../build/Build-Standalone.ps1) — independently reproduces the invocation sequence via `$hostModuleFiles` / `$hostFunctionMap` (and security/vulnerability equivalents) |
| Generated artefact | `dist/` is **empty**; no generated copy is currently maintained in the repository. The build template is treated as maintained source; generated artefacts are not. |
| Module loading | Dot-sourcing at point of use (`. (Join-Path $script:HostModules "…")`), immediately followed by the module's `Invoke-VK*` function call |
| Data passing | Each module receives the section dictionary by reference (`-Data $data["host"]`) and mutates it in place; modules return nothing meaningful |
| Elevation signal | `-IsAdmin $script:IsAdmin` passed to every module; `Invoke-IfAdmin` helper exists in [VK.Utilities.ps1](../core/VK.Utilities.ps1) but is **not used by any study-relevant module audited** |
| Test convention | **None existed.** `tests/` was empty. A minimal Pester structure was created in this tranche and passes under Windows PowerShell 5.1 with Pester 6.1.0 (50 passed, 0 failed — see §2.3) — see [tests/README.md](../tests/README.md) |

### 2.2 JSON envelope

Four top-level keys, created as `[ordered]` dictionaries at [Invoke-VKScan.ps1:88-93](../core/Invoke-VKScan.ps1#L88-L93):

```json
{ "scan_metadata": {}, "host": {}, "security": {}, "vulnerability": {} }
```

`scan_metadata` is populated **after** all modules run ([Invoke-VKScan.ps1:349-360](../core/Invoke-VKScan.ps1#L349-L360)) with: `schema_version`, `agent_version`, `hostname`, `running_user`, `running_user_sid`, `scan_start`, `scan_end`, `scan_duration_seconds`, `ran_as_admin`, `modules_executed`.

### 2.3 Serialisation depth

`ConvertTo-Json -Depth $script:VKJsonDepth` with `$script:VKJsonDepth = 5` ([VK.Config.ps1:39](../core/VK.Config.ps1#L39)).

Verified against the deepest study-relevant paths currently produced:

| Deepest path | Levels below root | Survives at depth 5 |
| --- | --- | --- |
| `host.windows_updates.pending_updates[].kb_numbers[]` | 5 | Yes |
| `host.network_shares[].permissions[].account` | 5 | Yes |
| `security.defender_advanced.asr_rules[].guid` | 4 | Yes |
| `security.legacy_protocols.tls_protocols[].client_enabled` | 4 | Yes |

#### Verification record — Tranche 1 (HISTORICAL)

> **Historical record, retained as the Tranche 1 audit evidence.** It records the schema-1.0 agent at depth 5. The current authoritative verification is in **§11.10**.

The contract tests were executed on the controlled-collection runtime and **passed**:

| Item | Value |
| --- | --- |
| Runtime | **Windows PowerShell 5.1.26100.9168** |
| Test framework | **Pester 6.1.0** |
| Result | **50 passed, 0 failed** |
| Depth outcome | **Configured JSON depth 5 preserved the then-current representative fixture** in full — no truncation marker was emitted and every required nested value survived the round trip |

This closed open question 1 (§7) *as it stood at Tranche 1*: depth 5 was adequate on 5.1 for the evidence the agent produced then, so no depth change was required for the schema-1.0 freeze. Depth was subsequently raised to 10 for schema 1.1 — see immediately below and §7.1.

#### Depth raised to 10 in Tranche 2A

**Resolved.** `$script:VKJsonDepth` is now **10**. Depth 5 was sufficient for the schema 1.0 payload and no more, and the schema 1.1 acquisition section plus the approved extensions need margin. The behavioural depth assertions in the Pester suite serialise the representative fixture at the configured depth and check for truncation markers, so a future overrun is caught by the tests rather than by inspection.

The warning below is retained as the standing rationale, and the depth setting must be re-evaluated again whenever nesting changes:

#### Depth had no design headroom at 5

1. The approved session/recent-profile and feature-state collectors (roadmap items 7–8) and the schema-1.1 acquisition envelope (§5) each add nesting. Option B (§5.4) deliberately keeps the new `acquisition` subtree shallow and adds **no** level to existing paths, which is one of the reasons it was accepted — but the extensions themselves may still introduce paths deeper than the current maximum of five levels.
2. Had the envelope wrapped module data (§5.4, Option A), every existing path would have gained a level and `kb_numbers[]` and `permissions[].account` **would truncate at depth 5**. That design was not adopted, but the arithmetic illustrates how little margin exists.
3. Windows PowerShell 5.1 substitutes the .NET type name string (e.g. `"System.Collections.Specialized.OrderedDictionary"`) on truncation rather than failing, so a future overrun would be **silent** in the output file. The depth assertions in the Pester suite are behavioural — they serialise at the configured depth on the running edition and check for those marker strings — so a regression is caught by the tests rather than by inspection. Those tests must be re-run, and the depth setting explicitly re-evaluated, as part of the tranche that introduces each extension.

---

## 3. Condition evidence audit (C1–C7)

Column definitions:

- **Establishes** — what the field directly supports as an observation.
- **Cannot establish** — inferences the field does not license.
- **Availability** — `available` (field reliably present and meaningful), `partial` (present but incomplete or elevation-dependent), `absent` (not collected).
- **Failure ambiguity** — how collection failure currently presents, and what it is confusable with.
- **PII** — whether the field carries personal or identifying information.

Failure-mode codes used in the tables, defined fully in §4.2: **A** = empty collection on failure; **B** = key absent on failure; **C** = failure coerced to a definite value; **D** = failure indistinguishable from "not present"; **E** = module reported as executed regardless of outcome.

### C1 — Remote reachability

| Item | Detail |
| --- | --- |
| Modules | [Host.NetworkConfig.ps1](../modules/host/Host.NetworkConfig.ps1), [Host.Services.ps1](../modules/host/Host.Services.ps1), [Security.Firewall.ps1](../modules/security/Security.Firewall.ps1) |
| Paths | `host.network_config.tcp_connections[]` → `local_address`, `local_port`, `remote_address`, `remote_port`, `state`, `pid`, `process_name`<br>`host.network_config.udp_listeners[]` → `local_address`, `local_port`, `pid`, `process_name`<br>`host.services[]` → `name`, `state`, `start_type`<br>`security.firewall_profiles[]` → `name`, `enabled`, `inbound_action`<br>`security.firewall_rules[]` → `display_name`, `direction`, `action` |
| Establishes | That a process was bound to a given local port at observation time; the owning process where resolvable; the service's run state; the host firewall's configured default inbound action per profile and its enabled inbound allow rules. |
| Cannot establish | **Remote reachability.** Per Rule 1: no network-path, segmentation, upstream-ACL or NAT evidence is collected. `firewall_profiles` is read from `ActiveStore` but the agent does not record *which* profile is currently active on which interface, so the applicable default inbound action cannot be determined from agent evidence alone. `tcp_connections` filters out `Bound` and `TimeWait` states, so some transient listeners are excluded by design. |
| Availability | **partial** — local bind state available; reachability absent |
| Failure ambiguity | **A, E.** All five `network_config` sub-collections are set to `@()` inside their `catch` blocks ([Host.NetworkConfig.ps1:65,96,138,172,199](../modules/host/Host.NetworkConfig.ps1#L65)). A failed `Get-NetTCPConnection` therefore yields `"tcp_connections": []`, byte-identical to a host with no connections. `network_config.summary` then reports `0`, lending false precision. `firewall_profiles`/`firewall_rules` remain `@()` on failure (**A**). `host.services` uses **B** — the key is never created if `Get-CimInstance Win32_Service` throws. |
| PII | Yes — `remote_address` and `local_address` are IP addresses; `process_name` may reveal user-installed software. |
| Required change | Per-module and per-sub-collection acquisition outcome (§5). Additionally recommended for a later tranche: record the active firewall profile per interface, so the applicable default inbound action is determinable. |
| Nessus / CIS-CAT | **Nessus supplies the remote half of C1** — externally observed open ports, service fingerprints and reachability from the scanner's vantage point. The agent supplies the local bind and process attribution that Nessus cannot see. C1 is only fully evidenced by reconciling both. |

### C2 — Component state

| Item | Detail |
| --- | --- |
| Modules | [Host.Services.ps1](../modules/host/Host.Services.ps1), [Host.Processes.ps1](../modules/host/Host.Processes.ps1), [Host.Software.ps1](../modules/host/Host.Software.ps1), [Host.Identification.ps1](../modules/host/Host.Identification.ps1), [Host.WindowsUpdates.ps1](../modules/host/Host.WindowsUpdates.ps1) |
| Paths | `host.services[]` → `name`, `display_name`, `state`, `start_type`, `logon_account`, `binary_path`, `pid`<br>`host.processes[]` → `name`, `pid`, `parent_pid`, `owner`, `executable`, `command_line`, `session_id`, `start_time`<br>`host.installed_software[]` → `name`, `version`, `publisher`, `install_date`<br>`host.os` → `name`, `architecture`, `version`, `build`<br>`host.windows_updates` → `pending_count`, `pending_updates[]`, `installed_recent[]`, `reboot_pending` |
| Establishes | Presence, version and publisher of registry-registered installed software; service existence, run state and start type; process execution at observation time; OS build level; patch state as reported by the Windows Update client. |
| Cannot establish | **Whether the installed component is the vulnerable build.** `installed_software.version` is the vendor `DisplayVersion` string, which frequently does not correspond to the file version a CVE is expressed against. The agent does not collect file versions of specific binaries. `Host.Software` reads only the two `HKLM` uninstall hives — **per-user software under `HKCU` and `HKU\<SID>` is not collected**, so user-scope installations (a common location for browsers and developer tooling) are invisible and their absence is not evidence of absence. Service `state` is a point-in-time observation, not a statement about boot-time behaviour. |
| Availability | **partial** — machine-scope software and services available; per-user software absent; build-level identification for CVE matching absent |
| Failure ambiguity | **A, B, D, E.** `host.services` and `host.processes` use pattern **B** (key never created on failure), which at least differs from a genuine empty set — but nothing records *why* it is missing. `host.installed_software` is assigned outside the `try`, so a failure to read one or both registry hives yields a **silently short list** with no marker (**D**) — the most dangerous case here, because a partial list is indistinguishable from a complete one. `Host.Processes` reports `"Process enumeration complete (0 processes)"` as `SUCCESS` even after a total failure (**E**). `windows_updates` returns early with a partial `$updateData` if the COM object cannot be created ([Host.WindowsUpdates.ps1:84-86](../modules/host/Host.WindowsUpdates.ps1#L84-L86)), leaving `pending_updates` absent entirely. |
| PII | Yes — `processes[].owner` is a domain-qualified username; `processes[].command_line` may contain usernames, file paths under user profiles, and occasionally credentials passed as arguments; `installed_software[].name` can reveal individual working patterns. |
| Required change | Acquisition outcome per module (§5), applied per-registry-hive for `Host.Software` so a partial read is visible. Feature-state collection (roadmap item 8) extends C2 within the frozen rule registry. |
| Nessus / CIS-CAT | Nessus supplies authoritative CVE-to-installed-version matching and its own credentialed software enumeration. The agent's contribution is corroborative breadth (services, processes, run state) rather than vulnerability identification. |

### C3 — Exploit prerequisite

| Item | Detail |
| --- | --- |
| Modules | [Security.SMB.ps1](../modules/security/Security.SMB.ps1), [Security.LegacyProtocols.ps1](../modules/security/Security.LegacyProtocols.ps1), [Security.RDP.ps1](../modules/security/Security.RDP.ps1), [Security.WinRM.ps1](../modules/security/Security.WinRM.ps1), [Host.Services.ps1](../modules/host/Host.Services.ps1) |
| Paths | `security.smb` → `smbv1_enabled`, `server_signing_required`, `client_signing_required`, `client_insecure_guest_auth`, `restrict_null_session_access`, `null_session_pipes[]`, `null_session_shares[]`<br>`security.legacy_protocols` → `llmnr_enabled`, `mdns_enabled`, `netbios_any_enabled`, `netbios_adapters[]`, `wpad_service_state`, `wpad_auto_detect`, `tls_protocols[]`<br>`security.rdp` → `rdp_enabled`, `nla_required`, `security_layer`, `encryption_level`, `port`<br>`security.winrm` → `service_state`, `allow_unencrypted`, `server_auth.*`, `listeners[]` |
| Establishes | The registry-declared configuration state of each protocol prerequisite at observation time. Where a registry value is genuinely present, this is a direct observation. |
| Cannot establish | **Effective runtime state, and — critically — the difference between an observed value and an assumed Windows default.** Several fields are populated with the documented Windows default when the registry value is *absent* rather than being marked unknown: `smb.server_signing_enabled` defaults to `$true` ([Security.SMB.ps1:95](../modules/security/Security.SMB.ps1#L95)), `smb.restrict_null_session_access` to `$true` (L121), `smb.server_reject_unencrypted` to `$true` (L107), and the entire `winrm.server_auth` block defaults `kerberos`/`negotiate` to `$true` ([Security.WinRM.ps1:69-70](../modules/security/Security.WinRM.ps1#L69-L70)). These are **inferences presented in the same field shape as observations**, with nothing to distinguish them. Additionally, TLS `tls_protocols[]` reports SCHANNEL registry state, which is not the same as the effective protocol set negotiated by any given application. |
| Availability | **partial** — registry state available; observed-vs-assumed provenance absent; effective runtime state absent |
| Failure ambiguity | **C (severe), A, E.** `legacy_protocols.llmnr_enabled` and `mdns_enabled` are set to **`$true` in their `catch` blocks** ([Security.LegacyProtocols.ps1:53,130](../modules/security/Security.LegacyProtocols.ps1#L53)) — a read failure is recorded as a positive assertion that the protocol is enabled. This is a fabricated observation and must not enter an analytical dataset as evidence. `smb.smbv1_enabled` correctly uses `$null` on failure (good practice, and the model the refactor should follow). `winrm.listeners` uses **A**. `Security.SMB` uses `-ErrorAction SilentlyContinue` on the SMBv1 registry probe, so failure and absence are conflated before the fallback even runs. |
| PII | Low — mostly configuration values. `winrm.trusted_hosts` and `null_session_shares[]` may contain internal hostnames; `netbios_adapters[].description` identifies hardware. |
| Required change | (i) Acquisition outcome per module (§5). (ii) **Replace the `catch`-block `$true` defaults in `Security.LegacyProtocols` with `$null` — this is the single highest-priority correctness fix identified in this audit.** (iii) Introduce an explicit observed-vs-default provenance marker for the fields listed above, so assumed defaults are separable from observations. Registry-scoped feature state arrives with roadmap item 8. |
| Nessus / CIS-CAT | Nessus independently detects SMBv1, signing posture and TLS versions from the network, giving an effective-state cross-check the agent cannot produce. CIS-CAT supplies benchmark-referenced expected values. |

### C4 — Compensating mitigation

| Item | Detail |
| --- | --- |
| Modules | [Security.HostSecurity.ps1](../modules/security/Security.HostSecurity.ps1), [Security.Firewall.ps1](../modules/security/Security.Firewall.ps1), [Security.UAC.ps1](../modules/security/Security.UAC.ps1), [Security.DefenderAdvanced.ps1](../modules/security/Security.DefenderAdvanced.ps1), [Security.FDE.ps1](../modules/security/Security.FDE.ps1) |
| Paths | `security.host_security` → `kernel_dma_protection`, `dep_policy`, `vbs_status`, `security_services[]` (`service_name`, `configured`, `running`), `security_properties[]`<br>`security.firewall_profiles[]` → `enabled`, `inbound_action`<br>`security.uac` → `uac_enabled`, `admin_approval_mode`, `consent_prompt_admin`, `secure_desktop_enabled`<br>`security.defender_advanced` → `asr_rules[]`, `network_protection`, `controlled_folder_access`, `tamper_protection` |
| Establishes | Directly observed platform mitigation state: VBS/Credential Guard/HVCI configured and running flags, DEP policy, Kernel DMA protection, UAC prompt configuration, ASR rule actions, firewall profile enablement. |
| Cannot establish | **That an observed mitigation actually mitigates the specific vulnerability under assessment.** Mitigation-to-vulnerability applicability is a rule-registry decision made downstream, not an agent observation. `asr_rules[]` reports only rules Defender returns as configured; a GUID absent from the array means "not returned", not "not applicable". Exploit-protection process mitigations are named in the module documentation but **are not actually collected** by the code. |
| Availability | **partial** — platform mitigations available; Defender mitigations conditionally available; per-process exploit protection absent |
| Failure ambiguity | **C (severe), B, E.** In `Security.HostSecurity`, if the `Win32_DeviceGuard` CIM query fails, `$DeviceGuardState` stays `$null`, `$servicesConfigured`/`$servicesRunning` stay empty, and the module then **emits a complete `security_services[]` array with every entry `configured: false, running: false`** ([Security.HostSecurity.ps1:137-156](../modules/security/Security.HostSecurity.ps1#L137-L156)). A query failure is thus rendered as a confident, fully-populated assertion that Credential Guard, HVCI and every other service is off. `security_properties[]` fails the same way. This is the most consequential false-negative pathway in the agent, because it manufactures apparent *absence of mitigation*. `Security.DefenderAdvanced` uses **B**: the module `return`s early — leaving `security.defender_advanced` entirely absent — both when Defender genuinely is not the active AV *and* when the `SecurityCenter2` probe returns nothing because it failed ([Security.DefenderAdvanced.ps1:35-39](../modules/security/Security.DefenderAdvanced.ps1#L35-L39)). |
| PII | No — configuration state only. |
| Required change | (i) Acquisition outcome per module (§5). (ii) **`Security.HostSecurity` must emit `null`, not `false`, for Device Guard services and properties when `$DeviceGuardState` is null.** (iii) `Security.DefenderAdvanced` must distinguish `unavailable` (Defender not the active AV — a legitimate, informative outcome) from `failed`/`restricted` (probe error), rather than returning silently in both cases. |
| Nessus / CIS-CAT | **CIS-CAT mappings remain external.** The agent supplies directly observed state only; benchmark identifiers, expected values and pass/fail determinations are CIS-CAT's contribution and are not reproduced in the agent. |

### C5 — Interactive use

| Item | Detail |
| --- | --- |
| Modules | [Host.Identification.ps1](../modules/host/Host.Identification.ps1), [Host.Processes.ps1](../modules/host/Host.Processes.ps1) (indirect) |
| Paths | `host.os.platform_role` (e.g. `Desktop`, `Mobile`, `Workstation`, `Enterprise Server`)<br>`host.domain_status.status`, `host.domain_status.domain_name`<br>`host.processes[].session_id`, `host.processes[].owner` (indirect, not aggregated)<br>`host.users.user_accounts[].last_logon`, `days_since_last_logon` (local accounts only) |
| Establishes | The host's declared platform role from SMBIOS/`PCSystemType`, and its domain or workgroup membership. Together these support a coarse role inference (workstation vs server). |
| Cannot establish | **Whether the host is actually interactively used, by whom, or how recently.** `platform_role` is a hardware chassis declaration, not a usage observation — a physically-desktop chassis running as an unattended server reports `Desktop`. `user_accounts[].last_logon` covers **local accounts only** (`Get-LocalUser`); on a domain-joined host, the accounts that actually log in interactively are domain accounts and are **entirely invisible**. Session type (console vs RDP vs service) is not collected. `processes[].session_id` is present but is not aggregated into any session-level evidence. |
| Availability | **absent** for direct interactive-use evidence; **partial** for role inference only |
| Failure ambiguity | **B.** `host.os` sub-keys are simply not written if the CIM query fails; `domain_status` likewise. Because `$Data["os"]` is pre-created as an empty `[ordered]@{}` before the `try`, a failure leaves `"os": {}` — an empty object that is not obviously a failure. |
| PII | `domain_name` and `hostname` are organisationally identifying. The planned session and recent-profile telemetry will introduce **direct personal identifiers** and is the primary pseudonymisation concern (§6). |
| Required change | **Roadmap item 7** — narrowly scoped, domain-aware session and recent-profile telemetry. Not implemented in this tranche. C5 is the weakest-evidenced condition in the current agent and the extension is a prerequisite for using it. |
| Nessus / CIS-CAT | Neither supplies interactive-use evidence. C5 depends on this agent's planned extension; it has no external corroboration source. |

### C6 — Low-privilege pathway

| Item | Detail |
| --- | --- |
| Modules | [Host.Users.ps1](../modules/host/Host.Users.ps1), [Security.RDP.ps1](../modules/security/Security.RDP.ps1), [Security.WinRM.ps1](../modules/security/Security.WinRM.ps1), [Vul.Privileges.Token.ps1](../modules/vulnerability/Vul.Privileges.Token.ps1), [Security.UAC.ps1](../modules/security/Security.UAC.ps1), plus the `Vul.*` permission modules |
| Paths | `host.user_accounts[]` → `rid`, `name`, `enabled`, `is_admin`, `is_system_account`, `principal_source`, `password_never_expires`, `last_logon`<br>`host.group_memberships[]` → `group_name`, `members[]`<br>`security.rdp` → `rdp_enabled`, `nla_required`, `allowed_users[]`<br>`security.winrm` → `service_state`, `server_auth.basic`, `allow_unencrypted`<br>`vulnerability.token_privileges` → `user`, `privileges[]` (`privilege`, `state`, `is_dangerous`), `dangerous_enabled_count`<br>`security.uac` → `uac_enabled`, `consent_prompt_standard` |
| Establishes | Local account inventory and administrator membership; which principals are permitted RDP access; whether remote-management entry points are running and how they authenticate; **the privileges held by the collecting account's token**; UAC's elevation posture for standard users. |
| Cannot establish | **Privileges held by any principal other than the account that ran the agent.** `whoami /priv` reports the *current token only* ([Vul.Privileges.Token.ps1:53](../modules/vulnerability/Vul.Privileges.Token.ps1#L53)). If the agent runs elevated, `dangerous_enabled_count` describes the administrator's token and says nothing about a low-privileged attacker's starting position — reading it as a low-privilege pathway would **invert the finding**. This makes `scan_metadata.ran_as_admin` a mandatory qualifier for any C6 use of this field. `Get-LocalGroupMember` also cannot resolve members of groups containing orphaned or unresolvable domain SIDs, and on domain-joined hosts the nested domain group memberships that confer local admin are not expanded. |
| Availability | **partial** — local account and entry-point evidence available; per-principal privilege evidence absent; domain-nested admin paths absent |
| Failure ambiguity | **A, B, C, E.** `host.user_accounts` and `host.group_memberships` are assigned outside their `try` blocks, so a failure yields `[]` (**A**). Within `group_memberships`, a per-group member failure inserts the **literal string `"Error retrieving members"` into the `members[]` array** ([Host.Users.ps1:89](../modules/host/Host.Users.ps1#L89)) — an in-band error sentinel that will be parsed downstream as a principal name unless explicitly filtered (**C**). `rdp.allowed_users` uses `-ErrorAction SilentlyContinue` and yields `[]` for both "group is empty" and "enumeration failed". `vulnerability.token_privileges` uses **B**. |
| PII | **Yes — the highest concentration in the agent.** `user_accounts[].name`, `group_memberships[].members[]`, `rdp.allowed_users[]`, `token_privileges.user`, and `scan_metadata.running_user` / `running_user_sid` are all direct principal identifiers. The planned session evidence will add more. |
| Required change | (i) Acquisition outcome per module (§5). (ii) Remove the in-band `"Error retrieving members"` sentinel in favour of a structured per-group outcome. (iii) Session/pathway evidence via roadmap item 7. (iv) Pseudonymisation of all principals **in the ingestion layer**, before analytical datasets are produced (§6.4). |
| Nessus / CIS-CAT | Nessus credentialed checks corroborate account and group state. CIS-CAT supplies benchmark expectations for user-rights assignment. Neither replaces the agent's token-privilege observation. |

### C7 — Protection degradation

| Item | Detail |
| --- | --- |
| Modules | [Security.Antivirus.ps1](../modules/security/Security.Antivirus.ps1), [Security.DefenderAdvanced.ps1](../modules/security/Security.DefenderAdvanced.ps1) |
| Paths | `security.antivirus` → `product_name`, `product_state` (`ProductState`, `HexadecimalState`, `OperationalState`, `SignatureStatus`), `running_mode`, `real_time_protection`, `antivirus_enabled`, `antispyware_enabled`, `antivirus_signature_updated`, `antispyware_signature_updated`<br>`security.defender_advanced` → `tamper_protection`, `network_protection`, `asr_rules_blocking` |
| Establishes | The registered AV product and its decoded `productState` (operational state and signature currency); for Defender, real-time protection state, running mode and signature timestamps; tamper-protection state. This is the agent's **strongest** condition evidence — it is directly observed, decoded from an authoritative provider, and timestamped. |
| Cannot establish | **Whether protection was degraded at any time other than the moment of observation.** All fields are point-in-time. A host whose real-time protection was disabled for a week and re-enabled an hour before collection reports as healthy. `signature_updated` timestamps partially compensate by revealing staleness. `product_state` for third-party AV depends on the vendor correctly registering with `SecurityCenter2`; several EDR products do not register or register misleadingly. |
| Availability | **available** for Defender; **partial** for third-party AV |
| Failure ambiguity | **D (severe), B, E.** The `SecurityCenter2` query uses `-ErrorAction SilentlyContinue` ([Security.Antivirus.ps1:33](../modules/security/Security.Antivirus.ps1#L33)). If the WMI namespace query fails or is denied, `$avInfo` is `$null` and the module writes **`product_name: "Not Detected"`** and returns. *"The WMI query failed"* and *"this host genuinely has no antivirus"* therefore produce **identical output**, and the second reading is a serious C7 finding. This is the clearest case in the agent where an acquisition failure masquerades as a substantive negative result. If the *outer* `catch` is reached instead, `security.antivirus` is absent entirely (**B**), which is at least detectable. |
| PII | No — product and state information only. |
| Required change | (i) **`Security.Antivirus` must separate `unavailable`/`failed`/`restricted` from an affirmative "no AV product registered" result. Until it does, `product_name: "Not Detected"` must not be treated as evidence of protection degradation.** (ii) Acquisition outcome per module (§5). |
| Nessus / CIS-CAT | Nessus credentialed AV plugins provide an independent detection path that does not rely on `SecurityCenter2`, and are the appropriate cross-check for the ambiguity above. |

### 3.1 Summary

| Condition | Availability | Dominant failure modes | Blocking gap |
| --- | --- | --- | --- |
| C1 Remote reachability | partial | A, E | Reachability is external by construction (Rule 1); active firewall profile not recorded |
| C2 Component state | partial | A, B, D, E | Per-user software hives not collected; partial reads invisible |
| C3 Exploit prerequisite | partial | **C**, A, E | Fabricated `$true` on read failure; assumed defaults indistinguishable from observations |
| C4 Compensating mitigation | partial | **C**, B, E | Device Guard failure renders as confident `false` |
| C5 Interactive use | **absent** | B | Requires roadmap item 7; no external corroboration exists |
| C6 Low-privilege pathway | partial | A, B, C, E | Token privileges describe the collector, not an attacker; in-band error sentinel |
| C7 Protection degradation | available / partial | **D**, B, E | `"Not Detected"` conflates failure with absence |

**Three defects fabricate evidence rather than merely losing it, and are the priority for the acquisition-status tranche:** the `Security.LegacyProtocols` `$true` defaults (C3), the `Security.HostSecurity` Device Guard `false` values (C4), and the `Security.Antivirus` `"Not Detected"` conflation (C7).

---

## 4. Current error-handling limitations

### 4.1 The runner cannot detect module failure

This is structural, and confirms the concern raised in the governing task.

1. **Every module catches its own errors internally.** No study-relevant module rethrows. Failures are written to a side-channel log via `Write-LogMessage` and execution continues.
2. **The runner wraps no module invocation in `try`/`catch`.** There is no error handling anywhere in [Invoke-VKScan.ps1](../core/Invoke-VKScan.ps1).
3. **`modules_executed` records invocation, not success.** `$modulesExecuted.Add(...)` runs unconditionally on the line after each call. A module that failed completely still appears in `modules_executed`, so the field cannot be used to gauge collection completeness.
4. **Every module ends with a hardcoded `SUCCESS` console message**, several of which include counts (`"(0 processes)"`) that read as findings.
5. **The error log is out-of-band and non-durable.** `Write-LogMessage` appends to `outputs/error.log`, which is **deleted at the start of every scan** ([Invoke-VKScan.ps1:83-85](../core/Invoke-VKScan.ps1#L83-L85)) and is never incorporated into the JSON. The preserved raw evidence therefore contains **no record of what failed**. For a dissertation artefact where raw JSON is the source evidence, this is disqualifying for any absence-based claim.
6. **A terminating error would abort the whole scan.** Because nothing is guarded at the runner level, an unhandled terminating error in any module ends the run before `ConvertTo-Json` executes and **no output file is produced at all**.

Consequence: **acquisition outcome cannot currently be inferred from the JSON by any means.** Rule 2 applies without exception until §5 is implemented.

### 4.2 Failure-mode taxonomy

| Code | Pattern | Representative sites | Downstream reading |
| --- | --- | --- | --- |
| **A** | Empty collection assigned on failure | `network_config.*` (all five), `firewall_profiles`, `firewall_rules`, `rdp.allowed_users`, `winrm.listeners`, `user_accounts`, `group_memberships`, `windows_updates.installed_recent` | Failure ≡ genuine empty. Silent. |
| **B** | Key absent on failure | `host.services`, `host.processes`, `security.uac`, `security.antivirus` (outer), `security.defender_advanced`, `vulnerability.token_privileges` | Detectable as missing, but cause unknowable. |
| **C** | Failure coerced to a definite value | `legacy_protocols.llmnr_enabled`/`mdns_enabled` → `$true`; `host_security.security_services[].configured`/`running` → `$false`; `group_memberships[].members[]` → `"Error retrieving members"` | **Fabricated observation.** Actively misleading. |
| **D** | Failure indistinguishable from a substantive negative | `antivirus.product_name` → `"Not Detected"`; `installed_software` silently short | **Failure presents as a finding.** |
| **E** | Reported as executed and successful regardless | `modules_executed`; all `Write-VKStatus … SUCCESS` | Completeness cannot be assessed. |

**Good practice already present**, which the refactor should generalise: `smb.smbv1_enabled` and `host_security.dep_policy`/`vbs_status`/`kernel_dma_protection` correctly use `$null` on failure; `winrm.service_state` uses the explicit string `"Unknown"`.

---

## 5. Proposed acquisition contract (proposal only — not implemented)

### 5.1 Outcome vocabulary

Exactly four values. Every study-relevant module emits precisely one per collection unit.

| Outcome | Meaning | Empty result permitted |
| --- | --- | --- |
| `success` | Collection completed correctly. **Includes a valid zero-result collection** — the provider was queried, answered, and the answer was legitimately empty. | Yes — and an empty result under `success` makes absence **assessable**, subject to the condition-specific qualification in Rule 2 |
| `failed` | Collection was attempted but ended because of an unexpected error (provider exception, malformed response, timeout, parse failure). | Result must be treated as unknown |
| `restricted` | Collection could not complete because permissions or policy denied access (access denied, insufficient privilege, blocked by policy or tamper protection). | Result must be treated as unknown |
| `unavailable` | The required API, provider, feature or capability was not present on the host (WMI namespace absent, cmdlet not present, optional feature not installed, Defender not the active AV). | Result must be treated as unknown |

`restricted` and `unavailable` are deliberately separated from `failed` because they carry different analytical meaning: `restricted` is usually remediable by re-collecting with elevation, whereas `unavailable` is a stable property of the host and is itself informative — "Defender is not the active AV" is a legitimate observation, not an error.

### 5.2 What acquisition outcome is NOT

The envelope records **only whether collection worked**. It must remain strictly separate from the following, all of which are determined downstream by the dissertation artefact:

- **condition applicability** — whether C*n* applies to this host at all;
- **contextual evidence state** — how the evidence is classified for analysis;
- **confirmed presence or absence** — a substantive claim, which requires `success` *plus* the data;
- **contextual direction or weight** — scoring inputs, which belong to the Priority Index calculation and are out of agent scope entirely.

The permitted inference is strictly one-directional and does **not** by itself license an absence claim:

- **`success` + empty ⇒ absence becomes *assessable*.** Whether it may be *asserted* is then decided by the condition-specific applicability, coverage, authority and field-semantics rules set out in Rule 2 (§1.1). Where those rules do not permit the inference, the contextual evidence state remains unknown or neutral.
- **Any outcome other than `success` ⇒ absence may never be claimed**, regardless of what the data field contains.

The agent asserts nothing beyond the acquisition outcome itself. It does not determine applicability, coverage, authority or field semantics, and it must not be extended to do so.

### 5.3 Example structure

```json
{
  "module_id": "security.antivirus",
  "observation_start": "2026-08-18T09:14:22Z",
  "observation_end": "2026-08-18T09:14:23Z",
  "acquisition_outcome": "restricted",
  "agent_version": "2.1.0",
  "schema_version": "1.1",
  "data": null,
  "error": {
    "category": "access_denied",
    "provider": "root/SecurityCenter2:AntiVirusProduct",
    "message": "Access denied querying SecurityCenter2 namespace.",
    "exception_type": "System.UnauthorizedAccessException"
  }
}
```

And the same module on a successful, genuinely-empty collection — the case the current agent cannot express:

```json
{
  "module_id": "host.network_config.udp_listeners",
  "observation_start": "2026-08-18T09:14:25Z",
  "observation_end": "2026-08-18T09:14:26Z",
  "acquisition_outcome": "success",
  "agent_version": "2.1.0",
  "schema_version": "1.1",
  "data": [],
  "error": null
}
```

`error` is `null` whenever `acquisition_outcome` is `success`, and populated for `failed`, `restricted` and `unavailable`. `observation_start`/`observation_end` are per-module and ISO 8601 UTC, distinct from the scan-level `scan_start`/`scan_end`.

### 5.4 Design decision: wrap, or parallel metadata collection?

**Option A — wrap each module's data**

Each module's section value becomes an envelope object with the payload under `data`.

- Outcome and payload are structurally inseparable, so no consumer can read the payload without encountering the outcome. This is the strongest possible guarantee against Rule 2 being violated by accident.
- **Breaks every existing JSON path.** `security.antivirus.product_name` becomes `security.antivirus.data.product_name`. Any downstream consumer of the existing contract must change in lockstep.
- **Adds one nesting level to every path**, which — per §2.3 — pushes `host.windows_updates.pending_updates[].kb_numbers[]` and `host.network_shares[].permissions[].account` past depth 5 and would truncate them. Requires a depth increase as a hard prerequisite.
- Requires editing every module's assignment site.

**Option B — parallel `acquisition` metadata collection (recommended)**

A fifth top-level key, keyed by module identifier, sitting alongside the untouched four-key envelope.

```json
{
  "scan_metadata": { "...": "..." },
  "acquisition": {
    "security.antivirus": {
      "observation_start": "2026-08-18T09:14:22Z",
      "observation_end": "2026-08-18T09:14:23Z",
      "acquisition_outcome": "restricted",
      "agent_version": "2.1.0",
      "schema_version": "1.1",
      "error": { "category": "access_denied", "provider": "root/SecurityCenter2:AntiVirusProduct", "message": "Access denied.", "exception_type": "System.UnauthorizedAccessException" }
    },
    "host.network_config": { "...": "..." }
  },
  "host": { "...": "..." },
  "security": { "...": "..." },
  "vulnerability": { "...": "..." }
}
```

**Recommendation: Option B**, for four reasons.

1. **Every existing JSON path is preserved unchanged.** The four required top-level sections and all documented field paths survive, so this document's C1–C7 mappings remain valid and no downstream consumer breaks. This matters disproportionately because the raw JSON is retained as immutable source evidence — evidence collected before and after the change stays directly comparable on the paths that carry the observations.
2. **It adds no nesting to existing paths.** The depth-5 truncation risk identified in §2.3 is avoided entirely for existing data; only the shallow `acquisition` subtree is new.
3. **It is additive at the module boundary.** Modules keep writing their data exactly as they do now; the runner wraps each invocation and records the outcome. Under Option A, every module's assignment site must change, which is a far larger diff against modules whose collection logic is otherwise validated.
4. **It naturally supports sub-module granularity.** `Host.NetworkConfig` performs five independent collections with five independent failure modes; `Host.Software` reads two registry hives. A flat, dotted key space (`host.network_config.udp_listeners`) expresses this cleanly, whereas Option A would force either a nested envelope per sub-collection or a loss of granularity.

**The accepted cost of Option B** is that outcome and payload are separable, so a careless consumer could read `security.antivirus` without consulting `acquisition["security.antivirus"]`. This is mitigated in the ingestion layer rather than the agent, by the schema-conformance rules in §5.5. That check belongs downstream and is a validation responsibility, consistent with the governing scope.

### 5.5 Schema handling and conformance

The acquisition envelope is **not** an optional enrichment. Under schema 1.1 it is part of the contract, and the ingestion layer enforces it.

#### 5.5.1 Schema 1.1 — acquisition metadata is required

- **Every study-relevant collection unit must carry the required acquisition metadata**: `module_id` (or its key position), `observation_start`, `observation_end`, `acquisition_outcome`, `agent_version` and `schema_version`, plus structured `error` information for any outcome other than `success`.
- **Missing required acquisition metadata makes the input schema-invalid.** A schema-1.1 artefact in which a study-relevant collection unit has no corresponding `acquisition` entry, or has an entry lacking a required field, does not conform to the contract.
- **Schema-invalid input is quarantined.** It is held, reported and excluded from analytical datasets pending investigation. It is not partially admitted, not repaired in place, and not silently downgraded.
- **Ingestion must not invent a `failed` outcome.** Substituting `failed` for absent metadata would fabricate an acquisition observation the agent never made, which is the same class of defect as the three agent-side behaviours identified in §3.1. Absent metadata is a **schema-validity** problem, not an acquisition outcome. The four outcomes are assertions by the collector about what happened at collection time; nothing downstream is entitled to author them.

#### 5.5.2 Schema 1.0 — legacy evidence

Evidence already collected under schema 1.0 carries no acquisition metadata by construction, and is therefore **legacy evidence**. It is not quarantined — it predates the contract rather than violating it — but it is read under restricted terms:

- **Directly observed presence may remain inspectable.** Where a schema-1.0 artefact records a positive observation (a service present and running, an AV product registered with a decoded `productState`, an RDP listener configured), that observation may still be examined, subject to the field-level caveats in §3.
- **Empty or missing results cannot support confirmed absence.** Under schema 1.0 there is no way to distinguish a successful zero-result collection from failure, restriction or unavailability (§4.1), so the first stage of Rule 2 can never be satisfied. Every empty or missing schema-1.0 value is therefore **unknown**, never absent.
- The three evidence-fabricating behaviours (§3.1) mean that some schema-1.0 *positive-looking* values are also unreliable — specifically `legacy_protocols.llmnr_enabled`/`mdns_enabled` when `$true`, `host_security.security_services[]` when `false`, and `antivirus.product_name` when `"Not Detected"`. These must be excluded from legacy inspection regardless of the rule above.

### 5.6 Implementation note for the later tranche

Because modules currently swallow their own errors (§4.1), a runner-level wrapper alone **cannot** determine outcome — it would record `success` for every module regardless. The refactor must therefore change how modules signal failure, not merely how the runner records it. The minimal viable approach is a shared helper in `VK.Utilities.ps1` that modules call to register an outcome for a named collection unit, defaulting to `success` and being downgraded from within existing `catch` blocks. This keeps the module diffs small and localised to the `catch` sites already identified in §4.2. Determining `restricted` versus `failed` requires exception-type and message inspection; `Security.WinRM` already contains a rudimentary version of this pattern ([Security.WinRM.ps1:82](../modules/security/Security.WinRM.ps1#L82)) that can be generalised.

---

## 6. Versioning and pseudonymisation

### 6.1 Does the Tranche 1 work change observable behaviour?

**Yes, marginally — but it does not change the evidence contract.**

Removing the duplicate `Host.NetworkConfig` execution changes two observable things:

1. `scan_metadata.modules_executed` no longer contains `"host.network_config"` twice.
2. `host.network_config` is now populated from a single observation rather than being written and then **silently overwritten** by a second, later observation. The previous behaviour meant the retained ARP, TCP and UDP data reflected the *second* run, taken after all other host modules had executed, while `scan_start` and the surrounding module order implied the first. The correction makes the observation point consistent with the documented module order.

No field is added, removed or renamed, and no field's meaning changes. The **evidence contract is unchanged**; only a redundant execution and a duplicated list entry are removed.

### 6.2 Versioning recommendation

The project has **no documented versioning policy** — `VK.Config.ps1` carries a bare `$script:VKAgentVersion = "2.0"` with no scheme stated, and `schema_version` is a hardcoded `"1.0"` string literal in the runner. There is therefore no established policy that *clearly requires* a patch increment, and per the governing instruction **no version has been changed in this tranche.**

Recommendations:

| Item | Current | Recommended | Rationale |
| --- | --- | --- | --- |
| Agent version, this tranche | 2.0 | **2.0.1** *(optional, at your discretion)* | Behaviour-affecting bug fix with no contract change. Only worth applying if you first adopt semantic versioning; otherwise leave at 2.0 and record the fix in a changelog. |
| Agent version, acquisition-status release | 2.0 | **2.1.0** | New capability (acquisition envelope, session telemetry, feature state), backwards-compatible for existing paths under Option B. |
| Schema version, this tranche | 1.0 | **1.0 — unchanged** | No contract change. |
| Schema version, acquisition-status release | 1.0 | **1.1** | A new fifth top-level `acquisition` key that is **additive for existing consumers but required by the schema 1.1 study contract — not optional**. Consumers reading only the four original sections remain compatible and need no change, which is what the minor increment signals; but a schema-1.1 artefact that omits required acquisition metadata for a study-relevant collection unit is **schema-invalid and quarantined** (§5.5.1). Reserve **2.0** for the breaking change that Option A would have required — it is not needed. |

I further recommend adopting an explicit versioning policy statement in `VK.Config.ps1` before the freeze (roadmap item 13), since "increment versions when the evidence contract changes" (item 12) cannot be enforced or tested against an unstated scheme.

### 6.3 Divergence that must be resolved before the freeze

The standalone build template emits a **different `scan_metadata` block** from the modular runner. Compare [Build-Standalone.ps1:378-386](../build/Build-Standalone.ps1#L378-L386) with [Invoke-VKScan.ps1:349-360](../core/Invoke-VKScan.ps1#L349-L360): the standalone build **omits `schema_version`, `running_user` and `running_user_sid`**.

This means the two execution modes do not produce the same evidence contract. `schema_version` in particular is the field the ingestion layer would use to route and validate — its absence in standalone output is a material defect. It is **out of scope for this tranche** (correcting it is not part of the duplicate-execution fix and would be an unrelated change), but it must be resolved before controlled collection, and the decision of which artefact is used for collection should be made explicitly. The Pester suite added in this tranche asserts the required `scan_metadata` fields against a fixture rather than against the build template, so it does not currently catch this; a build-output conformance test is recommended for the tranche that fixes it.

### 6.4 Pseudonymisation

Confirmed position, unchanged in this tranche:

- **Secured raw source evidence remains unchanged.** The agent collects and emits real principal names, SIDs, hostnames and domain names as observed, and the raw JSON is retained in the secured raw zone exactly as collected. Nothing in this section alters, redacts or reduces the raw artefact.
- **Pseudonymisation occurs in the ingestion layer**, before any analytical dataset is produced, using a **stable experiment-specific method** so that the same principal maps to the same pseudonym across hosts and across collection rounds — a requirement for any longitudinal or cross-host analysis.
- **No pseudonymisation, hashing or obfuscation has been added to the agent**, and none should be. Ad hoc or randomly-salted hashes computed at the agent would be unstable across runs and would destroy exactly the linkage the analysis depends on, while also degrading the raw evidence.

#### 6.4.1 Analytical ingestion uses an explicit field allow-list

Analytical datasets are built by **explicit allow-list**, not by copying the raw artefact and denying selected fields. Only fields named on the allow-list enter an analytical dataset; anything unlisted is excluded by default, including fields introduced by future agent versions.

This direction matters. A deny-list fails open — a new field added by a later agent release would flow into analysis unreviewed. An allow-list fails closed, so extending the agent (roadmap items 7–8, both of which add principal-bearing evidence) cannot silently widen the analytical surface. Each new field requires a deliberate decision to admit it.

Two consequences follow:

- **Free-text process command lines are excluded.** `host.processes[].command_line` is **not** on the allow-list and does not enter analytical datasets, unless a frozen rule specifically requires it. It is unbounded free text that can embed usernames, profile paths and credentials passed as arguments, and a mapping-based pseudonymiser cannot sanitise it.
- **Any required free-text value must be scrubbed before entering analytical datasets.** Where a frozen rule does require a free-text field, admission is conditional on scrubbing it first — not on pseudonymising the identifiers it happens to contain. Scrubbing removes the unbounded content; pseudonymisation only maps the identifiers it can recognise, and by construction cannot recognise a secret it has never seen.

#### 6.4.2 Fields requiring pseudonymisation at ingestion

Where a field below is admitted by the allow-list, it must be pseudonymised. Inclusion here identifies the treatment required; it does not by itself admit the field.

| Path | Identifier type |
| --- | --- |
| `scan_metadata.hostname`, `host.hostname` | Host identity |
| `scan_metadata.running_user`, `scan_metadata.running_user_sid` | Principal (name and SID) |
| `host.user_accounts[].name` | Principal |
| `host.base_sid` | Machine SID (identifies the host, and with RIDs reconstructs account SIDs) |
| `host.group_memberships[].members[]` | Principal |
| `security.rdp.allowed_users[]` | Principal |
| `vulnerability.token_privileges.user` | Principal |
| `host.processes[].owner` | Principal |
| `host.processes[].command_line` | **Free text — excluded from the allow-list (§6.4.1).** If a frozen rule requires it, it must be scrubbed before admission, not merely mapped. |
| `host.domain_status.domain_name` | Organisational identity |
| `host.manufacturer.serial_number` | Device identity |
| `host.network_interfaces[].mac_address`, `host.network_config.arp_table[].mac_address` | Device identity |
| `host.network_interfaces[].ip_address`, `host.network_config.tcp_connections[].remote_address` | Network identity |
| `host.sessions.session_principals[].user_name`, `.domain_name` *(implemented, Tranche 2C)* | **Principal — highest sensitivity in the agent** |
| `host.sessions.user_profiles[].sid` *(implemented, Tranche 2C)* | Principal (SID) |

`host.processes[].command_line` warrants specific attention: it is the only free-text field that can contain arbitrary secrets, which is why §6.4.1 excludes it from the allow-list outright rather than relying on pseudonymisation to make it safe.

---

## 7. Resolved decisions

The open questions raised during the Tranche 1 audit are now **closed**. The decisions below are recorded as change-controlled and govern subsequent tranches.

### 7.1 Controlled collection runtime — **Windows PowerShell 5.1**

Controlled collection runs under Windows PowerShell 5.1.

*Current consequence:* the agent must remain 5.1-compatible. No PowerShell 7-only syntax, operators or cmdlets may be introduced by the remaining extension, and depth behaviour must be re-verified on 5.1 whenever nesting changes — 5.1 truncates silently.

The configured JSON depth is now **10**, and the latest verification on this runtime is **617 passed / 0 failed / 0 skipped / 0 not run** under Pester 6.1.0 (§11.10). The depth-5 measurement and its rationale are retained in §2.3 as the Tranche 1 historical record; they no longer describe the current configuration.

### 7.2 Final collection artefact — **generated dependency-free standalone script**

Controlled collection uses the **generated dependency-free standalone script**.

*Status: **RESOLVED**, no longer blocking.* The divergence recorded at Tranche 1 — the standalone build omitting `schema_version`, `running_user` and `running_user_sid` from `scan_metadata` (§6.3) — was corrected in Tranche 2A. Metadata and contract parity are now **implemented and asserted against the generated output**, not merely against the build template: the parity suite generates the standalone into the Pester `TestDrive`, parses it, and asserts the full required `scan_metadata` field list, the five-section envelope, agent 2.1.0, schema 1.1, depth 10, every instrumented unit identifier, self-containment of the acquisition helpers, and dependency-freedom. Generation failure is surfaced as a **failing test** carrying the captured error; no generation-dependent test is skipped.

### 7.3 Fifth top-level `acquisition` key — **accepted for schema 1.1**

The `acquisition` key is accepted as a fifth top-level section for schema 1.1. §5.4 Option B stands as the design. `acquisition` will **not** be nested under `scan_metadata`.

*Consequence:* the four-section envelope is superseded for schema 1.1 by a five-section envelope. The key is additive for existing consumers but required by the schema-1.1 study contract (§5.5.1, §6.2) — a study-relevant collection unit without conforming acquisition metadata renders the artefact schema-invalid and subject to quarantine, and ingestion must not invent a `failed` outcome to fill the gap.

**Test impact — action required in Tranche 2.** The schema-1.0 output-contract test currently asserts **exactly four** top-level sections:

```powershell
# tests/VK.OutputContract.Tests.ps1 — 'Envelope: required top-level sections'
$keys | Should -Be @('scan_metadata', 'host', 'security', 'vulnerability')
```

This assertion is correct for schema 1.0 and **will fail once schema 1.1 introduces the required fifth `acquisition` section**. It must be updated during Tranche 2 to assert the five-section schema-1.1 envelope, ideally selecting the expected section list by `schema_version` so that both schema-1.0 legacy fixtures and schema-1.1 fixtures can be asserted in the same suite. The failure is expected and intended — it is the contract test doing its job — and must not be worked around by relaxing the assertion to a subset check, which would stop the test detecting a missing section.

### 7.4 The three evidence-fabricating behaviours — **must be corrected before pilot collection**

The three behaviours identified in §3.1 must be corrected **before pilot collection**, ahead of the full acquisition-status refactor:

1. `Security.LegacyProtocols` — `llmnr_enabled`/`mdns_enabled` set to `$true` in their `catch` blocks (C3);
2. `Security.HostSecurity` — Device Guard `security_services[]`/`security_properties[]` emitted as `false` when the CIM query failed (C4);
3. `Security.Antivirus` — `product_name: "Not Detected"` returned when the `SecurityCenter2` query failed or was denied (C7).

*Rationale:* these are the only defects that cause the agent to assert observations it did not make. Every other failure mode loses information; these three manufacture it. Pilot data collected before they are fixed would be contaminated in a way that cannot be detected or repaired after the fact, because the fabricated values are indistinguishable from genuine ones in the artefact. Each is a small, localised change at a known `catch` site (§4.2), and each is a behaviour change requiring change control and a version increment.

### 7.5 Per-user software-hive expansion — **excluded**

General expansion of `Host.Software` to per-user registry hives (`HKCU`, `HKU\<SID>`) is **excluded** as general-purpose inventory expansion, which is outside the governing scope.

*Exception:* a narrowly scoped observation may be added **only** where a frozen rule in the registry specifically requires it. Any such addition must be justified by the naming rule, limited to the fields that rule needs, and must not become a general per-user inventory.

*Consequence, which must be carried into the analysis:* the C2 coverage limitation recorded in §3 is now **permanent** rather than provisional. A successful empty or complete `installed_software` result covers machine-scope software only. Under the coverage axis of Rule 2 (§1.1), it can never support confirmed absence of a user-scope application, regardless of acquisition outcome.

---

## 8. Tranche 2A implementation record

Implemented against the decisions in §7. This section records **what exists in the code now**, as distinct from the §5 proposal.

### 8.1 Status

| Item | State |
| --- | --- |
| Agent version | **2.1.0** |
| Schema version | **1.1** |
| JSON depth | **10** |
| Five-section envelope | Implemented in the runner and the build source |
| Fail-closed acquisition helpers | Implemented in [core/VK.Utilities.ps1](../core/VK.Utilities.ps1) |
| Modular/standalone metadata parity | Corrected — §7.2 prerequisite discharged |
| Modules instrumented | **3 of the study-relevant set** |
| Modules outstanding | All others — Tranche 2B |
| Pilot eligibility | **No.** See the banner at the head of this document |
| Approved C1–C7 meanings | **Unchanged** |

Option B from §5.4 was implemented as decided in §7.3: a fifth top-level `acquisition` key, keyed by dotted collection-unit identifier, adding no nesting to existing payload paths and duplicating no payload data.

### 8.2 Helper interface

Documented in full in the header comment of [core/VK.Utilities.ps1](../core/VK.Utilities.ps1). Tranche 2B instruments the remaining modules with the same interface.

| Helper | Purpose |
| --- | --- |
| `Initialize-VKAcquisition` | Resets the store. Runner calls it once, before any module runs. |
| `Start-VKAcquisition -UnitId -DataPaths [-Provider]` | Registers a unit as **pending** and stamps `observation_start`. Called **before** the provider is invoked. |
| `Complete-VKAcquisition -UnitId` | Marks `success`. Called only after the query returned correctly — including a correct zero-result return. |
| `Set-VKAcquisitionFailure -UnitId [-ErrorRecord] [-Provider] [-Outcome] [-Category] [-Message]` | Records a non-success outcome, classified conservatively unless `-Outcome` overrides. |
| `Set-VKAcquisitionUnavailable -UnitId [-Category] [-Provider] [-Message]` | Wrapper for a capability that is legitimately absent. |
| `Get-VKAcquisitionClassification -ErrorRecord` | Conservative classifier. Never returns `success`. |
| `Complete-VKAcquisitionReport` | Fail-closed sweep. Runner calls it immediately before serialisation. |
| `Get-VKAcquisitionReport` | Projects the store into the ordered schema 1.1 section. |

### 8.3 How fail-closed behaviour is enforced

Four independent mechanisms, so no single omission can produce a false `success`:

1. **Registration defaults to pending.** `Start-VKAcquisition` records an internal `pending` state, never `success`. There is no code path that defaults a unit to success and later downgrades it.
2. **Success requires an explicit call.** Only `Complete-VKAcquisition` sets `success`, and it is reached only on the non-exception path after the provider returned. Invocation alone cannot produce it.
3. **The pre-serialisation sweep.** `Complete-VKAcquisitionReport` converts any unit not in a final state — or holding an outcome outside the permitted four — to `failed` / `incomplete_collection`, stamping any missing timestamp. A module that returns early, throws past its own handler, or is registered but never wired up therefore fails closed.
4. **The projection defends the vocabulary again.** `Get-VKAcquisitionReport` re-checks every outcome against the permitted four and emits `failed` / `incomplete_collection` for anything else, so the internal `pending` state cannot reach JSON even if the sweep were skipped.

Two further guards: completing a unit that was never registered yields `failed` / `unregistered_unit` rather than success, and `Set-VKAcquisitionFailure` is constrained by `ValidateSet` to the three non-success outcomes.

### 8.4 Collection-unit identifiers and governed data paths

Identifiers are stable and must not be renamed without a schema increment.

#### Security.LegacyProtocols — six units

| Unit identifier | Provider | Governed data paths |
| --- | --- | --- |
| `security.legacy_protocols.llmnr` | `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` | `security.legacy_protocols.llmnr_enabled`, `.llmnr_value_source` |
| `security.legacy_protocols.mdns` | `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` | `security.legacy_protocols.mdns_enabled`, `.mdns_value_source` |
| `security.legacy_protocols.netbios` | `root\CIMV2:Win32_NetworkAdapterConfiguration` | `security.legacy_protocols.netbios_adapters`, `.netbios_any_enabled` |
| `security.legacy_protocols.wpad_service` | `root\CIMV2:Win32_Service(WinHttpAutoProxySvc)` | `security.legacy_protocols.wpad_service_state`, `.wpad_service_start_type` |
| `security.legacy_protocols.wpad_auto_detect` | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings` | `security.legacy_protocols.wpad_auto_detect` |
| `security.legacy_protocols.tls_protocols` | `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols` | `security.legacy_protocols.tls_protocols` |

#### Security.HostSecurity — three units

| Unit identifier | Provider | Governed data paths |
| --- | --- | --- |
| `security.host_security.kernel_dma_protection` | `ntdll.dll:NtQuerySystemInformation(SystemDmaGuardPolicyInformation)` | `security.host_security.kernel_dma_protection` |
| `security.host_security.dep_policy` | `root\CIMV2:Win32_OperatingSystem` | `security.host_security.dep_policy` |
| `security.host_security.device_guard` | `root\Microsoft\Windows\DeviceGuard:Win32_DeviceGuard` | `security.host_security.vbs_status`, `.security_services`, `.security_properties` |

The Device Guard unit governs three paths because all three derive from the single `Win32_DeviceGuard` query and share its fate. Splitting them would imply independent authority they do not have.

#### Security.Antivirus — two units

| Unit identifier | Provider | Governed data paths |
| --- | --- | --- |
| `security.antivirus.products` | `root\SecurityCenter2:AntiVirusProduct` | `security.antivirus.product_name`, `.product_state`, `.products_detected` |
| `security.antivirus.defender_status` | `Get-MpComputerStatus` | `security.antivirus.running_mode`, `.real_time_protection`, `.antivirus_enabled`, `.antispyware_enabled`, `.antivirus_signature_updated`, `.antispyware_signature_updated` |

`security.antivirus.defender_status` is always registered. Where Defender is not the registered product it resolves to `unavailable` / `provider_not_applicable`; where the product query itself did not succeed it resolves to `unavailable` / `precondition_not_met`. Neither asserts anything about Defender's state.

### 8.4a Fail-closed hardening within the migrated modules

A post-implementation review of the three migrated modules found four residual paths where a provider **answered without throwing but supplied nothing**, and the module converted that into a substantive value and a `success` outcome. All four are corrected; agent, schema and depth are unchanged, as these complete the same unreleased change set.

| Gap | Was | Now |
| --- | --- | --- |
| `Test-Path` on the LLMNR, mDNS, WPAD auto-detect and SCHANNEL keys | A provider error produced a non-terminating error and `$false`, indistinguishable from an absent key, licensing the documented default | `-ErrorAction Stop` on the existence test; only a **successful** negative test may be read as "nothing configured" |
| Native `BootDmaCheck` | Non-zero NTSTATUS returned byte `0`, read as `kernel_dma_protection = $false` and recorded `success` | Non-zero NTSTATUS throws; the catch yields `$null` and a non-success outcome. NTSTATUS success with byte `0` remains a valid observed `false` |
| DEP policy | `$null` property cast to `[int]` became `0` → `"Always Off"` with `success` | Instance and property null-checked before conversion; missing value yields `$null` and `unavailable` / `provider_value_missing` |
| Defender status | `$null` from `Get-MpComputerStatus` left all fields null but completed `success` | Response null-checked before completion; yields `unavailable` / `provider_value_missing` with all six fields null |

**New error category:** `provider_value_missing` — the provider answered but supplied no value. Classified `unavailable`, because the capability was not furnished by the host. It is distinct from an exception-derived outcome and from a successful zero-result collection.

**The absence distinction is unaffected and, on these paths, now sound for the first time.** A successful zero-result collection remains `success` and continues to make absence *assessable* under Rule 2 (§1.1). What changed is that four routes which previously reached `success` without the provider having answered no longer do so. Concretely:

| Situation | Outcome | Payload | Absence assessable? |
| --- | --- | --- | --- |
| Key successfully observed absent | `success` | documented default, `value_source = default_inferred` | Yes, subject to §1.1 |
| Key existence undeterminable | `restricted` / `failed` | `$null`, no `value_source` | No |
| DEP policy genuinely `0` | `success` | `"Always Off"` | Yes, subject to §1.1 |
| DEP policy not supplied | `unavailable` | `$null` | No |
| Zero antivirus products registered | `success` | `products_detected = 0` | Yes, subject to §1.1 |
| Defender status not supplied | `unavailable` | all six fields `$null` | No |

**Additive shape note:** `security.antivirus` pre-initialises all six Defender fields to `$null`, so every path declared in a unit's `data_paths` is always present and explicitly not-observed rather than silently absent. No declared path is added or removed, and the C1–C7 mappings in §3 are unchanged.

### 8.5 Explicit observation versus default inference

Some Windows settings have a documented default that applies when no explicit value is configured. Schema 1.0 emitted the resulting effective value in the same field shape as a directly observed one, with nothing to separate them — and, worse, emitted the same value after a *failed* read.

Schema 1.1 separates three states for LLMNR and mDNS:

| Situation | Effective value | `*_value_source` | Acquisition outcome |
| --- | --- | --- | --- |
| Read succeeded, policy value present | observed value | `explicit` | `success` |
| Read succeeded, policy value absent | documented Windows default | `default_inferred` | `success` |
| Read did not succeed | `$null` | `$null` | `restricted` / `unavailable` / `failed` |

The distinction matters analytically. `explicit` is a direct observation of configured state. `default_inferred` is a sound inference *conditional on the read having succeeded* — which is exactly what the acquisition outcome now establishes. A non-success read produces neither.

`wpad_auto_detect` and the SCHANNEL `tls_protocols` entries assert **no** default: an absent value stays `$null`, because no documented host-wide default applies that the agent can observe.

Provenance markers are additive fields. Existing paths (`llmnr_enabled`, `mdns_enabled`) are preserved and are covered by tests.

### 8.6 What Tranche 2A does *not* change

- The approved C1–C7 condition meanings, contextual rules, weights, applicability and inference boundaries are untouched.
- Rule 2 (§1.1) is unchanged. A `success` outcome with an empty result makes absence **assessable**; it does not independently establish confirmed absence, which still requires the condition-specific applicability, coverage, authority and field-semantics rules to permit it.
- The C1–C7 audit in §3 stands as written. Its `Failure ambiguity` rows remain accurate for every module **except** the three migrated here; those three now express outcome explicitly. The rows are deliberately left intact so the pre-migration state remains on record.

### 8.7 Deferred to Tranche 2B

| Item | Note |
| --- | --- |
| Instrumenting the remaining study-relevant modules | The blocker for pilot eligibility. Until then, schema 1.1 output is incomplete for those units. |
| `Security.DefenderAdvanced` | Still queries `root\SecurityCenter2` with `-ErrorAction SilentlyContinue` and still returns early — leaving `security.defender_advanced` absent — both when Defender is genuinely not the active AV and when the probe failed. Same defect class as the corrected `Security.Antivirus` pathway, and it should be migrated first in Tranche 2B. |
| Session and recent-profile telemetry | Roadmap item 7. C5 remains `absent` until then. |
| Windows feature-state collection | Roadmap item 8, limited to the frozen rule registry. |
| Active-firewall-profile collection | Would let C1 determine the applicable default inbound action. |
| Per-user software hives | **Excluded** by §7.5 unless a frozen rule requires a narrowly scoped observation. |
| Build-output conformance beyond metadata | Parity tests now cover the generated artefact's metadata, envelope, versions, depth and dependency-freedom. Payload-level conformance of a generated collection is a Tranche 2B concern. |
---

## 9. Tranche 2B.1 implementation record

Seven further security modules instrumented against the same acquisition contract. Agent 2.1.0, schema 1.1 and JSON depth 10 are **unchanged** — this completes the same unreleased acquisition-contract release.

> **Still not pilot-ready.** Host and pathway modules remain uninstrumented, so a schema 1.1 artefact is still incomplete for those units. No output from this tranche may be used as controlled research evidence.

### 9.1 Modules migrated

`Security.DefenderAdvanced`, `Security.Firewall`, `Security.SMB`, `Security.RDP`, `Security.WinRM`, `Security.UAC`, `Security.FDE`.

`Security.FDE` is included because controlled Case 9 deliberately varies disk-encryption state as **irrelevant telemetry**. It does not contribute to C1–C7 scoring, but its acquisition outcome must be as trustworthy as any scored evidence.

### 9.2 Collection-unit register (20 new units, 31 total)

| Unit identifier | Provider | Governed paths |
| --- | --- | --- |
| `security.defender_advanced.asr_rules` | `Get-MpPreference` | `asr_rules`, `asr_rules_count`, `asr_rules_blocking` |
| `security.defender_advanced.protection_preferences` | `Get-MpPreference` | `network_protection`, `controlled_folder_access`, `pua_protection`, `cloud_protection`, `sample_submission` |
| `security.defender_advanced.tamper_protection` | `Get-MpComputerStatus` | `tamper_protection` |
| `security.firewall.profiles` | `Get-NetFirewallProfile` (ActiveStore) | `security.firewall_profiles` |
| `security.firewall.inbound_rules` | `Get-NetFirewallRule` (ActiveStore) | `security.firewall_rules` |
| `security.smb.smbv1` | `LanmanServer\Parameters\SMB1` / `Get-WindowsOptionalFeature` | `smbv1_enabled`, `smbv1_value_source` |
| `security.smb.server_registry` | `LanmanServer\Parameters` | `server_signing_required`, `server_signing_enabled`, `server_encrypt_data`, `server_reject_unencrypted`, `null_session_pipes`, `null_session_shares`, `restrict_null_session_access`, `server_value_sources` |
| `security.smb.client_registry` | `LanmanWorkstation\Parameters` | `client_signing_required`, `client_signing_enabled`, `client_insecure_guest_auth`, `client_value_sources` |
| `security.smb.server_configuration` | `Get-SmbServerConfiguration` | `smb2_enabled`, `server_multichannel`, `server_leasing`, `max_channel_per_session` |
| `security.rdp.terminal_server` | `Control\Terminal Server` | `rdp_enabled`, `restricted_admin_enabled` |
| `security.rdp.rdp_tcp` | `…\WinStations\RDP-Tcp` | `port`, `port_value_source`, `nla_required`, `security_layer`, `encryption_level`, `idle_timeout_ms`, `disconnect_timeout_ms`, `session_limit_ms` |
| `security.rdp.allowed_users` | `Get-LocalGroupMember(Remote Desktop Users)` | `allowed_users` |
| `security.winrm.service` | `root\CIMV2:Win32_Service(WinRM)` | `service_state`, `service_start_type` |
| `security.winrm.server_registry` | `WSMAN\Service` | `allow_unencrypted`, `server_auth`, `server_value_sources` |
| `security.winrm.client_registry` | `WSMAN\Client` | `client_auth`, `client_allow_unencrypted`, `client_value_sources` |
| `security.winrm.trusted_hosts` | `WSMAN\Client\TrustedHosts` | `trusted_hosts` |
| `security.winrm.listeners` | `WSMAN\Listener` | `listeners` |
| `security.uac.configuration` | `Policies\System` | all twelve `security.uac.*` fields |
| `security.fde.os_drive` | `Get-BitLockerVolume` | `security.fde_os_drive` |
| `security.fde.additional_volumes` | `Get-BitLockerVolume` | `security.fde_additional_volumes` |

### 9.3 Ambiguity and fabricated-state paths corrected

| Module | Was | Now |
| --- | --- | --- |
| DefenderAdvanced | Re-queried SecurityCenter2 with `SilentlyContinue` and returned early, so "Defender not active" and "probe failed" both left the section absent | Uses `security.antivirus.products`' outcome and product evidence as an explicit precondition: `precondition_not_met` when unknown, `provider_not_applicable` when Defender is not active |
| DefenderAdvanced | A missing ASR action defaulted to `0` / `"Disabled"` | Mismatched or null id/action withholds the ASR unit; protection-preference evidence from the same response survives |
| Firewall | Both collections stayed `@()` on failure | `$null` with a non-success outcome; a genuine zero-rule result is still `@()` |
| SMB | `SilentlyContinue` conflated a failed SMBv1 read with an absent value | Terminating reads; registry-explicit vs `feature_observed` distinguished via `smbv1_value_source` |
| SMB | Documented defaults indistinguishable from observations | `server_value_sources` / `client_value_sources` maps mark each field `explicit` or `default_inferred`; a failed read licenses none |
| SMB | No-admin silently omitted the cmdlet fields | `restricted` / `insufficient_privilege` |
| RDP | One `try` covered both registry keys, so either failure discarded both | Separate `terminal_server` and `rdp_tcp` units |
| RDP | `$null -eq 0` read as "RDP disabled"; `[int]$null` mapped to the least-secure security layer | Every property guarded before comparison or conversion |
| RDP | Failed group enumeration yielded `@()` | `$null`; a genuinely empty group is still `@()` |
| WinRM | Failed service query emitted the string `"Unknown"` | `$null` with a non-success outcome |
| WinRM | Partial listener enumeration could look complete | Terminating; one failure withholds the whole collection |
| UAC | Absent properties silently became `false`, `0` and mapped prompt modes | Every field pre-initialised `$null` and guarded |
| FDE | `Invoke-IfAdmin` swallowed errors; no-admin emitted nothing | Both units always registered; no-admin is `restricted` / `insufficient_privilege` |
| FDE | Missing properties rendered as "Not Fully Encrypted", "Protection Off", "Unknown or Not Encrypted" | Malformed volume throws; the collection is withheld |

### 9.4 Explicit versus default-inferred

Provenance is exposed additively, never by changing an existing value path:

- `security.smb.smbv1_value_source` — `explicit` \| `feature_observed`
- `security.smb.server_value_sources` / `client_value_sources` — per-field `explicit` \| `default_inferred`
- `security.winrm.server_value_sources` / `client_value_sources` — per-field `explicit` \| `default_inferred`
- `security.rdp.port_value_source` — `explicit` \| `default_inferred`

**UAC asserts no default at all.** Windows defaults for those policies vary by edition and servicing state, so inventing one would not be defensible. After a *successful* read an absent value stays `$null`, and the unit still records `success` because the read succeeded.

### 9.5 Successful-empty versus unsuccessful collection

| Situation | Outcome | Payload |
| --- | --- | --- |
| No enabled inbound firewall rules | `success` | `@()` |
| Firewall rule query failed | `restricted`/`failed` | `$null` |
| `Remote Desktop Users` group empty | `success` | `@()` |
| Group enumeration failed | `restricted`/`failed` | `$null` |
| No WinRM listeners configured | `success` | `@()` |
| Listener enumeration failed | non-success | `$null` |
| No additional BitLocker volumes | `success` | `@()` |
| Volume collection failed or malformed | non-success | `$null` |

Rule 2 (§1.1) is unchanged: `success` + empty makes absence **assessable**, never confirmed.

### 9.6 C1–C7 unchanged

No condition meaning, mapping, applicability rule, weight, score or inference boundary was altered. The §3 audit stands; only acquisition metadata and provenance were added, and existing payload paths were preserved.

### 9.7 Still deferred

- remaining host and pathway module instrumentation — **the pilot blocker**;
- domain-aware session and recent-profile telemetry;
- registry-restricted Windows feature-state collection;
- active-firewall-profile extension;
- per-user software hives;
- analytical ingestion, pseudonymisation and scoring.


---

## 10. Tranche 2B.2 implementation record

The seven remaining host and pathway modules instrumented. Agent 2.1.0, schema 1.1 and JSON depth 10 are **unchanged** — this completes the same unreleased acquisition-contract release. Twelve new units bring the total from 31 to **43**, completing migration of every existing study-relevant module.

### 10.1 Modules migrated

`Host.Identification`, `Host.NetworkConfig`, `Host.Services`, `Host.Processes`, `Host.Software`, `Host.Users`, `Vul.Privileges.Token`.

**Deliberately excluded from this tranche:** `Host.WindowsUpdates` (the frozen Table A2 defines C2's current agent sources as services, processes and installed software, with feature state planned separately); `Host.Network`; the ARP, routing and DNS collections inside `Host.NetworkConfig`; manufacturer and BIOS inventory for analytical use; all other vulnerability and permission modules.

### 10.2 Collection-unit register (12 new units)

| Unit identifier | Provider | Governed paths |
| --- | --- | --- |
| `host.identification.hostname` | `env:COMPUTERNAME` | `host.hostname` |
| `host.identification.operating_system` | `root\CIMV2:Win32_OperatingSystem` | `host.os.name`, `.architecture`, `.version`, `.build` |
| `host.identification.computer_system` | `root\CIMV2:Win32_ComputerSystem` | `host.os.platform_role`, `host.domain_status.status`, `.domain_name`, `.workgroup_name` |
| `host.network_config.tcp_connections` | `Get-NetTCPConnection` | `host.network_config.tcp_connections`, `.summary.tcp_connections` |
| `host.network_config.udp_listeners` | `Get-NetUDPEndpoint` | `host.network_config.udp_listeners`, `.summary.udp_listeners` |
| `host.services.inventory` | `root\CIMV2:Win32_Service` | `host.services` |
| `host.processes.inventory` | `root\CIMV2:Win32_Process` | `host.processes` |
| `host.software.hklm_native` | `HKLM:\Software\…\Uninstall` | `host.installed_software` |
| `host.software.hklm_wow6432` | `HKLM:\Software\WOW6432Node\…\Uninstall` | `host.installed_software` |
| `host.users.local_accounts` | `Get-LocalUser` | `host.base_sid`, `host.user_accounts` |
| `host.users.group_memberships` | `Get-LocalGroup` / `Get-LocalGroupMember` | `host.group_memberships`, `host.user_accounts[].is_admin` |
| `vulnerability.token_privileges.current_token` | `whoami.exe /priv /fo csv` | `vulnerability.token_privileges` |

### 10.3 Ambiguity and partial-result pathways corrected

| Module | Was | Now |
| --- | --- | --- |
| Identification | `[int]$osInfo.BuildNumber` on an absent value became build `0` | Every required property guarded before conversion |
| Identification | Manufacturer/BIOS failure sat in the same flow as identity | Legacy raw inventory, uninstrumented, cannot affect the three study units |
| NetworkConfig | All five sub-collections set to `@()` in `catch`, so failure was byte-identical to a genuinely empty host, and `summary` reported `0` | TCP and UDP yield `$null` with a non-success outcome; their summary counts are `$null`, never `0` |
| Services | Assignment inside `try`, so failure left the key absent; console reported `"(0 services)"` after failure | `$null` with a recorded outcome; no count reported after failure |
| Processes | Same shape; `"(0 processes)"` after total failure | `$null`; owner lookup remains optional enrichment |
| Software | Per-hive failure silently shortened the combined list | Per-entry failure makes the hive incomplete; combined list withheld unless every applicable hive succeeded |
| Software | `Sort-Object` collapses an empty pipeline to `$null` | Re-wrapped so a successful empty result stays `@()` |
| Users | Literal `"Error retrieving members"` inserted into `members[]` | Sentinel removed entirely; a member-query failure withholds the whole collection |
| Users | `is_admin` computed as `$false` when membership was unknown | `$null` whenever group evidence did not succeed |
| Users | `"Z"` appended to **local** time | `ToUniversalTime()` before the suffix; one reference time per invocation |
| Token | `whoami … 2>&1 \| ConvertFrom-Csv` fed error records into the parser | Native exit code checked first; required columns validated before completion |

### 10.4 Software shared-path rule

`host.software.hklm_native` and `host.software.hklm_wow6432` **deliberately govern the same path**, `host.installed_software`. The combined list is one analytical object, complete only when every *applicable* machine-scope hive succeeded:

- both applicable hives succeed → combined list emitted, both units `success`;
- any applicable hive fails → combined list **withheld as `$null`**.

A consumer must check **both** units before reading the path. WOW6432Node applicability is decided from `[Environment]::Is64BitOperatingSystem`, never from a failed path check — on 32-bit Windows the unit records `unavailable` / `provider_not_applicable` and is excluded from the completeness rule. Each record carries an additive `registry_scope` field (`hklm_native` / `hklm_wow6432`) for reconstruction.

**Retained limitation.** Only the two HKLM hives are read. A successful, complete machine-scope collection can never establish absence of a per-user (HKCU/HKU) installation: under the coverage axis of Rule 2 the result does not span that question.

### 10.5 Successful-empty versus unsuccessful

| Situation | Outcome | Payload |
| --- | --- | --- |
| Zero TCP connections / UDP listeners | `success` | `@()`, summary count `0` |
| TCP/UDP query failed | non-success | `$null`, summary count **`$null`** |
| Provider returned zero services/processes | `success` | `@()` |
| Services/processes query failed or returned null | non-success | `$null`, no count reported |
| Applicable hive read successfully but empty | `success` | `@()` |
| Any applicable hive failed | non-success | combined list `$null` |
| Group exists with no members | `success` | `members: []` |
| Any group-member query failed | non-success | `group_memberships` `$null`, `is_admin` `$null` |

### 10.6 Principal-bearing fields and analytical exclusions

Raw principal-bearing evidence is retained **unchanged** in the secured raw zone; no pseudonymisation occurs in the agent.

| Field | Treatment |
| --- | --- |
| `host.user_accounts[].name`, `host.group_memberships[].members[]`, `host.base_sid` | Pseudonymise at ingestion |
| `vulnerability.token_privileges.user` | Pseudonymise at ingestion |
| `host.processes[].owner`, `.executable` | **Outside** the analytical allow-list |
| `host.processes[].command_line` | **Excluded**; unbounded free text requiring scrubbing, not mapping |
| `host.manufacturer.*` | Legacy raw inventory, outside the register and the allow-list |

**Scope markers** are emitted additively: `host.user_accounts_scope = "local_only"` and `host.group_memberships_scope = "local_groups_only"`. `Get-LocalUser` and `Get-LocalGroupMember` observe the local SAM database only — on a domain-joined host the accounts that log in interactively are domain accounts and are invisible, and nested domain groups conferring local administrator rights are not expanded.

`user_accounts[].last_logon` reflects **local-account** logon only and does not establish domain-aware interactive use. `platform_role` is a declared chassis role, not usage. `processes[].owner`/`session_id` are process attributes, not aggregated session evidence. **C5 depends entirely on the deferred session extension.**

### 10.7 Current-token qualification

`vulnerability.token_privileges` describes **only the token the agent ran under**. Two qualifiers are emitted additively:

```
evidence_scope         = "collector_token_only"
collector_ran_as_admin = <bool>
```

This must never be read as a general low-privilege pathway. When `collector_ran_as_admin` is `true` it describes an **administrator's** token, so reading `dangerous_enabled_count` as an attacker's starting position would invert the finding.

### 10.8 C1–C7 unchanged

No condition meaning, mapping, applicability rule, weight, score or inference boundary was altered. Only acquisition metadata, provenance and scope markers were added; every existing payload path is preserved.

### 10.9 Remaining blockers *as at Tranche 2B.2* (HISTORICAL)

> Superseded by §11.9. Item 1 was resolved by Tranche 2C.

1. domain-aware session and recent-profile telemetry (C5/C6);
2. registry-restricted Windows feature-state collection (C2/C3);
3. validation of both extensions and the collection freeze.

Active-firewall-profile collection is a possible enhancement, not a prerequisite. Per-user software hives remain excluded.


---

## 11. Tranche 2C implementation record

Session and recent-profile telemetry for C5/C6. Agent 2.1.0, schema 1.1 and JSON depth 10 **unchanged** — no incompatibility was found. Three new units bring the total from 43 to **46**; module count 17 → **18**.

### 11.1 Module and units

`modules/host/Host.Sessions.ps1` → `Invoke-VKHostSessions`, invoked immediately after `Host.Users`.

| Unit | Provider | Governed paths |
| --- | --- | --- |
| `host.sessions.current_sessions` | `wtsapi32.dll:WTSEnumerateSessions` | `host.sessions.current_sessions`, `.current_sessions_summary` |
| `host.sessions.session_principals` | `wtsapi32.dll:WTSQuerySessionInformation(WTSUserName/WTSDomainName)` | `host.sessions.session_principals`, `.session_principals_summary` |
| `host.sessions.user_profiles` | `root\CIMV2:Win32_UserProfile` | `host.sessions.observation_window`, `.user_profiles`, `.user_profiles_summary` |

**The three units do not share analytical fate.** Principal-resolution failure does **not** discard observed session state; profile failure affects neither WTS unit; WTS failure does not affect profile evidence. All three are registered before any collection is attempted.

### 11.2 Evidence semantics — the load-bearing distinction

**`current_sessions` is DIRECT, POINT-IN-TIME evidence.** WTS enumerates the live session table; the result is authoritative for the observation instant and says nothing about any other moment. Session records are governed by their acquisition timestamps and are **not** windowed.

**`user_profiles[].last_use_time` is a RETROSPECTIVE PROXY.** `Win32_UserProfile.LastUseTime` advances on profile load *and* unload, can advance from background or service activity touching the hive, and is not reliably updated on every logoff path. It establishes *"this profile was touched within the window"*, **not** *"a user interactively logged on"*. Every record carries `evidence_strength = "profile_use_proxy"`, and `special` is emitted so system profiles remain identifiable for downstream exclusion.

**C5 therefore remains `partial`.** A single observation instant cannot characterise a 24-hour window, and the profile proxy cannot substitute for interactive-logon evidence. C6 gains session-holder evidence but the `Vul.Privileges.Token` collector-token limitation is unchanged.

### 11.3 Event 4624 deliberately excluded

Windows exposes only the **current** audit policy, not policy history across an observation window. An empty 4624 result could therefore never be shown to mean "no recent logon" — collection success alone would not imply temporal coverage. Rather than manufacture that certainty, 4624 is excluded and the limitation is stated. `quser.exe`, `qwinsta.exe`, `wevtutil.exe` and all free-text parsing are likewise excluded.

### 11.4 Field contract

`session_type` derives from `WTSClientProtocolType` (0 console, 1 legacy, 2 remote); the session **name is never used** to infer console or RDP. A `Listen` entry is classified `listener` directly from its connection state and is never queried for a principal, which Microsoft documents as having none. `session_type_source` records which source was used, so a session whose protocol query failed is self-describing as `other`/`connect_state` rather than silently misclassified.

`WTSLogonTime` is not collected (documented unsupported). Client name, client address, display info, working directory, application name, byte counts, idle time, credentials, tokens and host role are all excluded. `is_domain_principal` is **not** emitted — domain/local/AzureAD classification belongs to the ingestion artefact. `LocalPath` and `RoamingConfigured` are not collected.

### 11.5 Successful-empty versus unsuccessful

| Situation | Outcome | Payload |
| --- | --- | --- |
| Enumeration succeeds, zero sessions | `success` | `@()` + numeric zero summary |
| Enumeration failed / denied / unavailable | non-success | `$null` payload **and** `$null` summary |
| Principal query returns empty strings | `success` | `principal_present = false` |
| Any required principal query fails | non-success | whole collection + summary `$null`; **session state retained** |
| Profile provider returns nothing | `unavailable` / `provider_value_missing` | `$null` — *not* a successful empty |

Failure classification uses the **native error code** carried on `VoightKampff.WtsException` (5 → `restricted`/`access_denied`, 1314 → `restricted`/`insufficient_privilege`, 1722/7022 → `unavailable`), falling back to the shared classifier only when no structured code exists. No `IsAdmin` precondition is hard-coded: the provider call is attempted and the actual error classified.

### 11.6 Observation window

`$script:VKSessionWindowHours = 24` in `VK.Config.ps1`. The window qualifies `LastUseTime` **only**, so `observation_window` is governed by the `user_profiles` unit. It is emitted **unconditionally**, including on total failure, so an artefact is always self-describing. A single captured UTC reference time drives the window and every profile comparison; all ISO 8601 `Z` values are converted to UTC first.

### 11.7 Privacy

Raw user names, domains and SIDs are retained **unchanged** in the secured raw evidence. The agent performs no hashing, redaction, pseudonymisation or analytical filtering — all of that belongs to the separate Python ingestion artefact. Raw Voight-Kampff output therefore remains complete and suitable for its wider non-dissertation use.

Principal-bearing: `session_principals[].user_name`, `.domain_name`, `user_profiles[].sid`.

### 11.8 C1–C7 unchanged

No condition meaning, mapping, applicability rule, weight, score or inference boundary was altered. The agent gained no scoring, applicability or compliance logic.

### 11.9 Remaining blockers

Session and recent-profile telemetry is **no longer a blocker** — it is implemented and verified by this tranche.

1. **Registry-restricted Windows feature-state collection** for C2/C3;
2. **validation of that extension**, then **live pilot validation** and the **collection freeze**.

Active-firewall-profile collection remains an enhancement, not a prerequisite. Per-user software hives and Event 4624 remain excluded.

### 11.10 Verification record — Tranche 2C (CURRENT AUTHORITATIVE)

Executed on the controlled-collection runtime, **18 August 2026**:

| Item | Value |
| --- | --- |
| Runtime | **Windows PowerShell 5.1.26100.9168** |
| Test framework | **Pester 6.1.0** |
| Result | **617 passed, 0 failed** |
| Skipped / not run | **0 / 0** — no test is silently skipped, including the generation-dependent standalone tests |
| Agent / schema / depth | **2.1.0 / 1.1 / 10** |
| Coverage | **18 study-relevant modules, 46 acquisition units**, asserted exactly and in both directions |
| Depth outcome | **Configured JSON depth 10 preserved the representative fixture in full** — no truncation marker emitted, every required nested value survived the round trip |

This supersedes the Tranche 1 record in §2.3, which remains as the historical schema-1.0 / depth-5 measurement.

**This does not make the agent pilot-ready.** A green suite establishes that the implemented contract behaves as specified; it does not discharge the remaining blockers in §11.9, and no output from this build may be used as controlled research evidence.
