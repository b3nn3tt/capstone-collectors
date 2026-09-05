# Collector Version Matrix

This file records the exact collector versions imported into this repository and their validation state.

| Field | Voight-Kampff | VulnSight |
| --- | --- | --- |
| Upstream lineage | Private upstream repository: b3nn3tt/voight_kampff_windows_agent | https://github.com/b3nn3tt/vulnsight |
| Import date | 2026-08-19 | 2026-08-19 |
| Imported subdirectory | `collectors/voight-kampff` | `collectors/vulnsight` |
| Tool version | Agent 2.3.0 | 0.3.1 |
| Evidence schema | Agent schema 1.2; JSON depth 10 | Nessus export manifest 1.1 |
| Primary runtime | Windows PowerShell 5.1 | Python 3.11 |
| Test framework | Pester 6.1.0 | pytest 9.1.1 |
| Verified test result | **753 total; 753 passed; 0 failed; 0 skipped; 0 inconclusive; 0 not run; suite result `Passed`** at agent 2.3.0 — Pester 6.1.0 on Windows PowerShell Desktop 5.1.26100.9168, caller-imposed StrictMode `Off`. Preserved as history and superseded as the latest executed result: agent 2.2.0 — 659 passed; agent 2.1.1 — 646 passed, definitive committed-source duration `00:00:18.5527668`; agent 2.1.0 — 617 passed. | 781 passed; 0 failed |
| Module/unit summary | **46 modules; 48 acquisition units; 20 instrumented (study-relevant) modules** — counted from the repository at the commit below, not carried forward. The earlier "18 study-relevant modules" figure was understated and is corrected here. | Native `.nessus` acquisition and manifest workflow |
| Source branch / commit for the current version | `feat/voight-2.3-evidence-expansion` @ `2f93b4b9bd19329952c22de47ee587483882f1f3`, repository clean — implementation commit *feat(voight-kampff): collect Windows optional feature inventory*. **Pending merge at the time of this record (2026-09-05); not tagged and not frozen when observed on that date.** Current branch, merge, tag and freeze status must be obtained from the repository. Superseded ancestor provenance for 2.1.1 is preserved below | `main` @ `795ed1ed3df4c888e70dfa85bef01a5835caae71` |
| Live validation run | **Development live validation, 2026-09-05** — 137 valid optional-feature records, **48/48 acquisition units `success`**, no duplicate feature names, no malformed records, correct ordinal ordering. **Development validation only; not formal-pilot output, not research evidence, and not a freeze identity** | Non-campaign export validation, 2026-08-27 (scans `10`/`12` and `15`/`16`) |
| Current state (as recorded 2026-09-05) | **Development-validated acquisition component. Pending merge at the time of this record; untagged and unfrozen when observed.** Read current branch, merge, tag and freeze status from the repository rather than from this row. Collects the complete Windows optional-feature inventory as raw evidence, with no allowlist and no analytical interpretation | **Integration-validated acquisition component. Merged, unfrozen.** |
| Final freeze tag | NOT YET FROZEN | NOT YET FROZEN |
| Final artefact checksum | NOT YET FROZEN | NOT YET FROZEN |

The authoritative public snapshot begins with import commit 81f201307613e341c607b027e62fe5076b5ff9b9.

## Agent 2.3.0 scope and evidence boundary

| Field | Value |
| --- | --- |
| Schema increment | 1.1 → **1.2**, **additive** — five-section envelope, acquisition entry shape, field order and four-value outcome vocabulary all unchanged; no existing field path added to, removed, moved or redefined |
| New payload section | `host.windows_optional_features` |
| New acquisition unit | `host.windows_optional_features.inventory` (provider `Get-WindowsOptionalFeature -Online`) |
| Record shape | exactly `feature_name` and `state`; provider state string preserved verbatim and never reduced to a Boolean |
| Ordering | deterministic ordinal by `feature_name` |
| Collector interpretation | **None.** No allowlist, no category or security label, no risk, applicability or compliance judgement |
| Downstream responsibility | **Research-specific feature selection and contextual interpretation belong to the dissertation artefact, not the collector** |

## Rehearsal and pilot state

| Exercise | State |
| --- | --- |
| `REHEARSAL-WIN-01` (development integration rehearsal) | **Has run. Closed `PASS` with findings.** Its output is **permanently ineligible as research evidence**, and it **did not close `GATE B1`** — a rehearsal cannot close that gate |
| `PILOT-WIN-01` (formal single-host integration pilot) | **Has not run.** Its `PASS` remains the `GATE B1` prerequisite |
| `ISS-005` | Remains part of the `REHEARSAL-WIN-01` historical record and is not rewritten. Its **technical cause has been corrected and live-validated in agent 2.2.0 and 2.3.0** |
| `ISS-004` | Open **formal-pilot procedural reminder**: start instrumented timing **before** snapshot restoration |

## Agent 2.1.1 build provenance (definitive build, 2026-08-28) — SUPERSEDED

> **SUPERSEDED as the current version by agent 2.3.0** (see the matrix above). Retained unchanged as historical information: it records the 2.1.1 build identity and the reproducibility limitation observed at that time. **It was never a freeze, and it is not the current build identity.**

Recorded here because the freeze fields above are still empty and this is the identity a later freeze would be taken from. **It is not a freeze.**

| Field | Value |
| --- | --- |
| Source branch | `fix/voight-live-provider-edge-cases` |
| Source commit | `afa421ead68d94a678d96766424c6ead9f689933` |
| Source repository clean | Yes |
| Standalone | `VoightKampff_Standalone_v2.1.1.ps1` |
| Size | 458,575 bytes |
| SHA-256 | `165745478f86a05426798bb5d29fd5884e09d522eca0967d9d4c28640b40d208` |
| Embedded build time | `2026-08-28 15:31:53` — **no timezone or offset is encoded in the generated script** |
| Build manifest | `build-validation.manifest.json`, 2,781 bytes, SHA-256 `500a7436c49ca5cf4d46e0e77c11f4f34cc5a9c169078f812afd17e17e5ef175` |
| Checksum file | `SHA256SUMS.txt`, 204 bytes, SHA-256 `fa4c4e6e37e0e349ed7f917abe670f25f56300b84967424632c78fcca53e53a3` |
| Generated collector executed during the build | No — it was parsed only |

**Build reproducibility limitation (pre-freeze engineering issue).** `Build-Standalone.ps1` inserts the current local wall-clock value into the generated comment header via `Built: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`. **Two correct builds from identical source can therefore have identical size but different SHA-256 values.** The disposable parity build produced 458,575 bytes with SHA-256 `1547e0797d70169ca5c3b411641613181028456d806aa95f0aedc52da21f6a0c`; the definitive build produced 458,575 bytes with SHA-256 `165745478f86a05426798bb5d29fd5884e09d522eca0967d9d4c28640b40d208`. The disposable build was deleted before a byte comparison, so **the timestamp is not claimed to have been proven the sole differing content** — it explains the expected non-determinism, and nothing more. The build is **not** invalid, and no repair has been invented: the definitive artefact remains controlled through its recorded source commit, size, SHA-256, manifest and checksum file. Bit-reproducible builds are a candidate pre-freeze hardening item.

## Import rules

- Import clean working trees without nested `.git` directories.
- Exclude secrets, `.env`, evidence, caches, environments, transient test logs, and generated outputs.
- Record the source commit before copying.
- Run each collector's documented tests after import.
- Record any difference between the source commit and imported tree.
- Do not mark a version frozen until the **formal** single-host pilot `PILOT-WIN-01` has passed and the collection bundle has been checksummed. **The disposable development rehearsal `REHEARSAL-WIN-01` is a different exercise and can never substitute for it.** `REHEARSAL-WIN-01` has run and closed `PASS` with findings; `PILOT-WIN-01` has not run, so the freeze fields above remain deliberately empty.
- Development validation builds and their live runs are **not** freeze identities. Do not record a development standalone checksum in the freeze fields.
