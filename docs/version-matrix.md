# Collector Version Matrix

This file records the exact collector versions imported into this repository and their validation state.

| Field | Voight-Kampff | VulnSight |
| --- | --- | --- |
| Upstream lineage | Private upstream repository: b3nn3tt/voight_kampff_windows_agent | https://github.com/b3nn3tt/vulnsight |
| Import date | 2026-08-19 | 2026-08-19 |
| Imported subdirectory | `collectors/voight-kampff` | `collectors/vulnsight` |
| Tool version | Agent 2.1.1 | 0.3.1 |
| Evidence schema | Agent schema 1.1; JSON depth 10 | Nessus export manifest 1.1 |
| Primary runtime | Windows PowerShell 5.1 | Python 3.11 |
| Test framework | Pester 6.1.0 | pytest 9.1.1 |
| Verified test result | **646 total; 646 passed; 0 failed; 0 skipped; 0 inconclusive; 0 not run; suite result `Passed`** at agent 2.1.1 — Pester 6.1.0 on Windows PowerShell Desktop 5.1.26100.9168, definitive committed-source duration `00:00:18.5527668`, caller-imposed StrictMode `Off`. The agent 2.1.0 baseline of 617 passed / 0 failed / 0 skipped / 0 not run is preserved as history, superseded as the latest executed result. | 781 passed; 0 failed |
| Module/unit summary | 45 modules executed; 18 study-relevant instrumented modules; 46 acquisition units | Native `.nessus` acquisition and manifest workflow |
| Source branch / commit for the current version | `main` @ `a928acd942cae2dd071f416700eaaa9e6a4f421a`, repository clean — **merged through pull request #1**; repair commit `afa421ead68d94a678d96766424c6ead9f689933` and documentation commit `6830dce3feecc595eb9fbf351593ca9871b1552f` are preserved ancestors. **Merged but not tagged and not frozen** | `main` @ `795ed1ed3df4c888e70dfa85bef01a5835caae71` |
| Live integration-validation run | `CAPSTONE-WIN-01`, 2026-08-28 — 45 modules executed, 46 acquisition units, **46 success / 0 failed / 0 restricted / 0 unavailable**. Integration validation only; **not** rehearsal, pilot or controlled campaign evidence | Non-campaign export validation, 2026-08-27 (scans `10`/`12` and `15`/`16`) |
| Current state | **Integration-validated acquisition component. Merged, untagged, unfrozen.** **Not formal-pilot-ready** — the registry-restricted feature-state extension is absent (blocked on the WS-E feature-identifier slice) | **Integration-validated acquisition component. Unfrozen.** |
| Final freeze tag | NOT YET FROZEN | NOT YET FROZEN |
| Final artefact checksum | NOT YET FROZEN | NOT YET FROZEN |

The authoritative public snapshot begins with import commit 81f201307613e341c607b027e62fe5076b5ff9b9.

## Agent 2.1.1 build provenance (definitive build, 2026-08-28)

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
- Do not mark a version frozen until the **formal** single-host pilot `PILOT-WIN-01` has passed and the collection bundle has been checksummed. **The disposable development rehearsal `REHEARSAL-WIN-01` is a different exercise and can never substitute for it.** Neither has run, and the freeze fields above remain deliberately empty.
