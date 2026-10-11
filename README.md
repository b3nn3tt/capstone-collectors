# Capstone evidence collectors

Voight-Kampff and VulnSight acquire evidence for the MSc capstone. They are
upstream collection tools; the separate capstone artefact performs linkage,
modelling, C2 interpretation, ranking, and evaluation. The submitted Specification
and Design Report governs the active research.

## Current project checkpoint

On 10 October 2026 the recovered collector repository was clean on `main` at
`ac75457dc5bbc27adff22ef37ff67a673d5e9da1`. That revision supplies VK 2.3.0 with
schema 1.2 and VulnSight 0.3.1. A subsequent documentation-only commit has its own
identity and does not retroactively change the pilot's source provenance.

The current collection/integration pilot is complete: one Server 2016 host was
observed in SMB1 ON and OFF sessions, Nessus reported the same mapped CVE, and
the artefact verified capture linkage, development-only integration, report
replay, and backup. This is feasibility and integration evidence. Formal matched
targets and campaign collection remain to be specified and performed. Collector
versions, configuration, policy, and evidence rules must be frozen before those
targets are configured and formal campaigns begin; this README is not that freeze.

| Collector | Recorded version and verification | Responsibility |
| --- | --- | --- |
| [Voight-Kampff](collectors/voight-kampff/README.md) | Agent 2.3.0; schema 1.2; JSON depth 10; 753 recorded Pester passes | Raw Windows observations, complete optional-feature inventory, and per-unit acquisition outcomes |
| [VulnSight](collectors/vulnsight/README.md) | 0.3.1; export manifest 1.1; 781 recorded pytest passes | Explicitly selected native Nessus export, acquisition metadata, and checksum |

The figures above are recorded collector verification, not a fresh test run
performed by this documentation update. Acquisition success does not alone
establish formal evidence eligibility on every target.

## Active research boundary

Nessus establishes a host–CVE occurrence; VulnSight preserves the selected native
`.nessus` export and its provenance. VK records optional-feature state and the
associated acquisition outcome. The artefact resolves identity through a versioned
campaign manifest, validates inputs, preserves raw states, and derives present,
absent, or unknown C2 evidence under the admitted CVE-to-feature mapping.

C2 Windows optional-feature state is the only active contextual condition.
CIS-CAT and other conditions are deferred. Broader collector capabilities remain
available but do not become project predictors or additional conditions. Unknown
evidence never becomes an inferred favourable or adverse observation. Collectors
make no applicability judgement, score adjustment, or exploitation-probability claim.

## Practical use

Use each collector's linked README for its runtime, setup, commands, output
contract, and failure handling. VK runs through Windows PowerShell 5.1; VulnSight
uses its dedicated Python environment and explicit scan/history selection.
Retain original evidence and hashes. Keep credentials in local configuration
outside tracked project files. Research-specific campaign manifests and analytical
procedures belong in the sibling artefact repository.

Historical September gates, rehearsal labels, branch observations, and the broader
condition matrix in dated notes remain historical records. They do not redefine
the reconstructed October project's scope or complete the formal experiment.
The artefact's stock check and milestone work log describe current progress.
