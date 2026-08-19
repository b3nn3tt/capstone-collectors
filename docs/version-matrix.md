# Collector Version Matrix

This file records the exact collector versions imported into this repository and their validation state.

| Field | Voight-Kampff | VulnSight |
| --- | --- | --- |
| Upstream lineage | Private upstream repository: b3nn3tt/voight_kampff_windows_agent | https://github.com/b3nn3tt/vulnsight |
| Import date | 2026-08-19 | 2026-08-19 |
| Imported subdirectory | `collectors/voight-kampff` | `collectors/vulnsight` |
| Tool version | Agent 2.1.0 | 0.3.1 |
| Evidence schema | Agent schema 1.1; JSON depth 10 | Nessus export manifest 1.1 |
| Primary runtime | Windows PowerShell 5.1 | Python 3.11 |
| Test framework | Pester 6.1.0 | pytest 9.1.1 |
| Verified test result | 617 passed; 0 failed; 0 skipped; 0 not run | 781 passed; 0 failed |
| Module/unit summary | 18 modules; 46 acquisition units | Native `.nessus` acquisition and manifest workflow |
| Current state | Integration-pilot candidate | Integration-pilot candidate |
| Final freeze tag | NOT YET FROZEN | NOT YET FROZEN |
| Final artefact checksum | NOT YET FROZEN | NOT YET FROZEN |

The authoritative public snapshot begins with this repository's import commit. The SHA of that commit will be recorded after the hygiene amendment.

## Import rules

- Import clean working trees without nested `.git` directories.
- Exclude secrets, `.env`, evidence, caches, environments, transient test logs, and generated outputs.
- Record the source commit before copying.
- Run each collector's documented tests after import.
- Record any difference between the source commit and imported tree.
- Do not mark a version frozen until the single-host pilot has passed and the collection bundle has been checksummed.
