# Capstone-Relevant Collector Modifications

## Status

Voight-Kampff and VulnSight are pre-existing researcher-developed tools. This document summarises the modifications made to selected versions for the capstone evidence pathway. It does not claim that either tool originated in the dissertation.

## Voight-Kampff

Capstone-relevant work includes:

- formalising the JSON evidence contract and increasing the validated serialisation depth;
- defining stable acquisition units and governed data paths;
- distinguishing `success`, `failed`, `restricted`, and `unavailable` acquisition outcomes;
- preventing failed acquisition from being represented as absence, `false`, zero, or an invented text value;
- preserving successful empty collections distinctly from unsuccessful reads;
- adding observation, agent, schema, method, and outcome provenance;
- migrating and instrumenting study-relevant host, security, and vulnerability modules;
- adding contract tests, representative fixtures, modular-runner checks, and standalone-build parity;
- correcting PowerShell variable-name and automatic-variable collision hazards;
- adding domain-aware current-session, session-principal, and recent-profile proxy evidence; and
- documenting that recent-profile activity is not an interactive-logon record.

Windows optional-feature collection remains conditional upon the frozen rule registry supplying exact admitted identifiers and authoritative documentation.

## VulnSight

Capstone-relevant work includes:

- establishing explicit `.env` configuration validation and staged connectivity diagnostics;
- adding read-only scan and history discovery;
- requiring explicit numeric scan and history selection for export;
- acquiring native `.nessus` evidence through the Nessus API;
- applying bounded streaming, size limits, SHA-256 calculation, no-overwrite output, and atomic cleanup;
- defensively validating the Nessus XML root and structural counts without parsing findings into an analytical tree;
- creating a versioned acquisition manifest containing source, selection, export, artefact, and validation provenance;
- creating deterministic human-readable output filenames from a safe scan-name slug plus scan and history identifiers;
- reducing routine CLI output while retaining actionable diagnostics; and
- documenting the strict boundary between native acquisition and dissertation-side processing.

## Freeze status

Both versions are pilot candidates. Passing unit and contract tests is necessary but not sufficient for controlled-evidence eligibility. The single-host pilot must confirm real provider behaviour, cross-source identity, temporal alignment, immutable preservation, and downstream reconstructability before final collection versions are frozen.
