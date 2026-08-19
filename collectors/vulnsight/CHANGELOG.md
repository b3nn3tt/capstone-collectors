# Changelog

All notable changes to VulnSight are recorded here. The project is built in
deliberately controlled tranches, and each tranche is released as a version.

## 0.3.1 — Human-manageable filenames, manifest 1.1, and the user guide

The final Nessus sourcing pass. After this version VulnSight is complete for
its role in the dissertation and the component is parked.

### Added

- **Human-manageable deterministic filenames.** Exports are now named
  `<safe-scan-name>__scan-<SCAN_ID>__history-<HISTORY_ID>`, so a directory
  holding roughly thirteen systems is legible at a glance. For the verified
  lab acquisition that is `synthetic-lab-scan__scan-5__history-6.nessus` and
  `synthetic-lab-scan__scan-5__history-6.manifest.json`.
- The scan name is taken from `info.name` of the `GET /scans/{scan_id}`
  response **already** read for history eligibility. No additional API request
  is made to obtain it, and no other part of that response — `hosts`,
  `vulnerabilities`, `notes`, targets, policy or findings — is parsed,
  retained or exposed.
- One named, independently tested slug function reduces the untrusted provider
  name to `[a-z0-9-]` by Unicode normalisation, ASCII transliteration of
  accented Latin characters, lowercasing, replacement of every run outside
  `[a-z0-9]` with a single hyphen, hyphen collapsing and trimming, and a
  64-character cap. No provider string can create a directory, an absolute
  path, a drive letter, a UNC prefix, an alternate data stream or a traversal
  component.
- A documented fallback stem, `nessus__scan-<SCAN_ID>__history-<HISTORY_ID>`,
  used whenever `info` is absent, the name is absent, null, non-text or blank,
  or nothing survives slugging. Naming convenience never fails an otherwise
  valid export.
- **`docs/user-guide.md`**, a complete operational guide covering purpose and
  scope, prerequisites, environment creation, editable installation, `.env`
  configuration, secret handling, TLS guidance, every command, output naming,
  the manifest, independent SHA-256 verification, no-overwrite behaviour, exit
  codes, troubleshooting, reinstallation, and the evidential boundary. It is
  linked prominently from the top of `README.md`.

### Changed

- **The acquisition manifest contract is now
  `vulnsight.nessus-export-manifest/1.1`**, succeeding
  `vulnsight.nessus-export-manifest/1.0`.

  The change is **purely additive**: the scan section gains `scan.scan_name`,
  holding the exact provider string when supplied, `null` when absent or not
  text, and `""` only when Nessus explicitly supplied an empty string. The raw
  name is never replaced by the safe slug used in the filename — the two are
  recorded independently so neither can be mistaken for the other. Every other
  field, and the field order around it, is unchanged.

  Manifests already written under `vulnsight.nessus-export-manifest/1.0`
  remain valid historical acquisition records. They are **not rewritten, not
  renamed and not migrated**, and anything that understands `1.0` still reads
  them.
- The destination-existence check now runs immediately after the read-only
  eligibility request rather than before it, because the filename depends on
  the scan name that request supplies. It still runs **before any export
  request**: an existing destination means exactly one `GET` occurs and no
  `POST` is ever issued.
- `README.md` now leads with the acquisition-only boundary and the user-guide
  link, and defers operational detail to the guide.

### Explicitly unchanged

- **Existing evidence is never renamed, rewritten or migrated.** Artefacts and
  manifests already written under the previous `nessus_scan-N_history-M`
  scheme, and manifests written under schema `1.0`, remain valid historical
  acquisition records exactly as they are. A friendly-name export is a new
  acquisition record beside them, not a replacement.
- No `--label`, `--name`, `--filename` or `--force` option exists. A
  hand-typed label could misdescribe the evidence; the provider scan name
  supplies convenience, while the scan ID, history ID and hashes supply
  authority.
- Every Tranche 2 guarantee stands: server-supplied filenames ignored, unique
  invocation-scoped `.part` files, no overwrite, exact rollback of only
  invocation-created files, downloaded bytes never rewritten, and SHA-256
  computed over exactly the streamed `.nessus` bytes.
- Concise CLI output is unchanged: a table plus one `Next:` line for each
  listing, a compact `ITEM`/`VALUE` table for a successful export, one compact
  TLS warning on stderr, and full diagnostic detail retained in
  `nessus check`.

### Acquisition-only boundary

VulnSight connects to Nessus, discovers scans and histories, requires explicit
scan and history selection, exports the original `.nessus` artefact, validates
its basic XML structure, hashes the exact downloaded bytes, creates an
acquisition manifest, and never silently overwrites evidence.

It does not parse findings into an analytical dataset, normalise findings,
pseudonymise hosts or principals, query KEV or EPSS, merge Nessus evidence
with Voight-Kampff, evaluate C1–C7, calculate contextual adjustments, score or
rank vulnerabilities, or determine remediation priority. Those operations
belong to the separate MSc dissertation artefact.

Voight-Kampff ends with raw schema-1.1 JSON and acquisition provenance.
VulnSight ends with raw `.nessus` evidence and an acquisition manifest. The
MSc artefact begins with validation, controlled parsing, pseudonymisation,
filtering, normalisation and source reconciliation.

This release has not yet been executed by the user; the verification result
will be recorded when it has been.

## 0.3.0 — Tranche 2: explicit native `.nessus` export and acquisition manifest

### Verification

Tranche 2 was verified at three independent levels. They establish different
things and are deliberately not conflated.

**1. Test suite — behaviour against controlled doubles.** Python 3.11.15,
pytest 9.1.1: **573 passed, 0 failed, exit code 0**, in 1.12 seconds. The
suite is entirely offline. It exercises the code against mocked sessions,
synthetic responses, an injected clock and temporary directories, so it
establishes that VulnSight behaves as specified — not that the provider
behaves as assumed. A pre-run static estimate of 574 was a miscount; pytest's
count is authoritative and no filler test was added to reach the estimate.

**2. Live provider validation — behaviour against standalone Nessus.** All
four commands succeeded against the lab scanner:

- `nessus check`;
- `nessus scans list`;
- `nessus scans histories --scan 5`;
- `nessus scans export --scan 5 --history 6 --output-dir ".\evidence\raw\nessus"`.

The explicitly selected run was scan ID 5, history ID 6, provider status
`completed`. This establishes that the endpoint contract, the export request
body, the polling states and the download behaviour are correct for the
deployed standalone build — something no mocked test can show. TLS
certificate verification is intentionally disabled for this isolated lab
scanner, and the documented warning was emitted as designed.

**3. Independent artefact-integrity verification.** The export produced
`evidence/raw/nessus/nessus_scan-5_history-6.nessus` at **2,819,088 bytes**
with SHA-256 `baf1c643…03fe`, alongside its acquisition manifest. PowerShell
`Get-FileHash` computed the same digest independently of VulnSight's own
streaming hash.

Most significantly, that digest is **identical to the SHA-256 of an earlier
manual, unedited export of the same Nessus history**. The API acquisition path
therefore produced byte-for-byte identical raw evidence to a manual export.
This is the strongest available confirmation that the streamed download,
size checks, XML validation and no-overwrite commit preserve the provider's
bytes exactly rather than merely producing a plausible file.

### Correction to the Tranche 1 record

The authoritative Tranche 1 result is **282 tests collected and passed, with
0 failures**, verified live on Python 3.11.15 with pytest 9.1.1. An earlier
static estimate of 283 was wrong; pytest's count is authoritative and no
filler test has been added to reach the earlier figure.

The same run verified live against the standalone lab scanner:

- connectivity check passed;
- `GET /scans` returned HTTP 200;
- scan discovery passed, returning scan ID 5 (`synthetic-lab-scan`);
- history discovery passed through `GET /scans/5`, returning history ID 6
  with the provider status `completed`, which VulnSight marked
  export-eligible;
- TLS certificate verification is intentionally disabled for this isolated
  lab scanner;
- no export had been attempted at that point.

### Added

- `python -m vulnsight nessus scans export --scan <SCAN_ID> --history
  <HISTORY_ID> --output-dir <DIRECTORY>`, which acquires one native `.nessus`
  artefact for one explicitly selected completed run;
- an eligibility precheck that reads `GET /scans/{scan_id}`, locates the
  explicitly requested history ID and requires its provider-supplied status to
  be exactly `completed`, compared case-insensitively — failing before any
  export request if it is absent or ineligible, and never inferring completion
  from a timestamp;
- explicit scan and history selection: both identifiers must be positive
  integers, and there is no `latest`, no implicit selection and no name-based
  lookup;
- bounded export-status polling of
  `GET /scans/{scan_id}/export/{file_id}/status` at a fixed documented
  interval within a documented overall timeout, treating `ready` as success,
  `loading` as pending, a provider error state as failure, and any other state
  as an API-contract error rather than a reason to keep waiting;
- a streamed, size-limited download of
  `GET /scans/{scan_id}/export/{file_id}/download`, written in bounded chunks
  to a uniquely named `.part` file without ever holding the artefact in
  memory, honouring `Content-Length` while still enforcing the maximum size
  during streaming, and refusing a zero-byte body or a JSON or HTML error body
  served with a success status;
- safe structural XML validation with `defusedxml`, refusing DTD declarations,
  entity declarations and external references, requiring the root element
  `NessusClientData_v2` and at least one `Report`, and counting `Report`,
  `ReportHost` and `ReportItem` elements as acquisition-validation metadata
  only;
- a SHA-256 checksum computed over exactly the downloaded bytes as they are
  written;
- no-overwrite raw evidence: destination paths are checked before the scanner
  is contacted, filenames are generated locally rather than taken from the
  server, the bytes are moved into place rather than rewritten, and there is
  no `--force`;
- a two-file commit that rolls back only files created by the invocation,
  never deletes or alters a pre-existing file, and leaves no `.part` file
  behind after a handled failure;
- an acquisition sidecar manifest under the versioned contract
  `vulnsight.nessus-export-manifest/1.0`, written deterministically as UTF-8
  with a fixed field order, two-space indentation and a terminating newline;
- optional export settings `NESSUS_EXPORT_POLL_INTERVAL_SECONDS`,
  `NESSUS_EXPORT_POLL_TIMEOUT_SECONDS` and `NESSUS_EXPORT_MAX_BYTES`, each
  with a documented default so an existing `.env` remains valid unchanged;
- `defusedxml>=0.7.1` as a runtime dependency, required because a downloaded
  artefact is untrusted XML.

### Changed

- `POST /scans/{scan_id}/export` is now issued. It is the only write-shaped
  call in the project, exists solely because Nessus builds an export artefact
  that way, and does not launch, stop, reschedule, modify or delete a scan. No
  `PUT`, `PATCH` or `DELETE` request exists anywhere in the codebase.
- Discovery output is now terse: `scans list` and `scans histories` print the
  table and at most one short `Next:` line. The explanatory paragraphs that
  followed each table were removed and now live in the README and in `--help`.
- Configuration warnings, including the compact TLS-verification warning, now
  go to stderr rather than stdout.
- The `nessus check` command keeps its existing diagnostic detail.

### Not yet implemented

- **No findings parsing.** Acquisition stops at the raw file and its manifest.
  No finding is extracted, normalised or interpreted, and no analytical
  dataset, CVE table, score or model exists.
- Only the native `.nessus` format is supported: there is no CSV, HTML, PDF or
  database export option, and no filtered export.

## 0.2.0 — Tranche 1: read-only scan and history discovery

Added the ability to discover, but not to act upon, the scans and scan
executions visible to the configured Nessus account.

Added:

- `python -m vulnsight nessus scans list`, which lists scan configurations
  using `GET /scans`;
- `python -m vulnsight nessus scans histories --scan <identifier>`, which
  lists the individual executions of one explicitly selected scan by reading
  the `history` collection of a single `GET /scans/{scan_identifier}`
  scan-details response;
- validation of the `--scan` value, which accepts a positive integer scan ID,
  a canonical UUID, or an extended provider identifier in strict `8-4-4-4-N`
  hexadecimal form, and rejects blanks, zero, negative numbers, malformed and
  over-long identifiers, scan names, implicit selectors such as `latest`,
  path fragments, traversal sequences and values containing `/`, `\`, `?`,
  `#`, `%`, `.`, `:` or whitespace;
- typed models for a scan summary, a history summary and a discovery result,
  keeping raw provider identifiers, statuses and timestamps distinct from
  derived display values;
- an expanded offline test suite covering discovery, identifier validation
  and response-contract failures.

Compatibility corrections made during Tranche 1, before any export work:

- **Standalone Nessus history discovery uses `GET /scans/{identifier}`.** The
  history is read from the `history` collection of that scan-details
  response. Hosts, vulnerabilities, notes, targets, policy data and findings
  in that response are ignored: never parsed, never displayed, never saved.
- **The cloud-style `GET /scans/{identifier}/history` endpoint was removed.**
  The deployed standalone Nessus 10.12 scanner rejected it with HTTP 405,
  proving it does not exist on that target. It is not retained as a fallback,
  and VulnSight never issues a request it expects to fail in order to
  discover which endpoint works. HTTP 405 is now reported as an API
  incompatibility rather than a permissions problem.
- **The pagination implementation was removed with it.** It existed solely to
  page the cloud `/history` endpoint. The `history` array in a scan-details
  response is the complete history that endpoint supplies, and no paging
  metadata is invented. Duplicate-ID detection, malformed-record detection,
  deterministic ordering, the successful-empty distinction, verbatim status
  preservation and explicit export-eligibility all remain.
- **Numeric scan IDs are the recommended selector for standalone Nessus.**
  The live scanner reported a provider `uuid` of
  `01234567-89ab-cdef-0123-456789abcdef0123456789abcdef`, which is not a
  canonical UUID, so the earlier "any displayed UUID may be used" guidance
  was false. Such values are now accepted only under a strict `8-4-4-4-N`
  hexadecimal grammar with a final group of 12 to 64 characters, and the CLI
  states plainly that the numeric SCAN ID is what standalone Nessus expects,
  that a provider identifier works only where the deployed endpoint resolves
  it, and that VulnSight never selects by name.

Changed:

- the Nessus request plumbing was factored into `perform_get` and
  `classify_request_exception` so that discovery reuses the Tranche 0
  configuration, API-key handling, timeouts, TLS behaviour and error
  classification rather than defining a second client;
- the project version is now taken from a single authoritative location,
  `src/vulnsight/__init__.py`, from which `pyproject.toml` derives it.

What 0.2.0 explicitly does **not** do:

- it lists scan configurations and histories, and nothing more;
- **no export functionality exists yet**;
- it uses exactly two endpoints, `GET /scans` and
  `GET /scans/{scan_identifier}`, and performs `GET` requests only — no
  `POST`, `PUT`, `PATCH` or `DELETE` request exists anywhere in the discovery
  path;
- it writes no API response and no evidence file; nothing is persisted;
- it cannot launch, modify, stop, delete or export a scan;
- it does not yet parse `.nessus` XML;
- it does not automatically select a scan or a historical run — you choose
  the scan identifier, and later the history identifier, explicitly.

Unchanged:

- `python -m vulnsight nessus check` behaves exactly as it did in 0.1.0;
- the exit-code contract is unchanged.

## 0.1.0 — Tranche 0: connectivity preflight

Added:

- a `src`-layout Python project scaffold targeting Python 3.11 or later;
- configuration loading and validation from a local `.env` file, covering the
  Nessus endpoint, API access and secret keys, TLS verification and explicit
  connect and read timeouts;
- Nessus API-key authentication using the `X-ApiKeys` header, with key
  material excluded from object representations, log output and exception
  messages;
- DNS, TCP, HTTPS and API connectivity diagnostics;
- connectivity validation by a single read-only `GET /scans` request, whose
  response is validated and then discarded;
- structured, secret-free connectivity results;
- the stable exit-code contract: `0` success, `2` configuration or
  command-line input error, `3` network or TLS failure, `4` authentication or
  authorisation failure, `5` invalid or unexpected API response or internal
  failure;
- an entirely offline, mocked test suite;
- the command `python -m vulnsight nessus check`.
