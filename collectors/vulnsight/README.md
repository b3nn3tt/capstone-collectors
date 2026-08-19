# VulnSight

VulnSight acquires original `.nessus` evidence from a Nessus scanner in a way
that can be independently verified afterwards, and records how that
acquisition happened.

> **📖 [Read the User Guide →](docs/user-guide.md)**
>
> Step-by-step installation, configuration, every command, output naming,
> manifest details, independent hash verification, exit codes and
> troubleshooting.

## What VulnSight is, and is not

VulnSight is an **acquisition tool**. It connects to Nessus, discovers scans
and execution histories, requires explicit scan and history selection, exports
the original `.nessus` artefact, validates its basic XML structure, hashes the
exact downloaded bytes, creates an acquisition manifest, and never silently
overwrites evidence.

It does **not** parse findings into an analytical dataset, normalise Nessus
findings, pseudonymise hosts or principals, query KEV or EPSS, merge Nessus
evidence with Voight-Kampff, evaluate C1–C7, calculate contextual adjustments,
score or rank vulnerabilities, or determine remediation priority. Those
operations belong to the separate MSc dissertation artefact.

The boundary is deliberate:

- **Voight-Kampff** ends with raw schema-1.1 JSON and acquisition provenance.
- **VulnSight** ends with raw `.nessus` evidence and an acquisition manifest.
- **The MSc artefact** begins with validation, controlled parsing,
  pseudonymisation, filtering, normalisation and source reconciliation.

Keeping it sharp is what makes the evidence defensible: VulnSight's output can
be verified by anyone with `Get-FileHash` and the manifest, without trusting
any analytical judgement, because VulnSight makes none.

## Current scope (version 0.3.1)

The project is built in deliberately controlled tranches. `CHANGELOG.md`
records what each version added.

Tranche 0 (0.1.0) provided:

- a conventional `src`-layout Python project scaffold;
- configuration loading and validation from a local `.env` file;
- a single read-only Nessus connectivity preflight command;
- an offline test suite covering configuration, connectivity classification
  and command-line exit codes.

Tranche 1 (0.2.0) added read-only discovery:

- listing the scan configurations visible to the configured account;
- listing the individual executions of one explicitly selected scan;
- identifying which historical runs are export-eligible.

Tranche 2 (0.3.0, refined in 0.3.1) adds explicit native `.nessus` acquisition:

- exporting one explicitly selected completed run;
- bounded export-status polling;
- a streamed, size-limited download;
- safe structural XML validation;
- a SHA-256 checksum over exactly the downloaded bytes;
- a no-overwrite raw evidence file;
- an acquisition sidecar manifest beside it.

VulnSight uses exactly four endpoints. Three are `GET`:
`GET /scans`, `GET /scans/{scan_identifier}` and the export status and
download endpoints. One is a `POST`:
`POST /scans/{scan_id}/export`, which exists solely because Nessus builds an
export artefact that way. It does not launch, stop, reschedule, modify or
delete a scan, and no `PUT`, `PATCH` or `DELETE` request exists anywhere in
the codebase.

Acquisition stops at the raw file. VulnSight deliberately does **not** provide
`.nessus` parsing, finding extraction, CVE reconciliation, campaign manifests,
Voight-Kampff ingestion, CIS-CAT ingestion, NVD, KEV or EPSS retrieval,
pseudonymisation, scoring, modelling, contextual rules, a database, an API or
a frontend. Only the native `.nessus` format is supported; there are no CSV,
HTML, PDF or database export options.

No scan and no historical run is ever selected automatically: you choose both
identifiers. Existing evidence is never overwritten, and there is no
`--force`.

## Requirements

- Windows, with Windows PowerShell (all commands below are PowerShell, not
  Bash).
- Miniconda or Anaconda.
- Python 3.11 or later, in a dedicated Conda environment named `vulnsight`.
- Network access to a Nessus instance over HTTPS, normally on port 8834.
- A Nessus API access key and secret key.

## Who runs the commands

You run every command. The coding assistant writes and reviews files only; it
does not create environments, install packages, execute tests, run the
application or contact Nessus.

## Setting up

Change to the project directory (substitute your own path):

```powershell
Set-Location "C:\REPLACE\WITH\PATH\TO\vulnsight"
```

Create and activate the environment:

```powershell
conda create --name vulnsight python=3.11 -y
conda activate vulnsight
```

Confirm the interpreter that is actually in use:

```powershell
python --version
Get-Command python
```

Upgrade `pip`, then install the project in editable mode with its test
dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Configuration

Copy the example configuration without overwriting any existing `.env`:

```powershell
if (Test-Path ".env") { Write-Host ".env already exists; leaving it unchanged." } else { Copy-Item ".env.example" ".env"; Write-Host "Created .env from .env.example." }
```

Open it and enter your endpoint and keys:

```powershell
notepad .env
```

The settings are:

| Setting | Meaning |
| --- | --- |
| `NESSUS_BASE_URL` | Scanner base URL, for example `https://127.0.0.1:8834`. Only `http` and `https` are accepted; `https` is expected. |
| `NESSUS_ACCESS_KEY` | Nessus API access key. |
| `NESSUS_SECRET_KEY` | Nessus API secret key. |
| `NESSUS_VERIFY_TLS` | `true` or `false`. |
| `NESSUS_CONNECT_TIMEOUT_SECONDS` | Positive number of seconds. |
| `NESSUS_READ_TIMEOUT_SECONDS` | Positive number of seconds. |

Every setting above is required. Missing settings, blank values, malformed
URLs, unsupported schemes, invalid ports, invalid Boolean values and
non-positive timeouts are all rejected; VulnSight never guesses configuration
and never supplies credentials of its own.

These export settings are **optional**. Each has the documented default shown,
so an existing `.env` written before export existed remains valid without
change:

| Setting | Default | Meaning |
| --- | --- | --- |
| `NESSUS_EXPORT_POLL_INTERVAL_SECONDS` | `2` | Seconds between export-status polls. |
| `NESSUS_EXPORT_POLL_TIMEOUT_SECONDS` | `600` | Total seconds to wait for an export to become ready. |
| `NESSUS_EXPORT_MAX_BYTES` | `1073741824` | Largest artefact accepted, in bytes (1 GiB). |

The interval must not exceed the timeout. Whichever values are in force are
recorded in every acquisition manifest.

`.env` is excluded by `.gitignore` and must never be committed. Neither key is
ever printed, logged, placed in an object representation or included in an
exception message.

### Disabling TLS verification

`NESSUS_VERIFY_TLS=false` is supported so that a lab scanner using a
self-signed certificate can be reached. This disables certificate verification
and therefore removes protection against interception and impersonation. Use it
only against a local lab scanner you control, never against a production or
internet-facing scanner. When verification is disabled, successful output says
so explicitly.

## Running the connectivity check

```powershell
python -m vulnsight nessus check
$LASTEXITCODE
```

The check runs these stages in order:

1. load and validate configuration from `.env`;
2. parse the base URL and resolve the target host and port;
3. test TCP connectivity to that host and port;
4. issue one authenticated `GET /scans` request using the
   `X-ApiKeys: accessKey=…; secretKey=…` header;
5. confirm the response is a successful, valid JSON API response.

Successful output confirms the endpoint, TCP connectivity, API
authentication, that `/scans` returned a valid response, and whether TLS
verification was enabled or disabled. The scans themselves are never printed.

## Read-only discovery

### Listing scans

```powershell
python -m vulnsight nessus scans list
$LASTEXITCODE
```

This issues one `GET /scans` request and prints a deterministic row per scan,
sorted by scan ID. Each row shows the numeric scan ID, the provider UUID, the
name, the raw status, the folder ID and the last-modification time.

Use the **numeric SCAN ID** to select a scan. That is the selector standalone
Nessus expects, and it is the identifier the history command is designed
around. The UUID column is shown for provenance; standalone Nessus reports a
value there that is not a canonical UUID — the deployed 10.12 scanner returned
`01234567-89ab-cdef-0123-456789abcdef0123456789abcdef`, whose final group is
28 hexadecimal characters rather than 12. VulnSight accepts such a value only
under a strict format check, and whether the scanner resolves it is the
scanner's decision. VulnSight never selects a scan by name.

Status values are printed exactly as Nessus supplied them; VulnSight never
translates or normalises a provider status. Timestamps are shown as ISO 8601
in UTC for display only — the original integer Unix values are what the code
holds internally. A field Nessus did not supply is shown as `not supplied`,
never as an invented value.

Targets, credentials, policy contents, hosts and findings are never printed,
and the response is never saved.

An explicitly empty `scans` array is a successful result: VulnSight reports
`No scans returned` and exits `0`. A missing `scans` field, a null value or a
value of the wrong type is an invalid API response, not an empty result, and
exits `5`.

### Listing the history of one scan

Choose a numeric scan ID from the listing above, then:

```powershell
python -m vulnsight nessus scans histories --scan 5
$LASTEXITCODE
```

`--scan` accepts:

- a **positive integer scan ID** — recommended, and the selector standalone
  Nessus expects;
- a canonical UUID (`8-4-4-4-12` hexadecimal);
- an extended provider identifier in strict `8-4-4-4-N` hexadecimal form,
  where the final group is between 12 and 64 hexadecimal characters, matching
  what standalone Nessus reports in its `uuid` field. Such a value is passed
  through exactly as supplied, and works only if the deployed endpoint
  resolves it; if it does not, the scanner returns HTTP 404 and VulnSight
  reports the scan as not found or not visible.

Scan **names** are not accepted, because Nessus does not guarantee that a name
is unique, and implicit selectors such as `latest` are never accepted. Blank
values, zero, negative numbers, malformed identifiers, over-long values, path
fragments, traversal sequences and any value containing `/`, `\`, `?`, `#`,
`%`, `.`, `:` or whitespace are rejected with exit code `2` before any request
is made.

The command issues one `GET /scans/{scan}` request and reads **only** the
`history` collection of the scan-details response. It prints one row per
execution, sorted by history ID: the history ID, the history UUID, the raw
status, the start time, the last-modification time, any provider-supplied
type, any rollover marker, and whether the run is export-eligible.

Everything else in that scan-details response — hosts, vulnerabilities, notes,
targets, policy data, findings — is ignored. It is not parsed, not displayed
and not saved, and the response is released once the history has been
summarised.

Export eligibility is VulnSight's own derived judgement, not a provider field.
A run is export-eligible **only** when its provider-supplied status is exactly
`completed`, compared case-insensitively. Completion is never inferred from a
timestamp. Every other status is non-eligible in this version, and no run is
ever selected automatically.

An explicitly empty history collection is a successful result and is reported
as such; a missing, null or wrongly typed collection is an invalid response.

#### Why `GET /scans/{scan}` and not `/scans/{scan}/history`

An earlier build of this tranche called the cloud-style
`GET /scans/{scan}/history` endpoint. The deployed standalone **Nessus 10.12**
scanner rejected that request with **HTTP 405 (method not allowed)**, proving
the endpoint does not exist on this target. It has been removed entirely: it
is not retained as a fallback, and VulnSight never issues a request it expects
to fail in order to discover which endpoint works.

If any endpoint ever returns HTTP 405, VulnSight reports it as an API
incompatibility — explicitly not a permissions problem — with exit code `5`.

#### History response contract

The scan-details response must be an object containing a `history` field whose
value is a list:

| Condition | Result |
| --- | --- |
| `history` is a list of records | Parsed, sorted by history ID |
| `history` is `[]` | Success — an explicitly empty history |
| `history` is missing | Invalid response, exit `5` |
| `history` is `null` | Invalid response, exit `5` |
| `history` is not a list | Invalid response, exit `5` |
| Top level is not an object | Invalid response, exit `5` |

If a deployment carries the history somewhere else in the response, VulnSight
will **not** guess. It fails with a precise contract error that names the
top-level field *names* it did find — never their values — so the actual shape
can be reported and the contract corrected.

There is no pagination. The `history` array in a scan-details response is the
complete history that endpoint supplies, and VulnSight never invents paging
metadata. Duplicate history IDs, malformed records and malformed timestamps
remain response-contract errors with exit code `5`.

## Acquiring a native `.nessus` export

```powershell
python -m vulnsight nessus scans export --scan 5 --history 6 --output-dir ".\evidence\raw\nessus"
$LASTEXITCODE
```

All three arguments are required. `--scan` and `--history` must both be
positive integers: export addresses the scan by number, so a provider
identifier is refused here even though discovery accepts one. There is no
`latest`, no implicit selection and no name-based lookup.

Successful output is a compact table and nothing more:

```text
ITEM       VALUE
---------  -----
File       .\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.nessus
Manifest   .\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.manifest.json
Bytes      48213
SHA-256    3a7f…
```

### The acquisition pipeline

1. **Prepare the destination.** The output directory is created if absent.
2. **Confirm eligibility.** `GET /scans/{scan_id}` is read, the explicitly
   requested history ID is located, and its provider status must be exactly
   `completed`, compared case-insensitively. If it is missing or not completed,
   the command fails **before** any export request. Completion is never
   inferred from a timestamp. The same response supplies the scan name used to
   make the filenames legible, so no extra request is made for it.
3. **Protect the destination.** The two output paths are resolved and checked.
   If either already exists, the command stops here — still before any export
   request reaches the scanner.
4. **Request the export.** `POST /scans/{scan_id}/export` with exactly this
   body — no filter, chapter or plugin selection is ever added:

   ```json
   { "format": "nessus", "history_id": 6 }
   ```

   If the deployed API rejects this contract, VulnSight reports the HTTP status
   and stops. It does not try alternative bodies, query parameters or
   cloud-specific fallbacks.
5. **Poll within bounds.** `GET /scans/{scan_id}/export/{file_id}/status` is
   polled every `NESSUS_EXPORT_POLL_INTERVAL_SECONDS` for at most
   `NESSUS_EXPORT_POLL_TIMEOUT_SECONDS`. `ready` succeeds, `loading` continues,
   `error` fails, and any other state is treated as an API-contract error
   rather than a reason to keep waiting. Nothing is printed per poll.
6. **Stream the download.** `GET /scans/{scan_id}/export/{file_id}/download` is
   read in bounded chunks straight to a uniquely named `.part` file inside the
   destination directory, with the SHA-256 computed over exactly those bytes as
   they are written. The artefact is never held in memory. A declared
   `Content-Length` is honoured and a mismatch is treated as a truncated
   download; the size limit is enforced while streaming regardless. A zero-byte
   body, and a JSON or HTML error body served with a success status, are both
   refused.
7. **Validate safely.** See below.
8. **Commit.** The raw file and the manifest are created together. If the
   second cannot be created, only files created by this run are removed; no
   pre-existing file is ever deleted or altered, and no `.part` file survives a
   handled failure.

Filenames are generated locally and never taken from the server:

- `<safe-scan-name>__scan-<SCAN_ID>__history-<HISTORY_ID>.nessus`
- `<safe-scan-name>__scan-<SCAN_ID>__history-<HISTORY_ID>.manifest.json`

`<safe-scan-name>` is a mechanically sanitised slug of the provider's own scan
name, so a directory holding many systems stays legible; the numeric
identifiers that follow it are the authoritative part. The slug can only ever
match `[a-z0-9-]`, so a provider name can never introduce a directory, an
absolute path, a drive letter, a UNC prefix, an alternate data stream or a
`..` component. Where no usable name is available the stem falls back to
`nessus__scan-<SCAN_ID>__history-<HISTORY_ID>`; a missing name never fails an
otherwise valid export.

The raw provider name is preserved separately in the manifest under
`scan.scan_name`; the filename carries only its slug. There is no `--label`,
`--name` or `--filename` option — a hand-typed label could misdescribe the
evidence.

**Filenames are not evidence selectors.** The manifest and the SHA-256 are what
identify an artefact. See the
[User Guide](docs/user-guide.md#13-output-naming) for the full algorithm.

### XML safety and structural validation

A downloaded artefact is untrusted XML. It is parsed with `defusedxml`, which
refuses DTD declarations, entity declarations and external references, so
neither entity expansion nor an external fetch can be triggered by an artefact.
Parsing is incremental through a counting target, so no element tree is built
and memory stays constant.

The artefact must be well-formed, must have the root element
`NessusClientData_v2`, and must contain at least one `Report`. It need not
contain hosts or findings: a completed scan that found no live hosts is
legitimate evidence.

`Report`, `ReportHost` and `ReportItem` elements are counted. Those counts are
acquisition-validation metadata only — **no finding is extracted, normalised or
interpreted**.

### Immutability

The downloaded bytes are the canonical raw evidence. They are written once,
moved into place rather than rewritten, and never reserialised, pretty-printed,
re-encoded or line-ending-normalised. The final file is never reopened for
writing.

Integrity is established by preservation, exclusive creation and checksum
verification. No claim is made that operating-system read-only attributes make
the evidence immutable — they do not.

This has been confirmed in practice: for scan 5 / history 6 the acquired
artefact's SHA-256 matched both an independent PowerShell `Get-FileHash` and
the digest of an earlier manual, unedited export of the same history. The API
acquisition path produces byte-for-byte identical evidence to a manual export.

Verify independently:

```powershell
Get-FileHash ".\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.nessus" -Algorithm SHA256
```

and compare it with the `artefact.sha256` field of the manifest.

### The acquisition sidecar manifest

Each artefact is accompanied by a UTF-8 JSON manifest under the contract
`vulnsight.nessus-export-manifest/1.1`, written with a fixed field order,
two-space indentation and a terminating newline. It records the manifest
schema and creation time, the tool name and version, the source type, base URL
and TLS-verification setting, the scan ID and the raw provider scan name, the
selected history — including that history's raw provider status and timestamps
alongside their ISO 8601 renderings — the export format, request path, request
body, server file identifier, polling interval, polling timeout and maximum
permitted bytes, the export completion time, and the locally generated
filename, byte size, SHA-256, XML root and structural counts.

`scan.scan_name` holds the exact provider string when one was supplied, `null`
when it was absent or not text, and `""` only when Nessus explicitly supplied
an empty string. It is never replaced by the sanitised slug used in the
filename.

Schema `1.1` differs from `1.0` only by adding `scan.scan_name`. Manifests
already written under `1.0` remain valid historical acquisition records and
are never rewritten, migrated or renamed.

It contains **no** API access key, secret key, `X-ApiKeys` header, export
token, response headers, `.env` content, targets, credentials, plugin output,
findings, host details, scores or analytical conclusions. Any download token
returned by the scanner is never read into a result, printed, persisted or
represented.

The manifest may identify the lab endpoint, because it belongs beside secured
raw evidence.

### Git exclusions

`.gitignore` excludes the `evidence/` directory, `.nessus` files, `.part` files
and acquisition manifests stored inside a raw evidence directory, so generated
scan material cannot be committed accidentally. JSON files in general are not
ignored.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success — connectivity verified, a listing produced (including an explicitly empty one), or an artefact acquired. |
| 2 | Configuration or command-line input error — `.env` missing, a setting missing or invalid, a malformed `--scan`, `--history` or `--output-dir` value, a history that does not exist or is not `completed`, or a destination file that already exists. |
| 3 | Network or TLS failure — DNS resolution, connection refused, timeout, route failure, certificate verification failure, or a download interrupted in transit. |
| 4 | Authentication or authorisation failure — HTTP 401 or HTTP 403, never retried. |
| 5 | Unexpected API response or internal failure — HTTP 400, 404, 405, 429, another unexpected status, malformed JSON, a missing, null or wrongly typed collection, a malformed record or timestamp, a duplicate identifier, a malformed export response, an unknown export status, a polling timeout, an oversized, empty or truncated download, an artefact that fails XML validation, a failed commit, or an unexpected internal error. |

An HTTP 404 for a selected scan reports that the scan identifier was not found
or is not visible to the configured account. It is not reported as an
authentication failure.

## Running the tests

```powershell
python -m pytest -v
```

The suite is entirely offline. It uses mocks and synthetic values, contacts no
real Nessus instance and contains no real credentials. At version 0.3.1 it is
573 tests, all passing.

Passing tests establish that VulnSight behaves as specified against controlled
doubles. They do **not** establish that the provider behaves as assumed, and
they do not verify an artefact. Three distinct levels of assurance are kept
separate throughout this project:

| Level | What it establishes | How |
| --- | --- | --- |
| Test suite | VulnSight behaves as specified | Offline, mocked, injected clock |
| Live provider validation | The deployed Nessus contract is as assumed | Commands run against the lab scanner |
| Artefact integrity | The stored evidence is exactly what the scanner sent | Independent `Get-FileHash`, compared against a manual export |

`CHANGELOG.md` records the result of all three for each tranche.

## Troubleshooting

If `conda activate` is not recognised in PowerShell, initialise Conda for this
shell:

```powershell
conda init powershell
```

Then **close and reopen PowerShell** before trying `conda activate vulnsight`
again — the initialisation only takes effect in a new session.

If the connectivity check fails, share only the command output and a redacted
description of your configuration. Never paste the contents of `.env`, and
never share your API keys.
