# VulnSight User Guide

This guide takes you from an empty Conda environment to a verified, hashed
`.nessus` evidence file with an acquisition manifest beside it.

It is written for a technically competent Windows user who does not know
VulnSight's internals. Every command is Windows PowerShell.

---

## 1. Purpose and scope

VulnSight is an **acquisition tool**. Its entire job is to obtain the original
`.nessus` artefact from a Nessus scanner in a way that can be independently
verified afterwards, and to record how that acquisition happened.

VulnSight:

- connects to Nessus over HTTPS using API keys;
- discovers the scans visible to the configured account;
- discovers the execution histories of one explicitly selected scan;
- requires you to select both the scan and the history explicitly;
- exports the original `.nessus` artefact;
- validates its basic XML structure;
- calculates SHA-256 over exactly the downloaded bytes;
- writes an acquisition manifest beside the artefact;
- never silently overwrites evidence.

That is the whole of it. VulnSight's output is *raw evidence plus provenance*.

## 2. What VulnSight does not do

VulnSight does **not**:

- parse findings into an analytical dataset;
- normalise Nessus findings;
- pseudonymise hosts or principals;
- query KEV or EPSS;
- merge Nessus evidence with Voight-Kampff;
- evaluate C1–C7;
- calculate contextual adjustments;
- score or rank vulnerabilities;
- determine remediation priority.

Those operations belong to the separate MSc dissertation artefact, not to
VulnSight. See [§20](#20-evidential-and-dissertation-boundary).

## 3. Prerequisites

- Windows, with Windows PowerShell.
- Miniconda or Anaconda.
- Python 3.11 or later.
- Network access to a Nessus instance over HTTPS, normally on port 8834.
- A Nessus API access key and secret key for an account that can read and
  export scans.

## 4. Create and activate the environment

```powershell
Set-Location "C:\path\to\capstone-collectors\collectors\vulnsight"
conda create --name vulnsight python=3.11 -y
conda activate vulnsight
```

Confirm the interpreter actually in use:

```powershell
python --version
Get-Command python
```

If `conda activate` is not recognised, run `conda init powershell`, then
**close and reopen PowerShell** — the initialisation only takes effect in a
new session.

## 5. Install VulnSight

```powershell
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

This installs VulnSight in editable mode with its test dependencies:
`requests`, `python-dotenv` and `defusedxml`.

## 6. Create and configure `.env`

Copy the example without disturbing an existing file:

```powershell
if (Test-Path ".env") { Write-Host ".env already exists; leaving it unchanged." } else { Copy-Item ".env.example" ".env"; Write-Host "Created .env from .env.example." }
notepad .env
```

Required settings:

| Setting | Meaning |
| --- | --- |
| `NESSUS_BASE_URL` | Scanner base URL, e.g. `https://10.0.0.1:8834` |
| `NESSUS_ACCESS_KEY` | Nessus API access key |
| `NESSUS_SECRET_KEY` | Nessus API secret key |
| `NESSUS_VERIFY_TLS` | `true` or `false` |
| `NESSUS_CONNECT_TIMEOUT_SECONDS` | Positive number of seconds, e.g. `5` |
| `NESSUS_READ_TIMEOUT_SECONDS` | Positive number of seconds, e.g. `15` |

Optional export settings, each with the documented default shown. Leaving them
out is fine:

| Setting | Default | Meaning |
| --- | --- | --- |
| `NESSUS_EXPORT_POLL_INTERVAL_SECONDS` | `2` | Seconds between export-status polls |
| `NESSUS_EXPORT_POLL_TIMEOUT_SECONDS` | `600` | Total seconds to wait for an export |
| `NESSUS_EXPORT_MAX_BYTES` | `1073741824` | Largest artefact accepted (1 GiB) |

An example with obvious placeholders — **never use these values**:

```text
NESSUS_BASE_URL=https://REPLACE-WITH-SCANNER-HOST:8834
NESSUS_ACCESS_KEY=REPLACE_WITH_YOUR_ACCESS_KEY
NESSUS_SECRET_KEY=REPLACE_WITH_YOUR_SECRET_KEY
NESSUS_VERIFY_TLS=true
NESSUS_CONNECT_TIMEOUT_SECONDS=5
NESSUS_READ_TIMEOUT_SECONDS=15
```

Every required setting must be present and non-blank. VulnSight never guesses
configuration and never supplies credentials of its own.

## 7. Secret handling — please read

Your API keys are equivalent to scanner credentials.

- `.env` is excluded by `.gitignore`. **Never commit it.**
- Never paste `.env` contents into a message, ticket, log or dissertation
  appendix.
- Neither key is ever printed, logged, placed in an object representation, put
  into an exception message or written into a manifest. If you ever see key
  material in VulnSight output, treat it as a defect and report it.
- When sharing diagnostics, share the command output only.
- Rotate the keys in Nessus if you suspect exposure.

## 8. TLS verification

`NESSUS_VERIFY_TLS=true` is the correct setting and should be your default.

`NESSUS_VERIFY_TLS=false` exists so a lab scanner with a self-signed
certificate can be reached. It **disables certificate verification** and so
removes protection against interception and impersonation. Use it only against
a local lab scanner you control, never against a production or internet-facing
scanner.

When verification is disabled, VulnSight prints one compact warning to stderr
on every command, and records `"verify_tls": false` in the manifest, so the
condition is visible in the evidence rather than forgotten.

## 9. Check connectivity

```powershell
python -m vulnsight nessus check
$LASTEXITCODE
```

This is the one deliberately verbose command. It reports the endpoint, TCP
connectivity, API authentication, that `GET /scans` returned valid JSON, and
whether TLS verification was enabled. The scans themselves are never printed.

Run this first whenever something is not working.

## 10. List the visible scans

```powershell
python -m vulnsight nessus scans list
$LASTEXITCODE
```

Output is a table and one `Next:` line:

```text
SCAN ID  UUID                                                      NAME                STATUS     FOLDER  LAST MODIFIED (UTC)
-------  --------------------------------------------------------  ------------------  ---------  ------  --------------------
5        01234567-89ab-cdef-0123-456789abcdef0123456789abcdef      synthetic-lab-scan  completed  3       2026-01-15T14:30:00Z

Next: python -m vulnsight nessus scans histories --scan <SCAN ID>
```

Status values are shown exactly as Nessus supplied them. Targets, credentials,
policy contents, hosts and findings are never displayed, and the response is
not saved.

Use the **numeric SCAN ID**. The UUID column is shown for provenance;
standalone Nessus reports a value there that is not a canonical UUID.
VulnSight never selects a scan by name.

## 11. List the histories of one scan

```powershell
python -m vulnsight nessus scans histories --scan 5
$LASTEXITCODE
```

```text
HISTORY ID  UUID                                  STATUS     STARTED (UTC)         LAST MODIFIED (UTC)   TYPE   ROLLOVER  EXPORT-ELIGIBLE
----------  ------------------------------------  ---------  --------------------  --------------------  -----  --------  ---------------
6           …                                     completed  2026-01-15T14:00:00Z  2026-01-15T14:30:00Z  local  no        yes

Next: python -m vulnsight nessus scans export --scan 5 --history <HISTORY_ID> --output-dir ".\evidence\raw\nessus"
```

A run is marked export-eligible **only** when its provider status is exactly
`completed`, compared case-insensitively. Completion is never inferred from a
timestamp. No run is selected for you — the `Next:` line is a template, and you
supply the history ID.

## 12. Export a completed history

```powershell
python -m vulnsight nessus scans export --scan 5 --history 6 --output-dir ".\evidence\raw\nessus"
$LASTEXITCODE
```

All three arguments are required. Both `--scan` and `--history` must be
positive integers. There is no `latest`, no implicit selection and no
name-based lookup.

What happens, in order:

1. the output directory is created if absent;
2. `GET /scans/5` confirms history 6 exists and its status is exactly
   `completed`, and supplies the scan name used for the filename;
3. the destination paths are resolved and checked — if either file already
   exists the command stops here, **before any export is requested**;
4. `POST /scans/5/export` asks Nessus to build the artefact;
5. the export status is polled within a bounded time;
6. the artefact is streamed to a temporary `.part` file in bounded chunks, with
   SHA-256 computed over exactly those bytes as they are written;
7. the XML is validated structurally with a safe parser;
8. the artefact and its manifest are committed together.

Successful output is a compact table.

The identifiers, timestamps, byte count and SHA-256 digest shown below are synthetic illustrative values:

```text
ITEM      VALUE
--------  ----------------------------------------------------------------
File      .\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.nessus
Manifest  .\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.manifest.json
Bytes     1234567
SHA-256   0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

## 13. Output naming

Both files share one stem:

```text
<safe-scan-name>__scan-<SCAN_ID>__history-<HISTORY_ID>
```

It combines two different things deliberately:

- **`<safe-scan-name>`** — a human-readable, mechanically sanitised slug of the
  provider's own scan name, so a directory holding thirteen systems is legible
  at a glance;
- **`__scan-<SCAN_ID>__history-<HISTORY_ID>`** — the authoritative numeric
  identifiers.

The slug is produced by a fixed algorithm: Unicode normalisation, ASCII
transliteration of accented Latin characters, lowercasing, every run of
characters outside `[a-z0-9]` replaced by a single hyphen, hyphens collapsed
and trimmed, and a 64-character cap. The result can only ever match
`[a-z0-9-]`, so a provider name can never introduce a directory, an absolute
path, a drive letter, a UNC prefix, an alternate data stream or a `..`
component.

If Nessus supplies no usable name — the `info` block is absent, the name is
absent, null, not text or blank, or it contains nothing that survives
slugging — the stem falls back to:

```text
nessus__scan-<SCAN_ID>__history-<HISTORY_ID>
```

A missing name never fails an otherwise valid export.

Two scans whose names reduce to the same slug stay distinct, because the
numeric suffix is always appended. A name that matches a Windows reserved
device name such as `CON` or `LPT1` is harmless for the same reason: the
reserved names apply to the whole basename, which always carries the suffix.

There is **no** `--label`, `--name` or `--filename` option. A hand-typed label
could misdescribe the evidence. The provider's scan name supplies convenience;
the scan ID, history ID and hashes supply authority.

The raw, unmodified provider scan name is preserved in the manifest under
`scan.scan_name`. The filename carries only its slug. The two are recorded
independently so neither can be mistaken for the other.

> **Filenames are not evidence selectors.** They are a convenience for humans.
> The manifest and the SHA-256 are what identify an artefact.

## 14. The acquisition manifest

Each artefact has a UTF-8 JSON sidecar under the contract
`vulnsight.nessus-export-manifest/1.1`, written deterministically with a fixed
field order, two-space indentation and a terminating newline.

It records the manifest schema and creation time; the tool name and version;
the source type, base URL and TLS-verification setting; the scan ID, the raw
scan name, the selected history ID and that history's raw provider status,
UUID and timestamps alongside their ISO 8601 renderings; the export format,
request path, request body, server file identifier, polling interval, polling
timeout and maximum permitted bytes; the export completion time; and the
locally generated filename, byte size, SHA-256, XML root and structural
counts.

It contains **no** API access key, secret key, `X-ApiKeys` header, export
token, response headers, `.env` content, targets, credentials, plugin output,
findings, host details, scores or analytical conclusions.

Manifests written under the earlier schema `1.0` remain valid historical
acquisition records. Schema `1.1` only adds `scan.scan_name`. VulnSight never
rewrites, migrates or renames an existing manifest or artefact.

## 15. Verify the artefact independently

Do not take VulnSight's word for the hash. Compute it yourself:

```powershell
Get-FileHash ".\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.nessus" -Algorithm SHA256
```

Compare the result with `artefact.sha256` in the manifest:

```powershell
Get-Content ".\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.manifest.json"
```

They must match exactly. A one-liner that checks it for you:

```powershell
$m = Get-Content ".\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.manifest.json" | ConvertFrom-Json
$h = (Get-FileHash ".\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.nessus" -Algorithm SHA256).Hash.ToLower()
if ($h -eq $m.artefact.sha256) { "MATCH" } else { "MISMATCH" }
```

For a verified lab acquisition, the computed digest was independently compared
with the SHA-256 of an earlier manual, unedited export of the same history —
the API path produced byte-for-byte identical evidence to a manual export.

## 16. No-overwrite behaviour

VulnSight never overwrites evidence, and there is no `--force`.

If either destination file already exists, the export stops before contacting
the scanner and exits with code `2`. To re-acquire, move the existing
acquisition aside deliberately:

```powershell
New-Item -ItemType Directory ".\evidence\raw\nessus\superseded" -Force | Out-Null
Move-Item ".\evidence\raw\nessus\synthetic-lab-scan__scan-5__history-6.*" ".\evidence\raw\nessus\superseded\"
```

Related guarantees:

- server-supplied filenames are ignored entirely;
- the artefact is written to a unique, invocation-scoped `.part` file first;
- the downloaded bytes are moved into place, never rewritten;
- a handled failure removes only files created by that invocation, and leaves
  no `.part` behind;
- no pre-existing file is ever deleted or altered.

Evidence directories, `.nessus` files, `.part` files and manifests inside a raw
evidence directory are excluded by `.gitignore`, so generated scan material
cannot be committed by accident.

## 17. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success — connectivity verified, a listing produced (including an empty one), or an artefact acquired |
| 2 | Configuration or command-line input error — `.env` missing or invalid, a malformed `--scan`, `--history` or `--output-dir`, a history that does not exist or is not `completed`, or a destination file that already exists |
| 3 | Network or TLS failure — DNS, connection refused, timeout, route failure, certificate verification failure, or an interrupted download |
| 4 | Authentication or authorisation failure — HTTP 401 or 403, never retried |
| 5 | Unexpected API response or internal failure — an unexpected HTTP status, malformed JSON, a bad response contract, a polling timeout, an oversized, empty or truncated download, an artefact failing XML validation, or a failed commit |

Check it after every command:

```powershell
$LASTEXITCODE
```

## 18. Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `conda activate` not recognised | Run `conda init powershell`, then open a new PowerShell window |
| `ModuleNotFoundError: defusedxml` | The editable install predates the dependency. Re-run `python -m pip install -e ".[dev]"` |
| `--version` shows an old number | Same cause — reinstall as above |
| Exit 2, "Configuration error" | `.env` is missing or a setting is blank or malformed. Check the table in §6 |
| Exit 3, "TLS certificate … could not be verified" | Self-signed lab certificate. Install a trusted certificate, or set `NESSUS_VERIFY_TLS=false` for a lab scanner only |
| Exit 3, connection refused or timed out | Wrong host or port, scanner not running, or a firewall. Try `nessus check` |
| Exit 4, HTTP 401 | Access or secret key wrong. Regenerate them in Nessus |
| Exit 4, HTTP 403 | The account lacks permission to read or export scans |
| Exit 5, HTTP 404 on a scan | The scan ID is not visible to this account. Re-run `scans list` |
| Exit 5, HTTP 405 | The deployed Nessus API does not support that endpoint. Report the scanner version |
| Exit 2, "already exists" | Expected. Move the previous acquisition aside — see §16 |
| Exit 2, "not 'completed'" | The history is still running or was cancelled. Pick a completed one |
| Exit 5, polling timeout | A large scan. Raise `NESSUS_EXPORT_POLL_TIMEOUT_SECONDS` |
| Exit 5, "exceeds the permitted maximum" | Raise `NESSUS_EXPORT_MAX_BYTES` if the size is expected |

When reporting a problem, share the command, its output and the exit code.
**Never share `.env` or your API keys.**

## 19. Updating or reinstalling

After pulling changes, or whenever the version or dependencies change, refresh
the editable install:

```powershell
conda activate vulnsight
python -m pip install -e ".[dev]"
python -m vulnsight --version
```

The version is derived dynamically from the package, so the editable metadata
must be refreshed for `--version` to report the new number. This is the single
most common cause of confusing behaviour after an update.

Run the test suite to confirm the installation is healthy:

```powershell
python -m pytest -q
$LASTEXITCODE
```

The suite is entirely offline: it uses mocks and synthetic values, contacts no
real Nessus instance and contains no real credentials.

## 20. Evidential and dissertation boundary

This boundary is deliberate and should not be blurred.

**Voight-Kampff** ends with raw schema-1.1 JSON and acquisition provenance.

**VulnSight** ends with raw `.nessus` evidence and an acquisition manifest.

**The MSc artefact** begins with validation, controlled parsing,
pseudonymisation, filtering, normalisation and source reconciliation.

Everything analytical — parsing findings into a dataset, normalising them,
pseudonymising hosts or principals, querying KEV or EPSS, merging Nessus with
Voight-Kampff, evaluating C1–C7, calculating contextual adjustments, scoring,
ranking and determining remediation priority — belongs to that separate
artefact, not to VulnSight.

Keeping the boundary sharp is what makes the evidence defensible. VulnSight's
output can be verified by anyone with `Get-FileHash` and the manifest, without
trusting any analytical judgement, because VulnSight makes none. An analytical
step folded into acquisition would destroy that property.

VulnSight is complete for its sourcing role. It is not the dissertation
artefact and will not become one.
