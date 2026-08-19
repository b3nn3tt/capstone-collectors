"""Read-only Nessus scan and history discovery.

Two endpoints are used, and only ever with the GET method:

* ``GET /scans`` — the scan configurations visible to the configured account;
* ``GET /scans/{scan_identifier}`` — the scan details for one explicitly
  selected scan, from which only the ``history`` collection is read.

The deployed standalone Nessus 10.12 scanner rejects the cloud-style
``GET /scans/{scan_identifier}/history`` endpoint with HTTP 405, so that
endpoint is not used and is not retained as a fallback.

Nothing here creates, modifies, launches, stops, deletes or exports a scan,
and no response is written to disk.  Requests are issued through
:func:`vulnsight.nessus.client.perform_get`, so API-key handling, timeouts and
the configured TLS behaviour are those already established in Tranche 0.

Failures are raised as :class:`DiscoveryError`, which carries the same
outcome classification — and therefore the same stable exit codes — as the
connectivity preflight.
"""

from __future__ import annotations

import requests

from ..config import NessusConfig, redact
from .client import (
    SCANS_PATH,
    Outcome,
    classify_request_exception,
    perform_get,
)
from .errors import NessusError
from .identifiers import ScanIdentifier
from .models import (
    HistoryDiscoveryResult,
    HistorySummary,
    RecordError,
    ScanDiscoveryResult,
    ScanSummary,
    parse_identifier,
    parse_optional_bool,
    parse_optional_int,
    parse_optional_text,
    parse_timestamp,
)

#: Response fields that carry the collections this module reads.
SCANS_FIELD = "scans"
HISTORY_FIELD = "history"

#: The only part of the scan-details ``info`` block that is ever read: the
#: provider's scan name, used solely to make an exported filename legible.
#: No other ``info`` field, and no ``hosts``, ``vulnerabilities``, ``notes``,
#: ``compliance``, policy or findings data, is parsed, retained or exposed.
INFO_FIELD = "info"
SCAN_NAME_FIELD = "name"

#: Nessus reports a history identifier as ``history_id``; some builds use
#: ``id``.  The first field present wins, and both are integers.
HISTORY_ID_FIELDS: tuple[str, ...] = ("history_id", "id")

#: How many top-level field names a contract error may quote when the history
#: collection is absent.  Field *names* are structural and are safe to show;
#: field *values* — hosts, vulnerabilities, notes, targets, policy data — are
#: never read, printed or persisted.
MAX_REPORTED_FIELDS = 20


class DiscoveryError(NessusError):
    """A classified, secret-free discovery failure."""


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def list_scans(config: NessusConfig) -> ScanDiscoveryResult:
    """Return the scan configurations visible to the configured account.

    Issues exactly one ``GET /scans`` request.  The response is validated,
    summarised and then discarded; it is never written anywhere.
    """
    session = requests.Session()
    try:
        payload = _get_json(session, config, config.scans_url, SCANS_PATH)
    finally:
        session.close()

    return _parse_scan_list(payload)


def list_scan_history(
    config: NessusConfig, identifier: ScanIdentifier
) -> HistoryDiscoveryResult:
    """Return the individual executions of one explicitly selected scan.

    Issues exactly one ``GET /scans/{scan_identifier}`` request and reads only
    the ``history`` collection from the scan-details response.  Every other
    part of that response — hosts, vulnerabilities, notes, targets, policy
    data, findings — is ignored: it is neither parsed, displayed nor saved,
    and the payload is released once the history has been summarised.

    The ``history`` array in this response is the complete history collection
    for the scan.  The endpoint supplies no paging metadata, and none is
    invented.  No run is selected automatically.
    """
    url = f"{config.scans_url}/{identifier.value}"
    path = f"{SCANS_PATH}/{identifier.value}"

    session = requests.Session()
    try:
        payload = _get_json(session, config, url, path, identifier=identifier)
    finally:
        session.close()

    records = _extract_history(payload, identifier)
    runs = _parse_history_records(records, identifier)
    scan_name = _extract_scan_name(payload)
    del payload, records  # Release the scan-details response after parsing.

    return HistoryDiscoveryResult(
        scan_identifier=identifier.value, runs=runs, scan_name=scan_name
    )


# ---------------------------------------------------------------------------
# Request and response transport
# ---------------------------------------------------------------------------


def _get_json(
    session: requests.Session,
    config: NessusConfig,
    url: str,
    path: str,
    *,
    identifier: ScanIdentifier | None = None,
) -> object:
    """Issue one GET request and return its decoded JSON payload."""
    try:
        response = perform_get(session, config, url)
    except requests.exceptions.RequestException as exc:
        outcome, summary = classify_request_exception(config, exc, path)
        raise DiscoveryError(
            outcome,
            redact(summary, config),
            redact(f"{type(exc).__name__}: {exc}", config),
        ) from exc

    _raise_for_status(config, response, path, identifier)

    try:
        return response.json()
    except Exception as exc:  # requests raises a ValueError subclass here
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scanner returned a response for {path} that is not valid "
            "JSON.",
            redact(f"{type(exc).__name__}: {exc}", config),
        ) from exc


def _raise_for_status(
    config: NessusConfig,
    response: object,
    path: str,
    identifier: ScanIdentifier | None,
) -> None:
    """Classify the HTTP status, raising :class:`DiscoveryError` on failure.

    Authentication and authorisation failures are never retried.
    """
    status = getattr(response, "status_code", None)

    if status == 401:
        raise DiscoveryError(
            Outcome.AUTHENTICATION_ERROR,
            "Authentication was rejected (HTTP 401). Check the Nessus API "
            "access and secret keys in the .env file.",
        )
    if status == 403:
        raise DiscoveryError(
            Outcome.AUTHENTICATION_ERROR,
            "The authenticated account is not permitted to read "
            f"{path} (HTTP 403). Grant the account read access to scans.",
        )
    if status == 404:
        if identifier is not None:
            raise DiscoveryError(
                Outcome.API_ERROR,
                f"Scan identifier '{identifier.value}' was not found, or is "
                "not visible to the configured account (HTTP 404). This is "
                "not an authentication failure: list the scans first and "
                "choose an identifier from that output.",
            )
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The endpoint {config.endpoint}{path} was not found (HTTP 404). "
            "Check NESSUS_BASE_URL and the scanner's API version.",
        )
    if status == 405:
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scanner rejected GET {path} with HTTP 405 (method not "
            "allowed). The deployed Nessus API does not support this "
            "endpoint. VulnSight issues GET requests only, so this is an API "
            "incompatibility rather than a permissions problem; report the "
            "scanner version so the endpoint can be corrected.",
        )
    if status == 429:
        raise DiscoveryError(
            Outcome.API_ERROR,
            "The scanner rate-limited the request (HTTP 429). VulnSight does "
            "not retry automatically; wait and run the command again.",
        )
    if status is None or not 200 <= int(status) < 300:
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scanner returned an unexpected HTTP status ({status}) for "
            f"{path}.",
        )


# ---------------------------------------------------------------------------
# Scan-list parsing
# ---------------------------------------------------------------------------


def _parse_scan_list(payload: object) -> ScanDiscoveryResult:
    """Validate a ``GET /scans`` payload and summarise it deterministically."""
    if not isinstance(payload, dict):
        raise DiscoveryError(
            Outcome.API_ERROR,
            "The scan list response was valid JSON but not the expected "
            "object structure.",
        )
    if SCANS_FIELD not in payload:
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scan list response has no '{SCANS_FIELD}' field. A missing "
            "collection is an invalid response, not an empty result.",
        )

    records = payload[SCANS_FIELD]
    if records is None:
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scan list response has a null '{SCANS_FIELD}' field. A null "
            "collection is an invalid response, not an empty result.",
        )
    if not isinstance(records, list):
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scan list response has a '{SCANS_FIELD}' field that is not "
            "a list.",
        )

    summaries: list[ScanSummary] = []
    seen: set[int] = set()
    for index, record in enumerate(records):
        context = f"Scan record {index}"
        if not isinstance(record, dict):
            raise DiscoveryError(
                Outcome.API_ERROR, f"{context}: the record is not an object."
            )
        try:
            summary = ScanSummary(
                scan_id=parse_identifier(context, "id", record.get("id")),
                uuid=parse_optional_text(context, "uuid", record.get("uuid")),
                name=parse_optional_text(context, "name", record.get("name")),
                status=parse_optional_text(context, "status", record.get("status")),
                folder_id=parse_optional_int(
                    context, "folder_id", record.get("folder_id")
                ),
                last_modification_date=parse_timestamp(
                    context,
                    "last_modification_date",
                    record.get("last_modification_date"),
                ),
            )
        except RecordError as exc:
            raise DiscoveryError(Outcome.API_ERROR, str(exc)) from exc

        if summary.scan_id in seen:
            raise DiscoveryError(
                Outcome.API_ERROR,
                f"The scan list contains more than one scan with ID "
                f"{summary.scan_id}. Duplicate identifiers are a response "
                "contract error, so no listing is shown.",
            )
        seen.add(summary.scan_id)
        summaries.append(summary)

    # Deterministic display order only; no provider value is altered.
    summaries.sort(key=lambda scan: scan.scan_id)
    return ScanDiscoveryResult(scans=tuple(summaries))


# ---------------------------------------------------------------------------
# Scan-detail history extraction
# ---------------------------------------------------------------------------


def _extract_history(payload: object, identifier: ScanIdentifier) -> list:
    """Take the ``history`` collection out of a scan-details response.

    Only the history collection is read.  If the response does not carry the
    history where this contract expects it, the command fails with a precise
    error naming the top-level fields that were present, so that the actual
    shape can be reported and repaired.  The structure is never guessed at.
    """
    if not isinstance(payload, dict):
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scan-details response for '{identifier.value}' was valid "
            "JSON but not the expected object structure.",
        )

    if HISTORY_FIELD not in payload:
        present = sorted(str(key) for key in payload)
        shown = ", ".join(present[:MAX_REPORTED_FIELDS]) or "none"
        if len(present) > MAX_REPORTED_FIELDS:
            shown += ", …"
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scan-details response for '{identifier.value}' has no "
            f"'{HISTORY_FIELD}' field. A missing collection is an invalid "
            "response, not an empty result. VulnSight will not guess where "
            "the history lives. Top-level field names present were: "
            f"{shown}. Report these so the response contract can be "
            "corrected.",
        )

    records = payload[HISTORY_FIELD]
    if records is None:
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scan-details response for '{identifier.value}' has a null "
            f"'{HISTORY_FIELD}' field. A null collection is an invalid "
            "response, not an empty result.",
        )
    if not isinstance(records, list):
        raise DiscoveryError(
            Outcome.API_ERROR,
            f"The scan-details response for '{identifier.value}' has a "
            f"'{HISTORY_FIELD}' field that is not a list.",
        )

    return records


def _extract_scan_name(payload: object) -> str | None:
    """Read the provider's scan name from a scan-details response.

    This reads ``info.name`` and nothing else.  It is deliberately forgiving:
    a name is a naming convenience, so an absent, null or wrongly typed value
    yields ``None`` rather than failing an otherwise valid acquisition.  The
    value is returned exactly as supplied, including an explicitly empty
    string, which is distinct from an absent one.

    No name is ever inferred from a target, host, UUID or server-supplied
    export filename.
    """
    if not isinstance(payload, dict):
        return None

    info = payload.get(INFO_FIELD)
    if not isinstance(info, dict):
        return None

    name = info.get(SCAN_NAME_FIELD)
    if not isinstance(name, str):
        return None
    return name


def _parse_history_records(
    records: list, identifier: ScanIdentifier
) -> tuple[HistorySummary, ...]:
    """Validate history records and summarise them deterministically."""
    summaries: list[HistorySummary] = []
    seen: set[int] = set()

    for index, record in enumerate(records):
        context = f"History record {index}"
        if not isinstance(record, dict):
            raise DiscoveryError(
                Outcome.API_ERROR, f"{context}: the record is not an object."
            )

        id_field = next(
            (field for field in HISTORY_ID_FIELDS if field in record),
            HISTORY_ID_FIELDS[0],
        )
        try:
            summary = HistorySummary(
                history_id=parse_identifier(context, id_field, record.get(id_field)),
                uuid=parse_optional_text(context, "uuid", record.get("uuid")),
                status=parse_optional_text(context, "status", record.get("status")),
                creation_date=parse_timestamp(
                    context, "creation_date", record.get("creation_date")
                ),
                last_modification_date=parse_timestamp(
                    context,
                    "last_modification_date",
                    record.get("last_modification_date"),
                ),
                run_type=parse_optional_text(context, "type", record.get("type")),
                is_rollover=parse_optional_bool(
                    context, "is_rollover", record.get("is_rollover")
                ),
            )
        except RecordError as exc:
            raise DiscoveryError(Outcome.API_ERROR, str(exc)) from exc

        if summary.history_id in seen:
            raise DiscoveryError(
                Outcome.API_ERROR,
                f"The history for scan '{identifier.value}' contains more "
                f"than one run with ID {summary.history_id}. Duplicate "
                "identifiers are a response contract error, so no listing is "
                "shown.",
            )
        seen.add(summary.history_id)
        summaries.append(summary)

    # Deterministic display order only; no provider value is altered.
    summaries.sort(key=lambda run: run.history_id)
    return tuple(summaries)
