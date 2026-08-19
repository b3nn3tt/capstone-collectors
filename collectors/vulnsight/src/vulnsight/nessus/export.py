"""Native ``.nessus`` export: request, bounded polling and streamed download.

Three endpoints are used, in this order and no other:

* ``POST /scans/{scan_id}/export`` with the body
  ``{"format": "nessus", "history_id": <int>}`` — creates the artefact;
* ``GET  /scans/{scan_id}/export/{file_id}/status`` — polled until ``ready``;
* ``GET  /scans/{scan_id}/export/{file_id}/download`` — streamed to disk.

The POST is permitted solely because Nessus uses it to create the export
artefact.  It does not launch, stop, reschedule, modify or delete the scan.
No alternative request body, query parameter or cloud-specific fallback is
attempted: if the deployed API rejects this exact contract, the failure is
reported with its HTTP status so the contract can be corrected deliberately.

The export response may carry a download **token**.  It is never read into a
result, never printed, never persisted and never placed in the manifest; only
the ``file`` identifier is extracted.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests

from ..config import NessusConfig, redact
from .client import (
    SCANS_PATH,
    Outcome,
    classify_request_exception,
    perform_get,
    perform_get_stream,
    perform_post,
)
from .errors import ExportError

#: The only export format VulnSight will ever request.
EXPORT_FORMAT = "nessus"

#: The documented field carrying the server-side export identifier.  No
#: alternative field name is guessed at.
FILE_FIELD = "file"
STATUS_FIELD = "status"

#: Provider export states.  ``ready`` succeeds; ``loading`` is the only
#: documented pending state used by standalone Nessus; ``error`` fails.
#: Anything else is an API-contract error rather than a reason to keep polling.
STATUS_READY = "ready"
PENDING_STATUSES: frozenset[str] = frozenset({"loading"})
ERROR_STATUSES: frozenset[str] = frozenset({"error"})

#: Bytes read from the socket at a time while streaming the artefact.
DEFAULT_CHUNK_BYTES = 65_536

#: Largest identifier accepted in the ``file`` field.
MAX_FILE_ID = 2**63 - 1

#: Content types that indicate an error body masquerading as a download.
REJECTED_DOWNLOAD_TYPES = ("json", "html")


@dataclass(frozen=True)
class ExportSettings:
    """The bounded parameters governing an export, recorded in the manifest."""

    poll_interval_seconds: float
    poll_timeout_seconds: float
    max_bytes: int
    chunk_bytes: int = DEFAULT_CHUNK_BYTES

    @classmethod
    def from_config(cls, config: NessusConfig) -> "ExportSettings":
        """Build settings from the configured (or defaulted) values."""
        return cls(
            poll_interval_seconds=config.export_poll_interval_seconds,
            poll_timeout_seconds=config.export_poll_timeout_seconds,
            max_bytes=config.export_max_bytes,
        )


@dataclass(frozen=True)
class Clock:
    """The time source used while polling.

    Tests inject a fake monotonic clock and sleeper so that no test ever
    waits in real time.
    """

    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


@dataclass(frozen=True)
class DownloadResult:
    """The measured outcome of a streamed download."""

    size_bytes: int
    sha256: str


# ---------------------------------------------------------------------------
# URLs and paths
# ---------------------------------------------------------------------------


def export_path(scan_id: int) -> str:
    return f"{SCANS_PATH}/{scan_id}/export"


def status_path(scan_id: int, file_id: str) -> str:
    return f"{SCANS_PATH}/{scan_id}/export/{file_id}/status"


def download_path(scan_id: int, file_id: str) -> str:
    return f"{SCANS_PATH}/{scan_id}/export/{file_id}/download"


def _url(config: NessusConfig, path: str) -> str:
    return f"{config.endpoint}{path}"


def export_request_body(history_id: int) -> dict[str, object]:
    """The exact request body sent to standalone Nessus.

    The explicitly selected history is always included; it is never omitted,
    and no filter, chapter or plugin selection is ever added.
    """
    return {"format": EXPORT_FORMAT, "history_id": history_id}


# ---------------------------------------------------------------------------
# Step 1: request the export
# ---------------------------------------------------------------------------


def request_export(
    session: requests.Session,
    config: NessusConfig,
    scan_id: int,
    history_id: int,
) -> str:
    """Ask Nessus to build a native export and return its file identifier."""
    path = export_path(scan_id)
    body = export_request_body(history_id)

    try:
        response = perform_post(session, config, _url(config, path), body)
    except requests.exceptions.RequestException as exc:
        raise _transport_error(config, exc, path) from exc

    _raise_for_status(config, response, path, scan_id=scan_id)
    payload = _decode_json(config, response, path)
    return _extract_file_id(payload, path)


def _extract_file_id(payload: object, path: str) -> str:
    """Validate the documented ``file`` field and return it as safe text.

    Any download token in the response is deliberately not read.
    """
    if not isinstance(payload, dict):
        raise ExportError(
            Outcome.API_ERROR,
            f"The export response for {path} was valid JSON but not an object.",
        )
    if FILE_FIELD not in payload:
        raise ExportError(
            Outcome.API_ERROR,
            f"The export response for {path} has no '{FILE_FIELD}' field, so "
            "the export artefact cannot be identified.",
        )

    value = payload[FILE_FIELD]
    if value is None:
        raise ExportError(
            Outcome.API_ERROR,
            f"The export response for {path} has a null '{FILE_FIELD}' field.",
        )
    if isinstance(value, bool):
        raise ExportError(
            Outcome.API_ERROR,
            f"The export response for {path} has a Boolean '{FILE_FIELD}' "
            "field where an identifier was expected.",
        )
    if isinstance(value, int):
        if not 0 < value <= MAX_FILE_ID:
            raise ExportError(
                Outcome.API_ERROR,
                f"The export response for {path} has an out-of-range "
                f"'{FILE_FIELD}' identifier.",
            )
        return str(value)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate.isdigit() or candidate != candidate.lstrip("0"):
            raise ExportError(
                Outcome.API_ERROR,
                f"The export response for {path} has a '{FILE_FIELD}' "
                "identifier that is not safe to place in a request path. "
                "Only digits are accepted.",
            )
        if not 0 < int(candidate) <= MAX_FILE_ID:
            raise ExportError(
                Outcome.API_ERROR,
                f"The export response for {path} has an out-of-range "
                f"'{FILE_FIELD}' identifier.",
            )
        return candidate

    raise ExportError(
        Outcome.API_ERROR,
        f"The export response for {path} has a '{FILE_FIELD}' field that is "
        "neither an integer nor digit text.",
    )


# ---------------------------------------------------------------------------
# Step 2: bounded status polling
# ---------------------------------------------------------------------------


def wait_until_ready(
    session: requests.Session,
    config: NessusConfig,
    scan_id: int,
    file_id: str,
    settings: ExportSettings,
    clock: Clock | None = None,
) -> int:
    """Poll the export status until it is ``ready``; return the poll count.

    Polling is bounded by ``settings.poll_timeout_seconds`` and paced by
    ``settings.poll_interval_seconds``.  It never loops indefinitely, never
    prints per-poll output, and never retries an authentication or
    authorisation failure.  A provider error state fails immediately, and an
    undocumented state is treated as an API-contract error rather than a
    reason to keep waiting.
    """
    ticker = Clock() if clock is None else clock
    path = status_path(scan_id, file_id)
    started = ticker.monotonic()
    polls = 0

    while True:
        status = _poll_once(session, config, path)
        polls += 1

        if status.lower() == STATUS_READY:
            return polls
        if status.lower() in ERROR_STATUSES:
            raise ExportError(
                Outcome.API_ERROR,
                f"Nessus reported export status '{status}' for scan "
                f"{scan_id}. The scanner could not build the artefact; no "
                "file was written.",
            )
        if status.lower() not in PENDING_STATUSES:
            raise ExportError(
                Outcome.API_ERROR,
                f"Nessus reported the undocumented export status '{status}'. "
                "VulnSight will not keep polling on a state it does not "
                "recognise; report this status so the contract can be "
                "corrected.",
            )

        elapsed = ticker.monotonic() - started
        if elapsed + settings.poll_interval_seconds > settings.poll_timeout_seconds:
            raise ExportError(
                Outcome.API_ERROR,
                f"The export was still '{status}' after "
                f"{settings.poll_timeout_seconds:g} seconds. Polling stopped; "
                "no file was written. Raise "
                "NESSUS_EXPORT_POLL_TIMEOUT_SECONDS if this scan is large.",
            )
        ticker.sleep(settings.poll_interval_seconds)


def _poll_once(
    session: requests.Session, config: NessusConfig, path: str
) -> str:
    """Issue one status GET and return the raw provider status text."""
    try:
        response = perform_get(session, config, _url(config, path))
    except requests.exceptions.RequestException as exc:
        raise _transport_error(config, exc, path) from exc

    _raise_for_status(config, response, path)
    payload = _decode_json(config, response, path)

    if not isinstance(payload, dict):
        raise ExportError(
            Outcome.API_ERROR,
            f"The export status response for {path} was valid JSON but not "
            "an object.",
        )
    status = payload.get(STATUS_FIELD)
    if not isinstance(status, str) or not status.strip():
        raise ExportError(
            Outcome.API_ERROR,
            f"The export status response for {path} has no usable "
            f"'{STATUS_FIELD}' field.",
        )
    return status


# ---------------------------------------------------------------------------
# Step 3: streamed download
# ---------------------------------------------------------------------------


def download_export(
    session: requests.Session,
    config: NessusConfig,
    scan_id: int,
    file_id: str,
    settings: ExportSettings,
    destination: Path,
) -> DownloadResult:
    """Stream the artefact to *destination*, returning its size and digest.

    The response is consumed in bounded chunks, so the artefact is never held
    in memory.  The SHA-256 is computed over exactly the bytes written, while
    they are written.  *destination* is created exclusively and is the only
    file this function touches; the caller removes it if anything fails.
    """
    path = download_path(scan_id, file_id)

    try:
        response = perform_get_stream(session, config, _url(config, path))
    except requests.exceptions.RequestException as exc:
        raise _transport_error(config, exc, path) from exc

    try:
        _raise_for_status(config, response, path)
        _reject_error_body(response, path)
        declared = _declared_length(response, settings, path)
        result = _stream_to_file(response, settings, destination, path, config)
    finally:
        _close_quietly(response)

    if declared is not None and result.size_bytes != declared:
        raise ExportError(
            Outcome.API_ERROR,
            f"The download was incomplete: the scanner declared {declared} "
            f"bytes but {result.size_bytes} arrived. No evidence file was "
            "committed.",
        )
    return result


def _reject_error_body(response: object, path: str) -> None:
    """Refuse a JSON or HTML error body served with a success status."""
    headers = getattr(response, "headers", None) or {}
    content_type = str(headers.get("Content-Type", "") or "").lower()
    for rejected in REJECTED_DOWNLOAD_TYPES:
        if rejected in content_type:
            raise ExportError(
                Outcome.API_ERROR,
                f"The download endpoint {path} returned '{content_type}' "
                "rather than a Nessus XML artefact. This is an error body "
                "served with a success status; nothing was written.",
            )


def _declared_length(
    response: object, settings: ExportSettings, path: str
) -> int | None:
    """Validate ``Content-Length`` when the scanner supplies one."""
    headers = getattr(response, "headers", None) or {}
    raw = headers.get("Content-Length")
    if raw is None:
        return None
    text = str(raw).strip()
    if not text.isdigit():
        return None

    declared = int(text)
    if declared == 0:
        raise ExportError(
            Outcome.API_ERROR,
            f"The download endpoint {path} declared a zero-byte artefact. An "
            "empty export is never accepted as evidence.",
        )
    if declared > settings.max_bytes:
        raise ExportError(
            Outcome.API_ERROR,
            f"The declared artefact size of {declared} bytes exceeds the "
            f"permitted maximum of {settings.max_bytes} bytes. Nothing was "
            "downloaded. Raise NESSUS_EXPORT_MAX_BYTES if this is expected.",
        )
    return declared


def _stream_to_file(
    response: object,
    settings: ExportSettings,
    destination: Path,
    path: str,
    config: NessusConfig,
) -> DownloadResult:
    """Write the response body to *destination* in bounded chunks."""
    digest = hashlib.sha256()
    total = 0

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    handle_fd = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(handle_fd, "wb") as handle:
            for chunk in response.iter_content(chunk_size=settings.chunk_bytes):
                if not chunk:
                    continue
                total += len(chunk)
                if total > settings.max_bytes:
                    raise ExportError(
                        Outcome.API_ERROR,
                        "The artefact exceeded the permitted maximum of "
                        f"{settings.max_bytes} bytes while downloading. The "
                        "transfer was stopped and nothing was committed.",
                    )
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:  # pragma: no cover - platform dependent
                pass
    except requests.exceptions.RequestException as exc:
        raise _transport_error(config, exc, path) from exc

    if total == 0:
        raise ExportError(
            Outcome.API_ERROR,
            f"The download endpoint {path} returned zero bytes. An empty "
            "export is never accepted as evidence.",
        )
    return DownloadResult(size_bytes=total, sha256=digest.hexdigest())


def _close_quietly(response: object) -> None:
    """Close an HTTP response, ignoring a failure to do so."""
    closer = getattr(response, "close", None)
    if closer is None:
        return
    try:
        closer()
    except Exception:  # pragma: no cover - closing failures are not diagnostic
        pass


# ---------------------------------------------------------------------------
# Shared response handling
# ---------------------------------------------------------------------------


def _transport_error(
    config: NessusConfig, exc: requests.exceptions.RequestException, path: str
) -> ExportError:
    outcome, summary = classify_request_exception(config, exc, path)
    return ExportError(
        outcome,
        redact(summary, config),
        redact(f"{type(exc).__name__}: {exc}", config),
    )


def _decode_json(config: NessusConfig, response: object, path: str) -> object:
    try:
        return response.json()
    except Exception as exc:  # requests raises a ValueError subclass here
        raise ExportError(
            Outcome.API_ERROR,
            f"The scanner returned a response for {path} that is not valid "
            "JSON.",
            redact(f"{type(exc).__name__}: {exc}", config),
        ) from exc


def _raise_for_status(
    config: NessusConfig,
    response: object,
    path: str,
    *,
    scan_id: int | None = None,
) -> None:
    """Classify the HTTP status of an export-pipeline response.

    Authentication and authorisation failures are never retried.
    """
    status = getattr(response, "status_code", None)

    if status == 400:
        raise ExportError(
            Outcome.API_ERROR,
            f"The scanner rejected the export request to {path} as malformed "
            "(HTTP 400). VulnSight sends only the documented body "
            '{"format": "nessus", "history_id": <id>} and will not try '
            "alternatives; report this status so the contract can be "
            "corrected.",
        )
    if status == 401:
        raise ExportError(
            Outcome.AUTHENTICATION_ERROR,
            "Authentication was rejected (HTTP 401). Check the Nessus API "
            "access and secret keys in the .env file.",
        )
    if status == 403:
        raise ExportError(
            Outcome.AUTHENTICATION_ERROR,
            f"The authenticated account is not permitted to use {path} "
            "(HTTP 403). Grant the account permission to export scans.",
        )
    if status == 404:
        if scan_id is not None:
            raise ExportError(
                Outcome.API_ERROR,
                f"Scan {scan_id} was not found, or is not visible to the "
                "configured account (HTTP 404). This is not an "
                "authentication failure.",
            )
        raise ExportError(
            Outcome.API_ERROR,
            f"The endpoint {config.endpoint}{path} was not found (HTTP 404). "
            "The export artefact may have expired on the scanner.",
        )
    if status == 405:
        raise ExportError(
            Outcome.API_ERROR,
            f"The scanner rejected {path} with HTTP 405 (method not "
            "allowed). The deployed Nessus API does not support this export "
            "contract; report the scanner version so it can be corrected.",
        )
    if status == 429:
        raise ExportError(
            Outcome.API_ERROR,
            "The scanner rate-limited the export (HTTP 429). VulnSight does "
            "not retry automatically; wait and run the command again.",
        )
    if status is None or not 200 <= int(status) < 300:
        raise ExportError(
            Outcome.API_ERROR,
            f"The scanner returned an unexpected HTTP status ({status}) for "
            f"{path}.",
        )
