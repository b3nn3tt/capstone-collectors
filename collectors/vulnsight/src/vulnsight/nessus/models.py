"""Typed models for read-only Nessus scan and history discovery.

Two kinds of value are deliberately kept apart:

* **raw provider values** are dataclass *fields*.  They hold exactly what
  Nessus supplied — the integer identifiers, the verbatim status strings and
  the original integer Unix timestamps;
* **derived display values** are *properties*.  They are computed by VulnSight
  — ISO 8601 rendering of a timestamp, and export eligibility.

Nothing here performs input or output, and nothing is persisted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

#: Neutral marker shown when Nessus did not supply an optional field.
NOT_SUPPLIED = "not supplied"

#: The only provider status that makes a run export-eligible, compared
#: case-insensitively.  No other status, and no timestamp, implies completion.
EXPORT_ELIGIBLE_STATUS = "completed"

#: Accepted Unix-timestamp range: the epoch to the end of year 9999.
MIN_TIMESTAMP = 0
MAX_TIMESTAMP = 253_402_300_799


class RecordError(ValueError):
    """Raised when a provider record breaks the expected response contract.

    Malformed records are reported, never silently skipped or repaired.
    """


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------


def to_iso8601_utc(value: int) -> str:
    """Render an integer Unix timestamp as ISO 8601 in UTC."""
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_timestamp(context: str, field: str, value: object) -> int | None:
    """Validate an optional integer Unix timestamp, returning it unchanged.

    A missing value is accepted and returned as ``None``.  A value that is
    present but not a plausible integer Unix timestamp is an error: VulnSight
    never fabricates or coerces a time.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RecordError(
            f"{context}: field '{field}' is not an integer Unix timestamp."
        )
    if not MIN_TIMESTAMP <= value <= MAX_TIMESTAMP:
        raise RecordError(
            f"{context}: field '{field}' is outside the range of plausible "
            "Unix timestamps."
        )
    try:
        to_iso8601_utc(value)
    except (OverflowError, OSError, ValueError) as exc:  # pragma: no cover
        raise RecordError(
            f"{context}: field '{field}' is not a convertible Unix timestamp."
        ) from exc
    return value


def parse_identifier(context: str, field: str, value: object) -> int:
    """Validate a required positive integer identifier."""
    if value is None:
        raise RecordError(f"{context}: required field '{field}' is missing.")
    if isinstance(value, bool) or not isinstance(value, int):
        raise RecordError(f"{context}: field '{field}' is not an integer.")
    if value <= 0:
        raise RecordError(f"{context}: field '{field}' is not a positive integer.")
    return value


def parse_optional_int(context: str, field: str, value: object) -> int | None:
    """Validate an optional integer field, returning it unchanged."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RecordError(f"{context}: field '{field}' is not an integer.")
    return value


def parse_optional_text(context: str, field: str, value: object) -> str | None:
    """Validate an optional text field, returning it verbatim.

    Provider text — most importantly a status — is never translated,
    normalised, trimmed or case-folded on the way in.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise RecordError(f"{context}: field '{field}' is not text.")
    return value


def parse_optional_bool(context: str, field: str, value: object) -> bool | None:
    """Validate an optional Boolean field, returning it unchanged."""
    if value is None:
        return None
    if not isinstance(value, bool):
        raise RecordError(f"{context}: field '{field}' is not a Boolean.")
    return value


def display(value: object) -> str:
    """Render a value for the terminal, or the neutral missing-value marker."""
    if value is None:
        return NOT_SUPPLIED
    if isinstance(value, str) and not value.strip():
        return NOT_SUPPLIED
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def display_timestamp(value: int | None) -> str:
    """Render an optional raw timestamp as ISO 8601 UTC, or the marker."""
    if value is None:
        return NOT_SUPPLIED
    return to_iso8601_utc(value)


def is_export_eligible(status: str | None) -> bool:
    """True only when the provider status is exactly ``completed``.

    The comparison is case-insensitive.  Completion is never inferred from a
    timestamp or from the absence of a status.
    """
    if not isinstance(status, str):
        return False
    return status.lower() == EXPORT_ELIGIBLE_STATUS


# ---------------------------------------------------------------------------
# Scan summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanSummary:
    """One scan configuration as reported by ``GET /scans``.

    All fields are raw provider values.  ``scan_id`` is required; every other
    field is optional and is ``None`` when Nessus did not supply it.
    """

    scan_id: int
    uuid: str | None = None
    name: str | None = None
    status: str | None = None
    folder_id: int | None = None
    last_modification_date: int | None = None

    @property
    def last_modification_iso(self) -> str | None:
        """Derived ISO 8601 UTC rendering of the raw modification time."""
        if self.last_modification_date is None:
            return None
        return to_iso8601_utc(self.last_modification_date)


# ---------------------------------------------------------------------------
# History summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HistorySummary:
    """One execution of a scan, from the ``history`` collection of a
    ``GET /scans/{scan_identifier}`` scan-details response.

    All fields are raw provider values.  ``history_id`` is required; every
    other field is optional.
    """

    history_id: int
    uuid: str | None = None
    status: str | None = None
    creation_date: int | None = None
    last_modification_date: int | None = None
    run_type: str | None = None
    is_rollover: bool | None = None

    @property
    def started_iso(self) -> str | None:
        """Derived ISO 8601 UTC rendering of the raw creation time."""
        if self.creation_date is None:
            return None
        return to_iso8601_utc(self.creation_date)

    @property
    def last_modification_iso(self) -> str | None:
        """Derived ISO 8601 UTC rendering of the raw modification time."""
        if self.last_modification_date is None:
            return None
        return to_iso8601_utc(self.last_modification_date)

    @property
    def export_eligible(self) -> bool:
        """Derived: whether a later tranche could export this run.

        This is VulnSight's judgement, not a provider field, and it is true
        only for the verbatim provider status ``completed``.
        """
        return is_export_eligible(self.status)


# ---------------------------------------------------------------------------
# Discovery results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScanDiscoveryResult:
    """The outcome of a successful ``GET /scans`` discovery."""

    scans: tuple[ScanSummary, ...]

    @property
    def is_empty(self) -> bool:
        """True when Nessus returned an explicitly empty scan collection."""
        return not self.scans

    @property
    def count(self) -> int:
        return len(self.scans)


@dataclass(frozen=True)
class HistoryDiscoveryResult:
    """The outcome of a successful history discovery.

    The history is read from the ``history`` collection of a single
    ``GET /scans/{scan_identifier}`` response.  That collection is the
    complete history the endpoint supplies: it carries no paging metadata,
    and none is invented.

    ``scan_name`` is the provider's own scan name, taken verbatim from
    ``info.name`` of the same response.  It is a naming convenience only:
    ``None`` means Nessus supplied no usable name, and an empty string means
    it explicitly supplied one.  It is never authoritative for identifying a
    scan — the numeric identifiers are.
    """

    scan_identifier: str
    runs: tuple[HistorySummary, ...]
    scan_name: str | None = None

    @property
    def is_empty(self) -> bool:
        """True when Nessus returned an explicitly empty history collection."""
        return not self.runs

    @property
    def count(self) -> int:
        return len(self.runs)

    @property
    def export_eligible_runs(self) -> tuple[HistorySummary, ...]:
        """Derived: the runs whose provider status is exactly ``completed``."""
        return tuple(run for run in self.runs if run.export_eligible)
