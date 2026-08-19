"""Validation of user-supplied Nessus scan identifiers.

A scan is selected explicitly by the user.  Three identifier forms are
accepted:

* a positive integer scan ID, such as ``5`` — the recommended selector for a
  standalone Nessus scanner, and the form its ``GET /scans/{id}`` endpoint
  expects;
* a canonical hyphenated UUID (``8-4-4-4-12`` hexadecimal); or
* the extended provider identifier that standalone Nessus reports in the
  ``uuid`` field of its scan list.  The deployed 10.12 scanner returns values
  such as ``01234567-89ab-cdef-0123-456789abcdef0123456789abcdef``, which
  share the canonical hyphen positions but carry a longer final group.  Those
  are accepted only under the strict ``8-4-4-4-N`` hexadecimal grammar below,
  never as arbitrary alphanumeric text.

Whether the deployed endpoint actually resolves a provider identifier is the
scanner's decision, not VulnSight's: an identifier the scanner does not
recognise returns HTTP 404, which is reported as "not found or not visible".

Scan *names* are deliberately rejected because Nessus does not guarantee that
a name is unique, and implicit selectors such as ``latest`` are rejected
because the user must choose the scan.

Every accepted identifier consists solely of decimal digits, or of
hexadecimal digits and hyphens, so an accepted value is always safe to
interpolate into a URL path without further encoding.  Nothing here performs
any network access.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The largest scan ID that will be accepted, guarding against absurd input.
MAX_SCAN_ID = 2**63 - 1

#: Bounds on the final group of a hyphenated provider identifier.
MIN_FINAL_GROUP = 12
MAX_FINAL_GROUP = 64

#: The longest hyphenated identifier accepted: 8+4+4+4 hexadecimal digits,
#: four hyphens and a final group of at most :data:`MAX_FINAL_GROUP`.
MAX_IDENTIFIER_LENGTH = 8 + 4 + 4 + 4 + MAX_FINAL_GROUP + 4

#: Characters that must never appear in an identifier, checked explicitly so
#: that traversal and injection attempts produce a specific message.
FORBIDDEN_SEQUENCES: tuple[str, ...] = (
    "/",
    "\\",
    "?",
    "#",
    "..",
    ".",
    "%",
    "&",
    " ",
    "\t",
    ":",
    "@",
)

_DIGITS = re.compile(r"\A[0-9]+\Z")
_SIGNED_DIGITS = re.compile(r"\A[+-][0-9]+\Z")

#: The canonical UUID grammar, and the extended provider grammar that differs
#: from it only in the length of the final hexadecimal group.
_HYPHENATED = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    rf"-[0-9a-fA-F]{{{MIN_FINAL_GROUP},{MAX_FINAL_GROUP}}}\Z"
)

KIND_ID = "id"
KIND_UUID = "uuid"
KIND_PROVIDER = "provider"


class ScanIdentifierError(ValueError):
    """Raised when a supplied scan identifier is not acceptable.

    The message is constructed from static text and from the supplied value,
    which is user input rather than configuration, so it never carries a
    secret.
    """


@dataclass(frozen=True)
class ScanIdentifier:
    """A validated scan identifier.

    ``value`` is the exact text placed into the request path.  ``numeric_id``
    is populated only when the user supplied an integer scan ID.
    """

    value: str
    kind: str
    numeric_id: int | None = None

    @property
    def is_numeric(self) -> bool:
        """True when the user selected the scan by its numeric ID."""
        return self.kind == KIND_ID

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


def parse_scan_identifier(raw: object) -> ScanIdentifier:
    """Validate *raw* and return a :class:`ScanIdentifier`.

    Raises :class:`ScanIdentifierError` for anything that is not a positive
    integer scan ID or a strictly formatted hyphenated provider identifier.
    """
    if raw is None:
        raise ScanIdentifierError(
            "No scan identifier was supplied. Provide --scan with a positive "
            "integer scan ID, which is the selector standalone Nessus "
            "expects."
        )
    if not isinstance(raw, str):
        raise ScanIdentifierError(
            "The scan identifier must be text: a positive integer scan ID, or "
            "a hyphenated hexadecimal provider identifier."
        )

    candidate = raw.strip()
    if not candidate:
        raise ScanIdentifierError(
            "The scan identifier is blank. Provide a positive integer scan ID, "
            "or a hyphenated hexadecimal provider identifier."
        )

    if len(candidate) > MAX_IDENTIFIER_LENGTH:
        raise ScanIdentifierError(
            f"The scan identifier is {len(candidate)} characters long, which "
            f"exceeds the {MAX_IDENTIFIER_LENGTH}-character maximum."
        )

    for sequence in FORBIDDEN_SEQUENCES:
        if sequence in candidate:
            raise ScanIdentifierError(
                f"The scan identifier {candidate!r} contains the disallowed "
                f"sequence {sequence!r}. Supply only a positive integer scan "
                "ID or a hyphenated hexadecimal provider identifier; paths, "
                "query strings and fragments are not accepted."
            )

    if _SIGNED_DIGITS.match(candidate):
        raise ScanIdentifierError(
            f"The scan identifier {candidate!r} is not a positive integer. "
            "Scan IDs are whole numbers of 1 or greater."
        )

    if _DIGITS.match(candidate):
        numeric = int(candidate)
        if numeric <= 0:
            raise ScanIdentifierError(
                f"The scan identifier {candidate!r} is not a positive "
                "integer. Scan IDs are whole numbers of 1 or greater."
            )
        if numeric > MAX_SCAN_ID:
            raise ScanIdentifierError(
                f"The scan identifier {candidate!r} is larger than any scan "
                "ID Nessus issues."
            )
        # Reject padded forms such as "0123" so that one scan has one identifier.
        if candidate != str(numeric):
            raise ScanIdentifierError(
                f"The scan identifier {candidate!r} has leading zeroes. "
                f"Supply it as {numeric}."
            )
        return ScanIdentifier(value=candidate, kind=KIND_ID, numeric_id=numeric)

    if _HYPHENATED.match(candidate):
        # The value is preserved exactly as the provider supplied it.
        final_group = candidate.rsplit("-", 1)[1]
        kind = KIND_UUID if len(final_group) == MIN_FINAL_GROUP else KIND_PROVIDER
        return ScanIdentifier(value=candidate, kind=kind)

    raise ScanIdentifierError(
        f"The scan identifier {candidate!r} is not recognised. Supply a "
        "positive integer scan ID, such as 5 — that is the selector "
        "standalone Nessus expects — or a hyphenated hexadecimal provider "
        "identifier in 8-4-4-4-N form, where the final group is between "
        f"{MIN_FINAL_GROUP} and {MAX_FINAL_GROUP} hexadecimal characters. "
        "Scan names are not accepted because they need not be unique, and "
        "implicit selectors such as 'latest' are never accepted."
    )


def parse_export_scan_identifier(raw: object) -> ScanIdentifier:
    """Validate a scan identifier for **export**, which requires a numeric ID.

    Discovery keeps its wider provider-identifier support, but the export
    pipeline addresses the scan by number: the export, status and download
    paths are all built from it, and it is recorded in the manifest as an
    integer.  A provider identifier is therefore refused here rather than
    silently producing an artefact whose provenance is harder to check.
    """
    identifier = parse_scan_identifier(raw)
    if not identifier.is_numeric:
        raise ScanIdentifierError(
            f"Export requires the numeric scan ID, but {identifier.value!r} "
            "is a provider identifier. Run 'nessus scans list' and use the "
            "numeric SCAN ID column."
        )
    return identifier


def parse_history_identifier(raw: object) -> int:
    """Validate a history identifier, which is always a positive integer.

    A history is selected explicitly and by number.  There is no 'latest',
    no implicit selection and no name-based lookup.
    """
    if raw is None:
        raise ScanIdentifierError(
            "No history identifier was supplied. Provide --history with the "
            "positive integer HISTORY ID shown by 'nessus scans histories'."
        )
    if not isinstance(raw, str):
        raise ScanIdentifierError(
            "The history identifier must be text containing a positive "
            "integer HISTORY ID."
        )

    candidate = raw.strip()
    if not candidate:
        raise ScanIdentifierError(
            "The history identifier is blank. Provide the positive integer "
            "HISTORY ID shown by 'nessus scans histories'."
        )
    if len(candidate) > MAX_IDENTIFIER_LENGTH:
        raise ScanIdentifierError(
            f"The history identifier is {len(candidate)} characters long, "
            f"which exceeds the {MAX_IDENTIFIER_LENGTH}-character maximum."
        )

    for sequence in FORBIDDEN_SEQUENCES:
        if sequence in candidate:
            raise ScanIdentifierError(
                f"The history identifier {candidate!r} contains the "
                f"disallowed sequence {sequence!r}. Supply only a positive "
                "integer HISTORY ID; paths, query strings and fragments are "
                "not accepted."
            )

    if not _DIGITS.match(candidate):
        raise ScanIdentifierError(
            f"The history identifier {candidate!r} is not a positive "
            "integer. Use the HISTORY ID column of 'nessus scans histories'; "
            "history UUIDs, names and selectors such as 'latest' are never "
            "accepted."
        )

    numeric = int(candidate)
    if numeric <= 0:
        raise ScanIdentifierError(
            f"The history identifier {candidate!r} is not a positive "
            "integer. History IDs are whole numbers of 1 or greater."
        )
    if numeric > MAX_SCAN_ID:
        raise ScanIdentifierError(
            f"The history identifier {candidate!r} is larger than any "
            "history ID Nessus issues."
        )
    if candidate != str(numeric):
        raise ScanIdentifierError(
            f"The history identifier {candidate!r} has leading zeroes. "
            f"Supply it as {numeric}."
        )
    return numeric
