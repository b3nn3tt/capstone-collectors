"""Safe structural validation of a downloaded ``.nessus`` artefact.

A downloaded export is untrusted XML until it has been checked.  Validation
uses ``defusedxml``, which refuses DTD declarations, entity declarations and
external references, so no entity-expansion or external-fetch attack can be
triggered by an artefact.

Parsing is done incrementally through a counting target, so no element tree is
ever built: memory stays constant regardless of artefact size, and no finding
is extracted, normalised or interpreted.  The counts produced here are
acquisition-validation metadata only.

The file is opened read-only and is never rewritten, reserialised,
pretty-printed or re-encoded.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from defusedxml import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
from defusedxml.ElementTree import DefusedXMLParser, ParseError

from .client import Outcome
from .errors import XmlValidationError

#: The only acceptable root element of a native Nessus export.
NESSUS_ROOT = "NessusClientData_v2"

#: Elements counted purely to evidence that acquisition produced a structurally
#: complete document.  These are not findings and are not interpreted.
REPORT_TAG = "Report"
REPORT_HOST_TAG = "ReportHost"
REPORT_ITEM_TAG = "ReportItem"

#: Bytes fed to the parser at a time.
DEFAULT_CHUNK_BYTES = 65_536


@dataclass(frozen=True)
class XmlValidation:
    """Structural facts about a validated artefact."""

    root: str
    report_count: int
    report_host_count: int
    report_item_count: int


class _CountingTarget:
    """An ElementTree target that counts elements and builds no tree."""

    def __init__(self) -> None:
        self.root: str | None = None
        self.counts: dict[str, int] = {
            REPORT_TAG: 0,
            REPORT_HOST_TAG: 0,
            REPORT_ITEM_TAG: 0,
        }

    def start(self, tag: str, attrib: dict) -> None:
        if self.root is None:
            self.root = tag
        if tag in self.counts:
            self.counts[tag] += 1

    def end(self, tag: str) -> None:
        return None

    def data(self, data: str) -> None:
        return None

    def close(self) -> str | None:
        return self.root


def validate_nessus_file(
    path: Path, *, chunk_bytes: int = DEFAULT_CHUNK_BYTES
) -> XmlValidation:
    """Validate *path* structurally without altering a single byte of it.

    Raises :class:`~vulnsight.nessus.errors.XmlValidationError` for malformed
    or truncated XML, for a DTD, entity declaration or external reference, for
    a wrong root element, for a document with no ``Report``, and for HTML or
    JSON error content served in place of an artefact.

    A completed scan that found no live hosts and no findings is valid: only
    the root element and at least one ``Report`` are required.
    """
    target = _CountingTarget()
    parser = DefusedXMLParser(
        target=target,
        forbid_dtd=True,
        forbid_entities=True,
        forbid_external=True,
    )

    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(chunk_bytes)
                if not chunk:
                    break
                parser.feed(chunk)
        parser.close()
    except DTDForbidden as exc:
        raise _rejected(
            "it declares a DTD. VulnSight refuses DTDs in untrusted XML.", exc
        ) from exc
    except EntitiesForbidden as exc:
        raise _rejected(
            "it declares an XML entity. VulnSight refuses entity declarations "
            "and entity expansion in untrusted XML.",
            exc,
        ) from exc
    except ExternalReferenceForbidden as exc:
        raise _rejected(
            "it contains an external reference. VulnSight never resolves "
            "external references in untrusted XML.",
            exc,
        ) from exc
    except ParseError as exc:
        raise _rejected(
            "it is not well-formed XML. The artefact is malformed or the "
            "download was truncated.",
            exc,
        ) from exc

    if target.root != NESSUS_ROOT:
        raise _rejected(
            f"its root element is '{target.root}' rather than "
            f"'{NESSUS_ROOT}'. This is not a native Nessus export."
        )
    if target.counts[REPORT_TAG] < 1:
        raise _rejected(
            f"it contains no '{REPORT_TAG}' element, so no scan report was "
            "delivered."
        )

    return XmlValidation(
        root=target.root,
        report_count=target.counts[REPORT_TAG],
        report_host_count=target.counts[REPORT_HOST_TAG],
        report_item_count=target.counts[REPORT_ITEM_TAG],
    )


def _rejected(reason: str, exc: BaseException | None = None) -> XmlValidationError:
    detail = "" if exc is None else f"{type(exc).__name__}: {exc}"
    return XmlValidationError(
        Outcome.API_ERROR,
        f"The downloaded artefact was rejected because {reason} Nothing was "
        "committed to the evidence directory.",
        detail,
    )
