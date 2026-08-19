"""The shared, classified error type used across the Nessus integration.

Every failure VulnSight reports carries an :class:`~vulnsight.nessus.client.Outcome`,
so the stable exit-code contract established in Tranche 0 applies uniformly to
connectivity, discovery, export, XML validation and evidence handling.

Messages are built from static text and from non-secret values only.  No API
key, no ``X-ApiKeys`` header and no export token ever reaches an error message
or an object representation.
"""

from __future__ import annotations

from .client import EXIT_CODES, Outcome


class NessusError(Exception):
    """A classified, secret-free failure."""

    def __init__(self, outcome: Outcome, summary: str, detail: str = "") -> None:
        super().__init__(summary)
        self.outcome = outcome
        self.summary = summary
        self.detail = detail

    @property
    def exit_code(self) -> int:
        """The stable process exit code for this outcome."""
        return EXIT_CODES[self.outcome]


class ExportError(NessusError):
    """An export request, status poll or download failed."""


class XmlValidationError(NessusError):
    """A downloaded artefact is not a safe, well-formed ``.nessus`` document."""


class EvidenceError(NessusError):
    """A raw evidence file or manifest could not be created safely."""
