"""Nessus integration for VulnSight.

Tranche 0 added a read-only connectivity preflight.  Tranche 1 added
read-only scan and history discovery.  Tranche 2 adds explicit native
``.nessus`` export with an acquisition manifest.

Every request is a GET except one: ``POST /scans/{scan_id}/export``, which
Nessus requires in order to build an export artefact.  Nothing here launches,
stops, reschedules, modifies or deletes a scan, and no PUT, PATCH or DELETE
request exists anywhere in this package.
"""

from .acquisition import (
    AcquisitionResult,
    SelectedHistory,
    acquire_export,
    select_completed_history,
)
from .client import (
    EXIT_CODES,
    ConnectivityResult,
    Outcome,
    Stage,
    check_connectivity,
)
from .discovery import DiscoveryError, list_scan_history, list_scans
from .errors import EvidenceError, ExportError, NessusError, XmlValidationError
from .evidence import EvidencePaths, artefact_stem, plan_paths, safe_scan_slug
from .export import Clock, ExportSettings
from .identifiers import (
    ScanIdentifier,
    ScanIdentifierError,
    parse_export_scan_identifier,
    parse_history_identifier,
    parse_scan_identifier,
)
from .manifest import MANIFEST_SCHEMA, build_manifest, render_manifest
from .models import (
    HistoryDiscoveryResult,
    HistorySummary,
    ScanDiscoveryResult,
    ScanSummary,
)
from .nessus_xml import NESSUS_ROOT, XmlValidation, validate_nessus_file

__all__ = [
    "EXIT_CODES",
    "MANIFEST_SCHEMA",
    "NESSUS_ROOT",
    "AcquisitionResult",
    "Clock",
    "ConnectivityResult",
    "DiscoveryError",
    "EvidenceError",
    "EvidencePaths",
    "ExportError",
    "ExportSettings",
    "HistoryDiscoveryResult",
    "HistorySummary",
    "NessusError",
    "Outcome",
    "ScanDiscoveryResult",
    "ScanIdentifier",
    "ScanIdentifierError",
    "ScanSummary",
    "SelectedHistory",
    "Stage",
    "XmlValidation",
    "XmlValidationError",
    "acquire_export",
    "artefact_stem",
    "build_manifest",
    "check_connectivity",
    "list_scan_history",
    "list_scans",
    "parse_export_scan_identifier",
    "parse_history_identifier",
    "parse_scan_identifier",
    "plan_paths",
    "render_manifest",
    "safe_scan_slug",
    "select_completed_history",
    "validate_nessus_file",
]
