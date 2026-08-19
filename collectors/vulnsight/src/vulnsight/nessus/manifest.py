"""The acquisition sidecar manifest.

This records how one ``.nessus`` artefact was obtained, so its provenance and
integrity can be checked independently later.  It is an *acquisition*
manifest, not the complete experimental campaign manifest.

The manifest may identify the lab endpoint, because it lives beside secured
raw evidence.  It must nevertheless contain no secret: no API access key, no
secret key, no ``X-ApiKeys`` header, no export token, no response headers, no
``.env`` content, and no targets, credentials, plugin output, findings, host
details, scores or analytical conclusions.

It is written deterministically: UTF-8, a fixed field order, two-space
indentation and a terminating newline, so two acquisitions of the same
artefact differ only where the facts differ.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .evidence import EvidencePaths
from .export import EXPORT_FORMAT, ExportSettings, export_path, export_request_body
from .models import HistorySummary, to_iso8601_utc
from .nessus_xml import XmlValidation

#: The versioned contract identifier for this manifest.
#:
#: 1.1 adds ``scan.scan_name``, the provider's own scan name recorded exactly
#: as supplied.  The addition is purely additive: manifests already written
#: under 1.0 remain valid historical acquisition records, are never rewritten
#: or migrated, and are still readable by anything that understands 1.0.
MANIFEST_SCHEMA = "vulnsight.nessus-export-manifest/1.1"

SOURCE_TYPE = "nessus"
TOOL_NAME = "VulnSight"


def utc_now() -> str:
    """The current time as ISO 8601 in UTC, to the second."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_manifest(
    *,
    version: str,
    base_url: str,
    verify_tls: bool,
    scan_id: int,
    scan_name: str | None,
    history: HistorySummary,
    settings: ExportSettings,
    file_id: str,
    paths: EvidencePaths,
    size_bytes: int,
    sha256: str,
    validation: XmlValidation,
    created_utc: str,
    export_completed_utc: str,
) -> dict:
    """Build the manifest document.

    Raw provider values from the selected history are retained exactly as
    Nessus supplied them; the ISO 8601 renderings sit alongside them rather
    than replacing them.

    ``scan_name`` is likewise recorded verbatim: the exact provider string
    when one was supplied, ``None`` when it was absent or not text, and an
    empty string only when Nessus explicitly supplied one.  It is never
    replaced by the sanitised slug used in the filename — the raw name and
    the safe filename are recorded independently so neither can be mistaken
    for the other.
    """
    return {
        "manifest_schema": MANIFEST_SCHEMA,
        "manifest_created_utc": created_utc,
        "tool": {
            "name": TOOL_NAME,
            "version": version,
        },
        "source": {
            "type": SOURCE_TYPE,
            "base_url": base_url,
            "verify_tls": verify_tls,
        },
        "scan": {
            "scan_id": scan_id,
            "scan_name": scan_name,
            "history_id": history.history_id,
            "history_uuid": history.uuid,
            "history_status": history.status,
            "history_creation_date": history.creation_date,
            "history_creation_utc": _iso(history.creation_date),
            "history_last_modification_date": history.last_modification_date,
            "history_last_modification_utc": _iso(history.last_modification_date),
        },
        "export": {
            "format": EXPORT_FORMAT,
            "request_path": export_path(scan_id),
            "request_body": export_request_body(history.history_id),
            "file_id": file_id,
            "poll_interval_seconds": settings.poll_interval_seconds,
            "poll_timeout_seconds": settings.poll_timeout_seconds,
            "max_bytes": settings.max_bytes,
            "completed_utc": export_completed_utc,
        },
        "artefact": {
            "filename": paths.raw.name,
            "size_bytes": size_bytes,
            "sha256": sha256,
        },
        "validation": {
            "xml_root": validation.root,
            "report_count": validation.report_count,
            "report_host_count": validation.report_host_count,
            "report_item_count": validation.report_item_count,
        },
    }


def render_manifest(manifest: dict) -> bytes:
    """Serialise the manifest deterministically as UTF-8 bytes.

    Field order is the insertion order built above, which is fixed in code,
    so the rendering is stable across runs and platforms.
    """
    text = json.dumps(
        manifest,
        indent=2,
        ensure_ascii=False,
        sort_keys=False,
        separators=(",", ": "),
    )
    return (text + "\n").encode("utf-8")


def _iso(timestamp: int | None) -> str | None:
    if timestamp is None:
        return None
    return to_iso8601_utc(timestamp)
