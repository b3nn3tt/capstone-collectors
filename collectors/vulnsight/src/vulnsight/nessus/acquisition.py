"""End-to-end acquisition of one native ``.nessus`` export.

The pipeline is deliberately linear and explicit:

1. create the output directory;
2. confirm the explicitly requested history exists and that its
   provider-supplied status is exactly ``completed``, reading the scan name
   from that same response so the output can be named legibly;
3. resolve the two destination paths and refuse to continue if either
   already exists — before any export request reaches the scanner;
4. ``POST /scans/{scan_id}/export`` with the documented body;
5. poll ``.../status`` within a bounded time;
6. stream ``.../download`` to a unique ``.part`` file, hashing as it goes;
7. validate the artefact structurally with a safe XML parser;
8. commit the raw file and its sidecar manifest together.

Nothing is selected automatically: the caller supplies the scan ID and the
history ID.  Acquisition stops here — no finding is parsed or interpreted.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import requests

from ..config import NessusConfig
from .client import Outcome
from .discovery import list_scan_history
from .errors import EvidenceError, ExportError, NessusError
from .evidence import (
    EvidencePaths,
    assert_absent,
    commit,
    discard,
    ensure_directory,
    new_part_path,
    plan_paths,
)
from .export import (
    Clock,
    ExportSettings,
    download_export,
    request_export,
    wait_until_ready,
)
from .identifiers import ScanIdentifier
from .manifest import build_manifest, render_manifest, utc_now
from .models import HistorySummary
from .nessus_xml import XmlValidation, validate_nessus_file


@dataclass(frozen=True)
class AcquisitionResult:
    """What one successful acquisition produced.

    No export token, response header or API key is present, by construction.
    """

    raw_path: Path
    manifest_path: Path
    size_bytes: int
    sha256: str
    file_id: str
    polls: int
    history: HistorySummary
    validation: XmlValidation
    scan_name: str | None = None


@dataclass(frozen=True)
class SelectedHistory:
    """The explicitly requested run, plus the scan name from the same read.

    Both come from the single ``GET /scans/{scan_id}`` eligibility request:
    the name is taken from the response already being read, never from an
    extra request.
    """

    history: HistorySummary
    scan_name: str | None = None


def acquire_export(
    config: NessusConfig,
    scan: ScanIdentifier,
    history_id: int,
    output_dir: Path | str,
    *,
    clock: Clock | None = None,
    now: Callable[[], str] | None = None,
) -> AcquisitionResult:
    """Acquire one native export for an explicitly selected completed run."""
    if scan.numeric_id is None:  # pragma: no cover - guarded by the CLI parser
        raise EvidenceError(
            Outcome.CONFIGURATION_ERROR,
            "Export requires the numeric scan ID.",
        )
    scan_id = scan.numeric_id
    timestamp = utc_now if now is None else now
    settings = ExportSettings.from_config(config)

    ensure_directory(output_dir)

    # The read-only eligibility request also carries the scan name used to
    # make the filenames legible, so no extra request is made for it. The
    # destinations are resolved and checked immediately afterwards, still
    # before any export request reaches the scanner.
    selected = select_completed_history(config, scan, history_id)
    history = selected.history

    paths = plan_paths(output_dir, scan_id, history_id, selected.scan_name)
    assert_absent(paths)

    part_path: Path | None = None
    session = requests.Session()
    try:
        file_id = request_export(session, config, scan_id, history_id)
        polls = wait_until_ready(session, config, scan_id, file_id, settings, clock)
        part_path = new_part_path(paths)
        download = download_export(
            session, config, scan_id, file_id, settings, part_path
        )
    except BaseException:
        discard(part_path)
        raise
    finally:
        session.close()

    try:
        validation = validate_nessus_file(part_path)
        manifest = build_manifest(
            version=_tool_version(),
            base_url=config.endpoint,
            verify_tls=config.verify_tls,
            scan_id=scan_id,
            scan_name=selected.scan_name,
            history=history,
            settings=settings,
            file_id=file_id,
            paths=paths,
            size_bytes=download.size_bytes,
            sha256=download.sha256,
            validation=validation,
            created_utc=timestamp(),
            export_completed_utc=timestamp(),
        )
        commit(part_path, paths, render_manifest(manifest))
    except BaseException:
        discard(part_path)
        raise

    return AcquisitionResult(
        raw_path=paths.raw,
        manifest_path=paths.manifest,
        size_bytes=download.size_bytes,
        sha256=download.sha256,
        file_id=file_id,
        polls=polls,
        history=history,
        validation=validation,
        scan_name=selected.scan_name,
    )


def select_completed_history(
    config: NessusConfig, scan: ScanIdentifier, history_id: int
) -> SelectedHistory:
    """Return the requested run, or fail before any export request is made.

    The run must exist in the scan's own history collection and its
    provider-supplied status must be exactly ``completed``, compared
    case-insensitively.  Completion is never inferred from a timestamp, and
    no run is ever chosen on the user's behalf.

    The scan name from the same response is returned alongside it, so the
    caller can name the output legibly without a second request.
    """
    result = list_scan_history(config, scan)

    for run in result.runs:
        if run.history_id != history_id:
            continue
        if not run.export_eligible:
            raise ExportError(
                Outcome.CONFIGURATION_ERROR,
                f"History {history_id} of scan {scan.value} has the provider "
                f"status '{run.status}', not 'completed', so it is not "
                "eligible for export. Only a run Nessus reports as completed "
                "is exported; completion is never inferred from a timestamp. "
                "No export was requested.",
            )
        return SelectedHistory(history=run, scan_name=result.scan_name)

    available = ", ".join(str(run.history_id) for run in result.runs) or "none"
    raise ExportError(
        Outcome.CONFIGURATION_ERROR,
        f"History {history_id} was not found in the history of scan "
        f"{scan.value}. Run 'nessus scans histories --scan {scan.value}' and "
        f"choose a history ID from that output. Available history IDs: "
        f"{available}. No export was requested.",
    )


def _tool_version() -> str:
    from .. import __version__

    return __version__


__all__ = [
    "AcquisitionResult",
    "EvidencePaths",
    "NessusError",
    "SelectedHistory",
    "acquire_export",
    "select_completed_history",
]
