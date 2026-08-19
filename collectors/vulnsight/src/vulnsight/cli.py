"""Command-line interface for VulnSight.

Tranche 2 exposes four commands::

    python -m vulnsight nessus check
    python -m vulnsight nessus scans list
    python -m vulnsight nessus scans histories --scan 5
    python -m vulnsight nessus scans export --scan 5 --history 6 \\
        --output-dir ".\\evidence\\raw\\nessus"

Presentation lives here; configuration, connectivity, discovery, export and
evidence logic do not.  Output is deliberately terse: a table, at most one
``Next:`` suggestion, and a compact warning on stderr when TLS verification
is disabled.  The longer explanations live in the README and in ``--help``.

No scan and no historical run is ever selected automatically.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence, TextIO

from . import __version__
from .config import ConfigError, NessusConfig, load_config
from .nessus.acquisition import AcquisitionResult, acquire_export
from .nessus.client import EXIT_CODES, ConnectivityResult, Outcome, check_connectivity
from .nessus.discovery import list_scan_history, list_scans
from .nessus.errors import NessusError
from .nessus.identifiers import (
    ScanIdentifierError,
    parse_export_scan_identifier,
    parse_history_identifier,
    parse_scan_identifier,
)
from .nessus.models import (
    HistoryDiscoveryResult,
    ScanDiscoveryResult,
    display,
    display_timestamp,
)

#: The output directory suggested in ``Next:`` lines and documentation.
DEFAULT_EVIDENCE_HINT = r".\evidence\raw\nessus"

PROGRAM_NAME = "vulnsight"

EXIT_SUCCESS = EXIT_CODES[Outcome.SUCCESS]
EXIT_CONFIGURATION = EXIT_CODES[Outcome.CONFIGURATION_ERROR]
EXIT_NETWORK = EXIT_CODES[Outcome.NETWORK_ERROR]
EXIT_AUTHENTICATION = EXIT_CODES[Outcome.AUTHENTICATION_ERROR]
EXIT_API = EXIT_CODES[Outcome.API_ERROR]


def build_parser() -> argparse.ArgumentParser:
    """Construct the Tranche 1 argument parser."""
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description=(
            "VulnSight — contextual vulnerability prioritisation. "
            "Tranche 2 provides a Nessus connectivity preflight, read-only "
            "scan and history discovery, and explicit native .nessus export "
            "with an acquisition manifest."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{PROGRAM_NAME} {__version__}",
    )

    commands = parser.add_subparsers(dest="command", metavar="command")

    nessus = commands.add_parser(
        "nessus",
        help="Nessus scanner commands.",
        description="Nessus scanner commands.",
    )
    nessus_commands = nessus.add_subparsers(dest="subcommand", metavar="subcommand")
    nessus_commands.add_parser(
        "check",
        help="Verify connectivity and API authentication against Nessus.",
        description=(
            "Verify connectivity and API authentication against Nessus. "
            "This is a read-only check: no scan is created, modified, "
            "launched, stopped, exported or deleted."
        ),
    )

    scans = nessus_commands.add_parser(
        "scans",
        help="Scan and history discovery, and native .nessus export.",
        description=(
            "Scan and history discovery, and explicit native .nessus export. "
            "Discovery uses GET only and saves nothing. Export additionally "
            "uses POST /scans/{scan_id}/export, which is the only write-shaped "
            "call VulnSight makes and which creates an export artefact "
            "without launching, stopping, rescheduling, modifying or deleting "
            "the scan."
        ),
    )
    scans_commands = scans.add_subparsers(dest="scans_command", metavar="subcommand")

    scans_commands.add_parser(
        "list",
        help="List the scans visible to the configured account.",
        description=(
            "List the scan configurations visible to the configured Nessus "
            "account using GET /scans. Targets, credentials, policy contents, "
            "hosts and findings are never displayed, and the response is not "
            "saved."
        ),
    )

    histories = scans_commands.add_parser(
        "histories",
        help="List the execution history of one explicitly selected scan.",
        description=(
            "List the individual executions of one explicitly selected scan. "
            "The history is read from the 'history' collection of a single "
            "GET /scans/{scan} scan-details response; no other part of that "
            "response is parsed, displayed or saved. No scan and no "
            "historical run is chosen automatically."
        ),
    )
    histories.add_argument(
        "--scan",
        required=True,
        metavar="IDENTIFIER",
        help=(
            "The scan to inspect. Use the numeric SCAN ID shown by "
            "'nessus scans list' — that is the selector standalone Nessus "
            "expects. A hyphenated hexadecimal provider identifier is also "
            "accepted, but only works if the deployed endpoint resolves it. "
            "VulnSight never selects a scan by name."
        ),
    )

    export = scans_commands.add_parser(
        "export",
        help="Export one explicitly selected completed run as native .nessus.",
        description=(
            "Export one explicitly selected completed historical run as a "
            "native .nessus file, with a SHA-256 checksum and an acquisition "
            "manifest beside it. Both the scan and the history are chosen by "
            "you: there is no 'latest', no implicit selection and no "
            "name-based lookup. The run's provider status must be exactly "
            "'completed'; completion is never inferred from a timestamp. "
            "Eligibility is confirmed with GET /scans/{scan_id} before "
            "anything is requested, and an existing output file or manifest "
            "stops the command before the scanner is contacted. Existing "
            "evidence is never overwritten and there is no --force. Only the "
            "native .nessus format is supported, and no finding is parsed."
        ),
    )
    export.add_argument(
        "--scan",
        required=True,
        metavar="SCAN_ID",
        help=(
            "The numeric SCAN ID to export, from 'nessus scans list'. Export "
            "requires the numeric ID; a provider identifier is not accepted."
        ),
    )
    export.add_argument(
        "--history",
        required=True,
        metavar="HISTORY_ID",
        help=(
            "The numeric HISTORY ID of the completed run to export, from "
            "'nessus scans histories --scan <SCAN ID>'."
        ),
    )
    export.add_argument(
        "--output-dir",
        required=True,
        metavar="DIRECTORY",
        help=(
            "The raw evidence directory. It is created if absent. The "
            "filenames are generated locally and are never taken from the "
            "server."
        ),
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface and return a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_CONFIGURATION
    if getattr(args, "subcommand", None) is None:
        parser.print_help()
        return EXIT_CONFIGURATION

    if args.subcommand == "check":
        return _run_nessus_check()

    if getattr(args, "scans_command", None) is None:
        parser.print_help()
        return EXIT_CONFIGURATION
    if args.scans_command == "list":
        return _run_scans_list()
    if args.scans_command == "histories":
        return _run_scan_histories(args.scan)
    return _run_scans_export(args.scan, args.history, args.output_dir)


def run() -> None:  # pragma: no cover - thin process entry point
    """Console-script entry point."""
    sys.exit(main())


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def _streams(out: TextIO | None, err: TextIO | None) -> tuple[TextIO, TextIO]:
    return (sys.stdout if out is None else out, sys.stderr if err is None else err)


def _load_config(stderr: TextIO) -> NessusConfig | None:
    """Load configuration, reporting a configuration error to *stderr*."""
    try:
        return load_config()
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=stderr)
        return None


def _report_nessus_error(exc: NessusError, stderr: TextIO, action: str) -> int:
    """Present a classified failure concisely and return its exit code."""
    lines = [f"{action} failed: {exc.summary}"]
    if exc.detail:
        lines.append(f"Detail: {exc.detail}")
    print("\n".join(lines), file=stderr)
    return exc.exit_code


def _print_warnings(config: NessusConfig, stderr: TextIO) -> None:
    """Emit one compact warning line per configuration warning, on stderr."""
    for message in config.warnings:
        print(f"Warning: {message}", file=stderr)


# ---------------------------------------------------------------------------
# nessus check (Tranche 0 behaviour, unchanged)
# ---------------------------------------------------------------------------


def _run_nessus_check(
    out: TextIO | None = None, err: TextIO | None = None
) -> int:
    """Execute the connectivity preflight and present the outcome."""
    stdout, stderr = _streams(out, err)

    config = _load_config(stderr)
    if config is None:
        return EXIT_CONFIGURATION

    try:
        result = check_connectivity(config)
    except Exception:
        # Raw exception dumps are never shown during normal use.
        print(
            "Unexpected internal error while checking Nessus connectivity. "
            "Re-run the check; if the problem persists, review the "
            "configuration in .env.",
            file=stderr,
        )
        return EXIT_API

    if result.ok:
        print(format_success(result), file=stdout)
    else:
        print(format_failure(result), file=stderr)

    return result.exit_code


def format_success(result: ConnectivityResult) -> str:
    """Render a brief, secret-free success report."""
    tls_state = (
        "enabled"
        if result.verify_tls
        else "DISABLED (certificate verification was not performed)"
    )
    lines = [
        "Nessus connectivity check: PASSED",
        f"  Endpoint................ {result.endpoint}",
        "  TCP connectivity........ established",
        "  API authentication...... accepted",
        f"  GET /scans.............. valid JSON response (HTTP {result.http_status})",
        f"  TLS verification........ {tls_state}",
    ]
    lines.extend(f"  Warning: {message}" for message in result.warnings)
    return "\n".join(lines)


def format_failure(result: ConnectivityResult) -> str:
    """Render a concise, secret-free failure report."""
    lines = [
        "Nessus connectivity check: FAILED",
        f"  Endpoint................ {result.endpoint}",
        f"  Stage................... {result.stage.value}",
        f"  Reason.................. {result.summary}",
    ]
    if result.http_status is not None:
        lines.append(f"  HTTP status............. {result.http_status}")
    lines.append(
        "  TLS verification........ "
        + ("enabled" if result.verify_tls else "disabled")
    )
    lines.extend(f"  Warning: {message}" for message in result.warnings)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# nessus scans list
# ---------------------------------------------------------------------------


def _run_scans_list(out: TextIO | None = None, err: TextIO | None = None) -> int:
    """List the scans visible to the configured account."""
    stdout, stderr = _streams(out, err)

    config = _load_config(stderr)
    if config is None:
        return EXIT_CONFIGURATION

    try:
        result = list_scans(config)
    except NessusError as exc:
        return _report_nessus_error(exc, stderr, "Nessus discovery")
    except Exception:
        print(
            "Unexpected internal error while listing Nessus scans. Re-run the "
            "command; if the problem persists, review the configuration in "
            ".env.",
            file=stderr,
        )
        return EXIT_API

    print(format_scan_list(result), file=stdout)
    _print_warnings(config, stderr)
    return EXIT_SUCCESS


def format_scan_list(result: ScanDiscoveryResult) -> str:
    """Render the scan listing: a table and one Next: line, nothing else."""
    if result.is_empty:
        return "No scans returned."

    headers = (
        "SCAN ID",
        "UUID",
        "NAME",
        "STATUS",
        "FOLDER",
        "LAST MODIFIED (UTC)",
    )
    rows = [
        (
            str(scan.scan_id),
            display(scan.uuid),
            display(scan.name),
            display(scan.status),
            display(scan.folder_id),
            display_timestamp(scan.last_modification_date),
        )
        for scan in result.scans
    ]

    lines = _render_table(headers, rows, leading_blank=False)
    lines.append("")
    lines.append(
        "Next: python -m vulnsight nessus scans histories --scan <SCAN ID>"
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# nessus scans histories
# ---------------------------------------------------------------------------


def _run_scan_histories(
    raw_identifier: str, out: TextIO | None = None, err: TextIO | None = None
) -> int:
    """List the execution history of one explicitly selected scan."""
    stdout, stderr = _streams(out, err)

    try:
        identifier = parse_scan_identifier(raw_identifier)
    except ScanIdentifierError as exc:
        print(f"Invalid --scan value: {exc}", file=stderr)
        return EXIT_CONFIGURATION

    config = _load_config(stderr)
    if config is None:
        return EXIT_CONFIGURATION

    try:
        result = list_scan_history(config, identifier)
    except NessusError as exc:
        return _report_nessus_error(exc, stderr, "Nessus discovery")
    except Exception:
        print(
            "Unexpected internal error while listing the scan history. Re-run "
            "the command; if the problem persists, review the configuration "
            "in .env.",
            file=stderr,
        )
        return EXIT_API

    print(format_history_list(result), file=stdout)
    _print_warnings(config, stderr)
    return EXIT_SUCCESS


def format_history_list(result: HistoryDiscoveryResult) -> str:
    """Render the history listing: a table and one Next: line, nothing else."""
    if result.is_empty:
        return f"No history returned for scan '{result.scan_identifier}'."

    headers = (
        "HISTORY ID",
        "UUID",
        "STATUS",
        "STARTED (UTC)",
        "LAST MODIFIED (UTC)",
        "TYPE",
        "ROLLOVER",
        "EXPORT-ELIGIBLE",
    )
    rows = [
        (
            str(run.history_id),
            display(run.uuid),
            display(run.status),
            display_timestamp(run.creation_date),
            display_timestamp(run.last_modification_date),
            display(run.run_type),
            display(run.is_rollover),
            "yes" if run.export_eligible else "no",
        )
        for run in result.runs
    ]

    lines = _render_table(headers, rows, leading_blank=False)
    lines.append("")
    lines.append(
        "Next: python -m vulnsight nessus scans export "
        f"--scan {result.scan_identifier} --history <HISTORY_ID> "
        f'--output-dir "{DEFAULT_EVIDENCE_HINT}"'
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# nessus scans export
# ---------------------------------------------------------------------------


def _run_scans_export(
    raw_scan: str,
    raw_history: str,
    output_dir: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    """Acquire one native .nessus export for an explicitly selected run."""
    stdout, stderr = _streams(out, err)

    try:
        scan = parse_export_scan_identifier(raw_scan)
    except ScanIdentifierError as exc:
        print(f"Invalid --scan value: {exc}", file=stderr)
        return EXIT_CONFIGURATION

    try:
        history_id = parse_history_identifier(raw_history)
    except ScanIdentifierError as exc:
        print(f"Invalid --history value: {exc}", file=stderr)
        return EXIT_CONFIGURATION

    if not str(output_dir).strip():
        print(
            "Invalid --output-dir value: the output directory is blank.",
            file=stderr,
        )
        return EXIT_CONFIGURATION

    config = _load_config(stderr)
    if config is None:
        return EXIT_CONFIGURATION

    try:
        result = acquire_export(config, scan, history_id, output_dir)
    except NessusError as exc:
        return _report_nessus_error(exc, stderr, "Nessus export")
    except OSError as exc:
        print(
            f"Nessus export failed: the evidence directory could not be "
            f"written ({type(exc).__name__}).",
            file=stderr,
        )
        return EXIT_API
    except Exception:
        print(
            "Unexpected internal error while exporting the scan. Re-run the "
            "command; if the problem persists, review the configuration in "
            ".env.",
            file=stderr,
        )
        return EXIT_API

    print(format_export_result(result), file=stdout)
    _print_warnings(config, stderr)
    return EXIT_SUCCESS


def format_export_result(result: AcquisitionResult) -> str:
    """Render the acquisition outcome as a compact table."""
    rows = [
        ("File", str(result.raw_path)),
        ("Manifest", str(result.manifest_path)),
        ("Bytes", str(result.size_bytes)),
        ("SHA-256", result.sha256),
    ]
    return "\n".join(
        _render_table(("ITEM", "VALUE"), rows, leading_blank=False)
    )


# ---------------------------------------------------------------------------
# Table rendering
# ---------------------------------------------------------------------------


def _render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    leading_blank: bool = True,
) -> list[str]:
    """Render a fixed-column table with a rule beneath the headings."""
    widths = [len(heading) for heading in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def _line(cells: Sequence[str]) -> str:
        return "  ".join(
            cell.ljust(widths[index]) for index, cell in enumerate(cells)
        ).rstrip()

    lines = [""] if leading_blank else []
    lines.append(_line(headers))
    lines.append("  ".join("-" * width for width in widths))
    lines.extend(_line(row) for row in rows)
    return lines
