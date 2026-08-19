"""Acquisition sidecar manifest contract tests."""

from __future__ import annotations

import hashlib
import json

import pytest

from vulnsight.nessus.evidence import plan_paths
from vulnsight.nessus.export import ExportSettings
from vulnsight.nessus.manifest import (
    MANIFEST_SCHEMA,
    build_manifest,
    render_manifest,
)
from vulnsight.nessus.models import HistorySummary
from vulnsight.nessus.nessus_xml import XmlValidation
from conftest import FAKE_ACCESS_KEY, FAKE_SECRET_KEY, VALID_NESSUS_XML

FAKE_TOKEN = "TOKENtokenTOKEN-must-never-be-persisted"

HISTORY = HistorySummary(
    history_id=6,
    uuid="10000006-89ab-cdef-0123-456789abcdef",
    status="completed",
    creation_date=1_700_000_000,
    last_modification_date=1_700_003_600,
    run_type="local",
    is_rollover=False,
)

SETTINGS = ExportSettings(
    poll_interval_seconds=2.0, poll_timeout_seconds=600.0, max_bytes=1_073_741_824
)

VALIDATION = XmlValidation(
    root="NessusClientData_v2",
    report_count=1,
    report_host_count=1,
    report_item_count=2,
)

DIGEST = hashlib.sha256(VALID_NESSUS_XML).hexdigest()


@pytest.fixture
def manifest(tmp_path):
    return build_manifest(
        version="0.3.1",
        base_url="https://nessus.lab.invalid:8834",
        verify_tls=False,
        scan_id=5,
        scan_name="synthetic-lab-scan",
        history=HISTORY,
        settings=SETTINGS,
        file_id="9",
        paths=plan_paths(tmp_path, 5, 6, "synthetic-lab-scan"),
        size_bytes=len(VALID_NESSUS_XML),
        sha256=DIGEST,
        validation=VALIDATION,
        created_utc="2026-08-19T07:40:00Z",
        export_completed_utc="2026-08-19T07:39:58Z",
    )


# ---------------------------------------------------------------------------
# Contract
# ---------------------------------------------------------------------------


def test_the_contract_identifier_is_exact(manifest):
    assert manifest["manifest_schema"] == "vulnsight.nessus-export-manifest/1.1"
    assert MANIFEST_SCHEMA == "vulnsight.nessus-export-manifest/1.1"


def test_the_scan_section_field_order_is_fixed(manifest):
    assert list(manifest["scan"]) == [
        "scan_id",
        "scan_name",
        "history_id",
        "history_uuid",
        "history_status",
        "history_creation_date",
        "history_creation_utc",
        "history_last_modification_date",
        "history_last_modification_utc",
    ]


def test_top_level_field_order_is_fixed(manifest):
    assert list(manifest) == [
        "manifest_schema",
        "manifest_created_utc",
        "tool",
        "source",
        "scan",
        "export",
        "artefact",
        "validation",
    ]


def test_tool_and_source_provenance(manifest):
    assert manifest["tool"] == {"name": "VulnSight", "version": "0.3.1"}
    assert manifest["source"]["type"] == "nessus"
    assert manifest["source"]["base_url"] == "https://nessus.lab.invalid:8834"
    assert manifest["source"]["verify_tls"] is False


def test_raw_history_values_are_retained_verbatim(manifest):
    scan = manifest["scan"]

    assert scan["scan_id"] == 5
    assert scan["history_id"] == 6
    assert scan["history_uuid"] == HISTORY.uuid
    assert scan["history_status"] == "completed"
    assert scan["history_creation_date"] == 1_700_000_000
    assert scan["history_last_modification_date"] == 1_700_003_600


def test_utc_renderings_sit_alongside_the_raw_timestamps(manifest):
    scan = manifest["scan"]

    assert scan["history_creation_utc"] == "2023-11-14T22:13:20Z"
    assert scan["history_last_modification_utc"] == "2023-11-14T23:13:20Z"
    assert manifest["manifest_created_utc"].endswith("Z")
    assert manifest["export"]["completed_utc"].endswith("Z")


def test_absent_history_timestamps_stay_null(tmp_path):
    built = build_manifest(
        version="0.3.1",
        base_url="https://nessus.lab.invalid:8834",
        verify_tls=True,
        scan_id=5,
        scan_name="synthetic-lab-scan",
        history=HistorySummary(history_id=6, status="completed"),
        settings=SETTINGS,
        file_id="9",
        paths=plan_paths(tmp_path, 5, 6, "synthetic-lab-scan"),
        size_bytes=10,
        sha256=DIGEST,
        validation=VALIDATION,
        created_utc="2026-08-19T07:40:00Z",
        export_completed_utc="2026-08-19T07:39:58Z",
    )

    assert built["scan"]["history_creation_date"] is None
    assert built["scan"]["history_creation_utc"] is None
    assert built["scan"]["history_uuid"] is None


def test_export_provenance_records_the_bounded_parameters(manifest):
    export = manifest["export"]

    assert export["format"] == "nessus"
    assert export["request_path"] == "/scans/5/export"
    assert export["request_body"] == {"format": "nessus", "history_id": 6}
    assert export["file_id"] == "9"
    assert export["poll_interval_seconds"] == 2.0
    assert export["poll_timeout_seconds"] == 600.0
    assert export["max_bytes"] == 1_073_741_824


def test_artefact_and_validation_facts(manifest):
    assert manifest["artefact"]["filename"] == "synthetic-lab-scan__scan-5__history-6.nessus"
    assert manifest["artefact"]["size_bytes"] == len(VALID_NESSUS_XML)
    assert manifest["artefact"]["sha256"] == DIGEST
    assert manifest["validation"] == {
        "xml_root": "NessusClientData_v2",
        "report_count": 1,
        "report_host_count": 1,
        "report_item_count": 2,
    }


# ---------------------------------------------------------------------------
# Scan name (schema 1.1)
# ---------------------------------------------------------------------------


def build(tmp_path, scan_name, **overrides):
    """Build a manifest with a given scan name, defaults elsewhere."""
    arguments = {
        "version": "0.3.1",
        "base_url": "https://nessus.lab.invalid:8834",
        "verify_tls": True,
        "scan_id": 5,
        "scan_name": scan_name,
        "history": HISTORY,
        "settings": SETTINGS,
        "file_id": "9",
        "paths": plan_paths(tmp_path, 5, 6, scan_name),
        "size_bytes": 10,
        "sha256": DIGEST,
        "validation": VALIDATION,
        "created_utc": "2026-08-19T07:40:00Z",
        "export_completed_utc": "2026-08-19T07:39:58Z",
    }
    arguments.update(overrides)
    return build_manifest(**arguments)


@pytest.mark.parametrize(
    "scan_name",
    [
        "synthetic-lab-scan",
        "Weekly Perimeter Sweep",
        "Réseau Été",
        "  padded  ",
        "../../etc/passwd",
        "CON",
    ],
)
def test_the_raw_scan_name_is_preserved_exactly(tmp_path, scan_name):
    built = build(tmp_path, scan_name)

    assert built["scan"]["scan_name"] == scan_name


def test_a_missing_scan_name_is_null_not_empty(tmp_path):
    assert build(tmp_path, None)["scan"]["scan_name"] is None


def test_an_explicitly_empty_scan_name_is_empty_not_null(tmp_path):
    built = build(tmp_path, "")

    assert built["scan"]["scan_name"] == ""
    assert built["scan"]["scan_name"] is not None


def test_null_and_empty_names_render_distinctly(tmp_path):
    absent = render_manifest(build(tmp_path, None)).decode("utf-8")
    empty = render_manifest(build(tmp_path, "")).decode("utf-8")

    assert '"scan_name": null' in absent
    assert '"scan_name": ""' in empty
    assert absent != empty


@pytest.mark.parametrize(
    ("scan_name", "expected_stem"),
    [
        ("synthetic-lab-scan", "synthetic-lab-scan__scan-5__history-6"),
        ("Weekly Perimeter Sweep", "weekly-perimeter-sweep__scan-5__history-6"),
        ("../../etc/passwd", "etc-passwd__scan-5__history-6"),
        ("東京", "nessus__scan-5__history-6"),
        (None, "nessus__scan-5__history-6"),
        ("", "nessus__scan-5__history-6"),
    ],
)
def test_the_safe_filename_is_derived_independently_of_the_raw_name(
    tmp_path, scan_name, expected_stem
):
    built = build(tmp_path, scan_name)

    # The raw name is recorded as supplied; the filename carries only the slug.
    assert built["scan"]["scan_name"] == scan_name
    assert built["artefact"]["filename"] == f"{expected_stem}.nessus"


@pytest.mark.parametrize(
    "scan_name",
    [
        "../../etc/passwd",
        "C:\\Windows\\System32",
        "\\\\server\\share",
        "name\nwith\nnewlines",
        'quote"and\\backslash',
        "nul\x00byte",
        "tab\there",
    ],
)
def test_a_malicious_name_is_json_escaped_and_never_reaches_a_path(
    tmp_path, scan_name
):
    built = build(tmp_path, scan_name)
    rendered = render_manifest(built).decode("utf-8")

    # The raw value survives a JSON round trip byte-for-byte...
    assert json.loads(rendered)["scan"]["scan_name"] == scan_name
    # ...while the filename it produced contains none of it.
    filename = built["artefact"]["filename"]
    for forbidden in ("/", "\\", "..", ":", "\n", "\t", "\x00", '"'):
        assert forbidden not in filename


def test_the_manifest_never_records_a_server_supplied_export_filename(manifest):
    rendered = render_manifest(manifest).decode("utf-8")

    # Only the locally generated name is recorded, under artefact.filename.
    assert rendered.count("synthetic-lab-scan__scan-5__history-6.nessus") == 1
    assert "Content-Disposition" not in rendered
    assert "filename=" not in rendered


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "forbidden",
    [
        FAKE_ACCESS_KEY,
        FAKE_SECRET_KEY,
        FAKE_TOKEN,
        "X-ApiKeys",
        "accessKey",
        "secretKey",
        "token",
        "plugin_output",
        "ReportItem>",
    ],
)
def test_the_manifest_carries_no_secret_or_finding(manifest, forbidden):
    rendered = render_manifest(manifest).decode("utf-8")

    assert forbidden not in rendered


def test_the_manifest_has_no_targets_credentials_or_hosts(manifest):
    rendered = render_manifest(manifest).decode("utf-8").lower()

    for forbidden in ("target", "credential", "password", "hostname", "10.0.0."):
        assert forbidden not in rendered


# ---------------------------------------------------------------------------
# Deterministic rendering
# ---------------------------------------------------------------------------


def test_rendering_is_utf8_two_space_indented_and_newline_terminated(manifest):
    rendered = render_manifest(manifest)

    assert rendered.endswith(b"\n")
    assert b'\n  "manifest_created_utc"' in rendered
    assert rendered.decode("utf-8").startswith("{\n")


def test_rendering_is_byte_stable(manifest):
    assert render_manifest(manifest) == render_manifest(manifest)


def test_rendering_round_trips_as_json(manifest):
    parsed = json.loads(render_manifest(manifest).decode("utf-8"))

    assert parsed == manifest
    assert list(parsed) == list(manifest)


def test_unicode_is_preserved_rather_than_escaped(tmp_path):
    built = build_manifest(
        version="0.3.1",
        base_url="https://nessus.lab.invalid:8834",
        verify_tls=True,
        scan_id=5,
        scan_name="synthetic-lab-scan",
        history=HistorySummary(history_id=6, status="compléted"),
        settings=SETTINGS,
        file_id="9",
        paths=plan_paths(tmp_path, 5, 6, "synthetic-lab-scan"),
        size_bytes=10,
        sha256=DIGEST,
        validation=VALIDATION,
        created_utc="2026-08-19T07:40:00Z",
        export_completed_utc="2026-08-19T07:39:58Z",
    )

    assert "compléted" in render_manifest(built).decode("utf-8")
